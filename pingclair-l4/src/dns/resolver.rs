// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌐 Scoped Hickory queries with one deadline and bounded CNAME traversal.

use super::tasks::Provider;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverOpts};
use hickory_resolver::net::NetError;
use hickory_resolver::net::xfer::{DnsHandle, FirstAnswer};
use hickory_resolver::proto::op::{DnsRequestOptions, Query, ResponseCode};
use hickory_resolver::proto::rr::{Name, RData, RecordType};
use hickory_resolver::{NameServerPool, PoolContext, TlsConfig};
use pingclair_core::config::{Layer4Dns, Layer4IpVersions};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::{Instant, timeout};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Failure {
    Empty,
    NxDomain,
    Transient,
    Timeout,
    Invalid,
    Cancelled,
}

pub(super) struct Answer {
    pub addresses: Vec<SocketAddr>,
    pub fresh: Instant,
}

#[derive(PartialEq, Eq)]
pub(super) struct Endpoint {
    address: SocketAddr,
    tcp: bool,
    bind: Option<SocketAddr>,
}

pub(super) struct Resolver {
    name: Name,
    port: u16,
    versions: Layer4IpVersions,
    servers: Vec<NameServerConfig>,
    pub endpoints: Vec<Endpoint>,
    context: Arc<PoolContext>,
}

impl Resolver {
    pub fn prepare(config: &Layer4Dns) -> io::Result<Self> {
        let mut name = Name::from_ascii(&config.name).map_err(io::Error::other)?;
        name.set_fqdn(true);
        let servers = if let Some(resolvers) = &config.resolvers {
            resolvers
                .iter()
                .map(|resolver| {
                    let address = resolver
                        .parse::<IpAddr>()
                        .map(|ip| SocketAddr::new(ip, 53))
                        .or_else(|_| resolver.parse::<SocketAddr>())
                        .map_err(io::Error::other)?;
                    if address.port() == 0 {
                        return Err(io::ErrorKind::InvalidInput.into());
                    }
                    let mut udp = ConnectionConfig::new(ProtocolConfig::Udp);
                    let mut tcp = ConnectionConfig::new(ProtocolConfig::Tcp);
                    udp.port = address.port();
                    tcp.port = address.port();
                    Ok(NameServerConfig::new(address.ip(), true, vec![udp, tcp]))
                })
                .collect::<io::Result<Vec<_>>>()?
        } else {
            // 🛡️ A system configuration failure must not select a public fallback resolver.
            hickory_resolver::system_conf::read_system_conf()
                .map_err(io::Error::other)?
                .0
                .name_servers()
                .to_vec()
        };
        if servers.is_empty() || servers.len() > 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS policy requires 1 to 4 resolvers",
            ));
        }
        let mut endpoints = Vec::new();
        for server in &servers {
            for connection in &server.connections {
                let tcp = match connection.protocol {
                    ProtocolConfig::Udp => false,
                    ProtocolConfig::Tcp => true,
                };
                endpoints.push(Endpoint {
                    address: SocketAddr::new(server.ip, connection.port),
                    tcp,
                    bind: connection.bind_addr,
                });
            }
        }
        let mut options = ResolverOpts::default();
        options.timeout = Duration::from_secs(5);
        options.attempts = 1;
        options.num_concurrent_reqs = 1;
        options.max_active_requests = 1;
        options.cache_size = 0;
        let context = Arc::new(PoolContext::new(
            options,
            TlsConfig::new().map_err(io::Error::other)?,
        ));
        Ok(Self {
            name,
            port: config.port,
            versions: config.versions,
            servers,
            endpoints,
            context,
        })
    }

    pub async fn lookup(&self, mut cancelled: watch::Receiver<bool>) -> Result<Answer, Failure> {
        let provider = Provider::default();
        let tasks = provider.tasks.clone();
        let _guard = tasks.guard();
        let result = {
            let pool =
                NameServerPool::from_config(self.servers.clone(), self.context.clone(), provider);
            tokio::select! {
                biased;
                _ = cancelled.wait_for(|stop| *stop) => Err(Failure::Cancelled),
                result = timeout(Duration::from_secs(5), self.query(&pool)) => {
                    result.unwrap_or(Err(Failure::Timeout))
                }
            }
        };
        // 🧹 Retired DNS jobs occupy their global slot until transport workers are joined.
        tasks.drain().await;
        result
    }

    async fn query(&self, pool: &NameServerPool<Provider>) -> Result<Answer, Failure> {
        let families: &[RecordType] = match self.versions {
            Layer4IpVersions::Ipv4 => &[RecordType::A],
            Layer4IpVersions::Ipv6 => &[RecordType::AAAA],
            Layer4IpVersions::Ip => &[RecordType::A, RecordType::AAAA],
        };
        let mut answer = Answer {
            addresses: Vec::new(),
            fresh: Instant::now() + Duration::from_secs(u64::from(u32::MAX)),
        };
        for family in families {
            self.family(pool, *family, &mut answer).await?;
        }
        if answer.addresses.is_empty() {
            return Err(Failure::Empty);
        }
        answer.addresses.sort_unstable();
        Ok(answer)
    }

    async fn family(
        &self,
        pool: &NameServerPool<Provider>,
        family: RecordType,
        answer: &mut Answer,
    ) -> Result<(), Failure> {
        let mut current = self.name.clone();
        let mut visited = vec![current.clone()];
        loop {
            let response = match pool
                .lookup(
                    Query::query(current.clone(), family),
                    DnsRequestOptions::default(),
                )
                .first_answer()
                .await
            {
                Ok(response) => response,
                Err(error) if error.is_nx_domain() => return Err(Failure::NxDomain),
                Err(error) if error.is_no_records_found() => return Ok(()),
                Err(NetError::Timeout) => return Err(Failure::Timeout),
                Err(_) => return Err(Failure::Transient),
            };
            match response.response_code {
                ResponseCode::NoError => {}
                ResponseCode::NXDomain => return Err(Failure::NxDomain),
                _ => return Err(Failure::Transient),
            }
            let received = Instant::now();
            let queried = current.clone();
            loop {
                let mut alias = None;
                let mut found = false;
                for record in response
                    .answers
                    .iter()
                    .filter(|record| record.name == current)
                {
                    let ip = match &record.data {
                        RData::A(ip) if family == RecordType::A => Some(IpAddr::V4(ip.0)),
                        RData::AAAA(ip) if family == RecordType::AAAA => Some(IpAddr::V6(ip.0)),
                        RData::CNAME(name) => {
                            if alias.as_ref().is_some_and(|old| old != &name.0) {
                                return Err(Failure::Invalid);
                            }
                            alias = Some(name.0.clone());
                            answer.fresh = answer
                                .fresh
                                .min(received + Duration::from_secs(u64::from(record.ttl)));
                            None
                        }
                        _ => None,
                    };
                    if let Some(ip) = ip {
                        found = true;
                        let address = SocketAddr::new(ip.to_canonical(), self.port);
                        if !answer.addresses.contains(&address) {
                            if answer.addresses.len() == 64 {
                                return Err(Failure::Invalid);
                            }
                            answer.addresses.push(address);
                        }
                        answer.fresh = answer
                            .fresh
                            .min(received + Duration::from_secs(u64::from(record.ttl)));
                    }
                }
                if let Some(alias) = alias {
                    if found || visited.len() == 9 || visited.contains(&alias) {
                        return Err(Failure::Invalid);
                    }
                    visited.push(alias.clone());
                    current = alias;
                    continue;
                }
                if found || current == queried {
                    return Ok(());
                }
                break;
            }
        }
    }
}
