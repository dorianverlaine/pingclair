// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 DNS-driven upstream sources (`dynamic a` and `dynamic srv`).
//!
//! Caddy resolves these sources per request and caches the answer. Pingclair
//! keeps the same freshness without ever putting DNS on the request path: a
//! background refresher calls [`DynamicUpstreamSource::resolve_specs`] on the
//! configured interval and republishes the whole peer set at once, exactly
//! like the hostname refresher in `dns.rs`. The request path only ever reads
//! the published pool.
//!
//! The synchronous hickory resolver owns its own current-thread Tokio runtime,
//! so lookups fit the existing `spawn_blocking` refresh loop without dragging
//! async state into `LoadBalancer`.

use crate::upstream::UpstreamSpec;
use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use pingclair_core::config::{DynamicAddrUpstream, DynamicSrvUpstream, DynamicUpstreamConfig};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// One SRV record: the target hostname and the port the service listens on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    pub host: String,
    pub port: u16,
}

/// 🧭 Wraps hickory's synchronous resolver behind the two lookups the dynamic
/// sources need, with the configured timeouts and explicit name servers.
pub struct DynamicResolver {
    inner: Arc<Resolver>,
}

impl DynamicResolver {
    /// Builds a resolver from explicit server addresses (or the system
    /// configuration when none were given) and an optional per-lookup timeout.
    pub fn new(resolvers: &[String], timeout: Option<Duration>) -> io::Result<Self> {
        let config = if resolvers.is_empty() {
            ResolverConfig::default()
        } else {
            let mut config = ResolverConfig::new();
            for address in resolvers {
                let ip: IpAddr = address.parse().map_err(io::Error::other)?;
                config.add_name_server(NameServerConfig::new(
                    SocketAddr::new(ip, 53),
                    Protocol::Udp,
                ));
            }
            config
        };
        let mut options = ResolverOpts::default();
        if let Some(timeout) = timeout {
            options.timeout = timeout;
        }
        Ok(Self {
            inner: Arc::new(Resolver::new(config, options)?),
        })
    }

    /// 📜 Resolves every A/AAAA record of `name`, honoring the address-family
    /// filter (`ipv4`/`ipv6`) when one is configured.
    pub fn lookup_a(&self, name: &str, versions: Option<&str>) -> io::Result<Vec<IpAddr>> {
        let lookup = self.inner.lookup_ip(name).map_err(io::Error::other)?;
        Ok(lookup
            .iter()
            .filter(|ip| match versions {
                Some("ipv4" | "ip4") => ip.is_ipv4(),
                Some("ipv6" | "ip6") => ip.is_ipv6(),
                _ => true,
            })
            .collect())
    }

    /// 🧾 Resolves every SRV record of `name`; records whose target is `.`
    /// mean "service not available" and are skipped, matching RFC 2782.
    pub fn lookup_srv(&self, name: &str) -> io::Result<Vec<SrvRecord>> {
        let lookup = self.inner.srv_lookup(name).map_err(io::Error::other)?;
        Ok(lookup
            .iter()
            .filter(|record| !record.target().is_root())
            .map(|record| SrvRecord {
                host: record.target().to_string(),
                port: record.port(),
            })
            .collect())
    }
}

/// 🧭 One configured dynamic source, resolved to a fresh peer list on demand.
pub trait DynamicUpstreamSource: Send + Sync {
    /// A stable label for logs.
    fn describe(&self) -> String;

    /// Resolves the current peer set as concrete address specs.
    fn resolve_specs(&self) -> io::Result<Vec<UpstreamSpec>>;
}

/// 📜 A-record source: every address of one name on one fixed port.
struct ARecordSource {
    resolver: Arc<DynamicResolver>,
    config: DynamicAddrUpstream,
}

impl DynamicUpstreamSource for ARecordSource {
    fn describe(&self) -> String {
        format!("a://{}:{}", self.config.name, self.config.port)
    }

    fn resolve_specs(&self) -> io::Result<Vec<UpstreamSpec>> {
        let addresses = self
            .resolver
            .lookup_a(&self.config.name, self.config.versions.as_deref())?;
        if addresses.is_empty() {
            return Err(io::Error::other("no address records for the dynamic name"));
        }
        Ok(addresses
            .into_iter()
            .filter_map(|ip| UpstreamSpec::parse(&format!("{ip}:{}", self.config.port)))
            .collect())
    }
}

/// 🧾 SRV source: every target and port of the RFC 2782 records.
struct SrvSource {
    resolver: Arc<DynamicResolver>,
    config: DynamicSrvUpstream,
}

impl SrvSource {
    /// Builds the RFC 2782 name from the configured parts.
    fn lookup_name(&self) -> String {
        match (&self.config.service, &self.config.proto) {
            (Some(service), Some(proto)) => {
                format!("_{service}._{proto}.{}", self.config.name)
            }
            _ => self.config.name.clone(),
        }
    }
}

impl DynamicUpstreamSource for SrvSource {
    fn describe(&self) -> String {
        format!("srv://{}", self.lookup_name())
    }

    fn resolve_specs(&self) -> io::Result<Vec<UpstreamSpec>> {
        let records = self.resolver.lookup_srv(&self.lookup_name())?;
        if records.is_empty() {
            return Err(io::Error::other("no SRV records for the dynamic name"));
        }
        Ok(records
            .into_iter()
            .filter_map(|record| UpstreamSpec::parse(&format!("{}:{}", record.host, record.port)))
            .collect())
    }
}

/// 🏭 Builds the runtime source for one configured dynamic upstream.
pub fn dynamic_source(
    config: &DynamicUpstreamConfig,
) -> io::Result<Box<dyn DynamicUpstreamSource>> {
    match config {
        DynamicUpstreamConfig::A(addr) => Ok(Box::new(ARecordSource {
            resolver: Arc::new(DynamicResolver::new(
                &addr.resolvers,
                addr.dial_timeout_ms.map(Duration::from_millis),
            )?),
            config: addr.clone(),
        })),
        DynamicUpstreamConfig::Srv(srv) => Ok(Box::new(SrvSource {
            resolver: Arc::new(DynamicResolver::new(
                &srv.resolvers,
                srv.dial_timeout_ms.map(Duration::from_millis),
            )?),
            config: srv.clone(),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn srv_lookup_name_follows_rfc2782_parts() {
        let source = SrvSource {
            resolver: Arc::new(DynamicResolver::new(&[], None).unwrap()),
            config: DynamicSrvUpstream {
                name: "example.com".into(),
                service: Some("api".into()),
                proto: Some("tcp".into()),
                refresh_secs: None,
                resolvers: vec![],
                dial_timeout_ms: None,
                fallback_delay_ms: None,
                grace_period_ms: None,
            },
        };
        assert_eq!(source.lookup_name(), "_api._tcp.example.com");
        assert_eq!(source.describe(), "srv://_api._tcp.example.com");
    }

    #[test]
    fn a_record_source_describes_its_name_and_port() {
        let source = ARecordSource {
            resolver: Arc::new(DynamicResolver::new(&[], None).unwrap()),
            config: DynamicAddrUpstream {
                name: "example.test".into(),
                port: 9000,
                refresh_secs: None,
                resolvers: vec![],
                dial_timeout_ms: None,
                fallback_delay_ms: None,
                versions: Some("ipv6".into()),
            },
        };
        assert_eq!(source.describe(), "a://example.test:9000");
    }

    #[test]
    fn explicit_resolvers_must_be_ip_literals() {
        assert!(
            DynamicResolver::new(&["not-an-ip".into()], None).is_err(),
            "a hostname is not a resolver address"
        );
    }
}
