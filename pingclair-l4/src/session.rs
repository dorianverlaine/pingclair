// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔌 Load-time routing state and the bounded preread-to-relay connection path.

use crate::dns::{DnsPreparation, Source};
use crate::metrics::Metrics;
use crate::observation::{Counted, Observation, Outcome, Phase};
use crate::upstream::Upstream;
use crate::{Classification, ClientHello, RelayOptions, classify, relay};
use pingclair_core::config::{IpRanges, Layer4Dynamic, Layer4Server, Layer4TlsMatcher};
use pingclair_runtime::access_log::AccessLogger;
use prometheus::IntCounter;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::time::{Instant, timeout_at};

struct Matcher {
    tls: Option<Layer4TlsMatcher>,
    peers: IpRanges,
}

impl Matcher {
    fn matches(&self, hello: Option<&ClientHello<'_>>, peer: IpAddr) -> bool {
        if !self.peers.as_strings().is_empty() && !contains_peer(&self.peers, peer) {
            return false;
        }
        match (&self.tls, hello) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(tls), Some(hello)) => {
                (tls.sni.is_empty() || tls.sni.iter().any(|name| hello.matches_sni(name)))
                    && (tls.alpn.is_empty() || tls.alpn.iter().any(|alpn| hello.offers_alpn(alpn)))
            }
        }
    }
}

// 🌐 Dual-stack sockets report IPv4 peers as IPv6-mapped addresses.
fn contains_peer(ranges: &IpRanges, peer: IpAddr) -> bool {
    let canonical = peer.to_canonical();
    ranges.contains(peer) || (canonical != peer && ranges.contains(canonical))
}

struct Route {
    matches: Vec<Matcher>,
    upstream: Destination,
}

enum Destination {
    Static(Upstream),
    Dynamic(Source),
}

impl Destination {
    async fn connect(
        &self,
        budget: Duration,
        attempts: Option<&IntCounter>,
    ) -> io::Result<tokio::net::TcpStream> {
        let dial = |address| {
            if let Some(attempts) = attempts {
                attempts.inc();
            }
            tokio::net::TcpStream::connect(address)
        };
        match self {
            Self::Static(upstream) => upstream.connect_with(budget, dial).await,
            Self::Dynamic(source) => source.connect_with(budget, dial).await,
        }
    }
}

struct SessionPolicy {
    metrics: Metrics,
    listener: String,
    logger: Option<Arc<AccessLogger>>,
    relay: RelayOptions,
}

/// 🧭 Routing is retained through dial; established streams keep only session policy.
pub struct PreparedListener {
    policy: Arc<SessionPolicy>,
    max_connections: usize,
    log_config: Option<pingclair_core::config::LogConfig>,
    routes: Vec<Route>,
    blocked: IpRanges,
    needs_tls: bool,
    preread_limit: usize,
    preread_timeout: Duration,
    connect_timeout: Duration,
}

impl PreparedListener {
    /// 🏗️ Resolves upstreams and compiles CIDRs before a listener or reload is published.
    pub fn prepare(config: &Layer4Server, blocked: &[String]) -> io::Result<Self> {
        Self::prepare_with_previous(config, blocked, None)
    }

    /// ♻️ Reuses an unchanged logger so route reloads do not create writer threads.
    pub fn prepare_with_previous(
        config: &Layer4Server,
        blocked: &[String],
        previous: Option<&Self>,
    ) -> io::Result<Self> {
        Self::prepare_inner(config, blocked, previous, None)
    }

    /// 🌐 Compiles dynamic sources into a draft owned by the executable's DNS coordinator.
    pub fn prepare_with_dns(
        config: &Layer4Server,
        blocked: &[String],
        previous: Option<&Self>,
        dns: &mut DnsPreparation,
    ) -> io::Result<Self> {
        Self::prepare_inner(config, blocked, previous, Some(dns))
    }

    fn prepare_inner(
        config: &Layer4Server,
        blocked: &[String],
        previous: Option<&Self>,
        mut dns: Option<&mut DnsPreparation>,
    ) -> io::Result<Self> {
        if config.max_connections == 0 || config.max_connections > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid L4 connection limit",
            ));
        }
        if config.preread_buffer_size == 0 || config.proxy_buffer_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero L4 buffer size",
            ));
        }
        for millis in [
            config.preread_timeout_ms,
            config.proxy_connect_timeout_ms,
            config.proxy_timeout_ms,
        ] {
            if Instant::now()
                .checked_add(Duration::from_millis(millis))
                .is_none()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "L4 timeout overflow",
                ));
            }
        }
        let mut routes = Vec::with_capacity(config.routes.len());
        let mut needs_tls = false;
        let listener = pingclair_core::config::normalize_listen_addr(&config.listen);
        for (index, route) in config.routes.iter().enumerate() {
            let upstream = match (&route.dynamic, route.upstream.is_empty()) {
                (None, false) => Destination::Static(Upstream::prepare(&route.upstream)?),
                (Some(Layer4Dynamic::A(config)), true) => {
                    let dns = dns.as_deref_mut().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::Unsupported,
                            "dynamic L4 requires the DNS coordinator",
                        )
                    })?;
                    let source = dns.source(config)?;
                    dns.observe(&source, &listener, index);
                    Destination::Dynamic(source)
                }
                (None, true) | (Some(_), false) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "L4 route requires exactly one upstream source",
                    ));
                }
            };
            let mut matches = Vec::with_capacity(route.matches.len());
            for matcher in &route.matches {
                needs_tls |= matcher.tls.is_some();
                matches.push(Matcher {
                    tls: matcher.tls.clone(),
                    peers: IpRanges::parse(matcher.remote_ip.clone()).map_err(io::Error::other)?,
                });
            }
            routes.push(Route { matches, upstream });
        }
        let logger = match previous.filter(|previous| previous.log_config == config.log) {
            Some(previous) => previous.policy.logger.clone(),
            None => AccessLogger::from_config(config.log.as_ref())?
                .filter(|logger| logger.admits_source("layer4.log.access"))
                .map(Arc::new),
        };
        Ok(Self {
            policy: Arc::new(SessionPolicy {
                metrics: Metrics::prepare(&listener, routes.len()),
                listener,
                logger,
                relay: RelayOptions {
                    buffer_size: config.proxy_buffer_size,
                    idle_timeout: Duration::from_millis(config.proxy_timeout_ms),
                    half_close: config.proxy_half_close,
                },
            }),
            max_connections: config.max_connections,
            log_config: config.log.clone(),
            routes,
            needs_tls,
            blocked: IpRanges::parse(blocked.to_vec()).map_err(io::Error::other)?,
            preread_limit: config.preread_buffer_size,
            preread_timeout: Duration::from_millis(config.preread_timeout_ms),
            connect_timeout: Duration::from_millis(config.proxy_connect_timeout_ms),
        })
    }

    /// 🚦 Returns the listener quota captured before accepting any sockets.
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// 📊 Counts pre-session refusals without allocating an access-log entry.
    pub fn record_admission_rejection(&self) {
        if pingclair_runtime::metrics::enabled() {
            self.policy.metrics.rejected.inc();
        }
    }

    /// 🌊 Classifies and routes one raw stream without decrypting or constructing HTTP.
    pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
        self: Arc<Self>,
        stream: S,
        peer: SocketAddr,
    ) -> io::Result<()> {
        let policy = self.policy.clone();
        let mut observation = Observation::new(&policy.metrics, policy.logger.is_some());
        observation.log = policy
            .logger
            .as_ref()
            .map(|logger| (logger.as_ref(), policy.listener.as_str(), peer));
        // ⚡ Specialize byte accounting away when access logging is disabled.
        let result = if policy.logger.is_some() {
            self.serve_inner::<_, true>(stream, peer.ip(), &mut observation)
                .await
        } else {
            self.serve_inner::<_, false>(stream, peer.ip(), &mut observation)
                .await
        };
        observation.finish(&result);
        result
    }

    async fn serve_inner<S: AsyncRead + AsyncWrite + Unpin, const LOG: bool>(
        self: Arc<Self>,
        stream: S,
        peer: IpAddr,
        observation: &mut Observation<'_>,
    ) -> io::Result<()> {
        let mut stream = Counted::<_, LOG> {
            inner: stream,
            stats: &mut observation.downstream,
            written: observation.metrics.map(|m| &m.to_client),
        };
        if contains_peer(&self.blocked, peer) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        observation.phase = Phase::Preread;
        let mut prefix = Vec::new();
        if self.needs_tls {
            prefix
                .try_reserve_exact(self.preread_limit)
                .map_err(|error| {
                    observation.outcome = Some(Outcome::InternalError);
                    io::Error::other(error)
                })?;
            prefix.resize(self.preread_limit, 0);
            let deadline = Instant::now()
                .checked_add(self.preread_timeout)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "L4 timeout overflow")
                })?;
            let mut length = 0;
            let mut needed = 1;
            loop {
                if needed > self.preread_limit {
                    observation.outcome = Some(Outcome::PrereadOverflow);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "L4 preread buffer exceeded",
                    ));
                }
                while length < needed {
                    let read =
                        timeout_at(deadline, stream.read(&mut prefix[length..needed])).await??;
                    if read == 0 {
                        observation.outcome = Some(Outcome::PrereadEof);
                        return Ok(());
                    }
                    length += read;
                }
                match classify(&prefix[..length]) {
                    Classification::NeedMore(size) => needed = size,
                    classified @ (Classification::NotTls | Classification::Tls(_)) => {
                        if matches!(classified, Classification::NotTls)
                            && prefix[0] == 22
                            && let Some(metrics) = observation.metrics
                        {
                            metrics.declined.inc();
                        }
                        prefix.truncate(length);
                        break;
                    }
                }
            }
        }
        let classified = classify(&prefix);
        let hello = match &classified {
            Classification::Tls(hello) => Some(hello),
            Classification::NeedMore(_) | Classification::NotTls => None,
        };
        observation.phase = Phase::Routing;
        let (index, route) = self
            .routes
            .iter()
            .enumerate()
            .find(|(_, route)| {
                route.matches.is_empty()
                    || route
                        .matches
                        .iter()
                        .any(|matcher| matcher.matches(hello, peer))
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no L4 route matched"))?;
        observation.route = Some(index);
        observation.phase = Phase::Connect;
        let connect_started = LOG.then(Instant::now);
        let attempts = observation.metrics.map(|metrics| metrics.attempts(index));
        let upstream = route
            .upstream
            .connect(self.connect_timeout, attempts)
            .await?;
        observation.connect_time = connect_started.map(|started| started.elapsed());
        observation.upstream_addr = Some(upstream.peer_addr()?);
        upstream.set_nodelay(true)?;
        let relay_options = self.policy.relay;
        // 🧹 Old generations and dynamic pools cannot be pinned by a long-lived relay.
        drop(self);
        observation.phase = Phase::Relay;
        let mut upstream = Counted::<_, LOG> {
            inner: upstream,
            stats: &mut observation.upstream,
            written: observation.metrics.map(|m| &m.to_upstream),
        };
        relay(&mut stream, &mut upstream, prefix, relay_options).await
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "session_log_tests.rs"]
mod log_tests;
