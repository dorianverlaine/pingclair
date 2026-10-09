// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔌 Load-time routing state and the bounded preread-to-relay connection path.

use crate::metrics::Metrics;
use crate::observation::{Counted, Observation, Outcome, Phase};
use crate::upstream::Upstream;
use crate::{Classification, ClientHello, RelayOptions, classify, relay};
use pingclair_core::config::{IpRanges, Layer4Server, Layer4TlsMatcher};
use pingclair_runtime::access_log::AccessLogger;
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
    upstream: Upstream,
}

/// 🧭 Immutable state held for a connection's entire lifetime, including reloads.
pub struct PreparedListener {
    metrics: Metrics,
    max_connections: usize,
    listener: String,
    logger: Option<Arc<AccessLogger>>,
    log_config: Option<pingclair_core::config::LogConfig>,
    routes: Vec<Route>,
    blocked: IpRanges,
    needs_tls: bool,
    preread_limit: usize,
    preread_timeout: Duration,
    connect_timeout: Duration,
    relay: RelayOptions,
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
        for route in &config.routes {
            if route.dynamic.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "dynamic L4 runtime is not connected",
                ));
            }
            let upstream = Upstream::prepare(&route.upstream)?;
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
        let listener = pingclair_core::config::normalize_listen_addr(&config.listen);
        let logger = match previous.filter(|previous| previous.log_config == config.log) {
            Some(previous) => previous.logger.clone(),
            None => AccessLogger::from_config(config.log.as_ref())?
                .filter(|logger| logger.admits_source("layer4.log.access"))
                .map(Arc::new),
        };
        Ok(Self {
            metrics: Metrics::prepare(&listener, routes.len()),
            max_connections: config.max_connections,
            listener,
            logger,
            log_config: config.log.clone(),
            routes,
            needs_tls,
            blocked: IpRanges::parse(blocked.to_vec()).map_err(io::Error::other)?,
            preread_limit: config.preread_buffer_size,
            preread_timeout: Duration::from_millis(config.preread_timeout_ms),
            connect_timeout: Duration::from_millis(config.proxy_connect_timeout_ms),
            relay: RelayOptions {
                buffer_size: config.proxy_buffer_size,
                idle_timeout: Duration::from_millis(config.proxy_timeout_ms),
                half_close: config.proxy_half_close,
            },
        })
    }

    /// 🚦 Returns the listener quota captured before accepting any sockets.
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// 📊 Counts pre-session refusals without allocating an access-log entry.
    pub fn record_admission_rejection(&self) {
        if pingclair_runtime::metrics::enabled() {
            self.metrics.rejected.inc();
        }
    }

    /// 🌊 Classifies and routes one raw stream without decrypting or constructing HTTP.
    pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
        peer: SocketAddr,
    ) -> io::Result<()> {
        let mut observation = Observation::new(&self.metrics, self.logger.is_some());
        observation.log = self
            .logger
            .as_ref()
            .map(|logger| (logger.as_ref(), self.listener.as_str(), peer));
        // ⚡ Specialize byte accounting away when access logging is disabled.
        let result = if self.logger.is_some() {
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
        &self,
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
        let upstream = route.upstream.connect(self.connect_timeout).await?;
        observation.connect_time = connect_started.map(|started| started.elapsed());
        observation.upstream_addr = Some(upstream.peer_addr()?);
        upstream.set_nodelay(true)?;
        observation.phase = Phase::Relay;
        let mut upstream = Counted::<_, LOG> {
            inner: upstream,
            stats: &mut observation.upstream,
            written: observation.metrics.map(|m| &m.to_upstream),
        };
        relay(&mut stream, &mut upstream, prefix, self.relay).await
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "session_log_tests.rs"]
mod log_tests;
