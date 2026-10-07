// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔌 Load-time routing state and the bounded preread-to-relay connection path.

use crate::{Classification, ClientHello, RelayOptions, classify, relay};
use pingclair_core::config::{IpRanges, Layer4Server, Layer4TlsMatcher};
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout, timeout_at};

struct Matcher {
    tls: Option<Layer4TlsMatcher>,
    peers: IpRanges,
}

impl Matcher {
    fn matches(&self, hello: Option<&ClientHello<'_>>, peer: IpAddr) -> bool {
        if !self.peers.as_strings().is_empty() && !self.peers.contains(peer) {
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

struct Route {
    matches: Vec<Matcher>,
    upstreams: Vec<SocketAddr>,
}

/// 🧭 Immutable state held for a connection's entire lifetime, including reloads.
pub struct PreparedListener {
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
            let upstreams: Vec<_> = route.upstream.to_socket_addrs()?.collect();
            if upstreams.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "L4 upstream resolved to no addresses",
                ));
            }
            let mut matches = Vec::with_capacity(route.matches.len());
            for matcher in &route.matches {
                needs_tls |= matcher.tls.is_some();
                matches.push(Matcher {
                    tls: matcher.tls.clone(),
                    peers: IpRanges::parse(matcher.remote_ip.clone()).map_err(io::Error::other)?,
                });
            }
            routes.push(Route { matches, upstreams });
        }
        Ok(Self {
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

    /// 🌊 Classifies and routes one raw stream without decrypting or constructing HTTP.
    pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut stream: S,
        peer: IpAddr,
    ) -> io::Result<()> {
        if self.blocked.contains(peer) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let mut prefix = Vec::new();
        if self.needs_tls {
            prefix
                .try_reserve_exact(self.preread_limit)
                .map_err(io::Error::other)?;
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
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "L4 preread buffer exceeded",
                    ));
                }
                while length < needed {
                    let read =
                        timeout_at(deadline, stream.read(&mut prefix[length..needed])).await??;
                    if read == 0 {
                        return Ok(());
                    }
                    length += read;
                }
                match classify(&prefix[..length]) {
                    Classification::NeedMore(size) => needed = size,
                    Classification::NotTls | Classification::Tls(_) => {
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
        let route = self
            .routes
            .iter()
            .find(|route| {
                route.matches.is_empty()
                    || route
                        .matches
                        .iter()
                        .any(|matcher| matcher.matches(hello, peer))
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no L4 route matched"))?;
        let mut upstream = timeout(
            self.connect_timeout,
            TcpStream::connect(route.upstreams.as_slice()),
        )
        .await??;
        upstream.set_nodelay(true)?;
        relay(&mut stream, &mut upstream, prefix, self.relay).await
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
