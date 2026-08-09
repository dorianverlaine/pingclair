// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Upstream Server Management
//!
//! Provides types and helpers for defining and creating backend servers.
//! This module acts as a bridge between Pingclair's configuration and Pingora's native backend types.

pub use pingora_load_balancing::Backend as Upstream;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

// MARK: - Types

/// 🌐 Metadata stored in `Backend` extensions to select the upstream protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// 📜 Uses plaintext HTTP/1.1.
    Http,
    /// 🔐 Negotiates HTTP/2 or HTTP/1.1 over TLS.
    Https,
    /// 🚀 Uses prior-knowledge HTTP/2 over plaintext.
    H2c,
    /// 🔒 Requires HTTP/2 over TLS.
    H2,
}

/// A wrapper type for hostname string, stored in `Backend` extensions.
#[derive(Debug, Clone)]
pub struct HostName(pub String);

// MARK: - Resolver

/// 🔍 Name resolution behind a trait so the refresher can be driven by a
/// scripted resolver in tests. A container's address change and a resolver
/// outage are both untestable against the real system resolver, and those
/// are exactly the two behaviours the refresher exists for.
pub trait Resolve: Send + Sync + 'static {
    /// Resolves `host` to every address it currently maps to.
    ///
    /// An `Ok(vec![])` is treated by callers as a failed lookup, not as
    /// "this name has no backends" — the two are indistinguishable from a
    /// resolver and the safe reading is the one that keeps serving.
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>>;
}

/// The platform resolver, reached through the standard library (blocking).
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        (host, port).to_socket_addrs().map(|addrs| addrs.collect())
    }
}

// MARK: - Upstream Spec

/// 🧭 How to reach one configured upstream *before* name resolution.
///
/// Keeping the hostname (rather than only the address it resolved to at
/// boot) is what makes re-resolution possible: a container that restarts on
/// a new IP keeps the same name, so the name is the stable identity and the
/// address is the perishable part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamSpec {
    /// Host exactly as configured — bracketed for IPv6 literals.
    pub host: String,
    pub port: u16,
    pub scheme: Scheme,
    /// `Some` when the host is already an IP literal, which never needs a
    /// resolver and never goes stale.
    literal: Option<IpAddr>,
    /// 🏗️ `Some` when this upstream is a Unix-domain socket; the path is the
    /// dial target and no port or resolver participates in reaching it.
    pub unix_path: Option<String>,
}

impl UpstreamSpec {
    /// Parses a URL-like upstream string (e.g. `https://app:8443`) without
    /// touching the resolver.
    pub fn parse(address: &str) -> Option<Self> {
        let trimmed = address.trim();

        // 🏗️ Caddy spells Unix sockets as `unix//path` (and `unix/path` for a
        // relative one); `unix+h2c//` is the same socket speaking
        // prior-knowledge HTTP/2. Both must be recognized before the generic
        // host parsing below, which would otherwise read `unix` as a hostname.
        if let Some(path) = trimmed.strip_prefix("unix+h2c/") {
            return Self::unix_spec(Scheme::H2c, path);
        }
        if let Some(path) = trimmed.strip_prefix("unix/") {
            return Self::unix_spec(Scheme::Http, path);
        }

        let (scheme, minimal_url) = if let Some(stripped) = trimmed.strip_prefix("h2c://") {
            (Scheme::H2c, stripped)
        } else if let Some(stripped) = trimmed.strip_prefix("h2://") {
            (Scheme::H2, stripped)
        } else if let Some(stripped) = trimmed.strip_prefix("https://") {
            (Scheme::Https, stripped)
        } else if let Some(stripped) = trimmed.strip_prefix("http://") {
            (Scheme::Http, stripped)
        } else {
            (Scheme::Http, trimmed)
        };

        // A bracketed IPv6 literal owns every colon up to `]`, so the port
        // separator is only the last colon when it sits outside the brackets.
        let port_separator = match minimal_url.rfind(']') {
            Some(bracket) => minimal_url[bracket..]
                .rfind(':')
                .map(|offset| bracket + offset),
            None => minimal_url.rfind(':'),
        };

        let (host, port) = match port_separator {
            Some(index) => {
                let port = minimal_url[index + 1..].parse::<u16>().ok()?;
                (&minimal_url[..index], port)
            }
            None => {
                let default_port = if matches!(scheme, Scheme::Https | Scheme::H2) {
                    443
                } else {
                    80
                };
                (minimal_url, default_port)
            }
        };

        // 🧭 Caddy treats a bare `:9000` upstream as `127.0.0.1:9000`;
        // an empty host must not silently vanish into a peer that can
        // never be dialed.
        let host = if host.is_empty() { "127.0.0.1" } else { host };

        Some(Self {
            host: host.to_string(),
            port,
            scheme,
            literal: bare_host(host).parse::<IpAddr>().ok(),
            unix_path: None,
        })
    }

    /// Builds a spec whose dial target is a Unix socket instead of a host.
    fn unix_spec(scheme: Scheme, path: &str) -> Option<Self> {
        // 🚫 An empty path is a spelling mistake, and `/` (what `unix//` parses
        // to) names the root directory, which can never be a socket.
        if path.is_empty() || path == "/" {
            return None;
        }
        Some(Self {
            host: path.to_string(),
            port: 0,
            scheme,
            literal: None,
            unix_path: Some(path.to_string()),
        })
    }

    /// Whether this upstream depends on a resolver at all.
    pub fn needs_dns(&self) -> bool {
        self.unix_path.is_none() && self.literal.is_none()
    }

    /// 🏗️ Whether this upstream dials a Unix-domain socket.
    pub fn is_unix(&self) -> bool {
        self.unix_path.is_some()
    }

    /// `host:port` as written, for logging.
    pub fn authority(&self) -> String {
        if let Some(path) = &self.unix_path {
            return path.clone();
        }
        format!("{}:{}", self.host, self.port)
    }

    /// Resolves the spec to a single address, deterministically.
    ///
    /// IP literals skip the resolver entirely. Everything else goes through
    /// `resolver` and then [`pick_address`], so a name with several records
    /// yields the *same* answer every tick — an unstable pick would make the
    /// refresher rebuild the pool forever for a host that never moved.
    pub fn resolve(&self, resolver: &dyn Resolve) -> std::io::Result<SocketAddr> {
        if let Some(path) = &self.unix_path {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Unix-socket upstream `{path}` needs no resolution"),
            ));
        }
        if let Some(ip) = self.literal {
            return Ok(SocketAddr::new(ip, self.port));
        }

        let candidates = resolver.resolve(bare_host(&self.host), self.port)?;
        pick_address(candidates).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no address for `{}`", self.authority()),
            )
        })
    }

    /// Builds a Pingora backend for an already-resolved address, carrying the
    /// scheme and the *configured hostname* — the hostname drives SNI and the
    /// upstream `Host` header, so it must survive resolution.
    pub fn backend(&self, address: SocketAddr, weight: usize) -> Option<Upstream> {
        let mut backend = Upstream::new(&address.to_string()).ok()?;
        backend.weight = weight;
        backend.ext.insert(self.scheme);
        backend.ext.insert(HostName(self.host.clone()));
        Some(backend)
    }

    /// 🏗️ Builds a Pingora backend that dials a Unix socket.
    ///
    /// Pingora's `Backend::new` only parses inet addresses, so the Unix
    /// variant is assembled directly; its `SocketAddr` is the path that the
    /// peer builder later turns into a Unix-domain connection.
    #[cfg(unix)]
    pub fn unix_backend(&self, weight: usize) -> Option<Upstream> {
        let path = self.unix_path.as_ref()?;
        let addr = pingora_core::protocols::l4::socket::SocketAddr::Unix(
            std::os::unix::net::SocketAddr::from_pathname(path).ok()?,
        );
        let mut backend = Upstream {
            addr,
            weight,
            ext: Default::default(),
        };
        backend.ext.insert(self.scheme);
        backend.ext.insert(HostName(self.host.clone()));
        Some(backend)
    }

    /// Non-Unix platforms have no Unix sockets to dial; the upstream stays
    /// unusable instead of pretending a path can be reached.
    #[cfg(not(unix))]
    pub fn unix_backend(&self, _weight: usize) -> Option<Upstream> {
        None
    }
}

/// Chooses one address out of a resolver answer, deterministically.
///
/// `to_socket_addrs` makes no ordering promise and glibc deliberately
/// rotates records, so "take the first" is not stable across calls. Sorting
/// puts IPv4 ahead of IPv6 (`IpAddr`'s own ordering) and then breaks ties
/// numerically, which keeps a multi-record name pinned to one backend
/// instead of flapping between them every refresh.
pub fn pick_address(mut candidates: Vec<SocketAddr>) -> Option<SocketAddr> {
    candidates.sort_by_key(|address| (address.ip(), address.port()));
    candidates.into_iter().next()
}

/// Strips the brackets from an IPv6 literal; other hosts pass through.
fn bare_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host)
}

// MARK: - Public API

/// Creates a new `Upstream` (Pingora Backend) from a URL string.
///
/// Parses a URL-like string (e.g., "https://example.com:443") into a `SocketAddr`
/// and associated metadata (Scheme, Hostname) required for Pingora's backend.
///
/// - Parameter address_string: The URL string to parse. Supports `http://` and `https://` schemes.
/// - Returns: An `Option<Upstream>` containing the configured backend, or `None` if parsing fails.
///
/// **Design Check:**
/// Uses standard library resolution which is blocking. Acceptable for startup configuration phase.
pub fn create_upstream(address_string: &str) -> Option<Upstream> {
    let spec = UpstreamSpec::parse(address_string)?;
    if spec.is_unix() {
        return spec.unix_backend(1);
    }
    let address = spec.resolve(&SystemResolver).ok()?;
    spec.backend(address, 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_schemes_preserve_protocol_metadata() {
        for (address, expected) in [
            ("http://127.0.0.1:8001", Scheme::Http),
            ("https://127.0.0.1:8002", Scheme::Https),
            ("h2c://127.0.0.1:8003", Scheme::H2c),
            ("h2://127.0.0.1:8004", Scheme::H2),
            ("unix//run/php.sock", Scheme::Http),
            ("unix+h2c//run/grpc.sock", Scheme::H2c),
        ] {
            let upstream = create_upstream(address).unwrap();
            assert_eq!(*upstream.ext.get::<Scheme>().unwrap(), expected);
        }
    }

    /// 🏗️ Unix-socket upstreams keep their exact path, skip the resolver, and
    /// build backends whose address is the socket itself rather than an inet
    /// pair that can never dial.
    #[test]
    fn unix_socket_upstreams_skip_resolution_and_keep_their_path() {
        for (address, expected_path, expected_scheme) in [
            ("unix//run/php/php.sock", "/run/php/php.sock", Scheme::Http),
            ("unix/run/php/php.sock", "run/php/php.sock", Scheme::Http),
            ("unix+h2c//run/app.sock", "/run/app.sock", Scheme::H2c),
        ] {
            let spec =
                UpstreamSpec::parse(address).unwrap_or_else(|| panic!("{address} must parse"));
            assert_eq!(spec.unix_path.as_deref(), Some(expected_path), "{address}");
            assert_eq!(spec.scheme, expected_scheme, "{address}");
            assert!(spec.is_unix(), "{address}");
            assert!(!spec.needs_dns(), "{address} must never touch a resolver");
            assert_eq!(spec.authority(), expected_path, "{address}");

            let backend = spec
                .unix_backend(1)
                .unwrap_or_else(|| panic!("{address} must build"));
            assert!(
                matches!(
                    backend.addr,
                    pingora_core::protocols::l4::socket::SocketAddr::Unix(_)
                ),
                "{address} must dial a Unix socket"
            );
            assert_eq!(*backend.ext.get::<Scheme>().unwrap(), expected_scheme);
            assert_eq!(backend.ext.get::<HostName>().unwrap().0, expected_path);
        }
    }

    /// 🏗️ A Unix path with nothing after the separator is a mistake, not an
    /// upstream that silently means something else.
    #[test]
    fn empty_unix_paths_are_refused() {
        for address in ["unix//", "unix/", "unix+h2c//"] {
            assert!(
                UpstreamSpec::parse(address).is_none(),
                "{address} must not parse"
            );
        }
    }

    #[test]
    fn ip_literals_never_reach_the_resolver() {
        for address in ["127.0.0.1:8001", "http://10.0.0.7", "https://[::1]:8443"] {
            let spec = UpstreamSpec::parse(address).unwrap();
            assert!(!spec.needs_dns(), "{address} should be a literal");
        }
        assert!(UpstreamSpec::parse("http://app:8080").unwrap().needs_dns());
    }

    #[test]
    fn default_ports_follow_the_scheme() {
        for (address, port) in [
            ("http://app", 80),
            ("app", 80),
            ("https://app", 443),
            ("h2://app", 443),
            ("h2c://app", 80),
            ("app:9000", 9000),
        ] {
            assert_eq!(
                UpstreamSpec::parse(address).unwrap().port,
                port,
                "{address}"
            );
        }
    }

    #[test]
    fn bare_port_upstreams_default_to_loopback_like_caddy() {
        // 🧭 `reverse_proxy :9000` must dial 127.0.0.1:9000, not vanish into
        // an empty host that can never be resolved.
        for (address, expected_host, expected_port) in [
            (":9000", "127.0.0.1", 9000),
            ("https://:8443", "127.0.0.1", 8443),
            ("h2c://:3000", "127.0.0.1", 3000),
        ] {
            let spec =
                UpstreamSpec::parse(address).unwrap_or_else(|| panic!("{address} must parse"));
            assert_eq!(spec.host, expected_host, "{address}");
            assert_eq!(spec.port, expected_port, "{address}");
            assert!(!spec.needs_dns(), "{address} must be a loopback literal");
        }
    }

    #[test]
    fn bracketed_ipv6_keeps_its_colons() {
        let spec = UpstreamSpec::parse("http://[2001:db8::1]:8080").unwrap();
        assert_eq!(spec.host, "[2001:db8::1]");
        assert_eq!(spec.port, 8080);
        assert!(!spec.needs_dns());

        let default_port = UpstreamSpec::parse("http://[2001:db8::1]").unwrap();
        assert_eq!(default_port.host, "[2001:db8::1]");
        assert_eq!(default_port.port, 80);
    }

    #[test]
    fn the_configured_hostname_survives_resolution() {
        let spec = UpstreamSpec::parse("https://app.internal:8443").unwrap();
        let backend = spec
            .backend("10.0.0.5:8443".parse().unwrap(), 3)
            .expect("backend");

        assert_eq!(backend.addr.to_string(), "10.0.0.5:8443");
        assert_eq!(backend.weight, 3);
        assert_eq!(backend.ext.get::<HostName>().unwrap().0, "app.internal");
        assert_eq!(*backend.ext.get::<Scheme>().unwrap(), Scheme::Https);
    }

    #[test]
    fn address_choice_is_stable_regardless_of_answer_order() {
        let forward: Vec<SocketAddr> = ["10.0.0.9:80", "10.0.0.3:80", "[::1]:80"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        let mut reversed = forward.clone();
        reversed.reverse();

        // Same set, different order → same pick. A resolver that rotates
        // records must not make the refresher churn.
        assert_eq!(pick_address(forward), pick_address(reversed));
        assert_eq!(
            pick_address(vec![
                "[::1]:80".parse().unwrap(),
                "10.0.0.3:80".parse().unwrap()
            ]),
            Some("10.0.0.3:80".parse().unwrap()),
            "IPv4 is preferred when both families answer"
        );
    }

    #[test]
    fn an_empty_answer_is_a_failed_lookup() {
        struct Empty;
        impl Resolve for Empty {
            fn resolve(&self, _: &str, _: u16) -> std::io::Result<Vec<SocketAddr>> {
                Ok(Vec::new())
            }
        }

        let spec = UpstreamSpec::parse("http://app:8080").unwrap();
        assert!(spec.resolve(&Empty).is_err());
    }
}
