// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌐 What a Caddy-style address means, in the four ways the CLI needs it.
//!
//! The one idea underneath all of them: a hostname is not a bind address. When
//! someone writes `example.com`, they are naming a virtual host, and the server
//! is expected to bind every interface and route by `Host`/SNI. Only an IP
//! literal actually pins a socket to one interface. Getting that backwards
//! produces a server that starts, reports success, and answers nobody — so the
//! rule lives in one place with the string arithmetic that implements it.
//!
//! These are the quick-command helpers (`respond`, `reverse-proxy`,
//! `file-server`). The listener derivation the *configuration* goes through is
//! [`crate::listen`], which answers a different question: not what an address
//! means, but which sockets a compiled config needs.

/// 🌐 Splits `host:port` into (host, port), honoring bracketed IPv6.
fn host_and_port(address: &str) -> (&str, Option<u16>) {
    let trimmed = address
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    match trimmed.rfind(']') {
        Some(bracket) => match trimmed[bracket..].rfind(':') {
            Some(offset) => (
                &trimmed[..bracket + 1],
                trimmed[bracket + offset + 1..].parse::<u16>().ok(),
            ),
            None => (trimmed, None),
        },
        None => match trimmed.rfind(':') {
            // 🧭 The last colon separates host and port when the tail parses
            // as a port; a bare `:9000` yields an empty host (loopback).
            Some(index) => (&trimmed[..index], trimmed[index + 1..].parse::<u16>().ok()),
            None => (trimmed, None),
        },
    }
}

/// 🧭 Derives a concrete listen address from a Caddy-style `--from`/site
/// address: a bare hostname gets the scheme's default port, a bare `:port`
/// binds the wildcard, and an explicit host:port passes through.
pub(crate) fn listen_for_site(address: &str, https: bool) -> String {
    let default_port = if https { 443 } else { 80 };
    match host_and_port(address) {
        ("", Some(port)) => format!("[::]:{port}"),
        ("", None) => format!("[::]:{default_port}"),
        (host, port) => {
            // 🌐 A hostname is a virtual host, not a bind address: Caddy
            // binds every interface and routes by Host/SNI. Only an IP
            // literal pins the socket to one interface.
            if host.parse::<std::net::IpAddr>().is_ok() {
                match port {
                    Some(port) => format!("{host}:{port}"),
                    None => format!("{host}:{default_port}"),
                }
            } else {
                format!("[::]:{}", port.unwrap_or(default_port))
            }
        }
    }
}

/// 🏷️ Returns the hostname portion of an address (`example.com:8443` → `example.com`).
pub(crate) fn host_only(address: &str) -> &str {
    let (host, _) = host_and_port(address);
    host
}

/// 🧭 Renders an upstream address as a Host header value, like Caddy's
/// `--change-host-header` shortcut.
pub(crate) fn upstream_hostport(address: &str) -> String {
    let (scheme, rest) = if let Some(rest) = address.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = address.strip_prefix("h2://") {
        (true, rest)
    } else {
        (
            false,
            address
                .strip_prefix("http://")
                .or_else(|| address.strip_prefix("h2c://"))
                .unwrap_or(address),
        )
    };
    match host_and_port(rest) {
        ("", Some(port)) => format!("127.0.0.1:{port}"),
        ("", None) => format!("127.0.0.1:{}", if scheme { 443 } else { 80 }),
        (host, Some(port)) => format!("{host}:{port}"),
        (host, None) => format!("{host}:{}", if scheme { 443 } else { 80 }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🧭 Caddy-style address derivation used by the quick commands.
    #[test]
    fn cli_site_addresses_derive_like_caddy() {
        assert_eq!(listen_for_site(":2080", false), "[::]:2080");
        assert_eq!(listen_for_site("localhost", true), "[::]:443");
        assert_eq!(listen_for_site("example.com:8443", true), "[::]:8443");
        assert_eq!(listen_for_site("http://example.com", false), "[::]:80");
        assert_eq!(listen_for_site("127.0.0.1:9000", false), "127.0.0.1:9000");
        assert_eq!(host_only("example.com:8443"), "example.com");
        assert_eq!(host_only(":9000"), "");
        assert_eq!(
            upstream_hostport("https://localhost:9443"),
            "localhost:9443"
        );
        assert_eq!(upstream_hostport(":9000"), "127.0.0.1:9000");
        assert_eq!(upstream_hostport("backend.internal"), "backend.internal:80");
    }
}
