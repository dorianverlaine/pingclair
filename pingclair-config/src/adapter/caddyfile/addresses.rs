// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::AdapterError;
use crate::parser::ast::*;

/// 🏠 Whether a site name is a localhost-style host or an IP literal, which
/// Caddy serves over HTTPS with a locally-trusted certificate by default.
pub(super) fn is_local_https_default(name: &str) -> bool {
    name == "localhost"
        || name.ends_with(".localhost")
        || name.ends_with(".local")
        || name.ends_with(".internal")
        || name.parse::<std::net::IpAddr>().is_ok()
}

/// 🚫 Rejects a site address that cannot mean anything, before it becomes a
/// listener nobody can reach.
///
/// These three were accepted silently until 2026-08-05, and the reason they
/// went unnoticed is worth keeping: the format's own corpus tests all three,
/// and every one of those tests was **passing** — for the wrong reason. Each
/// fixture writes the bad address in the braceless form, so the file was being
/// refused by a misclassification one layer up rather than by any check on the
/// address. Fixing the misclassification is what made them visible.
///
/// 📌 Port `0` is deliberately not rejected: it means "let the operating system
/// choose", which is a real thing to ask for.
pub(super) fn reject_impossible_address(addr: &str) -> Result<(), AdapterError> {
    if let Some((scheme, _)) = addr.split_once("://") {
        match scheme {
            "http" | "https" => {}
            // 🌐 A browser speaks `ws://` over an ordinary HTTP listener, so
            // there is nothing for a server to bind: naming it here is a
            // misunderstanding worth correcting rather than a feature to add.
            "ws" | "wss" => {
                return Err(AdapterError::InvalidArgument(
                    "site address".into(),
                    format!(
                        "the scheme `{scheme}://` only exists in browsers; a server \
                         listens with `http://` or `https://`"
                    ),
                ));
            }
            other => {
                return Err(AdapterError::InvalidArgument(
                    "site address".into(),
                    format!("unsupported URL scheme `{other}://`"),
                ));
            }
        }
    }

    // 🔢 A port above 65535 does not exist. Left alone it parsed to `None` and
    // the site quietly became a bare hostname with no listener at all.
    let bare = addr
        .strip_prefix("https://")
        .or_else(|| addr.strip_prefix("http://"))
        .unwrap_or(addr);
    let after_bracket = bare.rfind(']').map_or(bare, |i| &bare[i..]);
    if let Some((_, port)) = after_bracket.rsplit_once(':')
        && !port.is_empty()
        && port.chars().all(|c| c.is_ascii_digit())
        && port.parse::<u16>().is_err()
    {
        return Err(AdapterError::InvalidArgument(
            "site address".into(),
            format!("port {port} is out of range"),
        ));
    }

    Ok(())
}

/// 🚫 Whether an address string uses Caddy syntax that Pingclair cannot
/// honor yet: a network prefix (`tcp/`, `unix/`), a Unix socket path
/// (`unix//...`), or a port range (`:8080-8085`).
pub(super) fn looks_like_unsupported_address(addr: &str) -> bool {
    let bare = addr
        .strip_prefix("https://")
        .or_else(|| addr.strip_prefix("http://"))
        .unwrap_or(addr);
    // 🔧 IPv6 zone identifiers (`fe80::1%eth0`) are valid Caddy syntax but
    // need socket-address parsing this codebase does not do yet. Reject them
    // instead of treating the zone as part of a hostname.
    if bare.contains('[') && bare.contains('%') {
        return true;
    }
    let has_network_prefix = bare.split('/').next().is_some_and(|head| {
        matches!(
            head,
            "tcp"
                | "tcp4"
                | "tcp6"
                | "udp"
                | "udp4"
                | "udp6"
                | "ip"
                | "ip4"
                | "ip6"
                | "unix"
                | "unixgram"
                | "unixpacket"
        )
    });
    let has_port_range = bare
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.contains('-'));
    has_network_prefix || has_port_range
}

// MARK: - URL Address Parsing

pub(super) struct ParsedAddress {
    pub(super) hostname: String,
    pub(super) listen: ListenAddr,
    /// 📍 Whether the address itself named a port or a scheme. A bare
    /// hostname (`example.com`) is a virtual-host selector, not a listener:
    /// the runtime derives 443/80 from TLS later, exactly like Caddy.
    pub(super) explicit: bool,
}

/// Parse a Caddy server address like `http://ai.408timeout.com:20615`
/// or `:8080` or `example.com`.
pub(super) fn parse_server_address(addr: &str) -> Option<ParsedAddress> {
    // 🚫 Caddy network addresses may carry a network prefix (`tcp/`,
    // `unix/`, ...) or a port range (`:8080-8085`). Neither has a runtime
    // equivalent here, and treating them as hostnames silently produces a
    // listener that serves the wrong thing.
    if addr.split('/').next().is_some_and(|head| {
        matches!(
            head,
            "tcp"
                | "tcp4"
                | "tcp6"
                | "udp"
                | "udp4"
                | "udp6"
                | "ip"
                | "ip4"
                | "ip6"
                | "unix"
                | "unixgram"
                | "unixpacket"
        )
    }) {
        return None;
    }

    let (scheme, rest) = if let Some(stripped) = addr.strip_prefix("https://") {
        (Scheme::Https, stripped)
    } else if let Some(stripped) = addr.strip_prefix("http://") {
        (Scheme::Http, stripped)
    } else {
        (Scheme::Http, addr)
    };
    let explicit_scheme = addr.contains("://");

    // rest is either: "host:port", ":port", "host", ""
    if rest.is_empty() {
        return None;
    }

    let (hostname, port, explicit_port) = if let Some(port) = rest.strip_prefix(':') {
        // :port
        let p = port.parse::<u16>().ok()?;
        ("[::]".to_string(), Some(p), true)
    } else if let Some(colon_pos) = rest.rfind(':') {
        // host:port
        let h = &rest[..colon_pos];
        let p = rest[colon_pos + 1..].parse::<u16>().ok()?;
        (h.to_string(), Some(p), true)
    } else {
        // host only (default port based on scheme)
        let p = match scheme {
            Scheme::Https => Some(443),
            Scheme::Http => Some(80),
        };
        (rest.to_string(), p, false)
    };

    // Caddy/nginx semantics: only an IP literal in the site address is a
    // bind address. A *hostname* selects the virtual host via the Host
    // header while the listener binds all interfaces. Previously the
    // hostname was passed literally to Pingora as the bind host, so
    // `bench.local:8080 { ... }` crashed at startup with a BindError unless
    // the name happened to resolve to a local interface (localhost worked,
    // real domains didn't) — see benchmarks/README.md.
    let bind_host = if is_ip_literal(&hostname) {
        hostname.clone()
    } else {
        "[::]".to_string()
    };

    Some(ParsedAddress {
        hostname: hostname.clone(),
        listen: ListenAddr {
            scheme,
            host: bind_host,
            port,
            force_plaintext: explicit_scheme && scheme == Scheme::Http,
            // 📍 A site address carries no listener flags; `listen` does.
            proxy_protocol: false,
        },
        // ⚙️ A bare hostname with neither scheme nor port is implicit; the
        // runtime decides the listener from TLS. Everything else (an IP
        // literal, `host:port`, `:port`, `http://`/`https://`) names a
        // listener explicitly.
        // 📍 Explicit means the address itself named a listener: an explicit
        // scheme (`http://`, `https://`), an explicit port (`:8080`,
        // `host:8080`) or an IP literal (which binds by definition). A bare
        // hostname carries only a default port for scheme inference and must
        // not create a listener on its own.
        explicit: explicit_scheme || explicit_port || is_ip_literal(&hostname),
    })
}

/// Whether `host` is an IP literal (bare or bracketed IPv6 included) rather
/// than a hostname.
pub(super) fn is_ip_literal(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
        || host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .is_some_and(|h| h.parse::<std::net::IpAddr>().is_ok())
}

// MARK: - P2 Address Semantics Tests

/// 📍 P2 regressions: a bare hostname site must not create an implicit
/// listener, a multi-listener site must keep its virtual-host name, and
/// Caddy's address forms must derive the expected listeners.
#[cfg(test)]
mod address_semantics_tests {
    use crate::compile;

    fn first_server(source: &str) -> pingclair_core::config::ServerConfig {
        compile(source)
            .expect("config must compile")
            .servers
            .into_iter()
            .next()
            .expect("at least one server")
    }

    #[test]
    fn bare_hostname_with_tls_derives_no_listener() {
        let server = first_server("example.com {\n    tls auto\n    file_server ./public\n}");
        assert!(
            server.listen.is_empty(),
            "a bare hostname must not pin a listener; got {:?}",
            server.listen
        );
        assert!(server.tls.is_some(), "tls auto must survive compilation");
        assert_eq!(server.name.as_deref(), Some("example.com"));
    }

    #[test]
    fn bare_hostname_without_tls_derives_no_listener() {
        let server = first_server("example.com {\n    file_server ./public\n}");
        assert!(
            server.listen.is_empty(),
            "a bare hostname must leave the listener to the runtime"
        );
        assert!(
            server.tls.is_some(),
            "a bare hostname must default to automatic HTTPS like Caddy"
        );
        assert!(
            server.tls.as_ref().unwrap().auto,
            "the default must be `tls auto`, not internal"
        );
    }

    #[test]
    fn auto_https_off_keeps_bare_hostname_plaintext() {
        let config =
            compile("{\n    auto_https off\n}\nexample.com {\n    file_server ./public\n}")
                .expect("compiles");
        assert!(
            config.servers[0].tls.is_none(),
            "auto_https off must suppress the automatic TLS default"
        );
    }

    #[test]
    fn explicit_schemes_still_create_listeners() {
        let https = first_server("https://example.com {\n    respond \"x\"\n}");
        assert_eq!(https.listen, vec!["[::]:443".to_string()]);
        assert!(https.tls.is_some(), "https:// must imply TLS");

        let http = first_server("http://example.com {\n    respond \"x\"\n}");
        assert_eq!(http.listen, vec!["[::]:80".to_string()]);
        assert!(http.tls.is_none(), "http:// must stay plaintext");
    }

    #[test]
    fn explicit_listen_is_not_duplicated_or_augmented() {
        let server = first_server("example.com {\n    listen :80\n    tls auto\n}");
        assert_eq!(
            server.listen,
            vec!["[::]:80".to_string()],
            "the explicit listener must appear exactly once"
        );

        let server = first_server("example.com {\n    listen :8443\n    tls auto\n}");
        assert_eq!(
            server.listen,
            vec!["[::]:8443".to_string()],
            "an explicit non-standard port must not gain an implicit :80"
        );
    }

    #[test]
    fn multi_listener_site_keeps_its_hostname() {
        let server =
            first_server("example.com {\n    listen :80\n    listen :443\n    tls auto\n}");
        assert_eq!(
            server.name.as_deref(),
            Some("example.com"),
            "a multi-listener site must stay a named virtual host"
        );
        assert_eq!(server.names, vec!["example.com".to_string()]);
    }

    #[test]
    fn bare_https_port_implies_tls() {
        let server = first_server(":443 {\n    respond \"x\"\n}");
        assert_eq!(server.name.as_deref(), Some("_"));
        assert_eq!(server.listen, vec!["[::]:443".to_string()]);
        assert!(server.tls.is_some(), ":443 must imply TLS");
    }

    #[test]
    fn multi_address_block_registers_every_hostname() {
        let server = first_server("example.com, www.example.com {\n    respond \"shared\"\n}");
        assert_eq!(
            server.name.as_deref(),
            Some("example.com"),
            "the first address is the primary name"
        );
        assert_eq!(
            server.names,
            vec!["example.com".to_string(), "www.example.com".to_string()]
        );
    }

    #[test]
    fn catch_all_schemes_get_the_conventional_listener() {
        let https = first_server("https:// {\n    respond \"x\"\n}");
        assert_eq!(https.listen, vec!["[::]:443".to_string()]);
        assert!(https.tls.is_some());

        let http = first_server("http:// {\n    respond \"x\"\n}");
        assert_eq!(http.listen, vec!["[::]:80".to_string()]);
        assert!(http.tls.is_none());
    }

    #[test]
    fn global_http_and_https_ports_parse() {
        let config = compile(
            "{\n    http_port 8080\n    https_port 8443\n}\nlocalhost {\n    respond \"x\"\n}",
        )
        .expect("port overrides must compile");
        assert_eq!(config.global.http_port, 8080);
        assert_eq!(config.global.https_port, 8443);
    }

    #[test]
    fn ip_literal_site_binds_to_the_literal() {
        let server = first_server("127.0.0.1 {\n    respond \"x\"\n}");
        assert_eq!(server.listen, vec!["127.0.0.1:80".to_string()]);
    }

    #[test]
    fn bind_directive_is_carried_separately() {
        let server = first_server("example.com {\n    bind 127.0.0.1\n    tls auto\n}");
        assert_eq!(server.bind.as_deref(), Some("127.0.0.1"));
        assert!(
            server.listen.is_empty(),
            "bind names an interface, not a listener"
        );
    }
}
