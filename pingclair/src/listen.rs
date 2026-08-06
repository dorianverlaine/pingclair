// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 Which sockets a configuration actually needs.
//!
//! A Pingclairfile never mentions port 80, and rarely mentions `listen` at
//! all — so something has to turn "serve example.com over HTTPS" into a set of
//! concrete bind addresses. That is this module, and it is the same derivation
//! twice: once at startup and once on reload, which is why
//! [`servers_by_bind_address`] lives beside the pieces it reuses rather than
//! next to the reload loop. When those two derivations disagreed, a reload
//! reported success and changed nothing.
//!
//! [`crate::addr`] answers the neighbouring question for the quick commands:
//! what a single address string means. Nothing here parses an address.

use std::collections::HashMap;

/// 🌐 Pingora requires a full `IP:port` socket address.
///
/// This helper accepts Caddy-style `:port` shorthand by binding the wildcard
/// address, so JSON configurations match the Pingclair DSL adapter's behavior.
pub(crate) fn normalize_listen_addr(addr: &str) -> String {
    match addr.strip_prefix(':') {
        Some(port) => format!("[::]:{port}"),
        None => addr.to_string(),
    }
}

/// 🧭 Reserves a unique private loopback address for one PROXY protocol ingress hop.
pub(crate) fn reserve_private_listener_address()
-> anyhow::Result<(std::net::TcpListener, std::net::SocketAddr)> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    Ok((listener, address))
}

/// 🚫 Port 80 is plaintext HTTP and never carries TLS, whatever the block says.
///
/// 🔁 Builds the plaintext-HTTP companion site for an HTTPS site, as Caddy does.
///
/// The idea in one sentence: a visitor who types `example.com` without a scheme
/// arrives over plain HTTP, so something has to be listening there to send them
/// to HTTPS — and the CA needs that same port in the clear to validate the
/// certificate. Caddy provisions both automatically, which is why a Caddyfile
/// never mentions `listen` or port 80 at all.
///
/// Returns `None` when there is nothing to provision:
///
/// - `auto_https off` — the operator opted out of all of this.
/// - the site serves no TLS, so there is no HTTPS to redirect to.
/// - the site has no concrete name; a redirect needs a host to send them to,
///   and a wildcard would guess wrong.
/// - the site already listens on the HTTP port, meaning the operator has said what
///   they want served there and we must not overrule it.
///
/// Under `auto_https disable_redirects` the listener is still provisioned but
/// carries no routes: the ACME challenge path is answered before routing, so
/// validation keeps working while ordinary requests get no redirect. That is
/// precisely what the mode asks for, and until now it did nothing at all.
pub(crate) fn automatic_http_companion(
    server_config: &pingclair_core::config::ServerConfig,
    mode: pingclair_core::config::AutoHttpsMode,
    listen_addrs: &[String],
    http_port: u16,
    https_port: u16,
) -> Option<pingclair_core::config::ServerConfig> {
    use pingclair_core::config::AutoHttpsMode;

    if mode == AutoHttpsMode::Off || server_config.tls.is_none() {
        return None;
    }

    let name = server_config.name.as_deref()?;
    if name.is_empty() || name.contains('*') {
        return None;
    }

    let already_serving_http = listen_addrs.iter().any(|addr| {
        addr.rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            == Some(http_port)
    });
    if already_serving_http {
        return None;
    }

    let routes = if mode == AutoHttpsMode::DisableRedirects {
        Vec::new()
    } else {
        // 🧭 The redirect target must land on the HTTPS port, not whatever
        // port the client used for plaintext HTTP. The default 443 needs no
        // suffix; a custom `https_port` does.
        let redirect_target = if https_port == 443 {
            "https://{host}{uri}".to_string()
        } else {
            format!("https://{{host}}:{https_port}{{uri}}")
        };
        vec![pingclair_core::config::RouteConfig {
            path: "/*".to_string(),
            // 🧭 308 rather than 302: the redirect is permanent, and unlike 301
            // it forbids a client from rewriting POST into GET, so a form
            // submitted over HTTP survives the hop to HTTPS.
            handler: pingclair_core::config::HandlerConfig::Redirect {
                to: redirect_target,
                code: 308,
            },
            methods: None,
            matcher: None,
        }]
    };

    Some(pingclair_core::config::ServerConfig {
        name: server_config.name.clone(),
        listen: vec![format!("[::]:{http_port}")],
        proxy_protocol_listen: Vec::new(),
        tls: None,
        routes,
        ..Default::default()
    })
}

/// 🔎 Reports whether this process can actually take the plaintext HTTP port.
///
/// Port 80 is privileged on Unix and is often already taken, and Pingora binds
/// its listeners far later — at which point a failure aborts a server that was
/// otherwise ready to serve HTTPS perfectly well. Probing first lets the
/// automatic listener be skipped with an explanation instead.
pub(crate) fn can_bind_automatic_http_port(http_port: u16) -> bool {
    std::net::TcpListener::bind(("0.0.0.0", http_port)).is_ok()
}

/// 🔐 Treats explicit TLS configuration as authoritative, except on the
/// plaintext HTTP port.
///
/// Everything except the HTTP port keeps the previous rule: an explicit `tls`
/// block enables TLS anywhere, and the HTTPS port (plus 8443, the legacy
/// convention) implies it even without one.
pub(crate) fn server_requires_tls(
    config: &pingclair_core::config::ServerConfig,
    addr: &str,
    http_port: u16,
    https_port: u16,
) -> bool {
    let port = addr
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok());

    // 🛡️ The plaintext HTTP port must never become a TLS listener: ACME's
    // HTTP-01 probe arrives in the clear and would fail a TLS handshake.
    if port == Some(http_port) {
        return false;
    }

    config.tls.is_some() || port.is_some_and(|port| port == https_port || port == 8443)
}

/// 🧭 Maps every server (and its automatic HTTP companion) to the concrete
/// bind addresses it serves, exactly like the startup listener derivation.
///
/// Reload used to key on `listen.first()` alone, which put a hostname site
/// on `0.0.0.0:80` and never touched the TLS listener that actually served
/// it — the reload reported success while behavior stayed frozen.
pub(crate) fn servers_by_bind_address(
    config: &pingclair_core::config::PingclairConfig,
) -> HashMap<String, Vec<pingclair_core::config::ServerConfig>> {
    let http_port = config.global.http_port;
    let https_port = config.global.https_port;
    let mut by_port: HashMap<String, Vec<pingclair_core::config::ServerConfig>> = HashMap::new();
    for server in &config.servers {
        let addrs: Vec<String> = if server.listen.is_empty() {
            let host = server
                .bind
                .as_deref()
                .filter(|host| !host.is_empty())
                .unwrap_or("[::]");
            let port = if server.tls.is_some() {
                https_port
            } else {
                http_port
            };
            vec![format!("{host}:{port}")]
        } else {
            server
                .listen
                .iter()
                .map(|addr| normalize_listen_addr(addr))
                .collect()
        };
        for addr in &addrs {
            by_port
                .entry(addr.clone())
                .or_default()
                .push(server.clone());
        }
        if let Some(companion) = automatic_http_companion(
            server,
            config.global.auto_https.clone(),
            &addrs,
            http_port,
            https_port,
        ) {
            let addr = format!("[::]:{http_port}");
            by_port.entry(addr).or_default().push(companion);
        }
    }
    by_port
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_listen_addr_expands_bare_port() {
        assert_eq!(normalize_listen_addr(":8443"), "[::]:8443");
        assert_eq!(normalize_listen_addr(":80"), "[::]:80");
        // Full socket addresses pass through untouched.
        assert_eq!(normalize_listen_addr("127.0.0.1:9000"), "127.0.0.1:9000");
        assert_eq!(normalize_listen_addr("[::]:443"), "[::]:443");
        // The normalized form must parse as a SocketAddr (Pingora + H3 both
        // require this).
        assert!(
            normalize_listen_addr(":8443")
                .parse::<std::net::SocketAddr>()
                .is_ok()
        );
    }

    #[test]
    fn explicit_tls_enables_nonstandard_https_listener() {
        let config = pingclair_core::config::ServerConfig {
            listen: vec!["127.0.0.1:21209".to_string()],
            tls: Some(Default::default()),
            ..Default::default()
        };
        assert!(server_requires_tls(&config, "127.0.0.1:21209", 80, 443));

        let plain = pingclair_core::config::ServerConfig::default();
        assert!(!server_requires_tls(&plain, "127.0.0.1:21209", 80, 443));
        assert!(server_requires_tls(&plain, "[::]:443", 80, 443));
        assert!(server_requires_tls(&plain, "[::]:8443", 80, 443));
    }

    /// 🚫 A `tls` block must not drag port 80 into TLS along with it.
    ///
    /// `example.com { listen :80  listen :443  tls auto }` is the config anyone
    /// writes first, and it used to make port 80 a TLS listener. Let's Encrypt
    /// then sent its plaintext HTTP-01 probe into a TLS handshake, the listener
    /// logged `[HTTP_REQUEST]`, and the order failed — automatic HTTPS could
    /// never obtain the certificate it was trying to install.
    #[test]
    fn port_80_stays_plaintext_even_with_an_explicit_tls_block() {
        let config = pingclair_core::config::ServerConfig {
            listen: vec!["[::]:80".to_string(), "[::]:443".to_string()],
            tls: Some(Default::default()),
            ..Default::default()
        };

        assert!(
            !server_requires_tls(&config, "[::]:80", 80, 443),
            "ACME HTTP-01 validation is plaintext on port 80 and must reach the proxy"
        );
        assert!(
            server_requires_tls(&config, "[::]:443", 80, 443),
            "the TLS block must still apply to the HTTPS listener"
        );
    }

    /// 🔁 An HTTPS site gets a plaintext port-80 companion, like Caddy's.
    #[test]
    fn automatic_https_provisions_a_redirecting_http_listener() {
        use pingclair_core::config::{AutoHttpsMode, HandlerConfig};

        let site = pingclair_core::config::ServerConfig {
            name: Some("example.com".to_string()),
            listen: vec!["[::]:443".to_string()],
            tls: Some(Default::default()),
            ..Default::default()
        };

        let companion =
            automatic_http_companion(&site, AutoHttpsMode::On, &["[::]:443".to_string()], 80, 443)
                .expect("an HTTPS site needs its plaintext companion");

        assert_eq!(companion.listen, vec!["[::]:80".to_string()]);
        assert!(
            companion.tls.is_none(),
            "the companion carries ACME validation traffic and must stay plaintext"
        );
        match &companion.routes.as_slice() {
            [route] => match &route.handler {
                HandlerConfig::Redirect { to, code } => {
                    assert_eq!(to, "https://{host}{uri}");
                    assert_eq!(*code, 308);
                }
                other => panic!("expected a redirect, got {other:?}"),
            },
            other => panic!("expected exactly one catch-all route, got {other:?}"),
        }
    }

    /// 🚫 Every reason to provision nothing at all.
    #[test]
    fn automatic_https_leaves_these_sites_alone() {
        use pingclair_core::config::AutoHttpsMode;

        let https = |name: Option<&str>| pingclair_core::config::ServerConfig {
            name: name.map(str::to_string),
            listen: vec!["[::]:443".to_string()],
            tls: Some(Default::default()),
            ..Default::default()
        };
        let ports = vec!["[::]:443".to_string()];

        assert!(
            automatic_http_companion(
                &https(Some("example.com")),
                AutoHttpsMode::Off,
                &ports,
                80,
                443,
            )
            .is_none(),
            "`auto_https off` opts out of all of this"
        );
        assert!(
            automatic_http_companion(&https(None), AutoHttpsMode::On, &ports, 80, 443).is_none(),
            "a redirect needs a concrete host to send the client to"
        );
        assert!(
            automatic_http_companion(
                &https(Some("*.example.com")),
                AutoHttpsMode::On,
                &ports,
                80,
                443,
            )
            .is_none(),
            "a wildcard would have to guess which host to redirect to"
        );

        let plaintext = pingclair_core::config::ServerConfig {
            name: Some("example.com".to_string()),
            listen: vec!["0.0.0.0:8080".to_string()],
            ..Default::default()
        };
        assert!(
            automatic_http_companion(
                &plaintext,
                AutoHttpsMode::On,
                &["0.0.0.0:8080".to_string()],
                80,
                443,
            )
            .is_none(),
            "there is no HTTPS to redirect to"
        );

        // 🛡️ An operator who wrote `listen :80` has said what belongs there.
        assert!(
            automatic_http_companion(
                &https(Some("example.com")),
                AutoHttpsMode::On,
                &["[::]:80".to_string(), "[::]:443".to_string()],
                80,
                443,
            )
            .is_none(),
            "an explicit port 80 listener must not be overruled"
        );
    }

    /// 🔁 `disable_redirects` keeps the listener but drops the redirect.
    ///
    /// Before this existed the mode parsed, compiled, and then went unread —
    /// a setting that validated and silently did nothing.
    #[test]
    fn disable_redirects_keeps_acme_reachable_without_redirecting() {
        use pingclair_core::config::AutoHttpsMode;

        let site = pingclair_core::config::ServerConfig {
            name: Some("example.com".to_string()),
            listen: vec!["[::]:443".to_string()],
            tls: Some(Default::default()),
            ..Default::default()
        };

        let companion = automatic_http_companion(
            &site,
            AutoHttpsMode::DisableRedirects,
            &["[::]:443".to_string()],
            80,
            443,
        )
        .expect("ACME still needs to be reachable on port 80");

        assert_eq!(companion.listen, vec!["[::]:80".to_string()]);
        assert!(
            companion.routes.is_empty(),
            "the challenge path is answered before routing, so no route means no redirect"
        );
    }
}
