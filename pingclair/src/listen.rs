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

use std::collections::{HashMap, HashSet};

/// 🌐 Pingora requires a full `IP:port` socket address.
///
/// The rule itself lives in `pingclair_core::config`, because the compiler and
/// the binder have to reach the same answer: an addressed `servers <address>`
/// block is refused unless its address names a listener, and a second copy of
/// this function here is how the two would come to disagree.
pub(crate) use pingclair_core::config::normalize_listen_addr;

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
/// 📴 `auto_https disable_redirects` creates no plaintext companion. Operators
/// who need a plaintext listener must declare it explicitly.
pub(crate) fn automatic_http_companion(
    server_config: &pingclair_core::config::ServerConfig,
    mode: pingclair_core::config::AutoHttpsMode,
    listen_addrs: &[String],
    explicit_http_names: &HashSet<String>,
    http_port: u16,
    https_port: u16,
) -> Option<pingclair_core::config::ServerConfig> {
    use pingclair_core::config::AutoHttpsMode;

    if matches!(mode, AutoHttpsMode::Off | AutoHttpsMode::DisableRedirects)
        || server_config.tls.is_none()
    {
        return None;
    }

    let mut names = if server_config.names.is_empty() {
        server_config.name.iter().cloned().collect()
    } else {
        server_config.names.clone()
    };
    names.retain(|name| {
        !name.is_empty()
            && name != "_"
            && !name.contains('*')
            && !explicit_http_names.contains(&name.to_ascii_lowercase())
    });
    let name = names.first()?.clone();

    let already_serving_http = listen_addrs.iter().any(|addr| {
        addr.rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            == Some(http_port)
    });
    if already_serving_http {
        return None;
    }

    // 🧭 Redirects omit the internal default HTTPS port, as Caddy does. A site
    // on a different port must retain that port so the redirect reaches it.
    let site_port = listen_addrs
        .iter()
        .filter_map(|address| address.rsplit_once(':')?.1.parse::<u16>().ok())
        .find(|port| *port == https_port)
        .or_else(|| {
            listen_addrs
                .first()?
                .rsplit_once(':')?
                .1
                .parse::<u16>()
                .ok()
        })
        .unwrap_or(https_port);
    let redirect_target =
        if matches!(site_port, 80 | 443) || site_port == http_port || site_port == https_port {
            "https://{host}{uri}".to_string()
        } else {
            format!("https://{{host}}:{site_port}{{uri}}")
        };
    let routes = vec![pingclair_core::config::RouteConfig {
        path: "/*".to_string(),
        // 🧭 A 308 keeps POST unchanged across a permanent hop to HTTPS.
        handler: pingclair_core::config::HandlerConfig::Redirect {
            to: pingclair_core::config::ConfigText::Template(redirect_target),
            code: 308,
        },
        methods: None,
        matcher: None,
    }];

    // 📍 The companion sits on the interfaces its site sits on, on the HTTP
    // port, as Caddy's redirect server does (from memory, source not read).
    // Hard-coding `[::]` put the redirect of a `bind 127.0.0.1` site on every
    // interface, the one listener of that site `bind` did not reach.
    let mut sockets: Vec<String> = Vec::with_capacity(1);
    for address in listen_addrs {
        let Some((host, _)) = address.rsplit_once(':') else {
            continue;
        };
        let socket = format!("{host}:{http_port}");
        if !sockets.contains(&socket) {
            sockets.push(socket);
        }
    }
    if sockets.is_empty() {
        sockets.push(format!("[::]:{http_port}"));
    }

    Some(pingclair_core::config::ServerConfig {
        name: Some(name),
        names,
        listen: sockets.clone(),
        proxy_protocol_listen: Vec::new(),
        plaintext_listen: sockets,
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
    let normalized = normalize_listen_addr(addr);
    if config
        .plaintext_listen
        .iter()
        .any(|declared| normalize_listen_addr(declared) == normalized)
    {
        return false;
    }

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

/// 🌐 Collects names whose conventional HTTP listener is explicitly configured.
///
/// Those names must stay routed to their plaintext site instead of being
/// captured by a synthetic redirect generated for a neighbouring HTTPS site.
pub(crate) fn explicit_http_names(
    config: &pingclair_core::config::PingclairConfig,
) -> HashSet<String> {
    let http_port = config.global.http_port;
    config
        .servers
        .iter()
        .filter(|server| {
            server.plaintext_listen.iter().any(|address| {
                normalize_listen_addr(address)
                    .rsplit_once(':')
                    .and_then(|(_, port)| port.parse::<u16>().ok())
                    == Some(http_port)
            })
        })
        .flat_map(|server| {
            if server.names.is_empty() {
                server.name.iter().cloned().collect::<Vec<_>>()
            } else {
                server.names.clone()
            }
        })
        .map(|name| name.to_ascii_lowercase())
        .collect()
}

/// 🔁 Every site's automatic HTTP companion, by site index, on the sockets
/// that will carry it.
///
/// A companion listens on the HTTP port of each host its site listens on. One
/// port is still one socket, though: when a wildcard on the HTTP port already
/// exists — a configured `[::]:80` site, or the companion of a site with no
/// `bind` — a companion address it covers is served through it, by the rule
/// `SharedPortFold` applies to configured sites. Linux binds only one of
/// `127.0.0.1:80` and `[::]:80`, so two sites with different `bind` hosts would
/// otherwise fail to start. 📌 Only the redirect is folded, never the bound
/// site itself, and that is what this configuration did before companions
/// followed `bind`.
///
/// Load path only: startup, reload and the listener policy derivation.
pub(crate) fn automatic_http_companions(
    config: &pingclair_core::config::PingclairConfig,
) -> Vec<Option<pingclair_core::config::ServerConfig>> {
    let http_port = config.global.http_port;
    let https_port = config.global.https_port;
    let explicit_http_names = explicit_http_names(config);
    let mut companions: Vec<Option<pingclair_core::config::ServerConfig>> = config
        .servers
        .iter()
        .map(|server| {
            automatic_http_companion(
                server,
                config.global.auto_https.clone(),
                &server.listen_addresses(http_port, https_port),
                &explicit_http_names,
                http_port,
                https_port,
            )
        })
        .collect();
    let wildcards: Vec<std::net::SocketAddr> = config
        .servers
        .iter()
        .flat_map(|server| server.listen_addresses(http_port, https_port))
        .chain(companions.iter().flatten().flat_map(|c| c.listen.clone()))
        .filter_map(|address| address.parse::<std::net::SocketAddr>().ok())
        .filter(|address| address.ip().is_unspecified())
        .collect();
    for companion in companions.iter_mut().flatten() {
        let mut sockets: Vec<String> = Vec::with_capacity(companion.listen.len());
        for address in &companion.listen {
            let socket = pingclair_core::config::covering_wildcard(address, &wildcards)
                .map_or_else(|| address.clone(), |wildcard| wildcard.to_string());
            if !sockets.contains(&socket) {
                sockets.push(socket);
            }
        }
        companion.plaintext_listen.clone_from(&sockets);
        companion.listen = sockets;
    }
    companions
}

/// 🔌 Puts every site on its `bind` host, then serves each specific address
/// through the wildcard socket on its port, when there is one (#246).
///
/// Startup and every reload call this before deriving a single listener, so
/// both derivations below see the sockets that will exist, one address per
/// port. 🛡️ The bind step matters for a JSON document, which never passed
/// through the compiler that applies it to a Pingclairfile. The automatic HTTPS
/// companions count too: they are not in `config.servers`, but they are
/// sockets, and a `127.0.0.1:80` site beside a companion on `[::]:80` would
/// collide with it exactly as with a configured one.
///
/// Borrowed when nothing folds, which is every configuration without a shared
/// port; this runs on the load path only.
pub(crate) fn bind_and_fold_listeners(
    config: &pingclair_core::config::PingclairConfig,
    automatic_http_available: bool,
) -> Result<
    std::borrow::Cow<'_, pingclair_core::config::PingclairConfig>,
    pingclair_core::config::SharedPortConflict,
> {
    let config = pingclair_core::config::bind_listeners(config);
    // 📌 `plan` keeps only the wildcards among these; a companion on a bound
    // host is a specific address and folds nothing.
    let runtime_sockets: Vec<String> = if automatic_http_available {
        automatic_http_companions(&config)
            .into_iter()
            .flatten()
            .flat_map(|companion| companion.listen)
            .collect()
    } else {
        Vec::new()
    };

    let fold = pingclair_core::config::SharedPortFold::plan(&config, &runtime_sockets)?;
    if fold.folded().is_empty() {
        return Ok(config);
    }
    for folded in fold.folded() {
        tracing::info!(
            specific = %folded.specific,
            wildcard = %folded.wildcard,
            "🔌 Serving a specific address through the wildcard listener on its port; \
             its sites are still matched by Host"
        );
    }
    let mut folded = config.into_owned();
    fold.apply(&mut folded);
    Ok(std::borrow::Cow::Owned(folded))
}

/// 🧭 Maps every server (and its automatic HTTP companion) to the concrete
/// bind addresses it serves, exactly like the startup listener derivation.
///
/// Reload used to key on `listen.first()` alone, which put a hostname site
/// on `0.0.0.0:80` and never touched the TLS listener that actually served
/// it — the reload reported success while behavior stayed frozen.
pub(crate) fn servers_by_bind_address(
    config: &pingclair_core::config::PingclairConfig,
    automatic_http_available: bool,
) -> HashMap<String, Vec<pingclair_core::config::ServerConfig>> {
    let http_port = config.global.http_port;
    let https_port = config.global.https_port;
    let companions = if automatic_http_available {
        automatic_http_companions(config)
    } else {
        Vec::new()
    };
    let mut by_port: HashMap<String, Vec<pingclair_core::config::ServerConfig>> = HashMap::new();
    for (index, server) in config.servers.iter().enumerate() {
        // 📌 The one derivation `validate_config` also uses; a private copy
        // here once pasted an IPv6 `bind` host without its brackets.
        for addr in server.listen_addresses(http_port, https_port) {
            by_port.entry(addr).or_default().push(server.clone());
        }
        // 🔁 Each companion right after its site, the order startup uses.
        if let Some(Some(companion)) = companions.get(index) {
            for addr in &companion.listen {
                by_port
                    .entry(addr.clone())
                    .or_default()
                    .push(companion.clone());
            }
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

    /// 📴 Explicit plaintext policy wins over every port and TLS heuristic.
    #[test]
    fn explicit_http_and_tls_off_listeners_stay_plaintext() {
        let explicit_http = pingclair_core::config::ServerConfig {
            listen: vec!["127.0.0.1:21209".to_string()],
            plaintext_listen: vec!["127.0.0.1:21209".to_string()],
            tls: Some(Default::default()),
            ..Default::default()
        };
        assert!(!server_requires_tls(
            &explicit_http,
            "127.0.0.1:21209",
            80,
            21209
        ));

        let tls_off = pingclair_core::config::ServerConfig {
            listen: vec!["[::]:443".to_string()],
            plaintext_listen: vec![":443".to_string()],
            ..Default::default()
        };
        assert!(!server_requires_tls(&tls_off, "[::]:443", 80, 443));
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

        let companion = automatic_http_companion(
            &site,
            AutoHttpsMode::On,
            &["[::]:443".to_string()],
            &HashSet::new(),
            80,
            443,
        )
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

    /// 🛡️ An explicitly configured HTTP host must not be replaced by a redirect.
    #[test]
    fn mixed_scheme_hostname_suppresses_automatic_redirect_companion() {
        use pingclair_core::config::AutoHttpsMode;

        let secure = pingclair_core::config::ServerConfig {
            name: Some("mixed.example".to_string()),
            names: vec!["mixed.example".to_string()],
            listen: vec!["[::]:443".to_string()],
            tls: Some(Default::default()),
            ..Default::default()
        };
        let explicit = HashSet::from(["mixed.example".to_string()]);
        assert!(
            automatic_http_companion(
                &secure,
                AutoHttpsMode::On,
                &["[::]:443".to_string()],
                &explicit,
                80,
                443,
            )
            .is_none()
        );
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
                &HashSet::new(),
                80,
                443,
            )
            .is_none(),
            "`auto_https off` opts out of all of this"
        );
        assert!(
            automatic_http_companion(
                &https(None),
                AutoHttpsMode::On,
                &ports,
                &HashSet::new(),
                80,
                443,
            )
            .is_none(),
            "a redirect needs a concrete host to send the client to"
        );
        assert!(
            automatic_http_companion(
                &https(Some("*.example.com")),
                AutoHttpsMode::On,
                &ports,
                &HashSet::new(),
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
                &HashSet::new(),
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
                &HashSet::new(),
                80,
                443,
            )
            .is_none(),
            "an explicit port 80 listener must not be overruled"
        );
    }

    /// 📍 A companion follows its site onto the bound interface, and is served
    /// through a wildcard that another site's companion already needs on the
    /// HTTP port, because Linux binds only one of the two.
    #[test]
    fn companions_listen_where_their_sites_do() {
        let https = |name: &str, bind: Option<&str>| pingclair_core::config::ServerConfig {
            name: Some(name.to_string()),
            bind: bind.map(str::to_string),
            tls: Some(Default::default()),
            ..Default::default()
        };
        let companion_sockets = |servers: Vec<pingclair_core::config::ServerConfig>| {
            let config = pingclair_core::config::PingclairConfig {
                servers,
                ..Default::default()
            };
            automatic_http_companions(&config)
                .into_iter()
                .map(|companion| companion.map(|companion| companion.listen))
                .collect::<Vec<_>>()
        };

        assert_eq!(
            [
                companion_sockets(vec![https("a.test", Some("127.0.0.1"))]),
                companion_sockets(vec![https("a.test", Some("::1"))]),
                companion_sockets(vec![
                    https("a.test", Some("127.0.0.1")),
                    https("b.test", None),
                ]),
            ],
            [
                vec![Some(vec!["127.0.0.1:80".to_string()])],
                vec![Some(vec!["[::1]:80".to_string()])],
                vec![
                    Some(vec!["[::]:80".to_string()]),
                    Some(vec!["[::]:80".to_string()]),
                ],
            ]
        );
    }

    /// 📴 Disabling redirects must leave the automatic plaintext port unbound.
    #[test]
    fn disable_redirects_does_not_create_a_companion() {
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
            &HashSet::new(),
            80,
            443,
        );
        assert!(companion.is_none());
    }
}
