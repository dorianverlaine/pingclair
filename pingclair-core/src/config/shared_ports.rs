// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔌 One port, one listener: folding specific addresses into a wildcard.
//!
//! The plain idea: when one site listens on `127.0.0.1:8080` and another on
//! `[::]:8080`, there must be a single socket on port 8080 that carries both
//! sites and tells them apart by `Host`, exactly as two hostname sites on the
//! same port are told apart.
//!
//! 🤡 Without this, the two addresses became two sockets. Linux refuses to
//! bind a specific address on a port that a wildcard socket already listens on
//! (and the other way round), so whichever bound first won. When the wildcard
//! won, Pingora retried `127.0.0.1:8080` forever, and every request to
//! `127.0.0.1:8080` was answered by the wildcard socket, which did not carry
//! the `127.0.0.1` site. macOS allows both sockets, which is why the bug only
//! ever showed on Linux, and only when the kernel picked that order (#246).
//!
//! 🧭 Caddy never has this problem because a site address's host is only a
//! `Host` matcher there: listeners come from the port (and `bind`). This
//! module keeps the narrower behaviour this project already had, where an
//! IP-literal site binds only its own address, for every port on which that is
//! all there is; it folds the address only when a wildcard socket must exist
//! on the same port anyway. 📌 Once folded, the literal site is reachable
//! through the wildcard socket by any client that sends its `Host`, which is
//! what Caddy does for every IP-literal site: the address in a site name
//! selects a site, it was never an access control. Each fold is logged when
//! the configuration loads, so it is not a silent change.
//!
//! 🚫 A `bind` restriction is never folded. `bind 127.0.0.1` is an explicit
//! promise that the site is unreachable from other interfaces, and serving it
//! through a wildcard socket would quietly break that promise. That
//! combination is refused instead.
//!
//! 📌 Everything here runs at load time — validation, startup, and reload —
//! and rewrites addresses in the configuration, so every later consumer
//! (listener grouping, TLS decisions, PROXY protocol, HTTP/3) sees one address
//! per port and nothing is decided per request.

use super::{PingclairConfig, normalize_listen_addr};
use std::net::{IpAddr, SocketAddr};

/// 🔌 A specific address that is served through a wildcard socket instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldedListener {
    /// 📍 The address a site named, such as `127.0.0.1:8080`.
    pub specific: String,
    /// 🌐 The wildcard socket that carries it, such as `[::]:8080`.
    pub wildcard: String,
}

/// 🚫 A configuration whose shared port cannot be served by one socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedPortConflict(pub String);

impl std::fmt::Display for SharedPortConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SharedPortConflict {}

/// 🔌 Which specific addresses one configuration folds, decided once per load.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SharedPortFold {
    folded: Vec<FoldedListener>,
}

impl SharedPortFold {
    /// 🧭 Decides the fold for `config`.
    ///
    /// `extra_wildcards` names wildcard sockets the runtime adds on its own —
    /// the automatic HTTPS companion on the HTTP port is the one that exists —
    /// because a specific address on that port collides with it just the same.
    ///
    /// # Errors
    ///
    /// Refuses a `bind`-restricted site on a port that also has a wildcard
    /// socket, and an addressed `servers <address>` block for an address that
    /// would no longer be a socket of its own.
    pub fn plan(
        config: &PingclairConfig,
        extra_wildcards: &[String],
    ) -> Result<Self, SharedPortConflict> {
        let http_port = config.global.http_port;
        let https_port = config.global.https_port;
        let every_address = config
            .servers
            .iter()
            .flat_map(|server| server.listen_addresses(http_port, https_port))
            .chain(
                extra_wildcards
                    .iter()
                    .map(|address| normalize_listen_addr(address)),
            );
        let wildcards: Vec<SocketAddr> = every_address
            .filter_map(|address| address.parse::<SocketAddr>().ok())
            .filter(|address| address.ip().is_unspecified())
            .collect();
        if wildcards.is_empty() {
            return Ok(Self::default());
        }

        let mut folded: Vec<FoldedListener> = Vec::new();
        for server in &config.servers {
            for address in server.listen_addresses(http_port, https_port) {
                let Some(wildcard) = covering_wildcard(&address, &wildcards) else {
                    continue;
                };
                // 🛡️ A derived address with no `listen` of its own came from
                // `bind` (or `default_bind`); see the module comment.
                if server.listen.is_empty() {
                    return Err(SharedPortConflict(format!(
                        "site {} is restricted to {address} by `bind`, but port {} also has the \
                         wildcard listener {wildcard}; one port is one socket, so the site would \
                         become reachable on every interface. Bind every site on that port to the \
                         same addresses, or move the restricted site to another port",
                        server.name.as_deref().unwrap_or("_"),
                        wildcard.port(),
                    )));
                }
                if !folded.iter().any(|known| known.specific == address) {
                    folded.push(FoldedListener {
                        specific: address,
                        wildcard: wildcard.to_string(),
                    });
                }
            }
        }

        // 🚫 An addressed block for a folded address would configure a socket
        // that no longer exists; ignoring it would silently drop its options.
        for key in config.global.listener_options.keys() {
            let normalized = normalize_listen_addr(key);
            if let Some(fold) = folded.iter().find(|fold| fold.specific == normalized) {
                return Err(SharedPortConflict(format!(
                    "`servers {key} {{ … }}` configures {key}, but that address shares its port \
                     with the wildcard listener {} and is served through it; address the block to \
                     {} instead",
                    fold.wildcard, fold.wildcard,
                )));
            }
        }
        Ok(Self { folded })
    }

    /// 🔎 Every address this fold moves, in configuration order.
    #[must_use]
    pub fn folded(&self) -> &[FoldedListener] {
        &self.folded
    }

    /// 🔁 Rewrites every server's addresses so each folded one names its
    /// wildcard, keeping the plaintext and PROXY protocol declarations that
    /// travel with an address in step with it.
    pub fn apply(&self, config: &mut PingclairConfig) {
        if self.folded.is_empty() {
            return;
        }
        for server in &mut config.servers {
            for addresses in [
                &mut server.listen,
                &mut server.plaintext_listen,
                &mut server.proxy_protocol_listen,
            ] {
                self.rewrite(addresses);
            }
        }
    }

    /// 🔁 Replaces folded entries and drops the duplicates that creates: a
    /// site listening on both `127.0.0.1:8080` and `[::]:8080` is one socket.
    fn rewrite(&self, addresses: &mut Vec<String>) {
        let mut rewritten: Vec<String> = Vec::with_capacity(addresses.len());
        for address in addresses.drain(..) {
            let normalized = normalize_listen_addr(&address);
            let next = match self.folded.iter().find(|fold| fold.specific == normalized) {
                Some(fold) => fold.wildcard.clone(),
                None => address,
            };
            if !rewritten
                .iter()
                .any(|known| normalize_listen_addr(known) == normalize_listen_addr(&next))
            {
                rewritten.push(next);
            }
        }
        *addresses = rewritten;
    }
}

/// 🌐 The wildcard socket on the same port that would receive traffic for
/// `address`, if there is one.
///
/// 📌 `[::]` is dual-stack (Pingora leaves `IPV6_V6ONLY` at the system
/// default, which is off on Linux and macOS), so it covers IPv4 and IPv6
/// addresses alike; `0.0.0.0` covers only IPv4. An IPv4 address prefers the
/// `0.0.0.0` socket when both exist, because that is the one it collides with
/// most directly.
fn covering_wildcard(address: &str, wildcards: &[SocketAddr]) -> Option<SocketAddr> {
    let specific = address.parse::<SocketAddr>().ok()?;
    if specific.ip().is_unspecified() {
        return None;
    }
    let on_port = || {
        wildcards
            .iter()
            .filter(move |wildcard| wildcard.port() == specific.port())
    };
    let ipv4_wildcard = on_port().find(|wildcard| wildcard.is_ipv4());
    let ipv6_wildcard = on_port().find(|wildcard| wildcard.is_ipv6());
    match specific.ip() {
        IpAddr::V4(_) => ipv4_wildcard.or(ipv6_wildcard).copied(),
        IpAddr::V6(_) => ipv6_wildcard.copied(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ListenerOptions, ServerConfig};

    fn site(name: &str, listen: &[&str]) -> ServerConfig {
        ServerConfig {
            name: Some(name.to_string()),
            names: vec![name.to_string()],
            listen: listen.iter().map(ToString::to_string).collect(),
            ..Default::default()
        }
    }

    fn config(servers: Vec<ServerConfig>) -> PingclairConfig {
        PingclairConfig {
            servers,
            ..Default::default()
        }
    }

    /// 🔌 #246: an IP-literal site and a hostname site on one port end up on
    /// one socket, which is a property of the configuration rather than of
    /// which socket the kernel happened to bind first.
    #[test]
    fn a_specific_address_folds_into_the_wildcard_on_its_port() {
        let mut config = config(vec![
            site("127.0.0.1", &["127.0.0.1:8080"]),
            site("example.test", &["[::]:8080"]),
            site("other.test", &["127.0.0.1:9090"]),
        ]);
        let fold = SharedPortFold::plan(&config, &[]).expect("foldable");
        fold.apply(&mut config);

        let listens: Vec<Vec<String>> = config
            .servers
            .iter()
            .map(|server| server.listen.clone())
            .collect();
        assert_eq!(
            listens,
            vec![
                vec!["[::]:8080".to_string()],
                vec!["[::]:8080".to_string()],
                // 🛡️ Alone on its port, the literal keeps binding only itself.
                vec!["127.0.0.1:9090".to_string()],
            ]
        );
        assert_eq!(
            config.servers[0].names,
            vec!["127.0.0.1".to_string()],
            "host matching is unchanged"
        );
    }

    /// 🔁 The automatic HTTPS companion is a wildcard socket too.
    #[test]
    fn a_runtime_wildcard_also_receives_specific_addresses() {
        let mut config = config(vec![site("127.0.0.1", &["127.0.0.1:80"])]);
        config.servers[0].plaintext_listen = vec!["127.0.0.1:80".to_string()];
        let fold = SharedPortFold::plan(&config, &["[::]:80".to_string()]).expect("foldable");
        fold.apply(&mut config);
        assert_eq!(config.servers[0].listen, vec!["[::]:80".to_string()]);
        assert_eq!(
            config.servers[0].plaintext_listen,
            vec!["[::]:80".to_string()]
        );
    }

    /// 🌐 IPv4 prefers `0.0.0.0`; IPv6 can only fold into `[::]`.
    #[test]
    fn address_families_pick_the_socket_that_covers_them() {
        let mut config = config(vec![
            site("a", &["127.0.0.1:8080", "[::1]:8080"]),
            site("b", &["0.0.0.0:8080"]),
            site("c", &["[::1]:9090"]),
            site("d", &["0.0.0.0:9090"]),
        ]);
        SharedPortFold::plan(&config, &[])
            .expect("foldable")
            .apply(&mut config);
        assert_eq!(
            config.servers[0].listen,
            vec!["0.0.0.0:8080".to_string(), "[::1]:8080".to_string()]
        );
        assert_eq!(config.servers[2].listen, vec!["[::1]:9090".to_string()]);
    }

    /// 🚫 A `bind` restriction is a promise about exposure and is not folded.
    #[test]
    fn a_bind_restricted_site_beside_a_wildcard_is_refused() {
        let mut restricted = site("internal.test", &[]);
        restricted.bind = Some("127.0.0.1".to_string());
        let config = config(vec![restricted, site("public.test", &[":80"])]);
        let error = SharedPortFold::plan(&config, &[]).expect_err("refused");
        assert!(error.0.contains("`bind`"), "{error}");
    }

    /// 🚫 An addressed block must not outlive the socket it configured.
    #[test]
    fn listener_options_for_a_folded_address_are_refused() {
        let mut config = config(vec![
            site("127.0.0.1", &["127.0.0.1:8080"]),
            site("example.test", &["[::]:8080"]),
        ]);
        config
            .global
            .listener_options
            .insert("127.0.0.1:8080".to_string(), ListenerOptions::default());
        assert!(SharedPortFold::plan(&config, &[]).is_err());
    }
}
