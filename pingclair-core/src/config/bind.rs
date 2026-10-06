// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📍 `bind` decides which interface a site's sockets sit on.
//!
//! The plain idea: `http://example.test:8080 { bind 127.0.0.1 }` asks for a
//! site on port 8080 that only this machine can reach. The address names the
//! port (and the `Host` the site answers), and `bind` names the interface, so
//! the socket is `127.0.0.1:8080`.
//!
//! 🤡 Before this module, `bind` was read only when a site had no address of
//! its own. A site with an explicit port kept the wildcard host its address
//! produced, so the example above listened on `[::]:8080` — every interface —
//! while the operator believed it was loopback-only.
//!
//! The fix is one rewrite at load time: every entry in `listen`, and in the
//! `plaintext_listen` and `proxy_protocol_listen` lists that must stay equal to
//! entries of `listen`, gets its host replaced by the bind host. Rewriting the
//! configuration, instead of teaching each reader about `bind`, is what keeps
//! the readers in agreement: TLS policy, PROXY protocol, the shared-port fold,
//! listener grouping and the HTTP/3 UDP socket all compare these strings, and a
//! reader that saw the rewritten `listen` beside an unrewritten
//! `plaintext_listen` would decide a plaintext port needs TLS.
//!
//! 🧭 Semantics follow Caddy (from memory, source not read): there `bind`
//! governs the listener address and a site address only contributes its port
//! and a `Host` matcher.
//!
//! 📌 Load path only — compilation, validation, startup and reload. Nothing
//! here runs per request.

use super::{PingclairConfig, ServerConfig, normalize_listen_addr};
use std::borrow::Cow;

/// 🌐 The host part of a socket address for a `bind` value.
///
/// An IPv6 address needs brackets before a port can follow it: `::1` plus
/// `443` must become `[::1]:443`, because `::1:443` is a different (and
/// portless) IPv6 address. Hostnames and IPv4 pass through unchanged, and a
/// value that is already bracketed stays as it is.
///
/// `None` for an empty value, which names no interface.
pub(crate) fn bind_socket_host(bind: &str) -> Option<String> {
    if bind.is_empty() {
        return None;
    }
    Some(match bind.parse::<std::net::Ipv6Addr>() {
        Ok(ipv6) => format!("[{ipv6}]"),
        Err(_) => bind.to_string(),
    })
}

impl ServerConfig {
    /// 📍 Puts every declared listener of this site on its `bind` host.
    ///
    /// Idempotent, so the compiler and the runtime can both apply it: the
    /// compiler so `adapt` shows the real addresses, the runtime so a JSON
    /// document posted to the Admin API gets the same answer. An entry whose
    /// port cannot be read is left alone for validation to report.
    pub fn apply_bind(&mut self) {
        let Some(host) = self.bind.as_deref().and_then(bind_socket_host) else {
            return;
        };
        for addresses in [
            &mut self.listen,
            &mut self.plaintext_listen,
            &mut self.proxy_protocol_listen,
        ] {
            let mut bound: Vec<String> = Vec::with_capacity(addresses.len());
            for address in addresses.drain(..) {
                let next = rebind(&address, &host).unwrap_or(address);
                // 🔁 `[::]:8080` and `127.0.0.1:8080` under one bind are one
                // socket; listing it twice would bind it twice.
                if !bound.contains(&next) {
                    bound.push(next);
                }
            }
            *addresses = bound;
        }
    }

    /// 🔎 Whether [`Self::apply_bind`] would change anything.
    fn bind_changes_listeners(&self) -> bool {
        let Some(host) = self.bind.as_deref().and_then(bind_socket_host) else {
            return false;
        };
        [
            &self.listen,
            &self.plaintext_listen,
            &self.proxy_protocol_listen,
        ]
        .into_iter()
        .flatten()
        .any(|address| rebind(address, &host).is_some_and(|next| next != *address))
    }
}

/// 📍 `address` with its host replaced by `host`, or `None` when its port
/// cannot be read.
fn rebind(address: &str, host: &str) -> Option<String> {
    let normalized = normalize_listen_addr(address);
    let (_, port) = normalized.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    Some(format!("{host}:{port}"))
}

/// 📍 The configuration with every site's listeners on its `bind` host.
///
/// Borrowed when no site's `bind` changes anything, which includes every
/// configuration compiled from a Pingclairfile: the compiler already applied
/// it. A JSON document is where the owned branch earns its clone.
#[must_use]
pub fn bind_listeners(config: &PingclairConfig) -> Cow<'_, PingclairConfig> {
    if !config
        .servers
        .iter()
        .any(ServerConfig::bind_changes_listeners)
    {
        return Cow::Borrowed(config);
    }
    let mut bound = config.clone();
    for server in &mut bound.servers {
        server.apply_bind();
    }
    Cow::Owned(bound)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(bind: &str, listen: &[&str]) -> ServerConfig {
        ServerConfig {
            bind: Some(bind.to_string()),
            listen: listen.iter().map(ToString::to_string).collect(),
            ..Default::default()
        }
    }

    /// 🛡️ An explicit address keeps its port and takes the bind host, and the
    /// lists that travel with `listen` move with it.
    #[test]
    fn bind_replaces_the_host_of_every_declared_listener() {
        let mut server = site("127.0.0.1", &["[::]:8080", ":443", "127.0.0.1:8080"]);
        server.plaintext_listen = vec![":8080".to_string()];
        server.proxy_protocol_listen = vec!["[::]:443".to_string()];
        server.apply_bind();
        let bound = (
            server.listen,
            server.plaintext_listen,
            server.proxy_protocol_listen,
        );
        assert_eq!(
            bound,
            (
                vec!["127.0.0.1:8080".to_string(), "127.0.0.1:443".to_string()],
                vec!["127.0.0.1:8080".to_string()],
                vec!["127.0.0.1:443".to_string()],
            )
        );
    }

    /// 🌐 IPv6 hosts are bracketed whether or not the operator wrote them so.
    #[test]
    fn an_ipv6_bind_host_is_bracketed() {
        for bind in ["::1", "[::1]"] {
            let mut server = site(bind, &[":8080"]);
            server.apply_bind();
            assert_eq!(server.listen, vec!["[::1]:8080".to_string()], "{bind}");
            assert_eq!(server.listen_addresses(80, 443), server.listen, "{bind}");
        }
        let derived = site("::1", &[]);
        assert_eq!(
            derived.listen_addresses(80, 443),
            vec!["[::1]:80".to_string()]
        );
    }

    /// 📌 Nothing to do is a borrow, and applying twice changes nothing.
    #[test]
    fn applying_bind_is_idempotent() {
        let config = PingclairConfig {
            servers: vec![site("127.0.0.1", &[":8080"])],
            ..Default::default()
        };
        let once = bind_listeners(&config).into_owned();
        assert!(matches!(bind_listeners(&once), Cow::Borrowed(_)));
    }
}
