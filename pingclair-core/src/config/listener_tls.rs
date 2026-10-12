// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔐 Whether one listener address speaks TLS, decided in one place.
//!
//! The same bytes on a socket are either an HTTP request or a TLS
//! ClientHello, so every reader that asks "is this listener encrypted?" has to
//! get the same answer: the runtime that installs the acceptor, the reload
//! path that rebuilds a listener, and the validator that refuses a
//! configuration before either of them runs. When the validator and the
//! runtime each carried their own copy of this rule, the validator could pass
//! a socket the runtime then opened differently.
//!
//! The rule, in priority order:
//!
//! 1. 📴 An address the site declared plaintext (an `http://` address, or
//!    `tls off`) is plaintext.
//! 2. 🛡️ The HTTP port is plaintext even beside a `tls` block: ACME's HTTP-01
//!    probe arrives in the clear and would fail a TLS handshake.
//! 3. 🔐 Otherwise a `tls` block, the HTTPS port, or 8443 (the legacy
//!    convention) means TLS.
//!
//! 📌 Load path only — validation, startup and reload. Nothing here runs per
//! request.

use super::{ServerConfig, normalize_listen_addr};

/// 🔒 The port browsers and clients assume is HTTPS, whatever `https_port`
/// says. Plaintext here is refused even when `https_port` names another port.
pub const CONVENTIONAL_HTTPS_PORT: u16 = 443;

/// 🔢 The port of a listen address, `None` when it does not spell one.
pub fn listen_port(address: &str) -> Option<u16> {
    address
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
}

impl ServerConfig {
    /// 🔐 Whether this site expects TLS on `address`; see the module rule.
    pub fn requires_tls_on(&self, address: &str, http_port: u16, https_port: u16) -> bool {
        let normalized = normalize_listen_addr(address);
        if self
            .plaintext_listen
            .iter()
            .any(|declared| normalize_listen_addr(declared) == normalized)
        {
            return false;
        }
        let port = listen_port(&normalized);
        if port == Some(http_port) {
            return false;
        }
        self.tls.is_some() || port.is_some_and(|port| port == https_port || port == 8443)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔐 A `tls` block enables TLS on any port; the HTTPS port and 8443
    /// imply it without one.
    #[test]
    fn explicit_tls_enables_a_nonstandard_https_listener() {
        let config = ServerConfig {
            listen: vec!["127.0.0.1:21209".to_string()],
            tls: Some(Default::default()),
            ..Default::default()
        };
        assert!(config.requires_tls_on("127.0.0.1:21209", 80, 443));

        let plain = ServerConfig::default();
        assert!(!plain.requires_tls_on("127.0.0.1:21209", 80, 443));
        assert!(plain.requires_tls_on("[::]:443", 80, 443));
        assert!(plain.requires_tls_on("[::]:8443", 80, 443));
    }

    /// 📴 Explicit plaintext policy wins over every port and TLS heuristic.
    #[test]
    fn explicit_http_and_tls_off_listeners_stay_plaintext() {
        let explicit_http = ServerConfig {
            listen: vec!["127.0.0.1:21209".to_string()],
            plaintext_listen: vec!["127.0.0.1:21209".to_string()],
            tls: Some(Default::default()),
            ..Default::default()
        };
        assert!(!explicit_http.requires_tls_on("127.0.0.1:21209", 80, 21209));

        let tls_off = ServerConfig {
            listen: vec!["[::]:443".to_string()],
            plaintext_listen: vec![":443".to_string()],
            ..Default::default()
        };
        assert!(!tls_off.requires_tls_on("[::]:443", 80, 443));
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
        let config = ServerConfig {
            listen: vec!["[::]:80".to_string(), "[::]:443".to_string()],
            tls: Some(Default::default()),
            ..Default::default()
        };

        assert!(
            !config.requires_tls_on("[::]:80", 80, 443),
            "ACME HTTP-01 validation is plaintext on port 80 and must reach the proxy"
        );
        assert!(
            config.requires_tls_on("[::]:443", 80, 443),
            "the TLS block must still apply to the HTTPS listener"
        );
    }
}
