// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🪪 What the TLS handshake learned that the HTTP layer still needs.
//!
//! The handshake and the request are handled in different places by different
//! code: the binary owns the certificate callback, this crate owns the request
//! lifecycle, and nothing carries facts between them by default. Pingora leaves
//! one slot for exactly this — `SslDigest::extension`, an `Arc<dyn Any>` the
//! acceptor fills in and the request handler downcasts.
//!
//! Only one fact travels through it today, and it is the one that makes mutual
//! TLS mean anything: **the name the client asked for during the handshake**.
//! Routing happens on the `Host` header, and a client is free to send one name
//! in the ClientHello and a different one in `Host`. On a listener where some
//! site demands a client certificate and another does not, that difference is a
//! way in — offer the unprotected name, get admitted without a certificate,
//! then ask for the protected site by header. Comparing the two closes it.

/// 🔐 The handshake facts one downstream connection carries into its requests.
#[derive(Debug, Clone)]
pub struct DownstreamTlsIdentity {
    /// 🏷️ The server name from the ClientHello, or empty when none was sent.
    ///
    /// Stored lowercase, because SNI is case-insensitive and the comparison
    /// against `Host` should not pay for a conversion per request.
    pub server_name: Box<str>,
}

impl DownstreamTlsIdentity {
    /// 🏷️ Records the name a client asked for, normalised once.
    pub fn new(server_name: &str) -> Self {
        Self {
            server_name: server_name.to_ascii_lowercase().into(),
        }
    }

    /// 🛡️ Reports whether this connection may ask for `hostname`.
    ///
    /// Takes the hostname with its port already removed, so there is exactly
    /// one place in this crate that knows how to split an authority.
    ///
    /// A client that sent no SNI matches nothing: it never named a site, so it
    /// cannot have named the one it is now asking for. Refusing is the honest
    /// answer, and it is what upstream does — the check exists precisely for
    /// listeners where being admitted is not the same as being authorised.
    pub fn may_request_host(&self, hostname: &str) -> bool {
        if self.server_name.is_empty() {
            return false;
        }
        // 🏠 A `Host` header may be in any case; the stored name is already
        // lowercase, so the comparison never allocates.
        hostname.len() == self.server_name.len()
            && hostname
                .bytes()
                .zip(self.server_name.bytes())
                .all(|(left, right)| left.to_ascii_lowercase() == right)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🛡️ SNI is case-insensitive, so the comparison has to be too — and it
    /// has to compare the whole name, not a prefix of it.
    #[test]
    fn host_matches_the_handshake_name_regardless_of_case() {
        let identity = DownstreamTlsIdentity::new("Secure.Example");
        assert!(identity.may_request_host("secure.example"));
        assert!(identity.may_request_host("SECURE.EXAMPLE"));
        assert!(!identity.may_request_host("other.example"));
        // 🚫 A prefix must not pass: the lengths are compared, not just the
        // bytes that happen to line up.
        assert!(!identity.may_request_host("secure.example.attacker.test"));
        assert!(!identity.may_request_host("secure.exampl"));
    }

    /// 🚫 No SNI means the client named nothing, so it authorised nothing.
    #[test]
    fn a_client_that_sent_no_sni_may_not_name_a_host() {
        let identity = DownstreamTlsIdentity::new("");
        assert!(!identity.may_request_host("secure.example"));
        assert!(!identity.may_request_host(""));
    }
}
