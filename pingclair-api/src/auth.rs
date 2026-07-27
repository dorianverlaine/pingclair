// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! API authentication

use std::net::IpAddr;

/// API key authentication
pub struct ApiKeyAuth {
    key: String,
}

impl ApiKeyAuth {
    /// Create new API key auth
    pub fn new(key: impl Into<String>) -> Self {
        Self { key: key.into() }
    }

    /// Validate an API key
    pub fn validate(&self, provided: &str) -> bool {
        // Constant-time comparison
        self.key.len() == provided.len()
            && self.key.bytes().zip(provided.bytes()).all(|(a, b)| a == b)
    }
}

/// Outcome of an admin API authentication check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthDecision {
    /// The request is allowed to proceed.
    Allowed,
    /// The request must be rejected with 401 Unauthorized.
    Unauthorized,
    /// The request must be rejected with 403 Forbidden.
    Forbidden,
}

/// Decide whether a request may access the admin API.
///
/// When an API key is configured, the request must present it as an
/// `Authorization: Bearer <key>` header. When no key is configured, only
/// loopback clients are allowed, so local operations keep working while
/// remote access to the unauthenticated API is refused.
pub fn authorize(
    key: Option<&ApiKeyAuth>,
    authorization: Option<&str>,
    peer: IpAddr,
) -> AuthDecision {
    match key {
        Some(auth) => match authorization.and_then(|h| h.strip_prefix("Bearer ")) {
            Some(provided) if auth.validate(provided) => AuthDecision::Allowed,
            _ => AuthDecision::Unauthorized,
        },
        None => {
            if peer.is_loopback() {
                AuthDecision::Allowed
            } else {
                AuthDecision::Forbidden
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const KEY: &str = "s3cret-admin-key";

    #[test]
    fn correct_key_is_allowed() {
        let auth = ApiKeyAuth::new(KEY);
        let decision = authorize(
            Some(&auth),
            Some("Bearer s3cret-admin-key"),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        );
        assert_eq!(decision, AuthDecision::Allowed);
    }

    #[test]
    fn wrong_key_is_unauthorized() {
        let auth = ApiKeyAuth::new(KEY);
        let decision = authorize(
            Some(&auth),
            Some("Bearer wrong-key"),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        );
        assert_eq!(decision, AuthDecision::Unauthorized);
    }

    #[test]
    fn missing_header_is_unauthorized() {
        let auth = ApiKeyAuth::new(KEY);
        let decision = authorize(Some(&auth), None, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(decision, AuthDecision::Unauthorized);
    }

    #[test]
    fn keyless_loopback_is_allowed() {
        let v4 = authorize(None, None, IpAddr::V4(Ipv4Addr::LOCALHOST));
        let v6 = authorize(None, None, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(v4, AuthDecision::Allowed);
        assert_eq!(v6, AuthDecision::Allowed);
    }

    #[test]
    fn keyless_remote_is_forbidden() {
        let decision = authorize(None, None, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(decision, AuthDecision::Forbidden);
    }
}
