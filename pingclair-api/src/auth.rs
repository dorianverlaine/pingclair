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

    /// 🔐 Validates a presented API key in constant time with respect to its
    /// contents.
    ///
    /// 🤡 The previous implementation was commented `Constant-time comparison`
    /// and was not one: `.all()` short-circuits, so it returned as soon as two
    /// bytes differed and the time it took revealed how many leading bytes were
    /// right. That is the classic way a secret is recovered one byte at a time,
    /// and the comment was the worst part — it told the next reader the property
    /// had been handled, so nobody looked.
    ///
    /// `subtle::ConstantTimeEq` reads every byte whatever it finds. Length is
    /// still compared normally, by `subtle` itself: a key's length is not the
    /// secret, and no implementation hides it.
    pub fn validate(&self, provided: &str) -> bool {
        use subtle::ConstantTimeEq as _;

        self.key.as_bytes().ct_eq(provided.as_bytes()).into()
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

/// 🌐 Policy for which browser origins may reach the admin API.
#[derive(Debug, Clone, Default)]
pub struct OriginPolicy {
    /// Allowed `Origin`/`Host` values. Empty means "only the listen address".
    pub allowed: Vec<String>,
    /// Apply the check even to loopback callers.
    pub enforce: bool,
    /// The address this admin server is bound to, always allowed.
    pub listen: String,
}

/// 🛡️ Decides whether a request's `Origin` may talk to the admin API.
///
/// **Why this check exists at all.** The admin API can replace the entire
/// running configuration. A page on any website could otherwise `fetch()` a new
/// config into a developer's locally-bound admin endpoint, and the only thing
/// stopping it would be that the attacker had to guess the port. Browsers send
/// `Origin` on exactly those cross-site requests, so refusing unknown ones
/// closes the hole.
///
/// **Why a request with no `Origin` is allowed by default.** `curl` and
/// `systemctl` send none, and browsers do not send one for same-origin
/// navigation. Refusing those would break every command-line use for no gain,
/// since the attack being prevented is specifically a *browser* one. An
/// operator who wants the stricter rule sets `enforce_origin`.
pub fn origin_allowed(policy: &OriginPolicy, origin: Option<&str>, peer: IpAddr) -> bool {
    let Some(origin) = origin else {
        // 🚪 No Origin header: a non-browser caller, unless enforcement is on.
        return !policy.enforce;
    };

    // 🧹 Compare hosts, not full URLs: `http://x:2019` and `https://x:2019`
    // name the same admin endpoint, and an operator writing `origins x:2019`
    // means both.
    let host_of = |value: &str| -> String {
        value
            .trim()
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/')
            .to_ascii_lowercase()
    };
    let candidate = host_of(origin);

    if host_of(&policy.listen) == candidate {
        return true;
    }
    if policy.allowed.iter().any(|a| host_of(a) == candidate) {
        return true;
    }
    // 🏠 Loopback origins are permitted unless enforcement is on, matching
    // Caddy: the endpoint is bound to loopback in the common case anyway.
    if !policy.enforce {
        let bare = candidate.split(':').next().unwrap_or_default();
        if bare == "localhost" || bare.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()) {
            return true;
        }
    }
    let _ = peer;
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// 🔐 The comparison must not stop at the first differing byte.
    ///
    /// ⚠️ What this test proves is behaviour, not timing. It cannot show that the
    /// comparison is constant-time — a timing assertion would be flaky on a
    /// shared runner and worthless anyway. The constant-time property comes from
    /// `subtle::ConstantTimeEq`; this test only guards the answers, so that
    /// switching to it did not quietly break authentication.
    ///
    /// 🤡 The comment above the old implementation said `constant-time` while the
    /// implementation was `.all()`, which short-circuits. A comment claiming a
    /// security property the code does not have is worse than no comment: it stops
    /// the next reader from checking.
    #[test]
    fn key_validation_answers_correctly_at_every_length() {
        let auth = ApiKeyAuth::new("s3cret-token");

        assert!(auth.validate("s3cret-token"));
        // 🎯 Differs at the first byte, the last byte, and in length — the three
        // shapes a short-circuiting comparison treats differently.
        assert!(!auth.validate("X3cret-token"));
        assert!(!auth.validate("s3cret-tokeX"));
        assert!(!auth.validate("s3cret-toke"));
        assert!(!auth.validate("s3cret-tokenn"));
        assert!(!auth.validate(""));
        assert!(!auth.validate("completely different and longer"));
    }

    /// 🔐 An empty configured key matches only an empty presentation — it must not
    /// become a key that matches everything.
    #[test]
    fn an_empty_configured_key_does_not_match_everything() {
        let auth = ApiKeyAuth::new("");
        assert!(!auth.validate("anything"));
        assert!(auth.validate(""));
    }

    fn policy(allowed: &[&str], enforce: bool) -> OriginPolicy {
        OriginPolicy {
            allowed: allowed.iter().map(|s| (*s).to_string()).collect(),
            enforce,
            listen: "127.0.0.1:2019".to_string(),
        }
    }

    /// 🛡️ The attack this exists to stop: a page on some other site posting a
    /// new configuration into a locally-bound admin endpoint.
    #[test]
    fn an_unknown_browser_origin_is_refused() {
        assert!(!origin_allowed(
            &policy(&[], false),
            Some("https://evil.example"),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        ));
    }

    /// 🚪 curl and systemctl send no Origin, and must keep working.
    #[test]
    fn a_request_without_an_origin_is_allowed_by_default() {
        assert!(origin_allowed(
            &policy(&[], false),
            None,
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        ));
    }

    /// 🛡️ …unless the operator asked for the stricter rule.
    #[test]
    fn enforce_origin_refuses_a_request_without_one() {
        assert!(!origin_allowed(
            &policy(&[], true),
            None,
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        ));
    }

    #[test]
    fn a_named_origin_is_allowed_whatever_its_scheme() {
        let p = policy(&["admin.example.com"], true);
        for origin in ["http://admin.example.com", "https://admin.example.com"] {
            assert!(
                origin_allowed(&p, Some(origin), IpAddr::V4(Ipv4Addr::LOCALHOST)),
                "{origin} should be allowed"
            );
        }
    }

    /// 🏠 The endpoint's own address always works, or the admin UI could not
    /// talk to the server hosting it.
    #[test]
    fn the_listen_address_is_always_allowed() {
        assert!(origin_allowed(
            &policy(&[], true),
            Some("http://127.0.0.1:2019"),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        ));
    }

    /// 🚫 A prefix must not satisfy the check: `evil.com` must not be admitted
    /// by an allow list containing `admin.evil.com.attacker.net`, nor the
    /// reverse.
    #[test]
    fn origins_match_whole_hosts_not_prefixes() {
        let p = policy(&["admin.example.com"], true);
        assert!(!origin_allowed(
            &p,
            Some("https://admin.example.com.attacker.net"),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        ));
    }

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
