// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔁 Transport-neutral policy for bounded, idempotent upstream redispatch.

use http::Method;
use pingclair_core::config::RetryConfig;
use std::time::{Duration, Instant};

/// 🔁 Returns the request-local retry deadline, when one is configured.
pub(crate) fn deadline(started: Instant, policy: &RetryConfig) -> Option<Instant> {
    policy
        .total_timeout_ms
        .and_then(|millis| started.checked_add(Duration::from_millis(millis)))
}

/// 💤 Returns the fixed delay applied before another upstream attempt.
pub(crate) fn backoff(policy: &RetryConfig) -> Duration {
    Duration::from_millis(policy.backoff_ms)
}

/// ⌛ Checks both the attempt cap and whether one backoff still fits the total deadline.
pub(crate) fn permits_another_attempt(
    policy: &RetryConfig,
    attempts: usize,
    retry_deadline: Option<Instant>,
) -> bool {
    attempts < policy.max_attempts
        && retry_deadline.is_none_or(|deadline| {
            Instant::now()
                .checked_add(backoff(policy))
                .is_some_and(|after_backoff| after_backoff < deadline)
        })
}

/// 🛡️ Allows status redispatch only for configured idempotent, bodyless requests.
pub(crate) fn permits_status_retry(
    policy: &RetryConfig,
    method: &Method,
    body_is_empty: bool,
    path: &str,
    status: u16,
    attempts: usize,
    retry_deadline: Option<Instant>,
) -> bool {
    body_is_empty
        && policy.status_codes.contains(&status)
        && policy
            .methods
            .iter()
            .any(|configured| configured.eq_ignore_ascii_case(method.as_str()))
        && (policy.path_patterns.is_empty()
            || policy
                .path_patterns
                .iter()
                .any(|pattern| glob_matches(pattern, path)))
        && permits_another_attempt(policy, attempts, retry_deadline)
}

/// 🧭 Matches one Caddy-style path glob (`/foo*`) against a request path.
///
/// `*` matches any run of characters; a pattern without `*` must equal the
/// path exactly, mirroring Caddy's path matcher.
fn glob_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let mut parts = pattern.split('*');
    let Some(first) = parts.next() else {
        return true;
    };
    if !value.starts_with(first) {
        return false;
    }
    let mut rest = &value[first.len()..];
    for part in parts {
        if part.is_empty() {
            continue;
        }
        let Some(index) = rest.find(part) else {
            return false;
        };
        rest = &rest[index + part.len()..];
    }
    pattern.ends_with('*') || rest.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_retry_requires_an_idempotent_bodyless_request() {
        let policy = RetryConfig {
            max_attempts: 3,
            status_codes: vec![503],
            methods: vec!["GET".to_string()],
            ..Default::default()
        };
        assert!(permits_status_retry(
            &policy,
            &Method::GET,
            true,
            "/probe",
            503,
            1,
            None
        ));
        assert!(!permits_status_retry(
            &policy,
            &Method::POST,
            true,
            "/probe",
            503,
            1,
            None
        ));
        assert!(!permits_status_retry(
            &policy,
            &Method::GET,
            false,
            "/probe",
            503,
            1,
            None
        ));
    }

    #[test]
    fn path_patterns_gate_status_redispatch_like_caddy() {
        let policy = RetryConfig {
            max_attempts: 3,
            status_codes: vec![503],
            methods: vec!["GET".to_string()],
            path_patterns: vec!["/api/*".to_string()],
            ..Default::default()
        };
        assert!(permits_status_retry(
            &policy,
            &Method::GET,
            true,
            "/api/users",
            503,
            1,
            None
        ));
        assert!(!permits_status_retry(
            &policy,
            &Method::GET,
            true,
            "/public",
            503,
            1,
            None
        ));
    }

    #[test]
    fn attempt_and_deadline_bounds_fail_closed() {
        let policy = RetryConfig {
            max_attempts: 2,
            backoff_ms: 10,
            ..Default::default()
        };
        assert!(!permits_another_attempt(&policy, 2, None));
        assert!(!permits_another_attempt(
            &policy,
            1,
            Some(Instant::now() + Duration::from_millis(5))
        ));
    }
}
