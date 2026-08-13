// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔁 Transport-neutral policy for bounded, idempotent upstream redispatch.

use http::Method;
use pingclair_core::config::{RetryConfig, RetryPredicate};
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

/// 🔎 Everything a retry predicate can ask about one failed attempt.
///
/// Borrowed rather than owned throughout: this is built at the moment an
/// attempt fails, and every field already exists somewhere the caller holds.
/// Copying them to ask a question that is usually "no" would be paying for the
/// unhappy path on the happy one.
pub(crate) struct AttemptFacts<'a> {
    pub method: &'a Method,
    pub path: &'a str,
    pub host: &'a str,
    pub scheme: &'a str,
    pub query: Option<&'a str>,
    pub request_headers: &'a http::HeaderMap,
    /// 🔌 `None` when the attempt never produced a response — a dial, TLS or
    /// read failure. That is what `{rp.is_transport_error}` asks about, and it
    /// is a genuinely different question from "which status came back".
    pub status: Option<u16>,
    pub response_headers: Option<&'a http::HeaderMap>,
}

impl AttemptFacts<'_> {
    fn is_transport_error(&self) -> bool {
        self.status.is_none()
    }
}

/// 🔁 Answers whether any configured `lb_retry_match` permits this retry.
///
/// An empty list means nothing was configured, and the caller falls back to the
/// flat status/method policy — which is also what a JSON configuration written
/// before predicates existed still uses.
///
/// `regex` resolves a pattern to the copy compiled at load. A pattern with no
/// compiled copy answers `false` rather than being compiled here: the load path
/// already refused invalid patterns, so a miss means the tables disagree, and
/// building a regex while an upstream is failing is the wrong time to find out.
pub(crate) fn retry_match_permits(
    predicates: &[RetryPredicate],
    facts: &AttemptFacts<'_>,
    regex: &dyn Fn(&str) -> Option<std::sync::Arc<regex::Regex>>,
) -> bool {
    predicates
        .iter()
        .any(|predicate| evaluate(predicate, facts, regex))
}

/// 🧭 One predicate against one attempt.
///
/// Recursion is bounded by `MAX_RETRY_PREDICATE_DEPTH`, which `validate_config`
/// enforces before any configuration reaches here — the same limit the
/// expression parser applies while parsing.
fn evaluate(
    predicate: &RetryPredicate,
    facts: &AttemptFacts<'_>,
    regex: &dyn Fn(&str) -> Option<std::sync::Arc<regex::Regex>>,
) -> bool {
    match predicate {
        RetryPredicate::All { of } => of.iter().all(|child| evaluate(child, facts, regex)),
        RetryPredicate::Any { of } => of.iter().any(|child| evaluate(child, facts, regex)),
        // 🔌 A transport error has no status, so every status test is false
        // against one. That is deliberate and it is why `{rp.is_transport_error}`
        // exists: an operator who wants both writes `||`.
        RetryPredicate::Status { any_of } => facts.status.is_some_and(|s| any_of.contains(&s)),
        RetryPredicate::StatusAtLeast { code } => facts.status.is_some_and(|s| s >= *code),
        RetryPredicate::TransportError => facts.is_transport_error(),
        RetryPredicate::ResponseHeader { name, value } => facts
            .response_headers
            .and_then(|headers| headers.get(name.as_str()))
            .is_some_and(|found| value == "*" || found.as_bytes() == value.as_bytes()),
        RetryPredicate::Method { any_of } => any_of
            .iter()
            .any(|configured| configured.eq_ignore_ascii_case(facts.method.as_str())),
        RetryPredicate::Path { any_of } => any_of
            .iter()
            .any(|pattern| glob_matches(pattern, facts.path)),
        RetryPredicate::PathRegexp { pattern } => {
            regex(pattern).is_some_and(|compiled| compiled.is_match(facts.path))
        }
        RetryPredicate::Host { any_of } => any_of
            .iter()
            .any(|configured| configured.eq_ignore_ascii_case(facts.host)),
        RetryPredicate::Protocol { name } => name.eq_ignore_ascii_case(facts.scheme),
        RetryPredicate::Query { key, any_of } => query_values(facts.query, key)
            .is_some_and(|found| any_of.iter().any(|want| want == "*" || want == found)),
        RetryPredicate::RequestHeader { name, any_of } => facts
            .request_headers
            .get(name.as_str())
            .is_some_and(|found| {
                any_of
                    .iter()
                    .any(|want| want == "*" || want.as_bytes() == found.as_bytes())
            }),
        RetryPredicate::HeaderRegexp { name, pattern } => facts
            .request_headers
            .get(name.as_str())
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| regex(pattern).is_some_and(|c| c.is_match(value))),
    }
}

/// 🔎 The first value of one query parameter, without allocating a map.
///
/// A retry decision asks about one key; parsing the whole string into a map to
/// answer that would allocate once per attempt for a question that is usually
/// asked about a single field.
fn query_values<'a>(query: Option<&'a str>, key: &str) -> Option<&'a str> {
    query?.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        (name == key).then_some(value)
    })
}

/// 🛡️ The same decision, asked with everything a `lb_retry_match` can inspect.
///
/// Two gates survive whichever matcher answers, because neither is about *when*
/// an operator wants a retry:
///
/// - **A request carrying a body is never replayed.** `lb_retry_match method
///   POST` says the operator considers POSTs retryable, and the attempt cap
///   still applies, but resending bytes this server has already streamed
///   upstream is a different and worse failure than not retrying.
/// - **The attempt cap and deadline still bound it.** A predicate decides
///   whether this failure is the retryable kind, not how many times.
pub(crate) fn permits_retry(
    policy: &RetryConfig,
    facts: &AttemptFacts<'_>,
    body_is_empty: bool,
    attempts: usize,
    retry_deadline: Option<Instant>,
    regex: &dyn Fn(&str) -> Option<std::sync::Arc<regex::Regex>>,
) -> bool {
    if !body_is_empty || !permits_another_attempt(policy, attempts, retry_deadline) {
        return false;
    }
    if !policy.retry_match.is_empty() {
        return retry_match_permits(&policy.retry_match, facts, regex);
    }
    // 🧭 Nothing configured, so the flat policy decides — which is also the
    // path a JSON configuration written before predicates existed takes.
    let Some(status) = facts.status else {
        return false;
    };
    policy.status_codes.contains(&status)
        && policy
            .methods
            .iter()
            .any(|configured| configured.eq_ignore_ascii_case(facts.method.as_str()))
        && (policy.path_patterns.is_empty()
            || policy
                .path_patterns
                .iter()
                .any(|pattern| glob_matches(pattern, facts.path)))
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

    /// 🛡️ A helper so a test states only what it is about.
    fn facts<'a>(
        method: &'a Method,
        path: &'a str,
        headers: &'a http::HeaderMap,
    ) -> AttemptFacts<'a> {
        AttemptFacts {
            method,
            path,
            host: "example.test",
            scheme: "https",
            query: None,
            request_headers: headers,
            status: Some(503),
            response_headers: None,
        }
    }

    fn permits(policy: &RetryConfig, method: &Method, body_is_empty: bool, path: &str) -> bool {
        let headers = http::HeaderMap::new();
        permits_retry(
            policy,
            &facts(method, path, &headers),
            body_is_empty,
            1,
            None,
            &|_| None,
        )
    }

    #[test]
    fn status_retry_requires_an_idempotent_bodyless_request() {
        let policy = RetryConfig {
            max_attempts: 3,
            status_codes: vec![503],
            methods: vec!["GET".to_string()],
            ..Default::default()
        };
        assert!(permits(&policy, &Method::GET, true, "/probe"));
        assert!(!permits(&policy, &Method::POST, true, "/probe"));
        assert!(!permits(&policy, &Method::GET, false, "/probe"));
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
        assert!(permits(&policy, &Method::GET, true, "/api/users"));
        assert!(!permits(&policy, &Method::GET, true, "/public"));
    }

    /// 🔁 Alternatives are OR'd and a block's contents are AND'd — the
    /// structure the whole change exists to preserve.
    #[test]
    fn alternatives_are_or_and_a_blocks_contents_are_and() {
        use pingclair_core::config::RetryPredicate;
        let policy = RetryConfig {
            max_attempts: 3,
            retry_match: vec![
                RetryPredicate::All {
                    of: vec![
                        RetryPredicate::Method {
                            any_of: vec!["POST".into()],
                        },
                        RetryPredicate::Path {
                            any_of: vec!["/orders*".into()],
                        },
                    ],
                },
                RetryPredicate::Status { any_of: vec![504] },
            ],
            ..Default::default()
        };
        let headers = http::HeaderMap::new();
        let permits = |method: &Method, path: &str, status: u16| {
            let mut facts = facts(method, path, &headers);
            facts.status = Some(status);
            permits_retry(&policy, &facts, true, 1, None, &|_| None)
        };

        // 🎯 The second alternative alone is enough, which is what a flattened
        // policy could never express: a 504 on any path, any method.
        assert!(permits(&Method::GET, "/anything", 504));
        // 🎯 And the first needs *both* of its conditions.
        assert!(permits(&Method::POST, "/orders/1", 500));
        assert!(!permits(&Method::POST, "/basket", 500));
        assert!(!permits(&Method::GET, "/orders/1", 500));
    }

    /// 🔌 A transport error is not a status, and every status test is false
    /// against one. An operator who wants both writes `||`, which is exactly
    /// what upstream's own fixtures do.
    #[test]
    fn a_transport_error_answers_no_status_test() {
        use pingclair_core::config::RetryPredicate;
        let headers = http::HeaderMap::new();
        let mut facts = facts(&Method::GET, "/x", &headers);
        facts.status = None;

        let status_only = RetryConfig {
            max_attempts: 3,
            retry_match: vec![RetryPredicate::StatusAtLeast { code: 500 }],
            ..Default::default()
        };
        assert!(!permits_retry(&status_only, &facts, true, 1, None, &|_| {
            None
        }));

        let either = RetryConfig {
            max_attempts: 3,
            retry_match: vec![RetryPredicate::Any {
                of: vec![
                    RetryPredicate::TransportError,
                    RetryPredicate::StatusAtLeast { code: 500 },
                ],
            }],
            ..Default::default()
        };
        assert!(permits_retry(&either, &facts, true, 1, None, &|_| None));
    }

    /// 🛡️ A body is never replayed and the attempt cap always applies, no
    /// matter how enthusiastically a predicate says yes.
    #[test]
    fn a_predicate_cannot_override_the_body_and_attempt_gates() {
        use pingclair_core::config::RetryPredicate;
        let policy = RetryConfig {
            max_attempts: 2,
            // 🎯 Matches everything, deliberately.
            retry_match: vec![RetryPredicate::StatusAtLeast { code: 100 }],
            ..Default::default()
        };
        let headers = http::HeaderMap::new();
        let facts = facts(&Method::POST, "/x", &headers);
        assert!(permits_retry(&policy, &facts, true, 1, None, &|_| None));
        assert!(
            !permits_retry(&policy, &facts, false, 1, None, &|_| None),
            "a request carrying a body is never replayed"
        );
        assert!(
            !permits_retry(&policy, &facts, true, 2, None, &|_| None),
            "the attempt cap still bounds it"
        );
    }

    /// 🔤 A regex predicate uses the copy compiled at load, and answers `false`
    /// rather than compiling one when the tables disagree.
    #[test]
    fn regex_predicates_use_the_precompiled_copy() {
        use pingclair_core::config::RetryPredicate;
        use std::sync::Arc;
        let policy = RetryConfig {
            max_attempts: 3,
            retry_match: vec![RetryPredicate::PathRegexp {
                pattern: "^/api/v[0-9]+/".into(),
            }],
            ..Default::default()
        };
        let headers = http::HeaderMap::new();
        let compiled = Arc::new(regex::Regex::new("^/api/v[0-9]+/").unwrap());
        let table = |pattern: &str| (pattern == "^/api/v[0-9]+/").then(|| Arc::clone(&compiled));

        assert!(permits_retry(
            &policy,
            &facts(&Method::GET, "/api/v2/orders", &headers),
            true,
            1,
            None,
            &table
        ));
        assert!(!permits_retry(
            &policy,
            &facts(&Method::GET, "/api/orders", &headers),
            true,
            1,
            None,
            &table
        ));
        // 🚫 Nothing compiled for it: fail closed, do not compile here.
        assert!(!permits_retry(
            &policy,
            &facts(&Method::GET, "/api/v2/orders", &headers),
            true,
            1,
            None,
            &|_| None
        ));
    }

    /// 🧱 A recursive type reachable from the Admin API must not be able to
    /// exhaust the stack while being read.
    ///
    /// This repository has already shipped that exact defect once, through
    /// `#[serde(untagged)]` on a recursive config type. The enum is tagged now,
    /// and this asserts the property rather than the mechanism: 20,000 levels
    /// of nesting must produce an error, not a crash.
    #[test]
    fn a_deeply_nested_predicate_is_refused_rather_than_overflowing() {
        let depth = 20_000;
        let json = format!(
            "{}{}{}",
            r#"{"op":"all","of":["#.repeat(depth),
            r#"{"op":"transport_error"}"#,
            "]}".repeat(depth)
        );
        let parsed = serde_json::from_str::<pingclair_core::config::RetryPredicate>(&json);
        assert!(
            parsed.is_err(),
            "a predicate this deep must be refused while being read"
        );
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
