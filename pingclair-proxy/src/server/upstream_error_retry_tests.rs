// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔁 When a failed upstream attempt may be retried on a fresh connection, and
//! how the retry budget caps that decision.

use super::*;

fn reused_only_error() -> Box<pingora_core::Error> {
    let mut error =
        pingora_core::Error::explain(pingora_core::ErrorType::ReadError, "upstream read error");
    error.retry = pingora_core::RetryType::ReusedOnly;
    error
}

/// 🧭 The bodyless case, which is the one every pre-existing test meant.
fn decide(
    error: &mut pingora_core::Error,
    client_reused: bool,
    retry_buffer_truncated: bool,
    policy: &RetryConfig,
    attempts: usize,
) -> bool {
    decide_upstream_error_retry(
        error,
        client_reused,
        retry_buffer_truncated,
        true,
        policy,
        attempts,
        None,
    )
}

#[test]
fn reused_connection_within_budget_is_decided_and_retryable() {
    let policy = RetryConfig::default();
    let mut error = reused_only_error();
    let retry = decide(&mut error, true, false, &policy, 0);

    assert!(retry, "a reused connection within budget must retry");
    assert!(
        error.retry(),
        "the retry marker must be decided before the loop reads it"
    );
}

#[test]
fn fresh_connection_never_retries_a_response_phase_error() {
    let policy = RetryConfig::default();
    let mut error = reused_only_error();
    let retry = decide(&mut error, false, false, &policy, 0);

    assert!(!retry, "a fresh connection must not retry");
    assert!(!error.retry());
}

#[test]
fn exhausted_retry_budget_caps_the_decision() {
    let policy = RetryConfig::default();
    let mut error = reused_only_error();
    let retry = decide(&mut error, true, false, &policy, policy.max_attempts);

    assert!(!retry, "the attempt cap must win over a reused connection");
    assert!(!error.retry());
}

#[test]
fn truncated_retry_buffer_disables_reuse_retries() {
    let policy = RetryConfig::default();
    let mut error = reused_only_error();
    let retry = decide(&mut error, true, true, &policy, 0);

    assert!(!retry, "a truncated retry buffer must disable retry");
    assert!(!error.retry());
}

/// 🛡️ A request that carried a body is not repeated after a response-phase
/// failure, however happy every other signal is.
///
/// This is the case the gate was added for, and the arguments below are
/// deliberately the *most* permissive ones: a reused connection, an
/// untruncated retry buffer, a fresh attempt budget, and an error Pingora
/// marks retryable. Every one of those says yes. The body says no, and the
/// body wins — because at this point the connection was already up and the
/// request was already on its way out, so the origin may have received the
/// whole thing and acted on it. Repeating it would perform the operation
/// twice, and Pingora will happily replay a buffered body if allowed to.
#[test]
fn a_body_bearing_request_is_never_repeated_after_a_response_phase_failure() {
    let policy = RetryConfig::default();
    let mut error = reused_only_error();
    let retry = decide_upstream_error_retry(&mut error, true, false, false, &policy, 0, None);

    assert!(
        !retry,
        "a request that carried a body was replayed to the origin"
    );
    assert!(
        !error.retry(),
        "the retry marker must also say no, or the loop will retry anyway"
    );
}

/// 🧭 The gate is about the body, not about the failure being unretryable.
///
/// Same error, same connection, same budget — only the body differs. Having
/// both directions in one test is what stops a future change from making
/// this path never retry at all and still passing.
#[test]
fn only_the_body_separates_a_repeatable_failure_from_an_unrepeatable_one() {
    let policy = RetryConfig::default();

    let mut bodyless = reused_only_error();
    assert!(decide_upstream_error_retry(
        &mut bodyless,
        true,
        false,
        true,
        &policy,
        0,
        None
    ));

    let mut with_body = reused_only_error();
    assert!(!decide_upstream_error_retry(
        &mut with_body,
        true,
        false,
        false,
        &policy,
        0,
        None
    ));
}
