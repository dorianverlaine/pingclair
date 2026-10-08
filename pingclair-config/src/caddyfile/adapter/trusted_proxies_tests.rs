// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌐 `trusted_proxies` inside `servers {}` reads the way Caddy reads it (#142).
//!
//! Caddy's `servers {}` block takes an ip_source module name first, and keeps
//! only the last `trusted_proxies` line. This adapter used to accept the bare
//! address list there, which Caddy refuses, and to add repeated lines together,
//! which trusts more peers than Caddy would for the same file.

/// 🧾 Compiles `source` and returns the refusal message, failing if it loads.
fn refusal(source: &str) -> String {
    crate::compile(source)
        .expect_err("the configuration must be refused")
        .to_string()
}

/// 🚫 The bare address list inside `servers {}`, addressed or not, is refused
/// with the spelling that works in its place. Before the fix both loaded.
#[test]
fn a_bare_address_list_inside_servers_is_refused_with_the_static_spelling() {
    let messages = [
        "{\n    servers {\n        trusted_proxies 10.0.0.0/8 192.168.0.0/16\n    }\n}\n\
         :8080 {\n    respond \"x\"\n}",
        "{\n    servers :8080 {\n        trusted_proxies 10.0.0.0/8 192.168.0.0/16\n    }\n}\n\
         :8080 {\n    respond \"x\"\n}",
    ]
    .map(refusal);
    for message in messages {
        assert!(
            message.contains("trusted_proxies static 10.0.0.0/8 192.168.0.0/16"),
            "the refusal must name the spelling to write instead: {message}"
        );
    }
}

/// 🛡️ A second `trusted_proxies` in one scope is refused rather than added to
/// the first. Before the fix the first two files below trusted both ranges,
/// where Caddy trusts only the last line; the third combines this build's own
/// top-level option with the `servers {}` one, which land in the same list.
#[test]
fn a_second_trusted_proxies_line_in_one_scope_is_refused() {
    for source in [
        "{\n    servers {\n        trusted_proxies static 10.0.0.0/8\n        \
         trusted_proxies static 192.168.0.0/16\n    }\n}\n:8080 {\n    respond \"x\"\n}",
        "{\n    servers :8080 {\n        trusted_proxies static 10.0.0.0/8\n        \
         trusted_proxies static 192.168.0.0/16\n    }\n}\n:8080 {\n    respond \"x\"\n}",
        "{\n    trusted_proxies 10.0.0.0/8\n    servers {\n        \
         trusted_proxies static 192.168.0.0/16\n    }\n}\n:8080 {\n    respond \"x\"\n}",
    ] {
        let message = refusal(source);
        assert!(
            message.contains("one line"),
            "the refusal must say how to combine the ranges: {message}"
        );
    }
}

/// 📌 `trusted_proxies_strict` is not implemented, and is refused rather than
/// accepted and ignored: it changes which forwarded address is believed, so a
/// silent no-op would pick a different client than the operator asked for.
#[test]
fn trusted_proxies_strict_is_refused_rather_than_ignored() {
    let message = refusal(
        "{\n    servers {\n        trusted_proxies static private_ranges\n        \
         trusted_proxies_strict\n    }\n}\n:8080 {\n    respond \"x\"\n}",
    );
    assert!(
        message.contains("trusted_proxies_strict"),
        "the refusal must name the option: {message}"
    );
}
