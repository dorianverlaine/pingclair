// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧩 Spellings for the capabilities the reference Caddyfile has no word for.
//!
//! Each sits where the reference keeps its own options of that kind, under
//! nginx's name when nginx has the concept: `send_timeout` and
//! `keepalive_requests` in `limits`, `deny` among the global options, and
//! `negotiate` inside `file_server`.

use crate::compile;
use pingclair_core::config::{HandlerConfig, Negotiation, PRIVATE_RANGES};

/// 🚫 `deny` lines accumulate, and `private_ranges` expands as it does for
/// `trusted_proxies`.
#[test]
fn deny_reaches_the_shared_block_list() {
    let config = compile(
        "{\n    deny 192.0.2.0/24 private_ranges\n    deny 203.0.113.7\n}\n\
         :8080 {\n    respond \"ok\"\n}\n",
    )
    .expect("deny loads");
    let mut expected = vec!["192.0.2.0/24".to_string()];
    expected.extend(PRIVATE_RANGES.iter().map(|range| (*range).to_string()));
    expected.push("203.0.113.7".to_string());
    assert_eq!(config.global.blocked_ips, expected);

    for refused in ["deny", "deny nope"] {
        let source = format!("{{\n    {refused}\n}}\n:8080 {{\n    respond \"ok\"\n}}\n");
        assert!(compile(&source).is_err(), "accepted `{refused}`");
    }
}

/// 📮 `send_timeout` and 🔁 `keepalive_requests` reach the listener limits.
#[test]
fn limits_spell_send_timeout_and_keepalive_requests() {
    let config = compile(
        ":8080 {\n    limits {\n        send_timeout 30s\n        keepalive_requests 500\n    }\n    \
         respond \"ok\"\n}\n",
    )
    .expect("both limits load");
    let limits = &config.servers[0].limits;
    assert_eq!(
        (limits.send_timeout_ms, limits.keepalive_requests),
        (Some(30_000), Some(500))
    );

    let off =
        compile(":8080 {\n    limits {\n        send_timeout 0\n    }\n    respond \"ok\"\n}\n")
            .expect("send_timeout 0 turns the bound off");
    assert_eq!(off.servers[0].limits.send_timeout_ms, Some(0));

    // 🚫 A bare number is not a duration, and zero requests serve nothing.
    for refused in [
        "send_timeout 30",
        "keepalive_requests 0",
        "keepalive_requests 1 2",
    ] {
        let source =
            format!(":8080 {{\n    limits {{\n        {refused}\n    }}\n    respond \"ok\"\n}}\n");
        assert!(compile(&source).is_err(), "accepted `{refused}`");
    }
}

/// 🧭 `negotiate markdown` reaches the file server; anything else is refused.
#[test]
fn file_server_negotiates_markdown() {
    let config = compile(":8080 {\n    file_server {\n        negotiate markdown\n    }\n}\n")
        .expect("negotiate loads");
    let negotiate = config.servers[0]
        .routes
        .iter()
        .find_map(|route| match &route.handler {
            HandlerConfig::FileServer { negotiate, .. } => Some(negotiate.clone()),
            _ => None,
        })
        .expect("a file server route");
    assert_eq!(negotiate, [Negotiation::Markdown]);

    for refused in ["negotiate", "negotiate html", "negotiate markdown markdown"] {
        let source = format!(":8080 {{\n    file_server {{\n        {refused}\n    }}\n}}\n");
        assert!(compile(&source).is_err(), "accepted `{refused}`");
    }
}
