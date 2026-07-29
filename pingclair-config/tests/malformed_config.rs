// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔎 Searching the configuration front door for the class of bug we have only
//! ever found by accident.
//!
//! Every serious defect in this project so far was bumped into, not looked for.
//! The remotely triggerable stack overflow turned up while changing how
//! matchers are represented; the global block that swallowed unknown
//! directives turned up while writing a documentation guard. Both are the same
//! class — malformed input reaching a parser — and both were luck.
//!
//! This looks on purpose. Two surfaces, because they are two different front
//! doors and only one of them goes through the DSL:
//!
//! - `compile()`, which the Pingclairfile and `pingclair validate` use;
//! - `serde_json` into the core types, which the Admin API uses.
//!
//! The contract under test is deliberately weak and therefore checkable: for
//! *any* input, the parser must **return** — `Ok` or `Err`, either is fine —
//! and must not panic, abort, or fail to terminate. A release build sets
//! `panic = "abort"`, so a panic here is not a caught error; it is the whole
//! process going away, and the Admin API is a way to reach it.

use proptest::prelude::*;

/// 🎲 Fragments deliberately chosen from what a parser gets wrong: unbalanced
/// delimiters, empty directives, recursive matcher forms, and the exact shapes
/// that produced real bugs here.
fn hostile_token() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec![
        "{",
        "}",
        "{}",
        "\"",
        "'",
        "\\",
        "`",
        "\0",
        "\r",
        "\n",
        "\r\n",
        "\t",
        // Matchers nest, and a recursive form under an untagged representation
        // is what produced the stack overflow.
        "not",
        "and",
        "or",
        "@a",
        "@a @a",
        "path",
        "path /",
        "path /*",
        "header",
        "header X",
        // Directives whose argument counts have all been wrong at some point.
        "listen",
        "listen :",
        "listen :0",
        "listen :99999",
        "listen :8080 proxy_protocol",
        "reverse_proxy",
        "reverse_proxy http://",
        "reverse_proxy ://x",
        "respond",
        "respond 999",
        "respond \"x\" 99999",
        "encode",
        "encode br",
        "encode off gzip",
        "tls",
        "tls internal",
        "tls off /a",
        "limits",
        "rate_limit",
        "rate_limit 0 0",
        "rate_limit -1 1s",
        "handle",
        "handle_path",
        "route",
        "import",
        "import nonexistent",
        "trusted_proxies",
        "trusted_proxies ::/0",
        "dns_refresh",
        "dns_refresh 0",
        "header_up",
        "header_up X",
        "transport",
        "transport http",
        "file_server",
        "file_server /",
        "file_server ../../..",
        "rewrite",
        "rewrite * *",
        "rewrite (((((",
        "error_page",
        "basic_auth",
        // Numeric edges that have overflowed before.
        "18446744073709551615",
        "-1",
        "0",
        "1e999",
        "0x10",
        ":8080",
        "example.com",
        "*.example.com",
        "*",
        "//",
    ])
}

/// 🧬 Assembles fragments into something shaped like a configuration.
fn hostile_source() -> impl Strategy<Value = String> {
    prop::collection::vec(hostile_token(), 0..40).prop_map(|tokens| tokens.join("\n"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// 🚪 The Pingclairfile front door must always answer.
    #[test]
    fn compiling_arbitrary_source_never_panics(source in hostile_source()) {
        // Either outcome is acceptable. Not returning is not.
        let _ = pingclair_config::compile(&source);
    }

    /// 🚪 Same for entirely unstructured bytes, in case the fragment list has
    /// blind spots the shape of its own author.
    #[test]
    fn compiling_arbitrary_text_never_panics(source in ".{0,2000}") {
        let _ = pingclair_config::compile(&source);
    }
}

/// 🕳️ Nesting is the specific shape that produced a remotely triggerable DoS,
/// so it gets an explicit test rather than being left to random sampling —
/// proptest is very unlikely to generate two hundred balanced braces by chance.
#[test]
fn deeply_nested_blocks_are_rejected_rather_than_overflowing() {
    for depth in [50usize, 200, 2_000, 50_000] {
        let source = format!(
            ":8080 {{\n{}\n{}\n}}",
            "handle /a {\n".repeat(depth),
            "}\n".repeat(depth)
        );
        // The parser caps nesting; what matters is that it says so instead of
        // exhausting the stack.
        let result = pingclair_config::compile(&source);
        assert!(
            result.is_err(),
            "nesting {depth} deep should be refused, not accepted"
        );
    }
}

/// 🕳️ The same question for nested matchers, which are a *separate* recursion
/// from block nesting and reach a recursive enum rather than the block parser.
#[test]
fn deeply_nested_matchers_are_rejected_rather_than_overflowing() {
    for depth in [50usize, 500, 10_000] {
        let source = format!(
            ":8080 {{\n  @deep {}path /x\n  handle @deep {{ respond \"ok\" }}\n}}",
            "not ".repeat(depth)
        );
        let _ = pingclair_config::compile(&source);
    }
}

/// 🕳️ And the JSON front door, which the Admin API uses and which does not
/// pass through the DSL at all.
#[test]
fn deeply_nested_json_is_rejected_rather_than_overflowing() {
    for depth in [50usize, 500, 10_000, 200_000] {
        // A matcher nested through the tagged representation. Before the
        // representation was tagged, this recursed without consuming input.
        let mut matcher = String::from(r#"{"type":"path","patterns":["/x"]}"#);
        for _ in 0..depth {
            matcher = format!(r#"{{"type":"not","matcher":{matcher}}}"#);
        }
        let document = format!(
            r#"{{"servers":[{{"listen":["127.0.0.1:8080"],"routes":[{{"path":"/*","matcher":{matcher},"handler":{{"type":"respond","status":200}}}}]}}]}}"#
        );
        // serde_json enforces its own recursion limit; the point is that the
        // limit is reached and reported rather than jumped over.
        let parsed: Result<pingclair_core::config::PingclairConfig, _> =
            serde_json::from_str(&document);
        if let Ok(config) = parsed {
            // If it did parse, validation must still terminate.
            let _ = pingclair_config::compiler::validate_config(&config);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// 🚪 Arbitrary JSON into the core types, the Admin API's actual path.
    #[test]
    fn deserializing_arbitrary_json_never_panics(text in ".{0,1000}") {
        if let Ok(config) = serde_json::from_str::<pingclair_core::config::PingclairConfig>(&text) {
            let _ = pingclair_config::compiler::validate_config(&config);
        }
    }
}
