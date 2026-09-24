// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌐 The `remote_ip` and `client_ip` matchers, as a configuration sees them.
//!
//! The ranges these matchers list are parsed once, when the configuration is
//! compiled. That makes a malformed range a configuration error: before, it
//! was re-parsed on every request, failed every time, and quietly matched
//! nothing — so a block list with a typo let through the address it named.

use pingclair_config::compile;

/// 🚫 The compile error for a site whose only matcher lists `ranges`.
fn refusal(matcher: &str, ranges: &str) -> String {
    let source =
        format!(":8080 {{\n    @guarded {matcher} {ranges}\n    respond @guarded 403\n}}\n");
    compile(&source)
        .expect_err("a malformed range must be refused")
        .to_string()
}

#[test]
fn a_malformed_range_is_refused_when_the_configuration_compiles() {
    for matcher in ["remote_ip", "client_ip"] {
        for bad in ["10.0.0.0/33", "not-an-address", "192.0.2.300"] {
            let error = refusal(matcher, &format!("10.0.0.0/8 {bad}"));
            assert!(
                error.contains(bad),
                "`{matcher} {bad}` must be named in the error, got: {error}"
            );
        }
    }
}

#[test]
fn well_formed_ranges_and_addresses_compile() {
    let source = ":8080 {\n    @guarded remote_ip 10.0.0.0/8 192.0.2.7 2001:db8::/32\n    respond @guarded 403\n}\n";
    compile(source).expect("addresses and CIDR ranges compile");
}

/// 🛡️ The Admin API and JSON configs read the core types directly; they must
/// refuse the same typo a Pingclairfile does.
#[test]
fn a_malformed_range_is_refused_from_json() {
    let error = serde_json::from_str::<pingclair_core::config::Matcher>(
        r#"{"remote_ip": ["10.0.0.0/33"]}"#,
    )
    .expect_err("a malformed range must be refused")
    .to_string();
    assert!(error.contains("10.0.0.0/33"), "got: {error}");
}
