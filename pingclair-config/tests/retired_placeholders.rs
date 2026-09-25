// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚫 `{remote_ip}` is refused when a configuration loads.
//!
//! The placeholder was this project's own invention and meant the verified
//! client, while the `remote_ip` matcher means the socket peer. Caddy has no
//! such placeholder, so a configuration using it is refused with the two
//! spellings that say what they mean.

use pingclair_config::{compile, compiler::validate_config};
use pingclair_core::config::PingclairConfig;

/// 🎯 The refusal names the placeholder, where it sits, and both replacements.
fn assert_names_the_way_out(error: &str) {
    for expected in [
        "{remote_ip}",
        "{remote_host}",
        "{client_ip}",
        "trusted_proxies",
    ] {
        assert!(error.contains(expected), "missing `{expected}` in: {error}");
    }
}

#[test]
fn a_pingclairfile_using_remote_ip_is_refused() {
    let source = ":8080 {\n    reverse_proxy 127.0.0.1:9000 {\n        header_up X-Real-IP {remote_ip}\n    }\n}\n";
    let error = compile(source)
        .expect_err("`{remote_ip}` must be refused")
        .to_string();
    assert_names_the_way_out(&error);
    assert!(
        error.contains("X-Real-IP"),
        "the location is named: {error}"
    );
}

#[test]
fn a_json_config_using_remote_ip_is_refused() {
    let document = r#"{
        "servers": [{
            "listen": ["127.0.0.1:8080"],
            "routes": [{
                "path": "/",
                "handler": { "type": "respond", "status": 200, "body": "peer {remote_ip}" }
            }]
        }]
    }"#;
    let config: PingclairConfig = serde_json::from_str(document).expect("the document parses");
    let error = validate_config(&config)
        .expect_err("`{remote_ip}` must be refused")
        .to_string();
    assert_names_the_way_out(&error);
    assert!(
        error.contains("/servers/0/routes/0/handler/body"),
        "the location is named: {error}"
    );
}

#[test]
fn the_replacements_compile() {
    let source = ":8080 {\n    reverse_proxy 127.0.0.1:9000 {\n        header_up X-Real-IP {client_ip}\n        header_up X-Peer {remote_host}\n    }\n}\n";
    compile(source).expect("`{client_ip}` and `{remote_host}` compile");
}
