// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;

const SOURCE: &str = r#"
// 🧩 Typed components compose into a single validated configuration.
Pingclair(version: 1) {
    TCPListener(on: "127.0.0.1:9443") {
        Route(when: .tls(sni: ["example.test"], alpn: ["h2"]), from: ["127.0.0.0/8"]) {
            Proxy(to: "127.0.0.1:8443")
        }
        Fallback { Proxy(to: "127.0.0.1:8080") }
    }
    .limits(connections: 128, preread: .kibibytes(16), relay: .bytes(1024))
    .timeouts(connect: .seconds(5), idle: .minutes(5))
    .halfClose(enabled: true)
}
"#;

#[test]
fn native_components_lower_to_the_existing_validated_model() {
    let native = crate::compile(SOURCE).unwrap();
    let legacy = crate::compile(
        r#"{
        layer4 {
            127.0.0.1:9443 {
                max_connections 128
                preread_buffer_size 16k
                proxy_buffer_size 1024
                proxy_connect_timeout 5s
                proxy_timeout 5m
                proxy_half_close on
                @secure {
                    tls {
                        sni example.test
                        alpn h2
                    }
                    remote_ip 127.0.0.0/8
                }
                route @secure {
                    proxy 127.0.0.1:8443
                }
                route {
                    proxy 127.0.0.1:8080
                }
            }
        }
    }"#,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(native).unwrap(),
        serde_json::to_value(legacy).unwrap()
    );
}

#[test]
fn malformed_or_ambiguous_composition_is_rejected_without_falling_back() {
    for (old, new) in [
        ("version: 1", "version: 2"),
        ("version: 1", "version: 1, version: 1"),
        ("connections: 128", "connections: 0"),
        ("connect: .seconds(5)", "connect: 5"),
        ("connect: .seconds(5)", "connect: .kibibytes(5)"),
        (
            "connect: .seconds(5)",
            "connect: .seconds(18446744073709551615)",
        ),
        ("Proxy(to:", "Proxy(target:"),
        (".halfClose(enabled: true)", ".unknown(enabled: true)"),
        (
            ".halfClose(enabled: true)",
            ".halfClose(enabled: true).halfClose(enabled: false)",
        ),
        ("Fallback {", "Fallback(when: true) {"),
        ("[\"h2\"]", "[]"),
        (
            "Proxy(to: \"127.0.0.1:8080\")",
            "Proxy(to: \"127.0.0.1:8080\").halfClose(enabled: true)",
        ),
    ] {
        assert!(
            crate::compile(&SOURCE.replace(old, new)).is_err(),
            "accepted {new}"
        );
    }
}

#[test]
fn diagnostics_name_the_file_without_echoing_literal_values() {
    let source = SOURCE.replace("connections: 128", "connections: \"do-not-print-this\"");
    let error = crate::compile_named(&source, Some(std::path::Path::new("edge.pingclair")))
        .unwrap_err()
        .to_string();
    assert!(error.contains("edge.pingclair") && error.contains("line "));
    assert!(!error.contains("do-not-print-this"));
    for source in [
        "Pingclair(",
        "Pingclair(version: [",
        "Pingclair(version: 1) {",
        "Pingclair(version: 1) {} garbage",
    ] {
        assert!(crate::compile(source).is_err());
    }
}

#[test]
fn adaptation_and_validation_remain_distinct() {
    let source = SOURCE.replace("connections: 128", "connections: 0");
    let adapted = crate::adapt(&source).unwrap();
    assert!(crate::compiler::validate_config(&adapted).is_err());
}

#[test]
fn nested_values_and_large_sources_are_bounded() {
    let nested = format!(
        "Pingclair(version: {}0{}) {{}}",
        "[".repeat(1000),
        "]".repeat(1000)
    );
    assert!(adapt(&nested).unwrap_err().to_string().contains("nesting"));
    assert!(
        adapt(&" ".repeat(1024 * 1024 + 1))
            .unwrap_err()
            .to_string()
            .contains("1 MiB")
    );
}

proptest::proptest! {
    #[test]
    fn arbitrary_native_input_never_panics(source in ".{0,2048}") {
        let _ = adapt(&source);
    }
}
