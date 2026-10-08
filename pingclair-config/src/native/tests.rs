// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;

const SOURCE: &str = r#"
// 🧩 Typed components compose into a single validated configuration.
TCPListener(on: "127.0.0.1:9443") {
    Route(when: .tls(sni: ["example.test"], alpn: ["h2"]), from: ["127.0.0.0/8"]) {
        Proxy(to: "127.0.0.1:8443")
    }
    Fallback { Proxy(to: "127.0.0.1:8080") }
}
.limits(connections: 128, preread: .kibibytes(16), relay: .bytes(1024))
.timeouts(connect: .seconds(5), idle: .minutes(5))
.halfClose(enabled: true)
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
        ("TCPListener(on:", "Listener(on:"),
        ("connections: 128", "connections: 128, connections: 128"),
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
        "Metrics(",
        "TCPListener(",
        "TCPListener(on: [",
        "TCPListener(on: \"127.0.0.1:9443\") { Fallback { Proxy(to: \"127.0.0.1:8080\") } } garbage",
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
        "Metrics(enabled: {}0{})",
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

#[test]
fn headerless_declarations_are_detected_and_composed() {
    let source = r#"
        // 🧩 Comments are skipped before detection.
        Metrics(enabled: true)
        Shutdown(grace: .seconds(5))
        Admin(listen: "127.0.0.1:2019")
        TCPListener(on: ":9443") {
            Fallback { Proxy(to: "127.0.0.1:8080") }
        }
    "#;
    assert!(is_native(source));
    assert!(is_native("let reused = \"value\""));
    let config = crate::compile(source).unwrap();
    assert!(config.global.metrics);
    assert_eq!(config.global.grace_period_secs, Some(5));
    assert_eq!(config.admin.unwrap().listen, "127.0.0.1:2019");
    assert_eq!(config.layer4.len(), 1);
}

#[test]
fn the_removed_version_header_is_refused_with_a_direction() {
    let source = r#"Pingclair(version: 1) {
        TCPListener(on: ":9443") { Fallback { Proxy(to: "127.0.0.1:8080") } }
    }"#;
    assert!(is_native(source));
    let error = adapt(source).unwrap_err().to_string();
    assert!(
        error.contains("header") && error.contains("top level"),
        "{error}"
    );
}

#[test]
fn bindings_reuse_values_and_component_trees() {
    let config = crate::compile(
        r#"
        let names = ["example.test"]
        let backend = Proxy(to: "127.0.0.1:8080")
        let secure = Fallback { backend }
        TCPListener(on: ":9443") {
            Route(when: .tls(sni: names)) { backend }
            secure
        }
        TCPListener(on: ":9444") {
            secure
        }
        "#,
    )
    .unwrap();
    assert_eq!(config.layer4.len(), 2);
    assert_eq!(config.layer4[0].routes.len(), 2);
    assert_eq!(config.layer4[1].routes.len(), 1);
    assert_eq!(config.layer4[0].routes[1], config.layer4[1].routes[0]);
    let tls = config.layer4[0].routes[0].matches[0].tls.as_ref().unwrap();
    assert_eq!(tls.sni, vec!["example.test".to_string()]);
}

#[test]
fn invalid_bindings_fail_closed() {
    for source in [
        "let x = x\nTCPListener(on: \":9443\") { Fallback { Proxy(to: \"127.0.0.1:80\") } }",
        "let used = later\nlet later = \"value\"\nTCPListener(on: \":9443\") { Fallback { Proxy(to: \"127.0.0.1:80\") } }",
        "let x = \"a\"\nlet x = \"b\"\nTCPListener(on: \":9443\") { Fallback { Proxy(to: \"127.0.0.1:80\") } }",
        "let true = \"x\"\nTCPListener(on: \":9443\") { Fallback { Proxy(to: \"127.0.0.1:80\") } }",
        "let X = \"x\"\nTCPListener(on: \":9443\") { Fallback { Proxy(to: \"127.0.0.1:80\") } }",
        "let address = \"127.0.0.1:80\"\nTCPListener(on: \":9443\") { address }",
        "let routes = Fallback { Proxy(to: \"127.0.0.1:80\") }\nTCPListener(on: routes) { Fallback { Proxy(to: \"127.0.0.1:80\") } }",
        "TCPListener(on: \":9443\") { let x = Fallback { Proxy(to: \"127.0.0.1:80\") } Fallback { Proxy(to: \"127.0.0.1:80\") } }",
    ] {
        assert!(crate::compile(source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn binding_expansion_is_bounded() {
    let mut source = String::from(
        "let hop = Fallback { Proxy(to: \"127.0.0.1:80\") }\nTCPListener(on: \":9443\") {\n",
    );
    for _ in 0..2000 {
        source.push_str("hop\n");
    }
    source.push_str("}\n");
    let error = adapt(&source).unwrap_err().to_string();
    assert!(error.contains("expansion"), "{error}");
}

#[test]
fn caddy_shaped_sources_are_not_native() {
    for source in [
        "{\n    email admin@example.com\n}",
        "example.com {\n    respond \"hi\"\n}",
        ":8080 {\n    file_server\n}",
        "respond \"hi\" 200",
        "",
    ] {
        assert!(!is_native(source), "detected {source:?} as native");
    }
}

proptest::proptest! {
    #[test]
    fn arbitrary_native_input_never_panics(source in ".{0,2048}") {
        let _ = adapt(&source);
    }
}
