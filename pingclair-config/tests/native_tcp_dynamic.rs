// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌐 Both DSLs lower to the same tagged DNS policy and common validation.

const SOURCE: &str = r#"TCPListener(on: ":9443") {
    Fallback { Proxy(dynamic: .a("backend.test", port: 443, resolvers: ["127.0.0.1:5353", "[::1]:5353"], versions: .ipv4, valid: .milliseconds(1250), stale: .seconds(2), allowIP: ["127.0.0.1/32"])) }
}"#;
const LEGACY: &str = r#"{
    layer4 {
        :9443 {
            route {
                proxy {
                    dynamic a {
                        name backend.test
                        port 443
                        resolvers 127.0.0.1:5353 [::1]:5353
                        versions ipv4
                        valid 1s250ms
                        stale 2s
                        allow_ip 127.0.0.1/32
                    }
                }
            }
        }
    }
}"#;

#[test]
fn typed_dynamic_sources_match_legacy_and_survive_formatting_and_bindings() {
    let native = pingclair_config::compile(SOURCE).unwrap();
    let legacy = pingclair_config::compile(LEGACY).unwrap();
    assert_eq!(native.layer4, legacy.layer4);
    let rebound = SOURCE.replace("TCPListener", "let fallback = Proxy(dynamic: .a(\"backend.test\", port: 443, resolvers: [\"127.0.0.1:5353\", \"[::1]:5353\"], versions: .ipv4, valid: .milliseconds(1250), stale: .seconds(2), allowIP: [\"127.0.0.1/32\"]))\nTCPListener");
    let begin = rebound.find("    Fallback").unwrap();
    let rebound = format!("{}    Fallback {{ fallback }}\n}}", &rebound[..begin]);
    assert_eq!(
        pingclair_config::compile(&rebound).unwrap().layer4,
        native.layer4
    );
    let formatted = pingclair_config::format::format(SOURCE).unwrap();
    assert_eq!(
        pingclair_config::compile(&formatted).unwrap().layer4,
        native.layer4
    );
    let value = serde_json::to_value(&native).unwrap();
    assert_eq!(value["layer4"][0]["routes"][0]["dynamic"]["type"], "a");
    assert!(value["layer4"][0]["routes"][0].get("upstream").is_none());
}

#[test]
fn malformed_sources_and_http_only_options_cannot_be_silently_accepted() {
    for source in [
        "Proxy()",
        "Proxy(to: \"host:443\", dynamic: .a(\"backend.test\", port: 443))",
        "Proxy(dynamic: .srv(\"backend.test\", port: 443))",
        "Proxy(dynamic: .a(port: 443))",
        "Proxy(dynamic: .a(\"backend.test\"))",
        "Proxy(dynamic: .a(\"backend.test\", \"second.test\", port: 443))",
        "Proxy(dynamic: .a(\"backend.test\", port: 443, refresh: .seconds(1)))",
        "Proxy(dynamic: .a(\"backend.test\", port: 443, dialTimeout: .seconds(1)))",
        "Proxy(dynamic: .a(\"backend.test\", port: 443, versions: .both))",
        "Proxy(dynamic: .a(\"backend.test\", port: 443, versions: .ipv4(1)))",
        "Proxy(dynamic: .a(\"backend.test\", port: 443, resolvers: []))",
        "Proxy(dynamic: .a(\"backend.test\", port: 443, valid: .seconds(0)))",
        "Proxy(dynamic: .a(\"backend.test\", port: 443, stale: .seconds(301)))",
        "Proxy(dynamic: .a(\"127.0.0.1\", port: 443))",
        "Proxy(dynamic: .a(\"backend.test\", port: 443, allowIP: [\"0.0.0.0/0\"]))",
    ] {
        assert!(
            pingclair_config::compile(&format!(
                "TCPListener(on: \":9443\") {{ Fallback {{ {source} }} }}"
            ))
            .is_err(),
            "{source}"
        );
    }
    for (before, after) in [
        ("proxy {", "proxy backend.test:443 {"),
        ("dynamic a {", "dynamic srv {"),
        ("name backend.test", "name backend.test\nname second.test"),
        ("port 443", "port 443\nport 8443"),
        ("port 443", ""),
        ("valid 1s250ms", "refresh 1s"),
        ("valid 1s250ms", "dial_timeout 1s"),
        ("valid 1s250ms", "valid 0"),
        ("stale 2s", "stale 301s"),
        ("resolvers 127.0.0.1:5353 [::1]:5353", "resolvers"),
        ("versions ipv4", "versions both"),
        ("allow_ip 127.0.0.1/32", "allow_ip ::/0"),
    ] {
        assert!(
            pingclair_config::compile(&LEGACY.replace(before, after)).is_err(),
            "{after}"
        );
    }
}
