// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;

/// 🔁 The twin comparison reads past the *encoding* of literal text.
///
/// A native literal and a legacy template that happens to contain no
/// placeholders describe the same bytes at request time, and the native
/// language deliberately spells them differently: `{"literal": "x"}` against
/// `"x"`. Folding the literal tag away here keeps the Caddyfile useful as an
/// oracle for everything the two languages share, while
/// `tests/native_contracts.rs` is where the difference itself is asserted — the
/// one place that must fail if native text starts being reinterpreted.
fn twin(config: pingclair_core::config::PingclairConfig) -> serde_json::Value {
    fn fold(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                if map.len() == 1
                    && let Some(serde_json::Value::String(text)) = map.get("literal")
                {
                    *value = serde_json::Value::String(text.clone());
                    return;
                }
                for child in map.values_mut() {
                    fold(child);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    fold(item);
                }
            }
            _ => {}
        }
    }
    let mut value = serde_json::to_value(config).expect("the config serialises");
    fold(&mut value);
    value
}

const SOURCE: &str = r#"
// 🧩 Typed components compose into a single validated configuration.
TCPListener(on: "127.0.0.1:9443") {
    Route(when: .all([.tls(sni: ["example.test"], alpn: ["h2"]), .from(["127.0.0.0/8"])])) {
        Proxy(to: "127.0.0.1:8443")
    }
    Fallback { Proxy(to: "127.0.0.1:8080") }
}
.limits(maxConnections: 128, preread: .kibibytes(16), relay: .bytes(1024))
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
    assert_eq!(twin(native), twin(legacy));
}

#[test]
fn malformed_or_ambiguous_composition_is_rejected_without_falling_back() {
    for (old, new) in [
        ("TCPListener(on:", "Listener(on:"),
        (
            "maxConnections: 128",
            "maxConnections: 128, maxConnections: 128",
        ),
        ("maxConnections: 128", "maxConnections: 0"),
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
    let source = SOURCE.replace(
        "maxConnections: 128",
        "maxConnections: \"do-not-print-this\"",
    );
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
    let source = SOURCE.replace("maxConnections: 128", "maxConnections: 0");
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
fn attributes_mark_conditions_and_secrets() {
    let source = r#"
        @Matcher
        let secure = .tls(sni: ["example.test"])
        @Secret
        let token = "do-not-print-this"
        TCPListener(on: ":9443") {
            Route(when: secure) { Proxy(to: "127.0.0.1:8080") }
        }
    "#;
    assert!(is_native(
        "@Matcher\nlet secure = .tls(sni: [\"example.test\"])"
    ));
    let config = crate::compile(source).unwrap();
    assert_eq!(config.layer4.len(), 1);
    assert_eq!(config.layer4[0].routes.len(), 1);
}

#[test]
fn secret_values_never_reach_diagnostics() {
    let error = crate::compile(
        r#"
        @Secret
        let token = "do-not-print-this"
        TCPListener(on: ":9443") { Unknown { Proxy(to: "127.0.0.1:8080") } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(!error.contains("do-not-print-this"), "{error}");
}

#[test]
fn invalid_attributes_fail_closed() {
    for source in [
        "@Matcherr\nlet x = .tls(sni: [\"a.test\"])\nTCPListener(on: \":9443\") { Fallback { Proxy(to: \"127.0.0.1:80\") } }",
        "@Secret(\"x\")\nlet token = \"y\"\nTCPListener(on: \":9443\") { Fallback { Proxy(to: \"127.0.0.1:80\") } }",
        "@Secret\n@Secret\nlet token = \"y\"\nTCPListener(on: \":9443\") { Fallback { Proxy(to: \"127.0.0.1:80\") } }",
        "@Matcher\nlet x = \"text\"\nTCPListener(on: \":9443\") { Fallback { Proxy(to: \"127.0.0.1:80\") } }",
        "@Secret\nlet person = Proxy(to: \"127.0.0.1:80\")\nTCPListener(on: \":9443\") { Fallback { Proxy(to: \"127.0.0.1:80\") } }",
        "@Matcher\n@Secret\nlet x = .tls(sni: [\"a.test\"])\nTCPListener(on: \":9443\") { Fallback { Proxy(to: \"127.0.0.1:80\") } }",
        "@Secret\nTCPListener(on: \":9443\") { Fallback { Proxy(to: \"127.0.0.1:80\") } }",
        "TCPListener(on: \":9443\") { @Matcher let x = .tls(sni: [\"a.test\"]) Fallback { Proxy(to: \"127.0.0.1:80\") } }",
        "let secure = .tls(sni: [\"a.test\"])\nTCPListener(on: \":9443\") { Route(when: secure) { Proxy(to: \"127.0.0.1:80\") } }",
    ] {
        assert!(crate::compile(source).is_err(), "accepted {source:?}");
    }
    let error = crate::compile("@Matcherr\nlet x = .tls(sni: [\"a.test\"])\nTCPListener(on: \":9443\") { Fallback { Proxy(to: \"127.0.0.1:80\") } }")
        .unwrap_err()
        .to_string();
    assert!(error.contains("did you mean @Matcher?"), "{error}");
}

#[test]
fn modifiers_must_follow_the_block() {
    let source = r#"
        TCPListener(on: "127.0.0.1:9443")
            .limits(maxConnections: 8) {
            Fallback { Proxy(to: "127.0.0.1:8080") }
        }
    "#;
    let error = adapt(source).unwrap_err().to_string();
    assert!(
        error.contains("block must come before modifiers"),
        "{error}"
    );
}

#[test]
fn http_listener_sites_lower_to_the_existing_validated_model() {
    let native = crate::compile(
        r#"
        HTTPListener(on: ":8080") {
            Site(host: "*") {
                Fallback { Respond(body: "hi", status: 200) }
            }
        }
        "#,
    )
    .unwrap();
    let legacy = crate::compile("http://:8080 {\n\trespond \"hi\" 200\n}\n").unwrap();
    assert_eq!(twin(native), twin(legacy));
}

#[test]
fn named_sites_lower_like_their_caddyfile_twin() {
    let native = crate::compile(
        r#"
        HTTPListener(on: ":8080") {
            Site(host: "example.com") {
                Fallback { Respond(body: "hi") }
            }
        }
        "#,
    )
    .unwrap();
    let legacy = crate::compile("http://example.com:8080 {\n\trespond \"hi\"\n}\n").unwrap();
    assert_eq!(twin(native), twin(legacy));
}

#[test]
fn several_http_listeners_are_allowed() {
    let config = crate::compile(
        r#"
        HTTPListener(on: ":8080") { Site(host: "a.test") { Fallback { Respond(body: "a") } } }
        HTTPListener(on: ":8081") { Site(host: "b.test") { Fallback { Respond(body: "b") } } }
        "#,
    )
    .unwrap();
    assert_eq!(config.servers.len(), 2);
}

#[test]
fn http_shape_mistakes_fail_closed() {
    for source in [
        "HTTPListener(on: \":8080\") {}",
        "HTTPListener(on: \":8080\") { Route(when: .tls(sni: [\"x\"])) { Proxy(to: \"127.0.0.1:80\") } }",
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Respond(body: \"hi\") } } }.limits(connections: 8)",
        "HTTPListener(on: \":8080\") { Site(host: \"*\") {} }",
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback {} } }",
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Respond(body: \"hi\", status: 999999) } } }",
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .tls(sni: [\"x\"])) { Respond(body: \"hi\") } } }",
    ] {
        assert!(crate::compile(source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn bind_extends_the_listener_addresses() {
    let native = crate::compile(
        r#"
        HTTPListener(on: ":8080") {
            Site(host: "*") { Fallback { Respond(body: "hi") } }
        }
        .bind([":8081"])
        "#,
    )
    .unwrap();
    let legacy = crate::compile("http://:8080, http://:8081 {\n\trespond \"hi\"\n}\n").unwrap();
    assert_eq!(twin(native), twin(legacy));
}

#[test]
fn protocols_toggle_http3_per_listener() {
    let native = crate::compile(
        r#"
        HTTPListener(on: ":8080") {
            Site(host: "*") { Fallback { Respond(body: "hi") } }
        }
        .protocols([.http1, .http2])
        "#,
    )
    .unwrap();
    let legacy = crate::compile(
        "{\n\tservers :8080 {\n\t\tprotocols h1 h2\n\t}\n}\nhttp://:8080 {\n\trespond \"hi\"\n}\n",
    )
    .unwrap();
    assert_eq!(twin(native), twin(legacy));
}

/// 🛡️ The file-level allowlist is the Caddyfile `servers { … }` option: the
/// names it lists survive, everything else with an underscore goes.
#[test]
fn underscore_allowlist_matches_the_servers_block() {
    let native = crate::compile(
        r#"
        UnderscoreHeaders(["X_Probe", "Webhook_*"])
        HTTPListener(on: ":8080") {
            Site(host: "*") { Fallback { Respond(body: "hi") } }
        }
        "#,
    )
    .unwrap();
    let legacy = crate::compile(
        "{\n\tservers {\n\t\texpected_underscore_headers X_Probe Webhook_*\n\t}\n}\nhttp://:8080 {\n\trespond \"hi\"\n}\n",
    )
    .unwrap();
    assert_eq!(twin(native), twin(legacy));
}

/// 🛡️ The two listener modifiers are the addressed `servers <address>` block:
/// same fields, same values, one socket.
#[test]
fn listener_trust_and_allowlist_match_the_addressed_servers_block() {
    let native = crate::compile(
        r#"
        HTTPListener(on: ":8080") {
            Site(host: "*") { Fallback { Respond(body: "hi") } }
        }
        .underscoreHeaders(["Other_Field"])
        .trustedProxies(ranges: ["10.0.0.0/8"], headers: [.xRealIP])
        "#,
    )
    .unwrap();
    let legacy = crate::compile(
        "{\n\tservers :8080 {\n\t\texpected_underscore_headers Other_Field\n\t\ttrusted_proxies static 10.0.0.0/8\n\t\tclient_ip_headers X-Real-IP\n\t}\n}\nhttp://:8080 {\n\trespond \"hi\"\n}\n",
    )
    .unwrap();
    assert_eq!(twin(native), twin(legacy));
    // 🧭 The documented example is the same shape `/documentation` checks.
    assert!(
        crate::compile(
            r#"UnderscoreHeaders(["X_Probe", "Webhook_*"])
HTTPListener(on: ":8443") {
    Site(host: "*") { Fallback { Respond(body: "hi") } }
}
.underscoreHeaders(["X_Probe"])
.trustedProxies(headers: [.xForwardedFor])"#
        )
        .is_ok()
    );
}

/// 🧭 A listener modifier replaces only the half it names: the label it does
/// not write still comes from the file-level declaration.
#[test]
fn listener_trust_replaces_only_the_half_it_names() {
    let config = crate::compile(
        r#"
        TrustedProxies(ranges: ["10.0.0.0/8"], headers: [.xRealIP])
        UnderscoreHeaders(["Global_Field", "X_Probe"])
        HTTPListener(on: ":8080") {
            Site(host: "*") { Fallback { Respond(body: "hi") } }
        }
        .underscoreHeaders(["Other_Field"])
        .trustedProxies(headers: [.xForwardedFor])
        "#,
    )
    .unwrap();
    assert_eq!(
        config.global.expected_underscore_headers,
        ["Global_Field", "X_Probe"]
    );
    assert_eq!(config.global.trusted_proxies, ["10.0.0.0/8"]);
    assert_eq!(config.global.client_ip_headers, ["X-Real-IP"]);
    let options = &config.global.listener_options[":8080"];
    assert_eq!(
        options.expected_underscore_headers.as_deref(),
        Some(["Other_Field".to_owned()].as_slice())
    );
    assert_eq!(
        options.client_ip_headers.as_deref(),
        Some(["X-Forwarded-For".to_owned()].as_slice())
    );
    // 🚫 The half that was not written stays `None`, which is what lets the
    // runtime fall back to the global list instead of an empty one.
    assert_eq!(options.trusted_proxies, None);
}

#[test]
fn underscore_and_trust_spellings_fail_closed() {
    let listener = r#"
        HTTPListener(on: ":8080") {
            Site(host: "*") { Fallback { Respond(body: "hi") } }
        }
    "#;
    for declaration in [
        // 📐 The declaration takes one unnamed array, nothing else.
        r#"UnderscoreHeaders("X_Probe")"#,
        r#"UnderscoreHeaders([])"#,
        r#"UnderscoreHeaders([1])"#,
        r#"UnderscoreHeaders(headers: ["X_Probe"])"#,
        r#"UnderscoreHeaders(["X_Probe"], ["Y_Field"])"#,
        // 🚫 Each entry must be a name an underscore guard could act on.
        r#"UnderscoreHeaders(["x-probe"])"#,
        r#"UnderscoreHeaders(["*"])"#,
        r#"UnderscoreHeaders(["x_*_bad"])"#,
        r#"UnderscoreHeaders(["X_ Probe"])"#,
        r#"UnderscoreHeaders(["X_Probe"]) { }"#,
        r#"UnderscoreHeaders(["X_Probe"]).unknown(1)"#,
        // 🚫 The Caddyfile's spelling is the compatibility layer's, not a
        // second native one: one directive, one spelling.
        r#"underscore_headers(["X_Probe"])"#,
    ] {
        assert!(
            crate::compile(&format!("{declaration}\n{listener}")).is_err(),
            "accepted {declaration}"
        );
    }
    for modifier in [
        // 📐 One unnamed array, and only one.
        ".underscoreHeaders()",
        ".underscoreHeaders([])",
        r#".underscoreHeaders("X_Probe")"#,
        r#".underscoreHeaders(["X_Probe"], ["Y_Field"])"#,
        r#".underscoreHeaders(["x-probe"])"#,
        r#".underscoreHeaders(["X_Probe"]).underscoreHeaders(["Y_Field"])"#,
        // 🛡️ A trust list needs at least one label, and each half keeps the
        // value rules the global declaration has.
        ".trustedProxies()",
        r#".trustedProxies(ranges: [])"#,
        r#".trustedProxies(headers: [])"#,
        r#".trustedProxies(ranges: "10.0.0.0/8")"#,
        r#".trustedProxies(ranges: ["not-a-cidr"])"#,
        r#".trustedProxies(proxies: ["10.0.0.0/8"])"#,
        r#".trustedProxies(headers: [.nope])"#,
        r#".trustedProxies(ranges: ["10.0.0.0/8"]).trustedProxies(headers: [.xRealIP])"#,
        // 🚫 As above: the snake case names the Caddyfile option, and the
        // native listener has exactly one spelling per decision.
        r#".underscore_headers(["X_Probe"])"#,
        r#".trusted_proxies(ranges: ["10.0.0.0/8"])"#,
    ] {
        assert!(
            crate::compile(&format!("{listener}{modifier}")).is_err(),
            "accepted {modifier}"
        );
    }
    // 📌 The spellings belong to the HTTP listener; a TCP listener has neither
    // the request fields nor the client-address decision.
    assert!(
        crate::compile(
            r#"TCPListener(on: "127.0.0.1:9443") {
    Fallback { Proxy(to: "127.0.0.1:8080") }
}
.underscoreHeaders(["X_Probe"])"#
        )
        .is_err()
    );
}

/// 📍 A bad entry is refused where it was written, not at startup.
#[test]
fn a_bad_allowlist_entry_points_at_the_declaration() {
    let error = crate::adapt(
        r#"
UnderscoreHeaders([
    "Webhook_*",
    "x-probe",
])
HTTPListener(on: ":8080") {
    Site(host: "*") { Fallback { Respond(body: "hi") } }
}
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("line 2:1:"), "{error}");
    assert!(error.contains("x-probe"), "{error}");
    assert!(
        error.contains("containing `_`"),
        "the message must say what an entry is: {error}"
    );
}

#[test]
fn limits_lower_to_the_resource_bounds() {
    let native = crate::compile(
        r#"
        HTTPListener(on: ":9090") {
            Site(host: "*") { Fallback { Respond(body: "hi") } }
        }
        .limits(headerTimeout: .seconds(30), maxConnections: 64)
        "#,
    )
    .unwrap();
    let legacy = crate::compile(
        "http://:9090 {\n\tlimits {\n\t\theader_timeout 30s\n\t\tmax_connections 64\n\t}\n\trespond \"hi\"\n}\n",
    )
    .unwrap();
    assert_eq!(twin(native), twin(legacy));
}

#[test]
fn http_listener_modifiers_fail_closed() {
    for source in [
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Respond(body: \"hi\") } } }.protocols([.http1])",
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Respond(body: \"hi\") } } }.protocols([.http1, .http2, .http4])",
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Respond(body: \"hi\") } } }.protocols([.http1, .http1, .http2])",
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Respond(body: \"hi\") } } }.bind(\":8081\")",
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Respond(body: \"hi\") } } }.bind([\":8080\"])",
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Respond(body: \"hi\") } } }.bind([\":8081\"]).bind([\":8082\"])",
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Respond(body: \"hi\") } } }.limits(longConnections: .seconds(1))",
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Respond(body: \"hi\") } } }.limits(headerTimeout: 30)",
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Respond(body: \"hi\") } } }.unknown(1)",
    ] {
        assert!(crate::compile(source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn tls_variants_lower_like_their_caddyfile_twins() {
    let cases = [
        (
            "HTTPListener(on: \":8443\") { Site(host: \"localhost\") { Fallback { Respond(body: \"hi\") } } }.tls(.internal)",
            "https://localhost:8443 {\n\ttls internal\n\trespond \"hi\"\n}\n",
        ),
        (
            "HTTPListener(on: \":8443\") { Site(host: \"example.test\") { Fallback { Respond(body: \"hi\") } } }.tls(.automatic(email: \"admin@example.com\"))",
            "https://example.test:8443 {\n\ttls admin@example.com\n\trespond \"hi\"\n}\n",
        ),
        (
            "HTTPListener(on: \":8443\") { Site(host: \"example.test\") { Fallback { Respond(body: \"hi\") } } }.tls(.files(certificate: \"/tmp/c.pem\", key: \"/tmp/k.pem\"))",
            "https://example.test:8443 {\n\ttls /tmp/c.pem /tmp/k.pem\n\trespond \"hi\"\n}\n",
        ),
    ];
    for (native_source, legacy_source) in cases {
        let native = crate::adapt(native_source).unwrap();
        let legacy = crate::adapt(legacy_source).unwrap();
        assert_eq!(twin(native), twin(legacy), "{native_source}");
    }
    // 🏛️ The internal authority needs no files and no public ACME, so it also
    // passes the full validation gate.
    assert!(crate::compile(cases[0].0).is_ok());
}

#[test]
fn access_logs_lower_like_their_caddyfile_twins() {
    let native = crate::compile(
        r#"
        HTTPListener(on: ":8080") {
            Site(host: "*") { Fallback { Respond(body: "hi") } }
        }
        .accessLog(output: .file("/tmp/access.log"), format: .json)
        "#,
    )
    .unwrap();
    let legacy = crate::compile(
        "http://:8080 {\n\tlog {\n\t\toutput file /tmp/access.log\n\t\tformat json\n\t}\n\trespond \"hi\"\n}\n",
    )
    .unwrap();
    assert_eq!(twin(native), twin(legacy));

    let bare_native = crate::compile(
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Respond(body: \"hi\") } } }.accessLog()",
    )
    .unwrap();
    let bare_legacy = crate::compile("http://:8080 {\n\tlog\n\trespond \"hi\"\n}\n").unwrap();
    assert_eq!(twin(bare_native), twin(bare_legacy));
}

#[test]
fn tls_and_log_mistakes_fail_closed() {
    let prefix = "HTTPListener(on: \":8443\") { Site(host: \"localhost\") { Fallback { Respond(body: \"hi\") } } }";
    for modifier in [
        ".tls(.acme(email: \"x\"))",
        ".tls(.files(certificate: \"/tmp/c.pem\"))",
        ".tls(.internal(email: \"x\"))",
        ".tls(.internal).tls(.internal)",
        ".accessLog(output: .socket)",
        ".accessLog(output: .file(1))",
    ] {
        let source = format!("{prefix}{modifier}");
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn http_conditions_lower_like_their_caddyfile_twins() {
    let cases = [
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .path(exact: \"/a\")) { Respond(body: \"m\") } } }",
            "http://:8080 {\n\trespond /a \"m\"\n}\n",
        ),
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .host([\"example.com\"])) { Respond(body: \"m\") } } }",
            "http://:8080 {\n\t@h host example.com\n\trespond @h \"m\"\n}\n",
        ),
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .method(.get, .post)) { Respond(body: \"m\") } } }",
            "http://:8080 {\n\t@m method GET POST\n\trespond @m \"m\"\n}\n",
        ),
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .path(.regex(\"^/old/(.*)$\"))) { Respond(body: \"m\") } } }",
            "http://:8080 {\n\t@m path_regexp ^/old/(.*)$\n\trespond @m \"m\"\n}\n",
        ),
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .all([.path(glob: \"/a/*\"), .host([\"example.com\"])])) { Respond(body: \"m\") } } }",
            "http://:8080 {\n\t@m {\n\t\thost example.com\n\t\tpath /a/*\n\t}\n\trespond @m \"m\"\n}\n",
        ),
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .not(.path(glob: \"/x/*\"))) { Respond(body: \"m\") } } }",
            "http://:8080 {\n\t@m not path /x/*\n\trespond @m \"m\"\n}\n",
        ),
    ];
    for (native_source, legacy_source) in cases {
        let native = crate::compile(native_source).unwrap();
        let legacy = crate::compile(legacy_source).unwrap();
        assert_eq!(twin(native), twin(legacy), "{native_source}");
    }
}

#[test]
fn native_only_conditions_lower_to_their_typed_shape() {
    let config = crate::compile(
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .path(prefix: \"/api\")) { Respond(body: \"m\") } } }",
    )
    .unwrap();
    let route = &config.servers[0].routes[0];
    assert_eq!(route.path, "/api*");
    assert_eq!(
        route.matcher,
        Some(pingclair_core::config::Matcher::Path {
            patterns: vec!["/api".to_string(), "/api/*".to_string()]
        })
    );

    let config = crate::compile(
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .any([.host([\"a.example\"]), .method(.get)])) { Respond(body: \"m\") } } }",
    )
    .unwrap();
    let route = &config.servers[0].routes[0];
    assert_eq!(route.path, "/*");
    assert_eq!(
        route.matcher,
        Some(pingclair_core::config::Matcher::Or(
            Box::new(pingclair_core::config::Matcher::Host(vec![
                "a.example".to_string()
            ])),
            Box::new(pingclair_core::config::Matcher::Method {
                methods: vec!["GET".to_string()]
            })
        ))
    );
}

#[test]
fn http_route_conditions_fail_closed() {
    let site =
        |route: &str| format!("HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ {route} }} }}");
    for route in [
        "Route(when: .path(exact: \"/a*\")) { Respond(body: \"m\") }",
        "Route(when: .path(prefix: \"/a/\")) { Respond(body: \"m\") }",
        "Route(when: .path()) { Respond(body: \"m\") }",
        "Route(when: .path(exact: \"/a\", glob: \"/b*\")) { Respond(body: \"m\") }",
        "Route(when: .path(.unknown(\"/a\"))) { Respond(body: \"m\") }",
        "Route(when: .method(.trace)) { Respond(body: \"m\") }",
        "Route(when: .method(.get, 5)) { Respond(body: \"m\") }",
        "Route(when: .host([])) { Respond(body: \"m\") }",
        "Route(when: .all([])) { Respond(body: \"m\") }",
        "Route { Respond(body: \"m\") }",
        "Route(when: .path(exact: \"/a\")) { Respond(body: \"m\") Respond(body: \"n\") }",
        "Fallback { Respond(body: \"f\") } Route(when: .path(exact: \"/a\")) { Respond(body: \"m\") }",
        "Fallback { Respond(body: \"f\") } Fallback { Respond(body: \"g\") }",
    ] {
        let source = site(route);
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn http_header_query_and_protocol_conditions_match_their_twins() {
    let cases = [
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .header(name: \"X-Foo\", value: \"bar\")) { Respond(body: \"m\") } } }",
            "http://:8080 {\n\t@m header X-Foo bar\n\trespond @m \"m\"\n}\n",
        ),
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .header(name: \"X-Foo\", exists: true)) { Respond(body: \"m\") } } }",
            "http://:8080 {\n\t@m header X-Foo *\n\trespond @m \"m\"\n}\n",
        ),
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .header(name: \"X-Foo\", startsWith: \"bar\")) { Respond(body: \"m\") } } }",
            "http://:8080 {\n\t@m header X-Foo bar*\n\trespond @m \"m\"\n}\n",
        ),
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .header(name: \"X-Foo\", endsWith: \"bar\")) { Respond(body: \"m\") } } }",
            "http://:8080 {\n\t@m header X-Foo *bar\n\trespond @m \"m\"\n}\n",
        ),
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .header(name: \"X-Foo\", contains: \"bar\")) { Respond(body: \"m\") } } }",
            "http://:8080 {\n\t@m header X-Foo *bar*\n\trespond @m \"m\"\n}\n",
        ),
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .header(.regex(name: \"X-Foo\", pattern: \"^b.*$\"))) { Respond(body: \"m\") } } }",
            "http://:8080 {\n\t@m header_regexp X-Foo ^b.*$\n\trespond @m \"m\"\n}\n",
        ),
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .query(name: \"debug\", value: \"1\")) { Respond(body: \"m\") } } }",
            "http://:8080 {\n\t@m query debug=1\n\trespond @m \"m\"\n}\n",
        ),
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .protocol(.http1, .http3)) { Respond(body: \"m\") } } }",
            "http://:8080 {\n\t@m protocol http1 http3\n\trespond @m \"m\"\n}\n",
        ),
    ];
    for (native_source, legacy_source) in cases {
        let native = crate::compile(native_source).unwrap();
        let legacy = crate::compile(legacy_source).unwrap();
        assert_eq!(twin(native), twin(legacy), "{native_source}");
    }
}

#[test]
fn http_address_and_variable_conditions_match_their_twins() {
    let cases = [
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .clientIP([\"127.0.0.1/32\"])) { Respond(body: \"m\") } } }",
            "http://:8080 {\n\t@m client_ip 127.0.0.1/32\n\trespond @m \"m\"\n}\n",
        ),
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .remoteIP([.privateRanges])) { Respond(body: \"m\") } } }",
            "http://:8080 {\n\t@m remote_ip private_ranges\n\trespond @m \"m\"\n}\n",
        ),
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .variable(name: \"foo\", values: [\"bar\"])) { Respond(body: \"m\") } } }",
            "http://:8080 {\n\t@m vars foo bar\n\trespond @m \"m\"\n}\n",
        ),
    ];
    for (native_source, legacy_source) in cases {
        let native = crate::compile(native_source).unwrap();
        let legacy = crate::compile(legacy_source).unwrap();
        assert_eq!(twin(native), twin(legacy), "{native_source}");
    }
}

#[test]
fn the_rest_of_the_conditions_fail_closed() {
    let site =
        |route: &str| format!("HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ {route} }} }}");
    for route in [
        "Route(when: .header(name: \"X\", value: \"v\", contains: \"c\")) { Respond(body: \"m\") }",
        "Route(when: .header(name: \"X\")) { Respond(body: \"m\") }",
        "Route(when: .header(name: \"X\", exists: false)) { Respond(body: \"m\") }",
        "Route(when: .query(name: \"debug\", exists: false)) { Respond(body: \"m\") }",
        "Route(when: .protocol()) { Respond(body: \"m\") }",
        "Route(when: .protocol(.http4)) { Respond(body: \"m\") }",
        "Route(when: .protocol(.http1, .http1)) { Respond(body: \"m\") }",
        "Route(when: .clientIP([])) { Respond(body: \"m\") }",
        "Route(when: .clientIP([\"not-a-cidr\"])) { Respond(body: \"m\") }",
        "Route(when: .remoteIP([.privateRange])) { Respond(body: \"m\") }",
        "Route(when: .variable(name: \"foo\", values: [])) { Respond(body: \"m\") }",
        "Route(when: .file(try: [\"x\"])) { Respond(body: \"m\") }",
    ] {
        let source = site(route);
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn http_terminals_lower_like_their_caddyfile_twins() {
    let cases = [
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { ServeFiles(root: \"/tmp/pub\") } } }",
            "http://:8080 {\n\troot * /tmp/pub\n\tfile_server\n}\n",
        ),
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Proxy(to: \"127.0.0.1:9000\") } } }",
            "http://:8080 {\n\treverse_proxy 127.0.0.1:9000\n}\n",
        ),
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Proxy(to: [\"127.0.0.1:9000\", \"127.0.0.1:9001\"]) } } }",
            "http://:8080 {\n\treverse_proxy 127.0.0.1:9000 127.0.0.1:9001\n}\n",
        ),
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .path(exact: \"/old\")) { Redirect(to: \"/new\", status: .permanent) } } }",
            "http://:8080 {\n\tredir /old /new 301\n}\n",
        ),
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Route(when: .path(exact: \"/old\")) { Redirect(to: \"/new\") } } }",
            "http://:8080 {\n\tredir /old /new\n}\n",
        ),
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Fail(status: 503, message: \"boom\") } } }",
            "http://:8080 {\n\terror \"boom\" 503\n}\n",
        ),
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Fail() } } }",
            "http://:8080 {\n\terror\n}\n",
        ),
        (
            "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { ServeMetrics() } } }",
            "http://:8080 {\n\tmetrics\n}\n",
        ),
    ];
    for (native_source, legacy_source) in cases {
        let native = crate::compile(native_source).unwrap();
        let legacy = crate::compile(legacy_source).unwrap();
        assert_eq!(twin(native), twin(legacy), "{native_source}");
    }
}

#[test]
fn http_terminal_mistakes_fail_closed() {
    let site = |handler: &str| {
        format!(
            "HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ {handler} }} }} }}"
        )
    };
    for handler in [
        "ServeFiles()",
        "ServeFiles(root: 1)",
        "ServeFiles(root: \"/tmp\", index: [])",
        "ServeFiles(root: \"/tmp\", browse: 1)",
        "Proxy()",
        "Proxy(to: 5)",
        "Proxy(to: [])",
        "Proxy(to: \"127.0.0.1:9000\", extra: 1)",
        "Redirect()",
        "Redirect(to: \"/new\", status: .moved)",
        "Redirect(to: \"/new\", status: 301)",
        "Fail(status: 999999)",
        "Fail(message: 1)",
        "ServeMetrics(unknown: true)",
    ] {
        let source = site(handler);
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn http_pipelines_lower_like_their_caddyfile_twins() {
    let cases = [
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                RequestHeader(.set("X-Trace", "probe"))
                RequestHeader(.append("X-Added", "yes"))
                RequestHeader(.remove("X-Drop"))
                RequestHeader(.replace("X-Rep", pattern: "f(.)o", with: "b$1r"))
                Respond(body: "ok")
            } } }"#,
            "http://:8080 {\n\troute {\n\t\trequest_header X-Trace probe\n\t\trequest_header +X-Added yes\n\t\trequest_header -X-Drop\n\t\trequest_header X-Rep f(.)o b$1r\n\t\trespond \"ok\"\n\t}\n}\n",
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                ResponseHeader(.set("X-Set", "v"), .append("X-Add", "yes"), .remove("X-Drop"), .setIfAbsent("X-Def", "1"), .replace("X-Rep", pattern: "f(.)o", with: "b$1r"))
                Respond(body: "ok")
            } } }"#,
            "http://:8080 {\n\troute {\n\t\theader {\n\t\t\tX-Set v\n\t\t\t+X-Add yes\n\t\t\t-X-Drop\n\t\t\t?X-Def 1\n\t\t\t>X-Rep f(.)o b$1r\n\t\t}\n\t\trespond \"ok\"\n\t}\n}\n",
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                Rewrite(method: .put)
                Rewrite(to: "/new")
                Rewrite(stripPrefix: "/api")
                Rewrite(stripSuffix: "/old")
                Rewrite(path: .regex(pattern: "^/x/(.*)$", replacement: "/y/$1"))
                Respond(body: "ok")
            } } }"#,
            "http://:8080 {\n\troute {\n\t\tmethod PUT\n\t\trewrite /new\n\t\turi strip_prefix /api\n\t\turi strip_suffix /old\n\t\turi path_regexp ^/x/(.*)$ /y/$1\n\t\trespond \"ok\"\n\t}\n}\n",
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") {
                Route(when: .path(exact: "/a")) {
                    RequestHeader(.set("X-A", "a"))
                    Respond(body: "ok")
                }
            } }"#,
            "http://:8080 {\n\t@m path /a\n\troute @m {\n\t\trequest_header X-A a\n\t\trespond \"ok\"\n\t}\n}\n",
        ),
    ];
    for (native_source, legacy_source) in cases {
        let native = crate::compile(native_source).unwrap();
        let legacy = crate::compile(legacy_source).unwrap();
        assert_eq!(twin(native), twin(legacy), "{native_source}");
    }
}

#[test]
fn a_middleware_pair_becomes_one_pipeline_in_writing_order() {
    let config = crate::compile(
        r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
            RequestHeader(.set("X-Trace", "probe"))
            ResponseHeader(.set("X-Set", "v"))
            Respond(body: "ok")
        } } }"#,
    )
    .unwrap();
    let HandlerConfig::Pipeline { handlers } = &config.servers[0].routes[0].handler else {
        panic!("two components must compose into a pipeline");
    };
    assert!(matches!(
        handlers[0].handler,
        HandlerConfig::RequestHeaders { .. }
    ));
    assert!(matches!(handlers[1].handler, HandlerConfig::Headers { .. }));
    assert!(matches!(handlers[2].handler, HandlerConfig::Respond { .. }));
    assert!(handlers.iter().all(|element| element.matcher.is_none()));
}

#[test]
fn one_component_stays_a_bare_handler() {
    let config = crate::compile(
        r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
            RequestHeader(.set("X-Trace", "probe"))
            Respond(body: "ok")
        } } }"#,
    )
    .unwrap();
    let HandlerConfig::Pipeline { handlers } = &config.servers[0].routes[0].handler else {
        panic!("expected a pipeline");
    };
    assert_eq!(handlers.len(), 2);

    let single = crate::compile(
        r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback { Respond(body: "ok") } } }"#,
    )
    .unwrap();
    assert!(matches!(
        single.servers[0].routes[0].handler,
        HandlerConfig::Respond { .. }
    ));
}

#[test]
fn headers_and_rewrites_that_cannot_mean_anything_fail_closed() {
    let site = |body: &str| {
        format!("HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ {body} }} }} }}")
    };
    for body in [
        // 🅿️ A route body ends in the component that answers.
        "RequestHeader(.set(\"X-A\", \"a\"))",
        "Respond(body: \"a\") Proxy(to: \"127.0.0.1:9000\")",
        "Rewrite(to: \"/new\")",
        "Respond(body: \"a\") Respond(body: \"b\")",
        // 🏷️ Header actions are typed, labeled-free, and unambiguous.
        "RequestHeader() Respond(body: \"ok\")",
        "RequestHeader(\"X-A\") Respond(body: \"ok\")",
        "RequestHeader(.set(\"X-A\")) Respond(body: \"ok\")",
        "RequestHeader(.set(\"X-A\", \"a\", \"b\")) Respond(body: \"ok\")",
        "RequestHeader(.set(\"X-A\", \"a\"), .set(\"X-A\", \"b\")) Respond(body: \"ok\")",
        "RequestHeader(.remove()) Respond(body: \"ok\")",
        "RequestHeader(.remove(\"X-A\", \"X-B\")) Respond(body: \"ok\")",
        "RequestHeader(.replace(\"X-A\", pattern: \"x\")) Respond(body: \"ok\")",
        "RequestHeader(.replace(\"X-A\", pattern: \"x\", with: 1)) Respond(body: \"ok\")",
        "RequestHeader(.setIfAbsent(\"X-A\", \"a\")) Respond(body: \"ok\")",
        "RequestHeader(.unknown(\"X-A\")) Respond(body: \"ok\")",
        "RequestHeader(actions: .set(\"X-A\", \"a\")) Respond(body: \"ok\")",
        "RequestHeader(.set(\"X-A\", \"a\")) { } Respond(body: \"ok\")",
        // ✂️ One rewrite, one operation, and only the typed verbs.
        "Rewrite() Respond(body: \"ok\")",
        "Rewrite(to: \"/a\", method: .put) Respond(body: \"ok\")",
        "Rewrite(to: 1) Respond(body: \"ok\")",
        "Rewrite(stripPrefix: 1) Respond(body: \"ok\")",
        "Rewrite(method: .trace) Respond(body: \"ok\")",
        "Rewrite(path: .glob(\"/x/*\")) Respond(body: \"ok\")",
        "Rewrite(path: .regex(pattern: \"^/x$\")) Respond(body: \"ok\")",
    ] {
        let source = site(body);
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn encode_follows_the_site_coding_list() {
    let cases = [
        (
            r#"HTTPListener(on: ":8080") {
                Site(host: "*") { Fallback { ServeFiles(root: "/tmp/pub") } }
                .encode(.zstd, .gzip)
            }"#,
            "http://:8080 {\n\tencode zstd gzip\n\troot * /tmp/pub\n\tfile_server\n}\n",
        ),
        (
            r#"HTTPListener(on: ":8080") {
                Site(host: "*") { Fallback { ServeFiles(root: "/tmp/pub") } }
                .encode(.zstd)
            }"#,
            "http://:8080 {\n\tencode zstd\n\troot * /tmp/pub\n\tfile_server\n}\n",
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback { ServeFiles(root: "/tmp/pub") } } }"#,
            "http://:8080 {\n\troot * /tmp/pub\n\tfile_server\n}\n",
        ),
    ];
    for (native_source, legacy_source) in cases {
        let native = crate::compile(native_source).unwrap();
        let legacy = crate::compile(legacy_source).unwrap();
        assert_eq!(twin(native), twin(legacy), "{native_source}");
    }

    // 🗜️ The file server follows the site's list, not its own default.
    for (index, expected) in [(1, true), (2, false)] {
        let config = crate::compile(cases[index].0).unwrap();
        let HandlerConfig::FileServer { compress, .. } = &config.servers[0].routes[0].handler
        else {
            panic!("expected a file server");
        };
        assert_eq!(*compress, expected, "{}", cases[index].0);
    }
}

#[test]
fn site_codings_that_cannot_mean_anything_fail_closed() {
    let site = |modifier: &str| {
        format!(
            "HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ Respond(body: \"ok\") }} }} {modifier} }}"
        )
    };
    for modifier in [
        ".encode()",
        ".encode(.br)",
        ".encode(.zstd, .zstd)",
        ".encode(.zstd).encode(.gzip)",
        ".encode(1)",
        ".encode(coding: .zstd)",
        ".encode(.zstd) { }",
        ".bogus(1)",
    ] {
        let source = site(modifier);
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn http_guards_lower_like_their_caddyfile_twins() {
    const BCRYPT: &str = "$2y$04$BjuNmKvAV.mEi7.yFrazX.S6w6OO7H0BzQfyVVFZBq/qbVXCVNX4W";
    const ARGON2: &str = "$argon2id$v=19$m=47104,t=1,p=1$P2nzckEdTZ3bxCiBCkRTyA$xQL3Z32eo5jKl7u5tcIsnEKObYiyNZQQf5/4sAau6Pg";
    let cases = [
        (
            format!(
                r#"HTTPListener(on: ":8080") {{ Site(host: "*") {{ Fallback {{
                BasicAuth(users: [.user("alice", hash: "{BCRYPT}")], algorithm: .bcrypt, realm: "Admin Area")
                Respond(body: "ok")
            }} }} }}"#
            ),
            format!(
                "http://:8080 {{\n\troute {{\n\t\tbasic_auth bcrypt \"Admin Area\" {{\n\t\t\talice {BCRYPT}\n\t\t}}\n\t\trespond \"ok\"\n\t}}\n}}"
            ),
        ),
        (
            format!(
                r#"HTTPListener(on: ":8080") {{ Site(host: "*") {{ Fallback {{
                BasicAuth(users: [.user("alice", hash: "{ARGON2}")], algorithm: .argon2id)
                Respond(body: "ok")
            }} }} }}"#
            ),
            format!(
                "http://:8080 {{\n\troute {{\n\t\tbasic_auth argon2id {{\n\t\t\talice {ARGON2}\n\t\t}}\n\t\trespond \"ok\"\n\t}}\n}}"
            ),
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                RateLimit(requests: 100, per: .minutes(1))
                Respond(body: "ok")
            } } }"#
                .to_string(),
            "http://:8080 {\n\troute {\n\t\trate_limit 100 1m\n\t\trespond \"ok\"\n\t}\n}"
                .to_string(),
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                RateLimit(requests: 100, per: .minutes(1), key: .header("X-Tenant-ID"), burst: 10, dryRun: true)
                Respond(body: "ok")
            } } }"#
                .to_string(),
            "http://:8080 {\n\troute {\n\t\trate_limit 100 1m {\n\t\t\tburst 10\n\t\t\tkey header X-Tenant-ID\n\t\t\tdry_run\n\t\t}\n\t\trespond \"ok\"\n\t}\n}"
                .to_string(),
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                RateLimit(requests: 100, per: .minutes(1), key: .tenant("X-Tenant-ID"))
                Respond(body: "ok")
            } } }"#
                .to_string(),
            "http://:8080 {\n\troute {\n\t\trate_limit 100 1m {\n\t\t\tkey tenant X-Tenant-ID\n\t\t}\n\t\trespond \"ok\"\n\t}\n}"
                .to_string(),
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                AccessControl(allowedIPs: ["10.0.0.0/8"], deniedUserAgents: ["(curl)"])
                Respond(body: "ok")
            } } }"#
                .to_string(),
            "http://:8080 {\n\troute {\n\t\taccess_control {\n\t\t\tallow_ip 10.0.0.0/8\n\t\t\tdeny_user_agent (curl)\n\t\t}\n\t\trespond \"ok\"\n\t}\n}"
                .to_string(),
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                CORS(origins: ["https://example.com"], methods: [.get, .post], headers: ["Content-Type"], exposedHeaders: ["X-Total"], allowCredentials: true, maxAge: .seconds(3600))
                Respond(body: "ok")
            } } }"#
                .to_string(),
            "http://:8080 {\n\troute {\n\t\tcors {\n\t\t\torigins https://example.com\n\t\t\tmethods GET POST\n\t\t\theaders Content-Type\n\t\t\texpose_headers X-Total\n\t\t\tallow_credentials true\n\t\t\tmax_age 3600\n\t\t}\n\t\trespond \"ok\"\n\t}\n}"
                .to_string(),
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                CORS(origins: ["*"])
                Respond(body: "ok")
            } } }"#
                .to_string(),
            // 📌 `cors *` would read the `*` as Caddy's matcher token, so the
            // twin has to name the origin inside the block.
            "http://:8080 {\n\troute {\n\t\tcors {\n\t\t\torigins *\n\t\t}\n\t\trespond \"ok\"\n\t}\n}"
                .to_string(),
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                SetVariable(name: "foo", value: "bar")
                Respond(body: "ok")
            } } }"#
                .to_string(),
            "http://:8080 {\n\troute {\n\t\tvars foo bar\n\t\trespond \"ok\"\n\t}\n}"
                .to_string(),
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                LimitRequestBody(max: .mebibytes(10), readTimeout: .seconds(5), writeTimeout: .seconds(5), set: "hello")
                Respond(body: "ok")
            } } }"#
                .to_string(),
            "http://:8080 {\n\troute {\n\t\trequest_body {\n\t\t\tmax_size 10mib\n\t\t\tread_timeout 5s\n\t\t\twrite_timeout 5s\n\t\t\tset \"hello\"\n\t\t}\n\t\trespond \"ok\"\n\t}\n}"
                .to_string(),
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                SkipLog()
                Respond(body: "ok")
            } } }"#
                .to_string(),
            "http://:8080 {\n\troute {\n\t\tlog_skip\n\t\trespond \"ok\"\n\t}\n}"
                .to_string(),
        ),
    ];
    for (native_source, legacy_source) in cases {
        let native = crate::compile(&native_source).unwrap();
        let legacy = crate::compile(&legacy_source).unwrap();
        assert_eq!(twin(native), twin(legacy), "{native_source}");
    }
}

#[test]
fn http_guards_that_cannot_mean_anything_fail_closed() {
    const BCRYPT: &str = "$2y$04$BjuNmKvAV.mEi7.yFrazX.S6w6OO7H0BzQfyVVFZBq/qbVXCVNX4W";
    let site = |body: &str| {
        format!(
            "HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ {body} Respond(body: \"ok\") }} }} }}"
        )
    };
    for body in [
        // 🔐 Credentials are an array of typed users, hashed with the named algorithm.
        "BasicAuth()",
        "BasicAuth(users: [])",
        "BasicAuth(users: [\"alice\"])",
        "BasicAuth(users: [.member(\"alice\", hash: \"x\")])",
        "BasicAuth(users: [.user(\"alice\")])",
        "BasicAuth(users: [.user(\"alice\", hash: \"plaintext\")])",
        "BasicAuth(users: [.user(\"alice\", hash: 1)])",
        "BasicAuth(users: [.user(\"alice\", hash: \"$2y$04$BjuNmKvAV.mEi7.yFrazX.S6w6OO7H0BzQfyVVFZBq/qbVXCVNX4W\"), .user(\"alice\", hash: \"$2y$04$BjuNmKvAV.mEi7.yFrazX.S6w6OO7H0BzQfyVVFZBq/qbVXCVNX4W\")])",
        "BasicAuth(users: [.user(\"alice\", hash: \"$2y$04$BjuNmKvAV.mEi7.yFrazX.S6w6OO7H0BzQfyVVFZBq/qbVXCVNX4W\")], algorithm: .sha256)",
        "BasicAuth(users: [.user(\"alice\", hash: \"$2y$04$BjuNmKvAV.mEi7.yFrazX.S6w6OO7H0BzQfyVVFZBq/qbVXCVNX4W\")], realm: 1)",
        // ⏱️ A window is whole seconds, and the key is a typed source.
        "RateLimit()",
        "RateLimit(per: .minutes(1))",
        "RateLimit(requests: 1)",
        "RateLimit(requests: 0, per: .minutes(1))",
        "RateLimit(requests: 1, per: .milliseconds(1500))",
        "RateLimit(requests: 1, per: .milliseconds(500))",
        "RateLimit(requests: 1, per: .minutes(1), key: .unknown)",
        "RateLimit(requests: 1, per: .minutes(1), key: .tenant)",
        "RateLimit(requests: 1, per: .minutes(1), key: .ip(\"X-A\"))",
        "RateLimit(requests: 1, per: .minutes(1), burst: \"10\")",
        "RateLimit(requests: 1, per: .minutes(1), dryRun: 1)",
        // 🛡️ A guard with no rule guards nothing.
        "AccessControl()",
        "AccessControl(allowedIPs: [])",
        "AccessControl(allowedIps: [\"10.0.0.0/8\"])",
        "AccessControl(allowedUserAgents: \"curl\")",
        // 🌐 Origins are required; methods are typed verbs.
        "CORS()",
        "CORS(origins: [])",
        "CORS(origins: [\"*\"], methods: [])",
        "CORS(origins: [\"*\"], methods: [\"GET\"])",
        "CORS(origins: [\"*\"], headers: [])",
        "CORS(origins: [\"*\"], maxAge: .milliseconds(1500))",
        "CORS(origins: [\"*\"], allowCredentials: 1)",
        // 🧰 A variable needs both halves.
        "SetVariable(name: \"foo\")",
        "SetVariable(value: \"bar\")",
        "SetVariable(name: 1, value: \"bar\")",
        // 📥 A body limit with nothing in it limits nothing.
        "LimitRequestBody()",
        "LimitRequestBody(set: \"\")",
        "LimitRequestBody(set: 1)",
        "LimitRequestBody(max: .seconds(1))",
        // 🙈 SkipLog takes nothing at all.
        "SkipLog(1)",
        "SkipLog(enabled: true)",
    ] {
        let source = site(body);
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
    // 🔑 A bcrypt hash under `.argon2id` is refused by the algorithm check,
    // which is the one refusal whose message has to name the algorithm.
    let error = crate::compile(&site(&format!(
        "BasicAuth(users: [.user(\"alice\", hash: \"{BCRYPT}\")], algorithm: .argon2id)"
    )))
    .unwrap_err()
    .to_string();
    assert!(error.contains("argon2id"), "{error}");
}

#[test]
fn guards_compose_in_writing_order() {
    let config = crate::compile(
        r#"HTTPListener(on: ":8080") { Site(host: "*") { Route(when: .path(prefix: "/admin")) {
            BasicAuth(users: [.user("alice", hash: "$2y$04$BjuNmKvAV.mEi7.yFrazX.S6w6OO7H0BzQfyVVFZBq/qbVXCVNX4W")])
            RateLimit(requests: 10, per: .seconds(1), key: .ip)
            SetVariable(name: "area", value: "admin")
            Proxy(to: "127.0.0.1:9000")
        } } }"#,
    )
    .unwrap();
    let route = &config.servers[0].routes[0];
    assert!(route.matcher.is_some());
    let HandlerConfig::Pipeline { handlers } = &route.handler else {
        panic!("expected a pipeline");
    };
    assert!(matches!(
        handlers[0].handler,
        HandlerConfig::BasicAuth { .. }
    ));
    assert!(matches!(
        handlers[1].handler,
        HandlerConfig::RateLimit { .. }
    ));
    assert!(matches!(handlers[2].handler, HandlerConfig::Vars { .. }));
    assert!(matches!(
        handlers[3].handler,
        HandlerConfig::ReverseProxy(_)
    ));
}

#[test]
fn composed_components_lower_like_their_caddyfile_twins() {
    let cases = [
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                Templates()
                ServeFiles(root: "/tmp/pub")
            } } }"#
                .to_string(),
            "http://:8080 {\n\troute {\n\t\ttemplates\n\t\tfile_server {\n\t\t\troot /tmp/pub\n\t\t}\n\t}\n}"
                .to_string(),
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                Templates(root: "/tmp/pub")
                ServeFiles(root: "/tmp/pub")
            } } }"#
                .to_string(),
            "http://:8080 {\n\troot * /tmp/pub\n\troute {\n\t\ttemplates\n\t\tfile_server\n\t}\n}"
                .to_string(),
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                ForwardAuth(to: "127.0.0.1:9001", uri: "/verify", copyHeaders: ["X-User", .rename("X-Role", to: "X-Auth-Role")])
                Respond(body: "ok")
            } } }"#
                .to_string(),
            "http://:8080 {\n\troute {\n\t\tforward_auth 127.0.0.1:9001 {\n\t\t\turi /verify\n\t\t\tcopy_headers X-User X-Role>X-Auth-Role\n\t\t}\n\t\trespond \"ok\"\n\t}\n}"
                .to_string(),
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                ACMEServer(ca: "local", lifetime: .hours(12), signWithRoot: true, challenges: ["http-01"], allow: .policy(domains: ["internal.example"]))
            } } }"#
                .to_string(),
            "http://:8080 {\n\tacme_server {\n\t\tca local\n\t\tlifetime 12h\n\t\tsign_with_root\n\t\tchallenges http-01\n\t\tallow {\n\t\t\tdomains internal.example\n\t\t}\n\t}\n}"
                .to_string(),
        ),
    ];
    for (native_source, legacy_source) in cases {
        let native = crate::compile(&native_source).unwrap();
        let legacy = crate::compile(&legacy_source).unwrap();
        assert_eq!(twin(native), twin(legacy), "{native_source}");
    }
}

#[test]
fn composed_components_that_cannot_mean_anything_fail_closed() {
    let site = |body: &str| {
        format!("HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ {body} }} }} }}")
    };
    for body in [
        // 🧩 Templates renders what follows, so the route still needs a terminal.
        "Templates()",
        "Templates(root: 1)",
        "Templates(unknown: \"/tmp\")",
        // 🔐 The gateway, its URI and its copied headers are all explicit.
        "ForwardAuth(to: \"127.0.0.1:9001\") Respond(body: \"ok\")",
        "ForwardAuth(uri: \"/verify\") Respond(body: \"ok\")",
        "ForwardAuth(to: \"127.0.0.1:9001\", uri: \"/verify\", copyHeaders: []) Respond(body: \"ok\")",
        "ForwardAuth(to: \"127.0.0.1:9001\", uri: \"/verify\", copyHeaders: \"X-User\") Respond(body: \"ok\")",
        "ForwardAuth(to: \"127.0.0.1:9001\", uri: \"/verify\", copyHeaders: [.copy(\"X-User\")]) Respond(body: \"ok\")",
        "ForwardAuth(to: \"127.0.0.1:9001\", uri: \"/verify\", copyHeaders: [.rename(\"X-Role\")]) Respond(body: \"ok\")",
        "ForwardAuth(to: \"127.0.0.1:9001\", uri: \"/verify\", copyHeaders: [.rename(\"X-Role\", to: \"X-Auth-Role\", extra: 1)]) Respond(body: \"ok\")",
        "ForwardAuth(to: \"127.0.0.1:9001\", uri: \"/verify\", copyHeaders: [\"X-User\", \"X-User\"]) Respond(body: \"ok\")",
        "ForwardAuth(to: \"127.0.0.1:9001\", uri: \"/verify\", transport: \"http\") Respond(body: \"ok\")",
        // 🏛️ An ACME server names what it issues; empty answers are refused.
        "ACMEServer(lifetime: .milliseconds(500))",
        "ACMEServer(lifetime: .seconds(0))",
        "ACMEServer(challenges: [])",
        "ACMEServer(allow: .policy())",
        "ACMEServer(allow: [\"internal.example\"])",
        "ACMEServer(deny: .only(domains: [\"x\"]))",
        "ACMEServer(signWithRoot: 1)",
        "ACMEServer(ca: 1)",
    ] {
        let source = site(body);
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn error_surfaces_lower_like_their_caddyfile_twins() {
    let cases = [
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") {
                ErrorRoute(for: [.status(404), .serverError]) { Respond(status: 500, body: "oops") }
                Fallback { Respond(body: "ok") }
            } }"#
                .to_string(),
            "http://:8080 {\n\thandle_errors 404 5xx {\n\t\trespond \"oops\" 500\n\t}\n\trespond \"ok\"\n}"
                .to_string(),
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") {
                ErrorRoute(for: [.anyError]) { Respond(status: 502, body: "boom") }
                Fallback { Respond(body: "ok") }
            } }"#
                .to_string(),
            "http://:8080 {\n\thandle_errors {\n\t\trespond \"boom\" 502\n\t}\n\trespond \"ok\"\n}"
                .to_string(),
        ),
        (
            // 🧵 A body that stops at middleware shapes the answer the runtime
            // already built, so no terminal is needed here.
            r#"HTTPListener(on: ":8080") { Site(host: "*") {
                ErrorRoute(for: [.serverError]) { ResponseHeader(.set("X-Err", "yes")) }
                Fallback { Respond(body: "ok") }
            } }"#
                .to_string(),
            "http://:8080 {\n\thandle_errors 5xx {\n\t\theader X-Err yes\n\t}\n\trespond \"ok\"\n}"
                .to_string(),
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") {
                Fallback { Respond(body: "ok") }
            }
            .errorPage(for: [.status(404)], file: "/404.html")
            .errorPage(for: [.status(500), .status(502), .status(503), .status(504)], file: "/50x.html")
            }"#
                .to_string(),
            "http://:8080 {\n\terror_page 404 /404.html\n\terror_page 500 502 503 504 /50x.html\n\trespond \"ok\"\n}"
                .to_string(),
        ),
    ];
    for (native_source, legacy_source) in cases {
        let native = crate::compile(&native_source).unwrap();
        let legacy = crate::compile(&legacy_source).unwrap();
        assert_eq!(twin(native), twin(legacy), "{native_source}");
    }
}

#[test]
fn error_surfaces_that_cannot_mean_anything_fail_closed() {
    let site = |body: &str| {
        format!(
            "HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ {body} Fallback {{ Respond(body: \"ok\") }} }} }}"
        )
    };
    for body in [
        // 🚨 A selector is required, and it has to name something an error
        // route can actually see.
        "ErrorRoute() { Respond(status: 500, body: \"x\") }",
        "ErrorRoute(for: []) { Respond(status: 500, body: \"x\") }",
        "ErrorRoute(for: [.success]) { Respond(status: 500, body: \"x\") }",
        "ErrorRoute(for: [.redirect]) { Respond(status: 500, body: \"x\") }",
        "ErrorRoute(for: [.informational]) { Respond(status: 500, body: \"x\") }",
        "ErrorRoute(for: [.status(200)]) { Respond(status: 500, body: \"x\") }",
        "ErrorRoute(for: [.status(404, 500)]) { Respond(status: 500, body: \"x\") }",
        "ErrorRoute(for: [.anyError, .serverError]) { Respond(status: 500, body: \"x\") }",
        "ErrorRoute(for: [.unknown]) { Respond(status: 500, body: \"x\") }",
        "ErrorRoute(for: [\"500\"]) { Respond(status: 500, body: \"x\") }",
        "ErrorRoute(for: [.status(500)]) { }",
        "ErrorRoute(for: [.status(500)]) { Respond(status: 500, body: \"x\") ServeFiles(root: \"./p\") }",
        // 🖼️ An error page is one code and one file.
        "ErrorRoute(for: [.status(500)]) { Fail(status: 500) } .errorPage(for: [.status(404)])",
    ] {
        let source = site(body);
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
    let with_modifier = |modifier: &str| {
        format!(
            "HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ Respond(body: \"ok\") }} }} {modifier} }}"
        )
    };
    for modifier in [
        ".errorPage()",
        ".errorPage(for: [], file: \"/404.html\")",
        ".errorPage(for: [.status(404)])",
        ".errorPage(for: [.status(404)], file: 1)",
        ".errorPage(for: [.serverError], file: \"/50x.html\")",
        ".errorPage(for: [.status(200)], file: \"/ok.html\")",
        ".errorPage(for: [.status(404), .status(404)], file: \"/404.html\")",
        ".errorPage(for: [.status(404)], file: \"/404.html\").errorPage(for: [.status(404)], file: \"/other.html\")",
        ".unknown(1)",
    ] {
        let source = with_modifier(modifier);
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
    // 🚫 A page for a status an answering error route already owns can never be
    // served; the pair is refused instead of shipped dead.
    for (error_route, page) in [
        (
            "ErrorRoute(for: [.status(404)]) { Respond(status: 404, body: \"x\") }",
            ".errorPage(for: [.status(404)], file: \"/404.html\")",
        ),
        (
            "ErrorRoute(for: [.serverError]) { Respond(status: 500, body: \"x\") }",
            ".errorPage(for: [.status(503)], file: \"/503.html\")",
        ),
    ] {
        let source = format!(
            "HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ {error_route} Fallback {{ Respond(body: \"ok\") }} }} {page} }}"
        );
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
    // 📎 Whereas a route that stops at middleware leaves the page reachable:
    // the runtime answers from the page after shaping the error in place.
    crate::compile(
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { ErrorRoute(for: [.serverError]) { ResponseHeader(.set(\"X-Err\", \"yes\")) } Fallback { Respond(body: \"ok\") } } .errorPage(for: [.status(503)], file: \"/503.html\") }",
    )
    .unwrap();
}

#[test]
fn every_condition_can_be_bound_once_and_reused() {
    let http = |condition: &str| {
        format!(
            "@Matcher\nlet shared = {condition}\nHTTPListener(on: \":8080\") {{\n    Site(host: \"*\") {{\n        Route(when: shared) {{ Respond(body: \"matched\") }}\n        Fallback {{ Respond(body: \"no\") }}\n    }}\n}}\n"
        )
    };
    for condition in [
        ".path(exact: \"/a\")",
        ".path(prefix: \"/a\")",
        ".path(glob: \"/a*\")",
        ".path(.regex(\"^/a$\"))",
        ".host([\"a.example\"])",
        ".method(.get, .post)",
        ".header(name: \"X-Debug\", value: \"1\")",
        ".header(.regex(name: \"Authorization\", pattern: \"^Bearer .+$\"))",
        ".query(name: \"tenant\", exists: true)",
        ".protocol(.http1, .http2)",
        ".clientIP([\"10.0.0.0/8\"])",
        ".remoteIP([.privateRanges])",
        ".variable(name: \"tier\", values: [\"paid\"])",
        ".all([.path(prefix: \"/admin\"), .method(.delete)])",
        ".any([.path(exact: \"/a\"), .path(exact: \"/b\")])",
        ".not(.host([\"blocked.example\"]))",
    ] {
        let source = http(condition);
        crate::compile(&source).unwrap_or_else(|error| {
            panic!("binding {condition} failed: {error}");
        });
    }
    // 🔌 The L4 condition is the one that was bindable first, and it stays so.
    crate::compile(
        "@Matcher\nlet secure = .tls(sni: [\"tunnel.example\"], alpn: [\"h2\"])\nTCPListener(on: \"127.0.0.1:9443\") {\n    Route(when: secure) { Proxy(to: \"127.0.0.1:8443\") }\n    Fallback { Proxy(to: \"127.0.0.1:8080\") }\n}\n",
    )
    .unwrap();
    // 🚫 A binding that is not a condition is still refused where it is written.
    for source in [
        "@Matcher\nlet text = \"not a condition\"\nHTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Respond(body: \"ok\") } } }\n",
        "@Matcher\nlet route = Route(when: .path(exact: \"/a\")) { Respond(body: \"ok\") }\nHTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Respond(body: \"ok\") } } }\n",
    ] {
        assert!(crate::compile(source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn file_server_options_lower_like_their_caddyfile_twins() {
    let native = crate::compile(
        r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
            ServeFiles(root: "./public", browse: true, browseLimit: 500, hide: [".git", "*.tmp"], status: 503, canonicalUris: false, etagFileExtensions: [".etag"], precompressed: [.br, .gzip], compress: false)
        } } }"#,
    )
    .unwrap();
    let legacy = crate::compile(
        "http://:8080 {\n\troot * ./public\n\tfile_server {\n\t\thide .git\n\t\thide *.tmp\n\t\tstatus 503\n\t\tdisable_canonical_uris\n\t\tetag_file_extensions .etag\n\t\tprecompressed br gzip\n\t\tcompress off\n\t\tbrowse {\n\t\t\tfile_limit 500\n\t\t}\n\t}\n}",
    )
    .unwrap();
    assert_eq!(twin(native), twin(legacy));
}

#[test]
fn file_server_options_that_cannot_mean_anything_fail_closed() {
    let site = |handler: &str| {
        format!(
            "HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ {handler} }} }} }}"
        )
    };
    for handler in [
        // 🗂️ A listing ceiling belongs to a listing.
        "ServeFiles(root: \"./public\", browseLimit: 500)",
        "ServeFiles(root: \"./public\", browse: true, browseLimit: -1)",
        // 🗜️ Sidecar codings are the three this build reads, once each.
        "ServeFiles(root: \"./public\", precompressed: [])",
        "ServeFiles(root: \"./public\", precompressed: [\"br\"])",
        "ServeFiles(root: \"./public\", precompressed: [.brotli])",
        "ServeFiles(root: \"./public\", precompressed: [.gzip, .gzip])",
        // 🔢 The maintenance status is a real status code.
        "ServeFiles(root: \"./public\", status: 99)",
        "ServeFiles(root: \"./public\", status: 600)",
        "ServeFiles(root: \"./public\", status: \"503\")",
        // 🚩 And every flag is a boolean, not a truthy token.
        "ServeFiles(root: \"./public\", passThru: 1)",
        "ServeFiles(root: \"./public\", canonicalUris: 1)",
        "ServeFiles(root: \"./public\", compress: 1)",
        // 📂 Lists are lists.
        "ServeFiles(root: \"./public\", hide: [])",
        "ServeFiles(root: \"./public\", etagFileExtensions: [])",
        "ServeFiles(root: \"./public\", hide: \".git\")",
    ] {
        let source = site(handler);
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn file_candidates_lower_like_their_caddyfile_twins() {
    let cases = [
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                TryFiles(candidates: [.requestPath, .requestPath(appending: "/index.html"), "/index.html"])
                ServeFiles(root: "/tmp/pub")
            } } }"#
                .to_string(),
            "http://:8080 {\n\troute {\n\t\ttry_files {path} {path}/index.html /index.html\n\t\tfile_server {\n\t\t\troot /tmp/pub\n\t\t}\n\t}\n}"
                .to_string(),
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                TryFiles(candidates: [.requestPath, .requestPath(appending: "/"), .path("/index.php", keepQuery: true)], root: "./public", policy: .mostRecentlyModified)
                ServeFiles(root: "./public")
            } } }"#
                .to_string(),
            "http://:8080 {\n\troot * ./public\n\troute {\n\t\ttry_files {path} {path}/ /index.php?{query} {\n\t\t\tpolicy most_recently_modified\n\t\t}\n\t\tfile_server\n\t}\n}"
                .to_string(),
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") {
                Route(when: .file(candidates: [.requestPath, .requestPath(appending: "/"), .path("/index.php", keepQuery: true)], root: "./public", policy: .mostRecentlyModified)) {
                    ServeFiles(root: "./public")
                }
            } }"#
                .to_string(),
            "http://:8080 {\n\t@existing {\n\t\tfile {\n\t\t\ttry_files {path} {path}/ /index.php?{query}\n\t\t\troot ./public\n\t\t\ttry_policy most_recently_modified\n\t\t}\n\t}\n\tfile_server @existing {\n\t\troot ./public\n\t}\n}"
                .to_string(),
        ),
    ];
    for (native_source, legacy_source) in cases {
        let native = crate::compile(&native_source).unwrap();
        let legacy = crate::compile(&legacy_source).unwrap();
        assert_eq!(twin(native), twin(legacy), "{native_source}");
    }
}

#[test]
fn file_candidates_that_cannot_mean_anything_fail_closed() {
    let site = |body: &str| {
        format!("HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ {body} }} }} }}")
    };
    for body in [
        // 📂 A candidate list is required and has to be a list.
        "TryFiles() ServeFiles(root: \"/tmp\")",
        "TryFiles(candidates: []) ServeFiles(root: \"/tmp\")",
        "TryFiles(candidates: \"/index.html\") ServeFiles(root: \"/tmp\")",
        "TryFiles(candidates: [1]) ServeFiles(root: \"/tmp\")",
        // 🚫 The engine's placeholders are not this language's spelling.
        "TryFiles(candidates: [\"{path}\"]) ServeFiles(root: \"/tmp\")",
        "TryFiles(candidates: [.requestPath(appending: \"/{path}.html\")]) ServeFiles(root: \"/tmp\")",
        "TryFiles(candidates: [.path]) ServeFiles(root: \"/tmp\")",
        "TryFiles(candidates: [.uri]) ServeFiles(root: \"/tmp\")",
        // 🌐 Globs and literal queries are refused by name.
        "TryFiles(candidates: [\"/assets/*\"]) ServeFiles(root: \"/tmp\")",
        "TryFiles(candidates: [\"/index.php?x=1\"]) ServeFiles(root: \"/tmp\")",
        "TryFiles(candidates: [\"\"]) ServeFiles(root: \"/tmp\")",
        "TryFiles(candidates: [.requestPath], keepQuery: true) ServeFiles(root: \"/tmp\")",
        // 🗂️ Policy and root are typed, and a policy has to be one of the five.
        "TryFiles(candidates: [.requestPath], policy: \"first_exist\") ServeFiles(root: \"/tmp\")",
        "TryFiles(candidates: [.requestPath], policy: .best) ServeFiles(root: \"/tmp\")",
        "TryFiles(candidates: [.requestPath], policy: .firstExist(1)) ServeFiles(root: \"/tmp\")",
        "TryFiles(candidates: [.requestPath], root: 1) ServeFiles(root: \"/tmp\")",
        "TryFiles(candidates: [.requestPath], root: \"/tmp\", root: \"/var\") ServeFiles(root: \"/tmp\")",
        // 📂 The condition refuses the same spellings.
        "Route(when: .file()) { Fail(status: 404) }",
        "Route(when: .file(candidates: [\"{path}\"])) { Fail(status: 404) }",
        "Route(when: .file(candidates: [.requestPath], policy: .best)) { Fail(status: 404) }",
    ] {
        let source = site(body);
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn intercept_lowers_like_its_caddyfile_twin() {
    let cases = [
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                Intercept {
                    Response(when: .status(.serverError)) { ReplaceStatus(status: 502) }
                    Response(when: .status(.success)) {
                        CopyResponseHeaders(exclude: ["Set-Cookie"])
                        CopyResponse(status: 201)
                    }
                }
                Proxy(to: "127.0.0.1:9000")
            } } }"#
                .to_string(),
            "http://:8080 {\n\troute {\n\t\tintercept {\n\t\t\t@err status 5xx\n\t\t\t@ok status 2xx\n\t\t\treplace_status @err 502\n\t\t\thandle_response @ok {\n\t\t\t\tcopy_response_headers {\n\t\t\t\t\texclude Set-Cookie\n\t\t\t\t}\n\t\t\t\tcopy_response 201\n\t\t\t}\n\t\t}\n\t\treverse_proxy 127.0.0.1:9000\n\t}\n}"
                .to_string(),
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                Intercept {
                    Response(when: .status(404)) { Respond(status: 200, body: "soft 404") }
                    Response { ReplaceStatus(status: 503) }
                }
                Proxy(to: "127.0.0.1:9000")
            } } }"#
                .to_string(),
            "http://:8080 {\n\troute {\n\t\tintercept {\n\t\t\t@missing status 404\n\t\t\thandle_response @missing {\n\t\t\t\trespond \"soft 404\" 200\n\t\t\t}\n\t\t\treplace_status 503\n\t\t}\n\t\treverse_proxy 127.0.0.1:9000\n\t}\n}"
                .to_string(),
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                Intercept {
                    Response(when: .header(name: "Content-Type", value: "text/*")) {
                        CopyResponseHeaders(include: ["Content-Type", "Etag"])
                        Respond(status: 200, body: "rewritten")
                    }
                }
                ServeFiles(root: "/tmp/pub")
            } } }"#
                .to_string(),
            "http://:8080 {\n\troute {\n\t\tintercept {\n\t\t\t@text header Content-Type text/*\n\t\t\thandle_response @text {\n\t\t\t\tcopy_response_headers {\n\t\t\t\t\tinclude Content-Type Etag\n\t\t\t\t}\n\t\t\t\trespond \"rewritten\" 200\n\t\t\t}\n\t\t}\n\t\tfile_server {\n\t\t\troot /tmp/pub\n\t\t}\n\t}\n}"
                .to_string(),
        ),
    ];
    for (native_source, legacy_source) in cases {
        let native = crate::compile(&native_source).unwrap();
        let legacy = crate::compile(&legacy_source).unwrap();
        assert_eq!(twin(native), twin(legacy), "{native_source}");
    }
}

#[test]
fn intercept_entries_that_cannot_mean_anything_fail_closed() {
    let site = |body: &str| {
        format!(
            "HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ {body} Proxy(to: \"127.0.0.1:9000\") }} }} }}"
        )
    };
    for body in [
        // 🧭 A block is required and it has to hold something.
        "Intercept()",
        "Intercept { }",
        "Intercept(unknown: 1) { }",
        "Intercept { Response() }",
        "Intercept { Response { } }",
        "Intercept { Response(unknown: 1) { ReplaceStatus(status: 503) } }",
        // 🥇 An entry that matches every response has to come last.
        "Intercept { Response { ReplaceStatus(status: 503) } Response(when: .status(500)) { ReplaceStatus(status: 502) } }",
        // 🚦 Statuses are codes and classes, in range.
        "Intercept { Response(when: .status()) { ReplaceStatus(status: 503) } }",
        "Intercept { Response(when: .status(99)) { ReplaceStatus(status: 503) } }",
        "Intercept { Response(when: .status(600)) { ReplaceStatus(status: 503) } }",
        "Intercept { Response(when: .status(.anyError)) { ReplaceStatus(status: 503) } }",
        "Intercept { Response(when: .status(.unknown)) { ReplaceStatus(status: 503) } }",
        "Intercept { Response(when: .status(code: 500)) { ReplaceStatus(status: 503) } }",
        // 🏷️ A header condition names a header and one predicate.
        "Intercept { Response(when: .header(name: \"X-Foo\")) { ReplaceStatus(status: 503) } }",
        "Intercept { Response(when: .header(name: \"X-Foo\", exists: false)) { ReplaceStatus(status: 503) } }",
        "Intercept { Response(when: .header(value: \"x\")) { ReplaceStatus(status: 503) } }",
        "Intercept { Response(when: .path(exact: \"/x\")) { ReplaceStatus(status: 503) } }",
        "Intercept { Response(when: \"status\") { ReplaceStatus(status: 503) } }",
        // 💬 The handler family is four names, and each has its own shape.
        "Intercept { Response(when: .status(500)) { Fail(status: 500) } }",
        "Intercept { Response(when: .status(500)) { Proxy(to: \"127.0.0.1:9000\") } }",
        "Intercept { Response(when: .status(500)) { ReplaceStatus() } }",
        "Intercept { Response(when: .status(500)) { ReplaceStatus(status: 999999) } }",
        "Intercept { Response(when: .status(500)) { ReplaceStatus(status: \"502\") } }",
        "Intercept { Response(when: .status(500)) { ReplaceStatus(status: 503) ReplaceStatus(status: 504) } }",
        "Intercept { Response(when: .status(500)) { CopyResponse(status: 999999) } }",
        "Intercept { Response(when: .status(500)) { CopyResponseHeaders() } }",
        "Intercept { Response(when: .status(500)) { CopyResponseHeaders(include: [], exclude: [\"X\"]) } }",
        "Intercept { Response(when: .status(500)) { CopyResponseHeaders(include: [\"X\"], exclude: [\"Y\"]) } }",
        "Intercept { Response(when: .status(500)) { CopyResponseHeaders(include: \"X\") } }",
    ] {
        let source = site(body);
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn php_fastcgi_lowers_like_its_caddyfile_twin() {
    // 🌐 Without a root the whole configuration compares: both spellings leave
    // the document root to the process's working directory.
    let native = crate::compile(
        r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback { PHPFastCGI(to: "unix//run/php-fpm.sock") } } }"#,
    )
    .unwrap();
    let legacy =
        crate::compile("http://:8080 {\n\tphp_fastcgi unix//run/php-fpm.sock\n}\n").unwrap();
    assert_eq!(twin(native), twin(legacy));
}

#[test]
fn php_fastcgi_expands_the_front_controller_shape() {
    let config = crate::compile(
        r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
            PHPFastCGI(to: "unix//run/php-fpm.sock", root: "./public", env: [.env("APP_ENV", "production")], captureStderr: true, readTimeout: .seconds(30))
        } } }"#,
    )
    .unwrap();
    let HandlerConfig::Pipeline { handlers } = &config.servers[0].routes[0].handler else {
        panic!("the expansion is a pipeline");
    };
    assert_eq!(handlers.len(), 3);
    // 🗂️ A directory without its slash is redirected, so relative links work.
    assert!(matches!(
        &handlers[0].handler,
        HandlerConfig::Redirect { code: 308, .. }
    ));
    // 🗂️ The rewrite names the candidates, the root, the policy and the split.
    let Some(Matcher::File {
        try_files,
        root,
        try_policy,
        split_path,
    }) = &handlers[1].matcher
    else {
        panic!("expected a file matcher");
    };
    assert_eq!(
        try_files,
        &[
            "{http.request.uri.path}",
            "{http.request.uri.path}/index.php",
            "index.php"
        ]
    );
    assert_eq!(root.as_deref(), Some("./public"));
    assert_eq!(try_policy.as_deref(), Some("first_exist_fallback"));
    assert_eq!(split_path, &[".php".to_string()]);
    // 🐘 And the proxy carries the FastCGI transport.
    let HandlerConfig::ReverseProxy(proxy) = &handlers[2].handler else {
        panic!("expected the proxy");
    };
    assert_eq!(proxy.upstreams, ["unix//run/php-fpm.sock"]);
    let fastcgi = proxy.fastcgi.as_ref().expect("a fastcgi transport");
    assert_eq!(fastcgi.root.as_deref(), Some("./public"));
    assert_eq!(fastcgi.split_path, [".php".to_string()]);
    assert_eq!(
        fastcgi.env.get("APP_ENV").map(String::as_str),
        Some("production")
    );
    assert!(fastcgi.capture_stderr);
    assert_eq!(fastcgi.read_timeout_ms, Some(30_000));
    // 🔤 `index: .off` leaves the plain proxy and nothing else.
    let bare = crate::compile(
        r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback { PHPFastCGI(to: "127.0.0.1:9000", index: .off) } } }"#,
    )
    .unwrap();
    let HandlerConfig::Pipeline { handlers } = &bare.servers[0].routes[0].handler else {
        panic!("still a pipeline");
    };
    assert_eq!(handlers.len(), 1);
    assert!(matches!(
        &handlers[0].handler,
        HandlerConfig::ReverseProxy(proxy) if proxy.fastcgi.is_some()
    ));
}

#[test]
fn php_fastcgi_leaves_the_static_files_to_the_next_component() {
    // 🧵 The rewrite stands down for anything that is not PHP, so the file
    // server written after it serves the rest — the Caddyfile composes the two
    // exactly this way, a pipeline inside a pipeline.
    let native = crate::compile(
        r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
            PHPFastCGI(to: "unix//run/php-fpm.sock", root: "./public")
            ServeFiles(root: "./public")
        } } }"#,
    )
    .unwrap();
    let legacy = crate::compile(
        "http://:8080 {\n\troot * ./public\n\tphp_fastcgi unix//run/php-fpm.sock\n\tfile_server\n}\n",
    )
    .unwrap();
    assert_eq!(twin(native), twin(legacy));
}

#[test]
fn php_fastcgi_that_cannot_mean_anything_fail_closed() {
    let site = |handler: &str| {
        format!(
            "HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ {handler} }} }} }}"
        )
    };
    for handler in [
        // 🐘 The pool and the split are required and have to be usable.
        "PHPFastCGI()",
        "PHPFastCGI(to: [])",
        "PHPFastCGI(to: 1)",
        "PHPFastCGI(to: \"127.0.0.1:9000\", split: [])",
        "PHPFastCGI(to: \"127.0.0.1:9000\", split: \".php\")",
        "PHPFastCGI(to: \"127.0.0.1:9000\", split: [\".phpé\"])",
        // 🔤 The index is a file name, or the explicit off switch.
        "PHPFastCGI(to: \"127.0.0.1:9000\", index: \"\")",
        "PHPFastCGI(to: \"127.0.0.1:9000\", index: .never)",
        // 🌱 Environment entries are pairs, once each.
        "PHPFastCGI(to: \"127.0.0.1:9000\", env: [])",
        "PHPFastCGI(to: \"127.0.0.1:9000\", env: [\"APP_ENV=production\"])",
        "PHPFastCGI(to: \"127.0.0.1:9000\", env: [.env(\"APP_ENV\")])",
        "PHPFastCGI(to: \"127.0.0.1:9000\", env: [.env(\"APP_ENV\", \"a\"), .env(\"APP_ENV\", \"b\")])",
        // 🗂️ The candidate override is the same typed vocabulary as TryFiles.
        "PHPFastCGI(to: \"127.0.0.1:9000\", tryFiles: [])",
        "PHPFastCGI(to: \"127.0.0.1:9000\", tryFiles: [\"{path}\"])",
        "PHPFastCGI(to: \"127.0.0.1:9000\", tryFiles: \"{path}\")",
        // ⏱️ Deadlines are durations, not bare numbers.
        "PHPFastCGI(to: \"127.0.0.1:9000\", readTimeout: 30)",
        "PHPFastCGI(to: \"127.0.0.1:9000\", captureStderr: 1)",
        "PHPFastCGI(to: \"127.0.0.1:9000\", unknown: 1)",
    ] {
        let source = site(handler);
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn proxy_header_lists_lower_like_their_caddyfile_twins() {
    // 🏷️ The actions are the components' own vocabulary, carried by the proxy
    // instead of by a component, so `header_up Host x` and
    // `RequestHeader(.set("Host", "x"))` mean the same thing.
    let native = crate::compile(
        r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
            Proxy(
                to: "127.0.0.1:9000",
                headersUp: [.set("Host", "app.internal"), .remove("Cookie"), .replace("X-Trace", pattern: "f(.)o", with: "b$1r")],
                headersDown: [.append("X-Served-By", "pingclair"), .setIfAbsent("X-Def", "1"), .remove("Server")]
            )
        } } }"#,
    )
    .unwrap();
    let legacy = crate::compile(
        "http://:8080 {\n\treverse_proxy 127.0.0.1:9000 {\n\t\theader_up Host app.internal\n\t\theader_up -Cookie\n\t\theader_up X-Trace f(.)o b$1r\n\t\theader_down +X-Served-By pingclair\n\t\theader_down ?X-Def 1\n\t\theader_down -Server\n\t}\n}",
    )
    .unwrap();
    assert_eq!(twin(native), twin(legacy));
}

/// 🧱 Every `reverse_proxy` runtime knob that used to be Caddyfile-only now
/// has a spelling, and it lowers to exactly the same configuration.
#[test]
fn the_remaining_proxy_knobs_lower_like_their_caddyfile_twins() {
    let cases: [(&str, &str); 3] = [
        (
            r#"Proxy(to: "127.0.0.1:9000").buffers(request: .mebibytes(4), response: .unlimited)"#,
            "reverse_proxy 127.0.0.1:9000 {\n\t\trequest_buffers 4MiB\n\t\tresponse_buffers unlimited\n\t}",
        ),
        (
            r#"Proxy(to: "127.0.0.1:9000").overload(maxInFlight: 100, maxPending: 50, pendingTimeout: .seconds(1), upstreamMaxConnections: 10)"#,
            "reverse_proxy 127.0.0.1:9000 {\n\t\toverload {\n\t\t\tmax_in_flight 100\n\t\t\tmax_pending 50\n\t\t\tpending_timeout 1s\n\t\t\tupstream_max_connections 10\n\t\t}\n\t}",
        ),
        (
            r#"Proxy(to: "127.0.0.1:9000").circuitBreaker(consecutiveFailures: 5, errorRatePercent: 50, minimumRequests: 20, windowRequests: 100, openFor: .seconds(30), halfOpenRequests: 2, failureStatuses: [503, 502])"#,
            "reverse_proxy 127.0.0.1:9000 {\n\t\tcircuit_breaker {\n\t\t\tconsecutive_failures 5\n\t\t\terror_rate_percent 50\n\t\t\tminimum_requests 20\n\t\t\twindow_requests 100\n\t\t\topen_for 30s\n\t\t\thalf_open_requests 2\n\t\t\tfailure_statuses 503 502\n\t\t}\n\t}",
        ),
    ];
    for (handler, legacy_body) in cases {
        let native = crate::compile(&format!(
            "HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ {handler} }} }} }}"
        ))
        .unwrap();
        let legacy = crate::compile(&format!("http://:8080 {{\n\t{legacy_body}\n}}")).unwrap();
        assert_eq!(twin(native), twin(legacy), "{handler}");
    }
}

#[test]
fn the_remaining_proxy_knob_mistakes_fail_closed() {
    let site = |handler: &str| {
        format!(
            "HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ {handler} }} }} }}"
        )
    };
    for handler in [
        r#"Proxy(to: "127.0.0.1:9000").buffers()"#,
        r#"Proxy(to: "127.0.0.1:9000").buffers(request: 0)"#,
        r#"Proxy(to: "127.0.0.1:9000").buffers(request: .seconds(1))"#,
        r#"Proxy(to: "127.0.0.1:9000").buffers(unknown: .mebibytes(1))"#,
        r#"Proxy(to: "127.0.0.1:9000").overload()"#,
        r#"Proxy(to: "127.0.0.1:9000").overload(pendingTimeout: .seconds(1))"#,
        r#"Proxy(to: "127.0.0.1:9000").overload(maxInFlight: 0)"#,
        r#"Proxy(to: "127.0.0.1:9000").circuitBreaker()"#,
        r#"Proxy(to: "127.0.0.1:9000").circuitBreaker(minimumRequests: 10)"#,
        r#"Proxy(to: "127.0.0.1:9000").circuitBreaker(errorRatePercent: 101)"#,
        r#"Proxy(to: "127.0.0.1:9000").circuitBreaker(consecutiveFailures: 5, failureStatuses: [])"#,
        r#"Proxy(to: "127.0.0.1:9000").circuitBreaker(consecutiveFailures: 5, failureStatuses: [200])"#,
        r#"Proxy(to: "127.0.0.1:9000").circuitBreaker(consecutiveFailures: 0)"#,
    ] {
        let source = site(handler);
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
}

/// 🌐 `dynamic:` lowers exactly like the Caddyfile's `dynamic` directive.
#[test]
fn proxy_dynamic_upstreams_lower_like_their_caddyfile_twins() {
    let native = crate::compile(
        r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
            Proxy(dynamic: .a("backend.internal", port: 8080, refresh: .seconds(30), resolvers: ["1.1.1.1"], dialTimeout: .seconds(2), versions: .ipv4))
        } } }"#,
    )
    .unwrap();
    let legacy = crate::compile(
        "http://:8080 {\n\treverse_proxy {\n\t\tdynamic a backend.internal 8080 {\n\t\t\trefresh 30s\n\t\t\tresolvers 1.1.1.1\n\t\t\tdial_timeout 2s\n\t\t\tversions ipv4\n\t\t}\n\t}\n}",
    )
    .unwrap();
    assert_eq!(twin(native), twin(legacy));

    let native = crate::compile(
        r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
            Proxy(dynamic: .srv("example.com", service: "https", proto: .tcp, grace: .seconds(30)))
        } } }"#,
    )
    .unwrap();
    let legacy = crate::compile(
        "http://:8080 {\n\treverse_proxy {\n\t\tdynamic srv example.com {\n\t\t\tservice https\n\t\t\tproto tcp\n\t\t\tgrace_period 30s\n\t\t}\n\t}\n}",
    )
    .unwrap();
    assert_eq!(twin(native), twin(legacy));
}

#[test]
fn proxy_dynamic_mistakes_fail_closed() {
    let site = |handler: &str| {
        format!(
            "HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ {handler} }} }} }}"
        )
    };
    for handler in [
        "Proxy()",
        "Proxy(to: \"127.0.0.1:9000\", dynamic: .a(\"x\", port: 80))",
        "Proxy(dynamic: \"x\")",
        "Proxy(dynamic: .b(\"x\"))",
        "Proxy(dynamic: .a(\"x\"))",
        "Proxy(dynamic: .a(port: 80))",
        "Proxy(dynamic: .a(\"x\", port: 0))",
        "Proxy(dynamic: .a(\"x\", port: 80, refresh: .seconds(0)))",
        "Proxy(dynamic: .a(\"x\", port: 80, resolvers: []))",
        "Proxy(dynamic: .a(\"x\", port: 80, versions: .ip))",
        "Proxy(dynamic: .a(\"x\", port: 80, unknown: 1))",
        "Proxy(dynamic: .srv(\"x\", service: \"https\"))",
        "Proxy(dynamic: .srv(\"x\", proto: .tcp))",
        "Proxy(dynamic: .srv(\"x\", unknown: 1))",
    ] {
        let source = site(handler);
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
}

/// 🗄️ `.cache(...)` lowers exactly like the Caddyfile's `cache` block.
#[test]
fn proxy_cache_lowers_like_its_caddyfile_twin() {
    let native = crate::compile(
        r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
            Proxy(to: "127.0.0.1:9000").cache(ttl: .seconds(30), maxSize: .mebibytes(128))
        } } }"#,
    )
    .unwrap();
    let legacy = crate::compile(
        "http://:8080 {\n\treverse_proxy 127.0.0.1:9000 {\n\t\tcache {\n\t\t\tttl 30s\n\t\t\tmax_size 134217728\n\t\t}\n\t}\n}",
    )
    .unwrap();
    assert_eq!(twin(native), twin(legacy));

    // 📏 The ceiling defaults in `pingclair-core`, so the two spellings can
    // never drift to different numbers.
    let native = crate::compile(
        r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
            Proxy(to: "127.0.0.1:9000").cache(ttl: .seconds(30))
        } } }"#,
    )
    .unwrap();
    let legacy = crate::compile(
        "http://:8080 {\n\treverse_proxy 127.0.0.1:9000 {\n\t\tcache {\n\t\t\tttl 30s\n\t\t}\n\t}\n}",
    )
    .unwrap();
    assert_eq!(twin(native), twin(legacy));
}

#[test]
fn proxy_cache_mistakes_fail_closed() {
    let site = |modifier: &str| {
        format!(
            "HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ Proxy(to: \"127.0.0.1:9000\"){modifier} }} }} }}"
        )
    };
    for modifier in [
        ".cache()",
        ".cache(maxSize: .mebibytes(1))",
        ".cache(ttl: 30)",
        ".cache(ttl: .seconds(0))",
        ".cache(ttl: .seconds(1.5))",
        ".cache(ttl: .seconds(30), maxSize: 0)",
        ".cache(ttl: .seconds(30), maxSize: .bytes(0))",
        ".cache(ttl: .seconds(30), unknown: 1)",
        ".cache(ttl: .seconds(30)).cache(ttl: .seconds(60))",
    ] {
        let source = site(modifier);
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn proxy_header_lists_that_cannot_mean_anything_fail_closed() {
    let site = |handler: &str| {
        format!(
            "HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ {handler} }} }} }}"
        )
    };
    for handler in [
        // 🏷️ The lists are arrays of actions, and they are not empty.
        "Proxy(to: \"127.0.0.1:9000\", headersUp: [])",
        "Proxy(to: \"127.0.0.1:9000\", headersUp: \".set(\\\"X\\\", \\\"1\\\")\")",
        "Proxy(to: \"127.0.0.1:9000\", headersUp: [.unknown(\"X\")])",
        // ❓ The request side has nothing to inspect, so `setIfAbsent` is a
        // response action on the downstream half only.
        "Proxy(to: \"127.0.0.1:9000\", headersUp: [.setIfAbsent(\"X-Def\", \"1\")])",
        // 🚫 And the shared rules still hold: one field, one `.set`.
        "Proxy(to: \"127.0.0.1:9000\", headersUp: [.set(\"X\", \"1\"), .set(\"X\", \"2\")])",
        "Proxy(to: \"127.0.0.1:9000\", headersDown: [.replace(\"X-Rep\", pattern: \"f(.)o\")])",
        "Proxy(to: \"127.0.0.1:9000\", headersDown: [.remove()])",
    ] {
        let source = site(handler);
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn retry_max_attempts_is_spellable_and_bounded() {
    let native = crate::compile(
        r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
            Proxy(to: ["127.0.0.1:9000", "127.0.0.1:9001"]).retry(maxAttempts: 2)
        } } }"#,
    )
    .unwrap();
    let legacy = crate::compile(
        "http://:8080 {\n\treverse_proxy 127.0.0.1:9000 127.0.0.1:9001 {\n\t\tretry {\n\t\t\tmax_attempts 2\n\t\t}\n\t}\n}",
    )
    .unwrap();
    assert_eq!(twin(native), twin(legacy));

    // 🧱 The range is the same one the shared validation enforces (1..=16),
    // refused here so the message carries the line the operator wrote.
    for setting in [
        "maxAttempts: 0",
        "maxAttempts: 17",
        "maxAttempts: .seconds(1)",
    ] {
        assert!(
            crate::compile(&format!(
                r#"HTTPListener(on: ":8080") {{ Site(host: "*") {{ Fallback {{
                    Proxy(to: "127.0.0.1:9000").retry({setting})
                }} }} }}"#
            ))
            .is_err(),
            "accepted {setting}"
        );
    }
}

#[test]
fn proxy_balance_health_and_timeouts_lower_like_their_caddyfile_twins() {
    let cases = [
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                Proxy(to: ["127.0.0.1:9000", "127.0.0.1:9001"])
                .loadBalance(.leastConn)
                .retry(tryDuration: .seconds(3), tryInterval: .milliseconds(250), maxFails: 3, failDuration: .seconds(30))
                .flush(.immediate)
                .timeouts(connect: .seconds(5), firstByte: .seconds(30), betweenReads: .seconds(30), read: .minutes(5), write: .minutes(5))
            } } }"#
                .to_string(),
            "http://:8080 {\n\treverse_proxy 127.0.0.1:9000 127.0.0.1:9001 {\n\t\tlb_policy least_conn\n\t\tlb_try_duration 3s\n\t\tlb_try_interval 250ms\n\t\tmax_fails 3\n\t\tfail_duration 30s\n\t\tflush_interval -1\n\t\ttransport http {\n\t\t\tdial_timeout 5s\n\t\t\tresponse_header_timeout 30s\n\t\t\tbetween_reads_timeout 30s\n\t\t\tread_timeout 5m\n\t\t\twrite_timeout 5m\n\t\t}\n\t}\n}"
                .to_string(),
        ),
        (
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                Proxy(to: ["127.0.0.1:9000", "127.0.0.1:9001"]).loadBalance(.cookie("session"))
            } } }"#
                .to_string(),
            "http://:8080 {\n\treverse_proxy 127.0.0.1:9000 127.0.0.1:9001 {\n\t\tlb_policy cookie session\n\t}\n}"
                .to_string(),
        ),
        (
            // ⚖️ The weight travels with its address.
            r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
                Proxy(to: [.upstream("127.0.0.1:9000", weight: 3), .upstream("127.0.0.1:9001")])
            } } }"#
                .to_string(),
            "http://:8080 {\n\treverse_proxy 127.0.0.1:9000 127.0.0.1:9001 {\n\t\tlb_policy weighted_round_robin 3 1\n\t}\n}"
                .to_string(),
        ),
    ];
    for (native_source, legacy_source) in cases {
        let native = crate::compile(&native_source).unwrap();
        let legacy = crate::compile(&legacy_source).unwrap();
        assert_eq!(twin(native), twin(legacy), "{native_source}");
    }
}

#[test]
fn proxy_tuning_that_cannot_mean_anything_fail_closed() {
    let site = |handler: &str| {
        format!(
            "HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ {handler} }} }} }}"
        )
    };
    for handler in [
        // 🎛️ Policies are typed values, and the hashing ones name a field.
        "Proxy(to: \"127.0.0.1:9000\").loadBalance(\"least_conn\")",
        "Proxy(to: \"127.0.0.1:9000\").loadBalance(.least_conn)",
        "Proxy(to: \"127.0.0.1:9000\").loadBalance(.cookie)",
        "Proxy(to: \"127.0.0.1:9000\").loadBalance(.ipHash(\"X-User\"))",
        // ⚖️ Weights live on the upstream value: positive, and round-robin's own.
        "Proxy(to: [.upstream(\"127.0.0.1:9000\", weight: 0)])",
        "Proxy(to: [.upstream(\"127.0.0.1:9000\", weight: \"2\")])",
        "Proxy(to: [.upstream(\"127.0.0.1:9000\"), \"127.0.0.1:9001\"])",
        "Proxy(to: [.member(\"127.0.0.1:9000\")])",
        "Proxy(to: [.upstream(\"127.0.0.1:9000\", backup: 1)])",
        "Proxy(to: [.upstream(\"127.0.0.1:9000\", weight: 2)]).loadBalance(.leastConn)",
        // ⏱️ Every deadline is a duration, not a bare number.
        "Proxy(to: \"127.0.0.1:9000\").retry(tryInterval: 250)",
        "Proxy(to: \"127.0.0.1:9000\").retry(tryDuration: 3)",
        "Proxy(to: \"127.0.0.1:9000\").timeouts(connect: 5)",
        "Proxy(to: \"127.0.0.1:9000\").timeouts(read: \"30s\")",
        "Proxy(to: \"127.0.0.1:9000\").retry(maxFails: \"3\")",
        "Proxy(to: \"127.0.0.1:9000\").retry(failDuration: 30)",
        "Proxy(to: \"127.0.0.1:9000\").flush(1)",
        "Proxy(to: \"127.0.0.1:9000\").flush(.unknown)",
        // 🚫 The modifiers are a closed set, once each, and Proxy takes no block.
        "Proxy(to: \"127.0.0.1:9000\").unknown(1)",
        "Proxy(to: \"127.0.0.1:9000\").loadBalance(.leastConn).loadBalance(.random)",
        "Proxy(to: \"127.0.0.1:9000\") { respond \"x\" }",
        "Proxy(to: \"127.0.0.1:9000\").timeouts()",
        "Proxy(to: \"127.0.0.1:9000\").retry()",
    ] {
        let source = site(handler);
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn proxy_health_checks_and_versions_lower_like_their_caddyfile_twins() {
    let native = crate::compile(
        r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
            Proxy(to: "127.0.0.1:9000")
            .versions(.h2)
            .healthCheck(.http(
                path: "/healthz",
                port: 8080,
                interval: .seconds(10),
                timeout: .seconds(2),
                passes: 2,
                fails: 3,
                status: [.success],
                body: "ready",
                headers: [.append("X-Probe", "1"), .append("X-Probe", "2")]
            ))
        } } }"#,
    )
    .unwrap();
    let legacy = crate::compile(
        "http://:8080 {\n\treverse_proxy 127.0.0.1:9000 {\n\t\thealth_uri /healthz\n\t\thealth_port 8080\n\t\thealth_interval 10s\n\t\thealth_timeout 2s\n\t\thealth_passes 2\n\t\thealth_fails 3\n\t\thealth_status 2xx\n\t\thealth_body ready\n\t\thealth_headers {\n\t\t\tX-Probe 1\n\t\t\tX-Probe 2\n\t\t}\n\t\ttransport http {\n\t\t\tversions 2\n\t\t}\n\t}\n}",
    )
    .unwrap();
    assert_eq!(twin(native), twin(legacy));
}

#[test]
fn health_checks_that_cannot_mean_anything_fail_closed() {
    let site = |handler: &str| {
        format!(
            "HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ {handler} }} }} }}"
        )
    };
    for handler in [
        "Proxy(to: \"127.0.0.1:9000\").healthCheck(\"/healthz\")",
        "Proxy(to: \"127.0.0.1:9000\").healthCheck(.tcp(path: \"/x\"))",
        "Proxy(to: \"127.0.0.1:9000\").healthCheck(.http())",
        "Proxy(to: \"127.0.0.1:9000\").healthCheck(.http(path: \"/x\", unknown: 1))",
        // 🚫 A probe only reads.
        "Proxy(to: \"127.0.0.1:9000\").healthCheck(.http(path: \"/x\", method: .post))",
        "Proxy(to: \"127.0.0.1:9000\").healthCheck(.http(path: \"/x\", interval: .milliseconds(500)))",
        "Proxy(to: \"127.0.0.1:9000\").healthCheck(.http(path: \"/x\", timeout: 5))",
        "Proxy(to: \"127.0.0.1:9000\").healthCheck(.http(path: \"/x\", passes: 0))",
        "Proxy(to: \"127.0.0.1:9000\").healthCheck(.http(path: \"/x\", fails: 0))",
        "Proxy(to: \"127.0.0.1:9000\").healthCheck(.http(path: \"/x\", port: 70000))",
        "Proxy(to: \"127.0.0.1:9000\").healthCheck(.http(path: \"/x\", status: []))",
        "Proxy(to: \"127.0.0.1:9000\").healthCheck(.http(path: \"/x\", status: [.unknown]))",
        "Proxy(to: \"127.0.0.1:9000\").healthCheck(.http(path: \"/x\", status: 200))",
        "Proxy(to: \"127.0.0.1:9000\").healthCheck(.http(path: \"/x\", headers: []))",
        "Proxy(to: \"127.0.0.1:9000\").healthCheck(.http(path: \"/x\", headers: [.remove(\"X\")]))",
        "Proxy(to: \"127.0.0.1:9000\").versions(\"2\")",
        "Proxy(to: \"127.0.0.1:9000\").versions(.http3)",
        "Proxy(to: \"127.0.0.1:9000\").versions(.h2(1))",
    ] {
        let source = site(handler);
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn upstream_tls_lowers_like_its_caddyfile_twin() {
    let native = crate::compile(
        r#"HTTPListener(on: ":8080") { Site(host: "*") { Fallback {
            Proxy(to: "https://10.0.0.10:8443")
            .upstreamTLS(.enabled(
                serverName: "app.internal",
                trustedCACerts: ["./ca.pem"],
                clientCert: "./c.pem",
                clientKey: "./k.pem"
            ))
        } } }"#,
    )
    .unwrap();
    let legacy = crate::compile(
        "http://:8080 {\n\treverse_proxy https://10.0.0.10:8443 {\n\t\ttransport http {\n\t\t\ttls\n\t\t\ttls_server_name app.internal\n\t\t\ttls_trusted_ca_certs ./ca.pem\n\t\t\ttls_client_auth ./c.pem ./k.pem\n\t\t}\n\t}\n}",
    )
    .unwrap();
    assert_eq!(twin(native), twin(legacy));
}

#[test]
fn upstream_tls_that_cannot_mean_anything_fail_closed() {
    let site = |handler: &str| {
        format!(
            "HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ {handler} }} }} }}"
        )
    };
    for handler in [
        "Proxy(to: \"127.0.0.1:9000\").upstreamTLS(\"enabled\")",
        "Proxy(to: \"127.0.0.1:9000\").upstreamTLS(.disabled)",
        "Proxy(to: \"127.0.0.1:9000\").upstreamTLS(.enabled(unknown: 1))",
        "Proxy(to: \"127.0.0.1:9000\").upstreamTLS(.enabled(clientCert: \"./c.pem\"))",
        "Proxy(to: \"127.0.0.1:9000\").upstreamTLS(.enabled(clientKey: \"./k.pem\"))",
        "Proxy(to: \"127.0.0.1:9000\").upstreamTLS(.enabled(trustedCACerts: [\"./ca.pem\"], insecureSkipVerify: true))",
        "Proxy(to: \"127.0.0.1:9000\").upstreamTLS(.enabled(trustedCACerts: \"./ca.pem\"))",
        "Proxy(to: \"127.0.0.1:9000\").upstreamTLS(.enabled(serverName: 1))",
        "Proxy(to: \"127.0.0.1:9000\").upstreamTLS(.enabled(insecureSkipVerify: 1))",
    ] {
        let source = site(handler);
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
    // 📌 A bare `.enabled` is the Caddyfile's bare `tls`.
    crate::compile(&site(
        "Proxy(to: \"https://10.0.0.10:8443\").upstreamTLS(.enabled)",
    ))
    .unwrap();
}

#[test]
fn a_secret_value_cannot_reach_the_configuration_yet() {
    // 🔐 The attribute promises "never shown". Until a field exists that can
    // *hold* a secret, every use of one would be written into the
    // configuration, the admin JSON and any log that dumps either — so the
    // use is refused, and the refusal does not repeat the value.
    const SENTINEL: &str = "review-sentinel-not-a-real-secret";
    let shapes = [
        format!(
            "@Secret\nlet token = \"{SENTINEL}\"\nHTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ Proxy(to: \"127.0.0.1:9000\", headersUp: [.set(\"X-Review\", token)]) }} }} }}\n"
        ),
        format!(
            "@Secret\nlet headers = [.set(\"X-Review\", \"{SENTINEL}\")]\nHTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ Proxy(to: \"127.0.0.1:9000\", headersUp: headers) }} }} }}\n"
        ),
        format!(
            "@Secret\nlet token = \"{SENTINEL}\"\nlet alias = token\nHTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ Proxy(to: \"127.0.0.1:9000\", headersUp: [.set(\"X-Review\", alias)]) }} }} }}\n"
        ),
        // 🏛️ A component binding carries the mark too: the refusal happens at
        // the use, wherever the value was stored on the way there.
        format!(
            "@Secret\nlet token = \"{SENTINEL}\"\nlet site = Site(host: \"*\") {{ Fallback {{ Proxy(to: \"127.0.0.1:9000\", headersUp: [.set(\"X-Review\", token)]) }} }}\nHTTPListener(on: \":8080\") {{ site }}\n"
        ),
    ];
    for source in shapes {
        let error = crate::compile(&source)
            .expect_err("a used @Secret value must be refused")
            .to_string();
        assert!(
            !error.contains(SENTINEL),
            "the refusal repeated the secret: {error}"
        );
        assert!(error.contains("@Secret"), "{error}");
        assert!(error.contains("line "), "{error}");
    }
    // 📌 Declaring one and using it for nothing is still allowed: the
    // attribute marks a value, and finding unused declarations is a lint, not
    // a load error.
    crate::compile(&format!(
        "@Secret\nlet token = \"{SENTINEL}\"\nHTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ Respond(body: \"ok\") }} }} }}\n"
    ))
    .unwrap();
    // 🚫 And a condition cannot be a secret at all.
    assert!(
        crate::compile(&format!(
            "@Matcher\nlet cond = .path(exact: \"/a\")\n@Secret\nlet token = \"{SENTINEL}\"\nHTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Route(when: token) {{ Respond(body: \"ok\") }} }} }}\n"
        ))
        .is_err()
    );
}

#[test]
fn a_step_that_may_answer_is_not_a_dead_end() {
    // 🅿️ `ServeFiles(passThru: true)` answers when the file exists and hands
    // the request on when it does not, so what follows it is reachable — the
    // review found the Caddyfile accepted this shape while the native language
    // refused it. Three readings, one per control-flow kind.
    let site = |body: &str| {
        format!("HTTPListener(on: \":8080\") {{ Site(host: \"*\") {{ Fallback {{ {body} }} }} }}")
    };
    // ➡️ A step that may answer, then the thing that answers a miss.
    crate::compile(&site(
        "ServeFiles(root: \"./public\", passThru: true) Respond(body: \"fallback\")",
    ))
    .unwrap();
    // ➡️ …and a route may end there: a miss is answered by whatever the site
    // does with an unanswered request.
    crate::compile(&site("ServeFiles(root: \"./public\", passThru: true)")).unwrap();
    // 🐘 The same reading covers the FastCGI expansion, which is why it no
    // longer needs a rule of its own.
    crate::compile(&site("PHPFastCGI(to: \"127.0.0.1:9000\")")).unwrap();
    // 📌 An explicit `passThru: false` is the always-answering file server,
    // which is a perfectly good way to end a route.
    crate::compile(&site("ServeFiles(root: \"./public\", passThru: false)")).unwrap();
    // 🚫 Something that always answers still ends the route, and middleware
    // alone still does not.
    for body in [
        "Respond(body: \"x\") ServeFiles(root: \"./public\", passThru: true)",
        "Respond(body: \"x\") Respond(body: \"y\")",
        "RequestHeader(.set(\"X-A\", \"1\"))",
    ] {
        let source = site(body);
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
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
