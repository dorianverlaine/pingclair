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
            .limits(connections: 8) {
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
    assert_eq!(
        serde_json::to_value(native).unwrap(),
        serde_json::to_value(legacy).unwrap()
    );
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
    assert_eq!(
        serde_json::to_value(native).unwrap(),
        serde_json::to_value(legacy).unwrap()
    );
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
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { ServeFiles(root: \"./pub\") } } }",
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
    assert_eq!(
        serde_json::to_value(native).unwrap(),
        serde_json::to_value(legacy).unwrap()
    );
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
    assert_eq!(
        serde_json::to_value(native).unwrap(),
        serde_json::to_value(legacy).unwrap()
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
    assert_eq!(
        serde_json::to_value(native).unwrap(),
        serde_json::to_value(legacy).unwrap()
    );
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
        assert_eq!(
            serde_json::to_value(native).unwrap(),
            serde_json::to_value(legacy).unwrap(),
            "{native_source}"
        );
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
    assert_eq!(
        serde_json::to_value(native).unwrap(),
        serde_json::to_value(legacy).unwrap()
    );

    let bare_native = crate::compile(
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Respond(body: \"hi\") } } }.accessLog()",
    )
    .unwrap();
    let bare_legacy = crate::compile("http://:8080 {\n\tlog\n\trespond \"hi\"\n}\n").unwrap();
    assert_eq!(
        serde_json::to_value(bare_native).unwrap(),
        serde_json::to_value(bare_legacy).unwrap()
    );
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
        ".accessLog(level: .info)",
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
        assert_eq!(
            serde_json::to_value(native).unwrap(),
            serde_json::to_value(legacy).unwrap(),
            "{native_source}"
        );
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
        "Route(when: .header(name: \"X\", value: \"y\")) { Respond(body: \"m\") }",
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
