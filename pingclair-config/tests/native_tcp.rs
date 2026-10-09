// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔌 The native TCP surface follows the language RFC, independently of Caddyfile spelling.

fn listener(route: &str, modifiers: &str) -> String {
    format!(r#"TCPListener(on: "127.0.0.1:19443") {{ {route} }} {modifiers}"#)
}

#[test]
fn tcp_limits_use_the_same_connection_label_as_http() {
    let source = listener(
        r#"Fallback { Proxy(to: "127.0.0.1:18443") }"#,
        ".limits(maxConnections: 7, preread: .kibibytes(8), relay: .kibibytes(32))",
    );
    let config = pingclair_config::compile(&source).unwrap();
    let mut expected = pingclair_core::config::Layer4Server::new("127.0.0.1:19443".into());
    expected.max_connections = 7;
    expected.preread_buffer_size = 8192;
    expected.proxy_buffer_size = 32768;
    expected.routes = vec![pingclair_core::config::Layer4Route {
        matches: vec![],
        upstream: "127.0.0.1:18443".into(),
    }];
    assert_eq!(config.layer4, vec![expected]);
    assert!(pingclair_config::compile(&source.replace("maxConnections:", "connections:")).is_err());
}

#[test]
fn tcp_source_addresses_are_typed_matcher_values() {
    let inline = listener(
        r#"Route(when: .from(["127.0.0.0/8", "::1/128"])) { Proxy(to: "127.0.0.1:18443") }"#,
        "",
    );
    let bound = format!(
        "@Matcher\nlet local = .from([\"127.0.0.0/8\", \"::1/128\"])\n{}",
        inline.replace(".from([\"127.0.0.0/8\", \"::1/128\"])", "local")
    );
    let config = pingclair_config::compile(&inline).unwrap();
    assert_eq!(
        serde_json::to_value(&config).unwrap(),
        serde_json::to_value(pingclair_config::compile(&bound).unwrap()).unwrap()
    );
    assert_eq!(
        config.layer4[0].routes[0].matches[0].remote_ip,
        ["127.0.0.0/8", "::1/128"]
    );
    assert!(pingclair_config::compile(&bound.replace("@Matcher\n", "")).is_err());
    for condition in [
        ".from([])",
        ".from([true])",
        ".from([\"bad CIDR\"])",
        ".from(ranges: [\"127.0.0.1\"])",
    ] {
        assert!(
            pingclair_config::compile(
                &inline.replace(".from([\"127.0.0.0/8\", \"::1/128\"])", condition)
            )
            .is_err()
        );
    }
}

#[test]
fn tcp_catalogue_reports_the_arguments_the_parser_accepts() {
    let catalogue: serde_json::Value = serde_json::from_str(
        &pingclair_config::describe::render_json(Some("TCPListener")).unwrap(),
    )
    .unwrap();
    assert_eq!(catalogue["entries"][0]["labels"], serde_json::json!(["on"]));
    for name in ["limits", "timeouts", "halfClose"] {
        let catalogue: serde_json::Value =
            serde_json::from_str(&pingclair_config::describe::render_json(Some(name)).unwrap())
                .unwrap();
        assert!(
            !catalogue["entries"][0]["labels"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{name}"
        );
    }
}

#[test]
fn tcp_condition_composition_preserves_and_or_semantics() {
    let legacy = pingclair_config::compile(
        r#"{
    layer4 {
        127.0.0.1:19443 {
            @secure {
                tls sni example.test
                remote_ip 127.0.0.0/8
            }
            @local remote_ip ::1/128
            route @secure @local {
                proxy 127.0.0.1:18443
            }
        }
    }
}"#,
    )
    .unwrap();
    for conjunction in [
        r#".all([.tls(sni: ["example.test"]), .from(["127.0.0.0/8"])])"#,
        r#".all([.from(["127.0.0.0/8"]), .tls(sni: ["example.test"])])"#,
    ] {
        let source = listener(
            &format!(
                r#"Route(when: .any([{conjunction}, .from(["::1/128"])])) {{ Proxy(to: "127.0.0.1:18443") }}"#
            ),
            "",
        );
        assert_eq!(
            pingclair_config::compile(&source).unwrap().layer4,
            legacy.layer4
        );
        assert_eq!(
            pingclair_config::compile(&pingclair_config::format::format(&source).unwrap())
                .unwrap()
                .layer4,
            legacy.layer4
        );
    }
    for condition in [
        ".all([])",
        ".any([])",
        ".all([.tls(), .tls()])",
        r#".all([.from(["127.0.0.1"]), .from(["::1"])])"#,
    ] {
        let source = listener(
            &format!(r#"Route(when: {condition}) {{ Proxy(to: "127.0.0.1:18443") }}"#),
            "",
        );
        assert!(pingclair_config::compile(&source).is_err(), "{condition}");
    }
}

#[test]
fn tcp_condition_cross_products_have_a_load_time_ceiling() {
    let names = std::iter::repeat_n(r#".tls(sni: ["example.test"])"#, 65)
        .collect::<Vec<_>>()
        .join(", ");
    let peers = std::iter::repeat_n(r#".from(["127.0.0.0/8"])"#, 65)
        .collect::<Vec<_>>()
        .join(", ");
    let source = listener(
        &format!(
            r#"Route(when: .all([.any([{names}]), .any([{peers}])])) {{ Proxy(to: "127.0.0.1:18443") }}"#
        ),
        "",
    );
    assert!(
        pingclair_config::compile(&source)
            .unwrap_err()
            .to_string()
            .contains("4096 matcher sets")
    );
}
