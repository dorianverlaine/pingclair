// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;
use pingclair_core::config::{Layer4Matcher, Layer4Route, Layer4Server, Layer4TlsMatcher};

const SOURCE: &str = r#"{
    layer4 {
        :9443 {
            max_connections 17
            preread_timeout 1m2s3ms
            preread_buffer_size 16k
            proxy_connect_timeout 2
            proxy_timeout 10m
            proxy_half_close on
            proxy_buffer_size 32K
            route @secure {
                proxy backend.example:443
            }
            @secure {
                tls {
                    sni EXAMPLE.test
                    alpn h2 http/1.1
                }
                remote_ip 192.0.2.0/24 ::1
            }
            route {
                proxy 127.0.0.1:8443
            }
        }
    }
}"#;

#[test]
fn layer4_adapts_complete_structure_and_round_trips_json() {
    let config = crate::adapt(SOURCE).unwrap();
    let expected = Layer4Server {
        listen: ":9443".into(),
        log: None,
        max_connections: 17,
        preread_timeout_ms: 62_003,
        preread_buffer_size: 16_384,
        proxy_connect_timeout_ms: 2_000,
        proxy_timeout_ms: 600_000,
        proxy_half_close: true,
        proxy_buffer_size: 32_768,
        routes: vec![
            Layer4Route {
                dynamic: None,
                matches: vec![Layer4Matcher {
                    tls: Some(Layer4TlsMatcher {
                        sni: vec!["EXAMPLE.test".into()],
                        alpn: vec!["h2".into(), "http/1.1".into()],
                    }),
                    remote_ip: vec!["192.0.2.0/24".into(), "::1".into()],
                }],
                upstream: "backend.example:443".into(),
            },
            Layer4Route {
                dynamic: None,
                matches: vec![],
                upstream: "127.0.0.1:8443".into(),
            },
        ],
    };
    assert_eq!(config.layer4, vec![expected]);
    validate_declarations(&config).unwrap();
    let decoded: PingclairConfig =
        serde_json::from_value(serde_json::to_value(&config).unwrap()).unwrap();
    assert_eq!(decoded.layer4, config.layer4);
    for config in [config, decoded] {
        validate(&config).unwrap();
    }
    crate::compile(SOURCE).unwrap();
}

#[test]
fn layer4_rejects_unsupported_syntax_and_ambiguous_options() {
    for (before, after, expected) in [
        (
            "preread_timeout 1m2s3ms",
            "matching_timeout 1s",
            "preread_timeout",
        ),
        ("proxy_timeout 10m", "idle_timeout 1s", "proxy_timeout"),
        (
            "proxy_timeout 10m",
            "proxy_timeout 1s2m",
            "units must decrease",
        ),
        (
            "proxy_timeout 10m",
            "proxy_timeout 18446744073709551615w",
            "overflow",
        ),
        (
            "preread_buffer_size 16k",
            "preread_buffer_size 0",
            "positive byte size",
        ),
        (
            "preread_buffer_size 16k",
            "preread_buffer_size 1.5k",
            "positive byte size",
        ),
        ("proxy_half_close on", "proxy_half_close yes", "on or off"),
        (
            "proxy_half_close on",
            "proxy_half_close on\nproxy_half_close off",
            "duplicate option",
        ),
        ("route @secure", "route @missing", "undefined matcher"),
        (
            "proxy backend.example:443",
            "proxy a:443 b:443",
            "expects 1 argument",
        ),
        ("proxy backend.example:443", "tls", "not supported"),
        ("alpn h2 http/1.1", "alpn h2\nalpn h3", "duplicate TLS"),
    ] {
        let error = crate::adapt(&SOURCE.replace(before, after))
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{after}: {error}");
    }
}

#[test]
fn layer4_json_cannot_bypass_policy_validation() {
    let value = serde_json::to_value(crate::adapt(SOURCE).unwrap()).unwrap();
    for (pointer, replacement, expected) in [
        (
            "/layer4/0/preread_buffer_size",
            serde_json::json!(0),
            "nonzero",
        ),
        (
            "/layer4/0/proxy_buffer_size",
            serde_json::json!(0),
            "nonzero",
        ),
        (
            "/layer4/0/proxy_timeout_ms",
            serde_json::json!(u64::MAX),
            "timer range",
        ),
        (
            "/layer4/0/routes/0/matches/0/remote_ip/0",
            serde_json::json!("10.0.0.0/99"),
            "CIDR",
        ),
        (
            "/layer4/0/routes/0/matches/0/tls/sni/0",
            serde_json::json!("*.test"),
            "exact ASCII",
        ),
        (
            "/layer4/0/routes/0/upstream",
            serde_json::json!("http://example:443"),
            "host:port",
        ),
        (
            "/layer4/0/routes/0/matches",
            serde_json::json!([]),
            "must be last",
        ),
        (
            "/layer4/0/listen",
            serde_json::json!("udp/:9443"),
            "IP address",
        ),
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        let config: PingclairConfig = serde_json::from_value(changed).unwrap();
        let error = crate::compiler::validate_config(&config)
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{pointer}: {error}");
    }
    for pointer in [
        "/layer4/0",
        "/layer4/0/routes/0",
        "/layer4/0/routes/0/matches/0",
        "/layer4/0/routes/0/matches/0/tls",
    ] {
        let mut changed = value.clone();
        changed
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("typo".into(), true.into());
        assert!(
            serde_json::from_value::<PingclairConfig>(changed).is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn layer4_detects_overlapping_http_and_tcp_listeners() {
    for (l4, http, overlaps) in [
        (":9443", "127.0.0.1:9443", true),
        ("127.0.0.1:9443", ":9443", true),
        ("0.0.0.0:9443", "127.0.0.1:9443", true),
        ("127.0.0.1:9443", "127.0.0.1:9443", true),
        ("127.0.0.1:9443", "127.0.0.2:9443", false),
        ("0.0.0.0:9443", "[::1]:9443", false),
        (":9443", ":8443", false),
    ] {
        let mut config = crate::adapt(&SOURCE.replace(":9443", l4)).unwrap();
        config.servers = crate::adapt(&format!("http://{http} {{\nrespond ok\n}} "))
            .unwrap()
            .servers;
        assert_eq!(
            validate_declarations(&config).is_err(),
            overlaps,
            "{l4} / {http}"
        );
        config.servers.clear();
        let mut second = config.layer4[0].clone();
        second.listen = http.into();
        config.layer4.push(second);
        assert_eq!(
            validate_declarations(&config).is_err(),
            overlaps,
            "{l4} / {http}"
        );
    }
}

#[test]
fn layer4_shorthand_and_alternative_matchers_keep_their_meaning() {
    let source = SOURCE.replace(
        "route @secure",
        "@bare tls\n@named tls sni example.test\nroute @bare @named",
    );
    let config = crate::adapt(&source).unwrap();
    assert_eq!(
        config.layer4[0].routes[0].matches,
        vec![
            Layer4Matcher {
                tls: Some(Layer4TlsMatcher::default()),
                remote_ip: vec![]
            },
            Layer4Matcher {
                tls: Some(Layer4TlsMatcher {
                    sni: vec!["example.test".into()],
                    alpn: vec![]
                }),
                remote_ip: vec![]
            },
        ]
    );
}

#[test]
fn layer4_directory_merge_preserves_every_listener() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("a.json"),
        serde_json::to_vec(&crate::adapt(SOURCE).unwrap()).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("b.caddyfile"),
        SOURCE.replace(":9443", ":9444"),
    )
    .unwrap();
    let config = crate::adapt_directory(dir.path()).unwrap();
    assert_eq!(
        config
            .layer4
            .iter()
            .map(|s| s.listen.as_str())
            .collect::<Vec<_>>(),
        vec![":9443", ":9444"]
    );
    crate::compile_directory(dir.path()).unwrap();
}

#[test]
fn layer4_overlap_checks_use_effective_bind_and_admin_addresses() {
    let mut config = crate::adapt(&SOURCE.replace(":9443", "127.0.0.1:9443")).unwrap();
    config.servers = crate::adapt("http://:9443 {\n respond ok\n}")
        .unwrap()
        .servers;
    config.servers[0].bind = Some("127.0.0.2".into());
    validate(&config).unwrap();
    config.servers[0].bind = Some("127.0.0.1".into());
    assert!(
        validate(&config)
            .unwrap_err()
            .to_string()
            .contains("overlaps")
    );
    config.servers[0].bind = None;
    config.global.default_bind = vec!["127.0.0.2".into()];
    validate(&config).unwrap();
    config.servers.clear();
    config.admin = crate::adapt("{\n admin 127.0.0.1:2019\n}").unwrap().admin;
    let admin = config.admin.as_mut().unwrap();
    admin.enabled = true;
    admin.listen = "127.0.0.1:9443".into();
    assert!(
        validate(&config)
            .unwrap_err()
            .to_string()
            .contains("overlaps")
    );
}

#[test]
fn layer4_logging_uses_the_existing_dialect_and_common_validation() {
    let source = SOURCE.replace(
        "proxy_timeout 10m",
        "log {\n output file /tmp/l4-test.log\n format json\n}\nproxy_timeout 10m",
    );
    let config = crate::compile(&source).unwrap();
    let log = config.layer4[0].log.as_ref().unwrap();
    assert!(matches!(
        log.format,
        pingclair_core::config::LogFormat::Json
    ));
    assert!(
        matches!(&log.output, pingclair_core::config::LogOutput::File(path) if path == "/tmp/l4-test.log")
    );
    for field in [
        "request_headers",
        "response_headers",
        "hostnames",
        "include_tls",
        "level",
        "sampling",
    ] {
        let mut document = serde_json::to_value(&config).unwrap();
        document["layer4"][0]["log"][field] = match field {
            "include_tls" => serde_json::json!(true),
            "level" => serde_json::json!("debug"),
            "sampling" => serde_json::json!({"interval_secs": 0, "first": 1, "thereafter": 1}),
            _ => serde_json::json!(["example"]),
        };
        let decoded = serde_json::from_value(document).unwrap();
        assert!(
            crate::compiler::validate_config(&decoded).is_err(),
            "accepted {field}"
        );
    }
    assert!(crate::compile(&SOURCE.replace("proxy_timeout 10m", "log audit")).is_err());
    assert!(crate::compile(&SOURCE.replace("proxy_timeout 10m", "log\nlog")).is_err());
    assert!(crate::compile(&SOURCE.replace("proxy_timeout 10m", "log")).is_ok());
}

#[test]
fn layer4_rejects_invalid_admission_limits_in_dsl_and_json() {
    for value in [0, 4097] {
        let source = SOURCE.replace("max_connections 17", &format!("max_connections {value}"));
        let config = crate::adapt(&source).unwrap();
        assert!(validate_declarations(&config).is_err());
        let decoded: PingclairConfig =
            serde_json::from_value(serde_json::to_value(&config).unwrap()).unwrap();
        assert!(validate_declarations(&decoded).is_err());
    }
}
