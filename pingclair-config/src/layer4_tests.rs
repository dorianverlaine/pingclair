// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;
use pingclair_core::config::{Layer4Matcher, Layer4Route, Layer4Server, Layer4TlsMatcher};

const SOURCE: &str = r#"{
    layer4 {
        :9443 {
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
        preread_timeout_ms: 62_003,
        preread_buffer_size: 16_384,
        proxy_connect_timeout_ms: 2_000,
        proxy_timeout_ms: 600_000,
        proxy_half_close: true,
        proxy_buffer_size: 32_768,
        routes: vec![
            Layer4Route {
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
        assert!(
            validate(&config)
                .unwrap_err()
                .to_string()
                .contains("not implemented")
        );
    }
    assert!(
        crate::compile(SOURCE)
            .unwrap_err()
            .to_string()
            .contains("not implemented")
    );
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
        dir.path().join("b.pingclair"),
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
    assert!(
        crate::compile_directory(dir.path())
            .unwrap_err()
            .to_string()
            .contains("not implemented")
    );
}
