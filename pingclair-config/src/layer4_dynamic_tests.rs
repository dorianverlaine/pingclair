// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;
use serde_json::{Value, json};

fn document() -> Value {
    let mut value = serde_json::to_value(
        crate::adapt("{\n layer4 {\n :9443 {\n route {\n proxy backend.test:443\n }\n }\n }\n}")
            .unwrap(),
    )
    .unwrap();
    let route = &mut value["layer4"][0]["routes"][0];
    route.as_object_mut().unwrap().remove("upstream");
    route["dynamic"] = json!({"type": "a", "name": "backend.test", "port": 443});
    value
}

fn check(value: Value) -> Result<PingclairConfig, String> {
    let config: PingclairConfig = serde_json::from_value(value).map_err(|e| e.to_string())?;
    crate::compiler::validate_config(&config).map_err(|e| e.to_string())?;
    Ok(config)
}

#[test]
fn dynamic_json_defaults_round_trip_and_static_json_stays_compatible() {
    let config = check(document()).unwrap();
    let expected = Layer4Dynamic::A(Layer4Dns {
        name: "backend.test".into(),
        port: 443,
        resolvers: None,
        versions: pingclair_core::config::Layer4IpVersions::Ip,
        valid_ms: None,
        stale_ms: 60_000,
        allow_ip: None,
    });
    assert_eq!(config.layer4[0].routes[0].dynamic, Some(expected));
    assert!(config.layer4[0].routes[0].upstream.is_empty());
    assert_eq!(
        check(serde_json::to_value(&config).unwrap())
            .unwrap()
            .layer4,
        config.layer4
    );
    let mut static_doc = document();
    let route = &mut static_doc["layer4"][0]["routes"][0];
    route.as_object_mut().unwrap().remove("dynamic");
    route["upstream"] = "127.0.0.1:443".into();
    let config = check(static_doc).unwrap();
    assert!(config.layer4[0].routes[0].dynamic.is_none());
}

#[test]
fn every_entry_point_rejects_ambiguous_or_absent_sources() {
    for dynamic in [true, false] {
        let mut value = document();
        let route = &mut value["layer4"][0]["routes"][0];
        if dynamic {
            route["upstream"] = "127.0.0.1:443".into();
        } else {
            route.as_object_mut().unwrap().remove("dynamic");
        }
        assert!(check(value).unwrap_err().contains("exactly one"));
    }
}

#[test]
fn dynamic_schema_has_explicit_tags_and_no_ignored_fields_or_aliases() {
    for (field, value) in [
        ("type", json!("srv")),
        ("type", json!("A")),
        ("versions", json!("both")),
        ("versions", json!("IPv4")),
        ("refresh", json!(60)),
        ("dial_timeout", json!(5)),
        ("typo", json!(true)),
    ] {
        let mut doc = document();
        doc["layer4"][0]["routes"][0]["dynamic"][field] = value;
        assert!(check(doc).is_err(), "accepted {field}");
    }
    let mut doc = document();
    doc["layer4"][0]["routes"][0]["dynamic"]
        .as_object_mut()
        .unwrap()
        .remove("type");
    assert!(check(doc).is_err());
    assert!(
        serde_json::from_str::<Layer4Dynamic>(
            r#"{"type":"a","name":"one.test","name":"two.test","port":443}"#,
        )
        .is_err()
    );
}

#[test]
fn common_validation_enforces_name_port_resolver_and_deadline_contracts() {
    for (field, value, expected) in [
        ("name", json!("127.0.0.1"), "fixed ASCII DNS"),
        ("name", json!("::1"), "fixed ASCII DNS"),
        ("name", json!("*.test"), "fixed ASCII DNS"),
        ("name", json!("{sni}"), "fixed ASCII DNS"),
        ("name", json!("https://backend.test"), "fixed ASCII DNS"),
        ("name", json!("a..test"), "fixed ASCII DNS"),
        ("name", json!("-bad.test"), "fixed ASCII DNS"),
        ("name", json!("a".repeat(64)), "fixed ASCII DNS"),
        ("port", json!(0), "port"),
        ("resolvers", json!([]), "1 to 4"),
        ("resolvers", json!(vec!["1.1.1.1"; 5]), "1 to 4"),
        ("resolvers", json!(["dns.test:53"]), "numeric IP"),
        ("resolvers", json!(["127.0.0.1:0"]), "nonzero"),
        ("resolvers", json!(["[::1]"]), "numeric IP"),
        ("valid_ms", json!(0), "positive duration"),
        ("valid_ms", json!(u64::MAX), "timer range"),
        ("stale_ms", json!(300_001), "0 and 300s"),
    ] {
        let mut doc = document();
        doc["layer4"][0]["routes"][0]["dynamic"][field] = value;
        assert!(check(doc).unwrap_err().contains(expected), "{field}");
    }
    let mut doc = document();
    let dns = &mut doc["layer4"][0]["routes"][0]["dynamic"];
    dns["name"] = "Backend.TEST.".into();
    dns["resolvers"] = json!(["127.0.0.1", "127.0.0.1:5353", "::1", "[::1]:5353"]);
    dns["valid_ms"] = 1.into();
    dns["stale_ms"] = 0.into();
    check(doc).unwrap();
}

#[test]
fn broad_cidrs_cannot_incidentally_authorize_loopback_or_link_local() {
    for (ranges, accepted) in [
        (json!([]), false),
        (json!(["127.0.0.1"]), false),
        (json!(["10.0.0.0/99"]), false),
        (json!(["0.0.0.0/0"]), false),
        (json!(["::/0"]), false),
        (json!(["126.0.0.0/7"]), false),
        (json!(["169.0.0.0/8"]), false),
        (json!(["fe00::/8"]), false),
        (json!(["::/127"]), false),
        (json!(["::ffff:0:0/96"]), false),
        (json!(["::fffe:0:0/95"]), false),
        (
            json!(["127.0.0.0/8", "169.254.0.0/16", "::1/128", "fe80::/10"]),
            true,
        ),
        (json!(["10.20.0.0/16", "fc00::/7"]), true),
        (
            json!(["::ffff:127.0.0.1/128", "::ffff:169.254.0.0/112"]),
            true,
        ),
    ] {
        let mut doc = document();
        doc["layer4"][0]["routes"][0]["dynamic"]["allow_ip"] = ranges.clone();
        assert_eq!(check(doc).is_ok(), accepted, "{ranges}");
    }
}

#[test]
fn pool_budget_counts_distinct_full_policies_across_listeners() {
    let mut config = check(document()).unwrap();
    for index in 1..257 {
        let mut listener = config.layer4[0].clone();
        listener.listen = format!("127.0.0.1:{}", 10_000 + index);
        config.layer4.push(listener);
    }
    crate::compiler::validate_config(&config).unwrap();
    for (index, listener) in config.layer4.iter_mut().enumerate() {
        let Layer4Dynamic::A(dns) = listener.routes[0].dynamic.as_mut().unwrap();
        dns.port = u16::try_from(index + 1).unwrap();
    }
    assert!(
        crate::compiler::validate_config(&config)
            .unwrap_err()
            .to_string()
            .contains("256")
    );
    config.layer4[256].routes[0] = config.layer4[0].routes[0].clone();
    crate::compiler::validate_config(&config).unwrap();
}
