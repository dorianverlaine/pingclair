// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 Native contracts are tested independently of the compatibility adapter.

fn site(body: &str) -> String {
    format!(
        r#"HTTPListener(on: "127.0.0.1:18080") {{ Site(host: "*") {{ Fallback {{ {body} }} }} }}"#
    )
}

#[test]
fn abort_ends_the_native_route() {
    let config =
        pingclair_config::compile(&site("Abort()")).expect("Abort is a terminal operation");
    assert!(matches!(
        config.servers[0].routes[0].handler,
        pingclair_core::config::HandlerConfig::Abort
    ));
    for body in [
        "Abort() Respond(body: \"unreachable\")",
        "Abort(status: 444)",
    ] {
        assert!(pingclair_config::compile(&site(body)).is_err());
    }
}

#[test]
fn omitted_and_explicit_response_statuses_survive_json_round_trip() {
    let source = r#"HTTPListener(on: "127.0.0.1:18080") {
        Site(host: "*") {
            ErrorRoute(for: [.status(503)]) { Respond(body: "inherited") }
            ErrorRoute(for: [.status(404)]) { Respond(body: "explicit", status: 200) }
            Fallback { Respond(body: "ordinary") }
        }
    }"#;
    let config = pingclair_config::compile(source).unwrap();
    let document = serde_json::to_value(&config).unwrap();
    let decoded: pingclair_core::config::PingclairConfig =
        serde_json::from_value(document.clone()).unwrap();
    pingclair_config::compiler::validate_config(&decoded).unwrap();
    assert_eq!(serde_json::to_value(&decoded).unwrap(), document);
    let server = &decoded.servers[0];
    let handlers = [
        &server.error_routes[0].handlers[0].handler,
        &server.error_routes[1].handlers[0].handler,
        &server.routes[0].handler,
    ];
    let serialized: Vec<_> = handlers
        .into_iter()
        .map(|handler| serde_json::to_value(handler).unwrap())
        .collect();
    assert_eq!(
        serialized,
        vec![
            serde_json::json!({"type":"respond", "body":{"literal":"inherited"}, "headers":{}}),
            serde_json::json!({"type":"respond", "status":200, "body":{"literal":"explicit"}, "headers":{}}),
            serde_json::json!({"type":"respond", "body":{"literal":"ordinary"}, "headers":{}}),
        ]
    );
}

#[test]
fn invalid_final_response_statuses_are_refused_by_every_entry_point() {
    for status in [0, 99, 100, 103, 199, 600, 65535] {
        assert!(
            pingclair_config::compile(&site(&format!("Respond(body: \"bad\", status: {status})")))
                .is_err()
        );
        let mut config = pingclair_config::compile(&site("Respond(body: \"ok\")")).unwrap();
        config.servers[0].routes[0].handler = serde_json::from_value(serde_json::json!({
            "type":"respond", "status":status, "body":null
        }))
        .unwrap();
        assert!(pingclair_config::compiler::validate_config(&config).is_err());
    }
}

#[test]
fn unimplemented_error_proxy_is_refused_by_shared_validation() {
    let source = r#"HTTPListener(on: "127.0.0.1:18080") {
        Site(host: "*") {
            ErrorRoute(for: [.serverError]) { Proxy(to: "127.0.0.1:9000") }
            Fallback { Fail(status: 503) }
        }
    }"#;
    let adapted = pingclair_config::adapt(source).unwrap();
    let json = serde_json::to_string(&adapted).unwrap();
    let decoded = serde_json::from_str(&json).unwrap();
    for config in [&adapted, &decoded] {
        let error = pingclair_config::compiler::validate_config(config)
            .expect_err("an error proxy cannot execute until it has its own upstream slot");
        assert!(
            error
                .to_string()
                .contains("an error route cannot proxy yet")
        );
    }
    assert!(pingclair_config::compile(source).is_err());
}

#[test]
fn native_header_text_stays_literal_after_json_round_trip() {
    let source = site(
        r#"RequestHeader(.set("X-Request", "{host}"), .append("X-Request", "{path}"))
        ResponseHeader(.setIfAbsent("X-Default", "{host}"))
        Proxy(to: "127.0.0.1:9000", headersUp: [.set("X-Up", "{host}")],
              headersDown: [.append("X-Down", "{path}")])"#,
    );
    let compiled = pingclair_config::compile(&source).unwrap();
    let document = serde_json::to_value(&compiled).unwrap();
    let serialized = serde_json::to_string(&document).unwrap();
    assert!(serialized.contains(r#""literal":"{host}""#));
    assert!(serialized.contains(r#""literal":"{path}""#));
    let decoded: pingclair_core::config::PingclairConfig =
        serde_json::from_value(document.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), document);
}

#[test]
fn extracting_a_positional_value_into_a_binding_preserves_the_document() {
    let inline = site(r#"ResponseHeader(.set("X-Test", "hello")) Respond(body: "ok")"#);
    let bound = format!(
        "let text = \"hello\"\n{}",
        site(r#"ResponseHeader(.set("X-Test", text)) Respond(body: "ok")"#)
    );
    assert_eq!(
        serde_json::to_value(pingclair_config::compile(&inline).unwrap()).unwrap(),
        serde_json::to_value(pingclair_config::compile(&bound).unwrap()).unwrap()
    );
}

#[test]
fn condition_composition_preserves_the_matcher_role() {
    for expression in ["condition", ".all([condition])", ".any([.not(condition)])"] {
        for attribute in ["", "@Matcher\n"] {
            let source = format!(
                r#"{attribute}let condition = .path(prefix: "/api")
HTTPListener(on: "127.0.0.1:18080") {{ Site(host: "*") {{ Route(when: {expression}) {{ Respond(body: "ok") }} }} }}"#
            );
            assert_eq!(
                pingclair_config::compile(&source).is_ok(),
                !attribute.is_empty(),
                "{source}"
            );
        }
    }
    let source =
        "let condition = .path(prefix: \"/api\")\n@Matcher\nlet composed = .all([condition])\n"
            .to_string()
            + &site("Respond(body: \"ok\")");
    assert!(pingclair_config::compile(&source).is_err());
}

#[test]
fn conditional_file_serving_accepts_a_successor_and_may_end_a_route() {
    let files = r#"ServeFiles(root: "./public", passThru: true)"#;
    // ➡️ A step that may answer: what follows it runs when the file is a miss.
    assert!(
        pingclair_config::compile(&site(&format!("{files} Respond(body: \"fallback\")"))).is_ok()
    );
    // ➡️ …and a route may end there, because a miss is answered by whatever
    // the site does with an unanswered request. Refusing this was the review's
    // third finding: the Caddyfile accepts the same shape.
    assert!(pingclair_config::compile(&site(files)).is_ok());
    // 🚫 Something that always answers still ends the route.
    assert!(
        pingclair_config::compile(&site(
            r#"ServeFiles(root: "./public") Respond(body: "unreachable")"#
        ))
        .is_err()
    );
}

#[test]
fn describe_returns_all_transport_contexts_for_a_shared_name() {
    let all: serde_json::Value =
        serde_json::from_str(&pingclair_config::describe::render_json(None).unwrap()).unwrap();
    for name in ["Proxy", "Route", "Fallback"] {
        let selected: serde_json::Value =
            serde_json::from_str(&pingclair_config::describe::render_json(Some(name)).unwrap())
                .unwrap();
        let expected: Vec<_> = all["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["name"] == name)
            .collect();
        assert_eq!(selected["entries"], serde_json::to_value(expected).unwrap());
    }
}
