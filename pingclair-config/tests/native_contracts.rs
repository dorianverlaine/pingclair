// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 Native contracts are tested independently of the compatibility adapter.

fn site(body: &str) -> String {
    format!(
        r#"HTTPListener(on: "127.0.0.1:18080") {{ Site(host: "*") {{ Fallback {{ {body} }} }} }}"#
    )
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
