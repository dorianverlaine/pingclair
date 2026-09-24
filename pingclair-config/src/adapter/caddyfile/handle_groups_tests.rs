// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use pingclair_core::config::{HandlerConfig, HandlerElement, Matcher};

fn compiled_handler(directives: &str) -> HandlerConfig {
    crate::compile(&format!("example.com {{\n{directives}\n}}"))
        .expect("configuration compiles")
        .servers[0]
        .routes[0]
        .handler
        .clone()
}

fn pipeline(handlers: Vec<HandlerElement>) -> HandlerConfig {
    HandlerConfig::Pipeline { handlers }
}

fn branch(path: &str, handler: HandlerConfig) -> HandlerElement {
    HandlerElement::with_matcher(
        Matcher::Path {
            patterns: vec![path.into()],
        },
        handler,
    )
}

#[test]
fn nested_handle_groups_preserve_sorted_bodies_and_scope() {
    let header = compiled_handler("handle {\n header X-Selected yes\n}");
    let fallback = compiled_handler("handle {\n respond fallback\n}");
    let expected = pipeline(vec![HandlerElement::plain(HandlerConfig::FirstMatch {
        handlers: vec![branch("/api/a", header), HandlerElement::plain(fallback)],
    })]);
    for wrapper in ["handle /api/*", "handle_path /api/*", "route"] {
        let actual = compiled_handler(&format!(
            "{wrapper} {{\n handle /api/a {{\n header X-Selected yes\n }}\n handle {{\n respond fallback\n }}\n}}"
        ));
        let actual = match actual {
            HandlerConfig::HandlePath { handlers, .. } => pipeline(handlers),
            handler => handler,
        };
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            serde_json::to_value(&expected).unwrap(),
            "{wrapper}"
        );
    }
    let sorted = compiled_handler(
        "handle /api/* {\n handle {\n respond fallback\n }\n handle /api/a {\n header X-Selected yes\n }\n}",
    );
    assert_eq!(
        serde_json::to_value(sorted).unwrap(),
        serde_json::to_value(&expected).unwrap()
    );
    let deeper = compiled_handler(
        "handle /api/* {\n handle /api/* {\n handle /api/a {\n header X-Selected yes\n }\n handle {\n respond fallback\n }\n }\n handle {\n respond outer\n }\n}",
    );
    let expected_deeper = pipeline(vec![HandlerElement::plain(HandlerConfig::FirstMatch {
        handlers: vec![
            branch("/api/*", expected),
            HandlerElement::plain(compiled_handler("handle {\n respond outer\n}")),
        ],
    })]);
    assert_eq!(
        serde_json::to_value(deeper).unwrap(),
        serde_json::to_value(expected_deeper).unwrap()
    );
}

#[test]
fn nested_handle_groups_include_error_routes() {
    let config = crate::compile(
        "example.com {\n handle_errors {\n handle /api/a {\n header X-Selected yes\n }\n handle {\n respond fallback\n }\n }\n}",
    ).unwrap();
    let expected = vec![HandlerElement::plain(HandlerConfig::FirstMatch {
        handlers: vec![
            branch(
                "/api/a",
                compiled_handler("handle {\n header X-Selected yes\n}"),
            ),
            HandlerElement::plain(compiled_handler("handle {\n respond fallback\n}")),
        ],
    })];
    assert_eq!(
        serde_json::to_value(&config.servers[0].error_routes[0].handlers).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}

#[test]
fn nested_handle_groups_preserve_interleaved_route_steps() {
    let actual = compiled_handler(
        "route {\n handle /api/a {\n header X-Selected yes\n }\n rewrite * /changed\n handle /changed {\n respond fallback\n }\n respond done\n}",
    );
    let selected =
        compiled_handler("route {\n handle {\n header X-Selected yes\n }\n rewrite * /changed\n}");
    let unmatched = pipeline(vec![
        HandlerElement::plain(compiled_handler("rewrite * /changed")),
        HandlerElement::plain(HandlerConfig::FirstMatch {
            handlers: vec![branch(
                "/changed",
                compiled_handler("handle {\n respond fallback\n}"),
            )],
        }),
    ]);
    let expected = pipeline(vec![
        HandlerElement::plain(HandlerConfig::FirstMatch {
            handlers: vec![branch("/api/a", selected), HandlerElement::plain(unmatched)],
        }),
        HandlerElement::plain(compiled_handler("respond done")),
    ]);
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}

#[test]
fn nested_handle_groups_include_prefix_stripping_siblings() {
    let actual = compiled_handler(
        "route {\n handle_path /api/* {\n header X-Selected yes\n }\n handle {\n respond fallback\n }\n}",
    );
    let HandlerConfig::Pipeline { mut handlers } =
        compiled_handler("handle_path /api/* {\n header X-Selected yes\n}")
    else {
        panic!("site middleware wraps the prefix-stripping handler");
    };
    let expected = pipeline(vec![HandlerElement::plain(HandlerConfig::FirstMatch {
        handlers: vec![
            branch("/api/*", handlers.remove(0).handler),
            HandlerElement::plain(compiled_handler("handle {\n respond fallback\n}")),
        ],
    })]);
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}
