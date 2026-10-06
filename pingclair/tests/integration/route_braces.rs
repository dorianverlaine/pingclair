// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 Literal braces must not turn a route's candidate list into a parameter route.

use super::TestServer;

#[tokio::test]
async fn test_route_braces_are_literal_and_preserve_wildcard_candidates() {
    let config = r#"
        {
            admin off
        }
        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            @php path *.php
            redir @php /php 307
            respond /{id} "literal"
            respond "/open{" "open"
            respond "/close}" "close"
            respond "/{{id}}" "double"
            respond /prefix/{id}/* "prefix"
            respond "fallback"
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let mut answers = Vec::new();
    for path in [
        "/x.php",
        "/x",
        "/{id}",
        "/open{",
        "/close}",
        "/{{id}}",
        "/prefix/{id}",
        "/prefix/{id}/",
        "/prefix/{id}/child",
        "/prefix/value/child",
        "/prefix/{id}/child.php",
    ] {
        let reply = client.get(server.url(0, path)).send().await.unwrap();
        let location = reply
            .headers()
            .get("location")
            .map(|value| value.to_str().unwrap().to_string());
        answers.push((
            reply.status().as_u16(),
            location,
            reply.text().await.unwrap(),
        ));
    }
    let body = |text: &str| (200, None, text.to_string());
    let redirect = || (307, Some("/php".to_string()), String::new());
    assert_eq!(
        answers,
        [
            redirect(),
            body("fallback"),
            body("literal"),
            body("open"),
            body("close"),
            body("double"),
            body("fallback"),
            body("prefix"),
            body("prefix"),
            body("fallback"),
            redirect(),
        ]
    );
}
