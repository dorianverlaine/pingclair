// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📏 Equal-length wildcard routes keep file order at site and handle scope.

use super::{TestServer, no_proxy_client};

#[tokio::test]
async fn test_equal_length_route_patterns_keep_file_order() {
    // 📏 Issue #230: `/abb*` and `/a*b` both match `/abb` and tie on trimmed
    // length, so the one written first must answer, in a site and inside a
    // sorted `handle` block alike. `/foo` and `/foo*` are twins, so the exact
    // one still answers `/foo` although it is written last.
    for scope in ["site", "handle"] {
        for (first, second) in [("/abb*", "/a*b"), ("/a*b", "/abb*")] {
            let directives = format!(
                "@readiness path __PINGCLAIR_TEST_READINESS_PATH__\n\
                 respond @readiness __PINGCLAIR_TEST_READINESS_TOKEN__\n\
                 respond {first} first\nrespond {second} second\n\
                 respond /foo* prefix\nrespond /foo exact"
            );
            let routes = match scope {
                "handle" => format!("handle {{\n{directives}\n}}"),
                _ => directives,
            };
            let config = format!(
                r#"
                {{
                    admin off
                }}
                http://__PINGCLAIR_TEST_LISTEN__ {{
                    {routes}
                }}
                "#
            );
            let mut server = TestServer::new_pingclairfile(&config);
            assert!(
                server.wait_until_ready().await,
                "{scope}: server failed to start"
            );
            let client = no_proxy_client();
            let mut answers = Vec::new();
            for path in ["/abb", "/foo", "/foobar"] {
                let reply = client.get(server.url(0, path)).send().await.unwrap();
                answers.push((reply.status().as_u16(), reply.text().await.unwrap()));
            }
            assert_eq!(
                answers,
                [
                    (200, "first".into()),
                    (200, "exact".into()),
                    (200, "prefix".into())
                ],
                "{scope}: {first} before {second}"
            );
        }
    }
}
