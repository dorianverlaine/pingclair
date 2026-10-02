// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔤 A route path ignores ASCII letter case, whatever its shape (issue #198).
//!
//! Caddy's `path` matcher lowercases both the pattern and the request path.
//! Wildcard route paths here already did (#193), but exact and prefix ones
//! went through a radix tree that compared bytes exactly, so `/Health`
//! answered only `/Health`. Each case below writes a route in one case and
//! requests it in another.

use super::TestServer;
use super::no_proxy_client;

/// 🎯 Exact, prefix and suffix routes, written in mixed or lower case, answer
/// the same whichever case the request spells. Before the fix the exact and
/// prefix requests in a different case fell through to the catch-all.
#[tokio::test]
async fn test_mixed_case_requests_reach_the_same_route_as_lowercase_ones() {
    let config = r#"
        {
            admin off
        }

        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            respond /Health "exact" 200
            respond /Admin/* "mixed-case prefix" 200
            respond /api/* "lowercase prefix" 200
            @php path *.PHP
            respond @php "suffix" 200
            respond "catch-all" 200
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = no_proxy_client();
    let mut answers = Vec::new();
    for path in [
        "/health",
        "/HEALTH",
        "/Health",
        "/admin/users",
        "/ADMIN/Users",
        "/api/v1",
        "/API/v1",
        "/index.php",
        "/Index.Php",
        "/elsewhere",
    ] {
        let reply = client.get(server.url(0, path)).send().await.unwrap();
        answers.push((path, reply.text().await.unwrap()));
    }

    assert_eq!(
        answers,
        [
            ("/health", "exact".to_string()),
            ("/HEALTH", "exact".to_string()),
            ("/Health", "exact".to_string()),
            ("/admin/users", "mixed-case prefix".to_string()),
            ("/ADMIN/Users", "mixed-case prefix".to_string()),
            ("/api/v1", "lowercase prefix".to_string()),
            ("/API/v1", "lowercase prefix".to_string()),
            ("/index.php", "suffix".to_string()),
            ("/Index.Php", "suffix".to_string()),
            ("/elsewhere", "catch-all".to_string()),
        ]
    );
}

/// 🪚 A prefix strip agrees with the case-insensitive route that chose it
/// (#214). `handle_path /API/*` is selected for `/api/users`, so it must also
/// strip `/api`; before the fix it compared bytes exactly and forwarded the
/// path untouched. `uri strip_prefix` and `uri strip_suffix` share the rule,
/// as in Caddy, where both go through one case-insensitive trim.
#[tokio::test]
async fn test_prefix_strips_agree_with_case_insensitive_routes() {
    let config = r#"
        {
            admin off
        }

        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            handle_path /API/* {
                respond "handle_path {path}" 200
            }
            handle /static/* {
                uri strip_prefix /STATIC
                respond "strip_prefix {path}" 200
            }
            @php path *.php
            handle @php {
                uri strip_suffix .PHP
                respond "strip_suffix {path}" 200
            }
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = no_proxy_client();
    let mut answers = Vec::new();
    for path in ["/api/users", "/Api/users", "/static/app.js", "/index.php"] {
        let reply = client.get(server.url(0, path)).send().await.unwrap();
        answers.push((path, reply.text().await.unwrap()));
    }

    assert_eq!(
        answers,
        [
            ("/api/users", "handle_path /users".to_string()),
            ("/Api/users", "handle_path /users".to_string()),
            ("/static/app.js", "strip_prefix /app.js".to_string()),
            ("/index.php", "strip_suffix /index".to_string()),
        ]
    );
}
