// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;

/// 🧩 An unmatched site header belongs to every route, including a `handle`
/// that answers before the site's fallback pipeline can run.
#[tokio::test]
async fn site_header_reaches_terminal_handle_and_fallback() {
    let config = r#"
        {
            admin off
        }

        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            header X-Site "on"
            handle /api/* {
                header X-Route "api"
                respond "api" 200
            }
            respond "top" 200
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = no_proxy_client();
    for (path, body, route_header) in [("/api/x", "api", Some("api")), ("/top", "top", None)] {
        let response = client.get(server.url(0, path)).send().await.unwrap();
        assert_eq!(response.status(), 200, "{path}");
        assert_eq!(response.headers().get("x-site").unwrap(), "on", "{path}");
        assert_eq!(
            response
                .headers()
                .get("x-route")
                .map(|value| value.to_str().unwrap()),
            route_header,
            "{path}"
        );
        assert_eq!(response.text().await.unwrap(), body, "{path}");
    }
}
