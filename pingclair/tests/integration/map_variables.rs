// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔤 Literal, regex, and default `map` rows reach later handlers.

use super::{TestServer, no_proxy_client};

#[tokio::test]
async fn map_values_reach_headers_and_respond() {
    let config = r#"
        {
            admin off
        }

        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            map {http.request.uri.path} {mapped} {
                /one first
                ~^/api/(.*)$ api-$1
                default none
            }
            header X-Mapped {http.vars.mapped}
            respond "{http.vars.mapped}"
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = no_proxy_client();
    for (path, expected) in [
        ("/one", "first"),
        ("/api/users", "api-users"),
        ("/other", "none"),
    ] {
        let response = client.get(server.url(0, path)).send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-mapped")
                .and_then(|value| value.to_str().ok()),
            Some(expected),
            "the map value must be visible to a later header handler on {path}"
        );
        assert_eq!(response.text().await.unwrap(), expected);
    }
}
