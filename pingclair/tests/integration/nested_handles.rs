// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;

#[tokio::test]
async fn nested_handle_groups_stop_after_a_match_without_a_response() {
    let mut server = TestServer::new_pingclairfile(
        r#"
        {
            admin off
        }
        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            handle @readiness {
                respond "__PINGCLAIR_TEST_READINESS_TOKEN__"
            }
            handle /api/* {
                handle /api/a {
                    header X-Selected yes
                }
                handle {
                    respond fallback
                }
                respond done
            }
        }
        "#,
    );
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();
    for (path, body, selected) in [
        ("/api/a", "done", Some("yes")),
        ("/api/b", "fallback", None),
    ] {
        let response = client.get(server.url(0, path)).send().await.unwrap();
        let actual = (
            response.status().as_u16(),
            response
                .headers()
                .get("x-selected")
                .map(|value| value.to_str().unwrap().to_owned()),
            response.text().await.unwrap(),
        );
        assert_eq!(
            actual,
            (200, selected.map(str::to_owned), body.into()),
            "{path}"
        );
    }
}

#[tokio::test]
async fn nested_handle_groups_keep_interleaved_rewrites_in_place() {
    let mut server = TestServer::new_pingclairfile(
        r#"
        {
            admin off
        }
        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            handle @readiness {
                respond "__PINGCLAIR_TEST_READINESS_TOKEN__"
            }
            handle /api/* {
                route {
                    handle /api/a {
                        header X-Selected yes
                    }
                    rewrite * /changed
                    handle /changed {
                        respond fallback
                    }
                    respond done
                }
            }
        }
        "#,
    );
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();
    for (path, body) in [("/api/a", "done"), ("/api/b", "fallback")] {
        let response = client.get(server.url(0, path)).send().await.unwrap();
        assert_eq!(response.status(), 200, "{path}");
        assert_eq!(response.text().await.unwrap(), body, "{path}");
    }
}
