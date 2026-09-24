// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌐 `remote_ip` sees the connection, `client_ip` sees the client.
//!
//! Behind a trusted load balancer the two addresses differ: the connection
//! comes from the balancer, and the balancer reports the real client in
//! `X-Forwarded-For`. Caddy's `remote_ip` matches the first and `client_ip`
//! the second. Both used to match the forwarded client here, so a rule meant
//! for "requests arriving through the balancer" matched none of them.
//!
//! The test client connects from loopback and loopback is trusted, so the
//! client plays the balancer: loopback is the peer, and whatever it writes
//! into `X-Forwarded-For` is the client it vouches for.

use super::{TestServer, no_proxy_client};

/// 🧾 A site that says which of its IP matchers agreed, at both the route
/// level and inside a `handle` block, where matchers are evaluated per handler.
fn ip_matcher_server() -> TestServer {
    let config = r#"
        {
            admin off
            servers {
                trusted_proxies static 127.0.0.1/32 ::1/128
            }
        }

        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            handle /nested {
                @peer remote_ip 127.0.0.0/8 ::1
                respond @peer "nested remote_ip matched the proxy"
                respond "nested remote_ip missed"
            }

            @remote_is_proxy {
                path /remote
                remote_ip 127.0.0.0/8 ::1
            }
            respond @remote_is_proxy "remote_ip matched the proxy"

            @remote_is_client {
                path /remote-as-client
                remote_ip 203.0.113.0/24
            }
            respond @remote_is_client "remote_ip matched the forwarded client"

            @client_is_forwarded {
                path /client
                client_ip 203.0.113.0/24
            }
            respond @client_is_forwarded "client_ip matched the forwarded client"

            respond "no match"
        }
    "#;
    TestServer::new_pingclairfile(config)
}

#[tokio::test]
async fn test_remote_ip_matches_the_proxy_and_client_ip_the_forwarded_client() {
    let mut server = ip_matcher_server();
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let mut answers = Vec::new();
    for path in ["/remote", "/remote-as-client", "/client", "/nested"] {
        let body = client
            .get(server.url(0, path))
            .header("X-Forwarded-For", "203.0.113.7")
            .send()
            .await
            .expect("request")
            .text()
            .await
            .expect("body");
        answers.push((path, body));
    }

    assert_eq!(
        answers,
        [
            ("/remote", "remote_ip matched the proxy".to_string()),
            ("/remote-as-client", "no match".to_string()),
            (
                "/client",
                "client_ip matched the forwarded client".to_string()
            ),
            ("/nested", "nested remote_ip matched the proxy".to_string()),
        ]
    );
}
