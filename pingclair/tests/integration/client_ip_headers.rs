// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ Which request headers may name the client behind a trusted proxy.
//!
//! The test client connects from loopback and loopback is a trusted proxy, so
//! the client plays the part of a proxy reporting a visitor. The question is
//! which of its headers count. `CF-Connecting-IP` used to count whenever the
//! peer was trusted, ahead of everything else, so any client reaching the
//! server through an ingress that passes headers through untouched could name
//! itself with it. It now counts only when `client_ip_headers` lists it.

use super::{TestServer, no_proxy_client};

/// 🧾 A site that trusts loopback and echoes the verified client address,
/// with `servers_options` written into the global `servers` block.
fn echo_identity_server(servers_options: &str) -> TestServer {
    TestServer::new_pingclairfile(&format!(
        r#"
        {{
            admin off
            servers {{
                trusted_proxies static 127.0.0.1/32
                {servers_options}
            }}
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            respond "{{client_ip}}"
        }}
        "#
    ))
}

/// 🔎 Sends one request per header set and collects each verified address.
async fn identities(server: &TestServer, cases: &[&[(&str, &str)]]) -> Vec<String> {
    let client = no_proxy_client();
    let mut seen = Vec::new();
    for headers in cases {
        let mut request = client.get(server.url(0, "/whoami"));
        for (name, value) in *headers {
            request = request.header(*name, *value);
        }
        seen.push(request.send().await.unwrap().text().await.unwrap());
    }
    seen
}

/// 🚫 Without `client_ip_headers`, `CF-Connecting-IP` names nobody: the
/// forwarding chain decides, and with no chain the peer itself is the client.
#[tokio::test]
async fn test_cf_connecting_ip_is_ignored_unless_configured() {
    let mut server = echo_identity_server("");
    assert!(server.wait_until_ready().await, "server failed to start");

    let seen = identities(
        &server,
        &[
            &[
                ("CF-Connecting-IP", "203.0.113.7"),
                ("X-Forwarded-For", "198.51.100.9"),
            ],
            &[("CF-Connecting-IP", "203.0.113.7")],
        ],
    )
    .await;
    assert_eq!(seen, vec!["198.51.100.9", "127.0.0.1"]);
}

/// ☁️ `client_ip_headers CF-Connecting-IP` makes that header the only source:
/// it names the client, and an `X-Forwarded-For` beside it is not consulted.
#[tokio::test]
async fn test_configured_client_ip_headers_are_the_only_source() {
    let mut server = echo_identity_server("client_ip_headers CF-Connecting-IP");
    assert!(server.wait_until_ready().await, "server failed to start");

    let seen = identities(
        &server,
        &[
            &[
                ("CF-Connecting-IP", "203.0.113.7"),
                ("X-Forwarded-For", "198.51.100.9"),
            ],
            &[("X-Forwarded-For", "198.51.100.9")],
        ],
    )
    .await;
    assert_eq!(seen, vec!["203.0.113.7", "127.0.0.1"]);
}
