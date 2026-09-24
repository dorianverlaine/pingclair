// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ A block list with a malformed entry is refused, not half-installed.
//!
//! `blocked_ips` used to be checked by nobody: the listener logged a warning
//! and dropped an entry it could not parse, and the Admin API accepted it
//! outright. An operator who mistyped one address in a block list got a list
//! that let exactly that address through, and every door said "valid".
//!
//! 📌 The posted document is JSON because `blocked_ips` has no Pingclairfile
//! spelling: Caddy has no global block-list option, and this one exists only
//! in the JSON schema. The running server itself is configured in the DSL.
//!
//! 🧭 The Pingclairfile way to block addresses is the Caddy one, a `client_ip`
//! matcher with `abort`; the tests below prove that spelling blocks what it
//! names, serves everyone else, and believes a forwarded address only from a
//! trusted proxy.

use super::{TestServer, admin_test_pingclairfile, no_proxy_client};

/// 🚫 POST /load refuses a block list with an entry that is not a network,
/// names it, and leaves the running configuration serving.
#[tokio::test]
async fn test_admin_load_refuses_a_malformed_blocked_ips_entry() {
    let mut server = TestServer::new_pingclairfile(&admin_test_pingclairfile(
        "/__ready_blocked_ips",
        "still-ready",
    ));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let document = r#"{"global":{"blocked_ips":["192.0.2.1","not-an-ip"]},"servers":[{"name":"blocked.example.com","routes":[{"path":"/*","handler":{"type":"respond","status":200}}]}]}"#;
    let response = client
        .post(server.admin_url("/load"))
        .header("Content-Type", "application/json")
        .body(document)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = response.text().await.unwrap();
    assert!(
        body.contains("blocked_ips contains invalid IP or CIDR `not-an-ip`"),
        "the refusal must name the option and the entry; got: {body}"
    );

    // 🧭 The previous configuration is still the one answering.
    let response = client
        .get(server.url(0, "/__ready_blocked_ips"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "still-ready");
}

/// 🛡️ A site that blocks one documentation range with `client_ip` + `abort`.
///
/// 📌 `/loopback` aborts for a loopback client too, which is what proves the
/// matcher saw the socket peer when no proxy is trusted.
fn client_ip_block_pingclairfile(global: &str) -> String {
    format!(
        r#"
        {{
            admin off
            {global}
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            @blocked client_ip 203.0.113.0/24 2001:db8::/32
            abort @blocked

            @loopback {{
                client_ip 127.0.0.0/8 ::1
                path /loopback*
            }}
            abort @loopback

            respond "served"
        }}
        "#
    )
}

/// 🚦 Sends one GET, returning the body, or `None` when the server closed the
/// connection without answering — which is what `abort` looks like on HTTP/1.1.
async fn fetch(server: &TestServer, path: &str, forwarded_for: Option<&str>) -> Option<String> {
    let mut request = no_proxy_client().get(server.url(0, path));
    if let Some(address) = forwarded_for {
        request = request.header("X-Forwarded-For", address);
    }
    let response = request.send().await.ok()?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    Some(response.text().await.unwrap())
}

/// 🚫 Behind a trusted proxy, `client_ip` matches the forwarded client: the
/// blocked range gets no response at all, and anyone else is served.
#[tokio::test]
async fn test_client_ip_abort_blocks_the_forwarded_client_behind_a_trusted_proxy() {
    let mut server = TestServer::new_pingclairfile(&client_ip_block_pingclairfile(
        "servers {\n                trusted_proxies static 127.0.0.1/32\n            }",
    ));
    assert!(server.wait_until_ready().await, "server failed to start");

    assert_eq!(
        fetch(&server, "/page", Some("203.0.113.9")).await,
        None,
        "a client in the blocked range must get no response"
    );
    assert_eq!(
        fetch(&server, "/page", Some("198.51.100.7"))
            .await
            .as_deref(),
        Some("served"),
        "a client outside the blocked range must be served"
    );
    assert_eq!(
        fetch(&server, "/page", None).await.as_deref(),
        Some("served"),
        "the proxy itself, forwarding nobody, must be served"
    );
}

/// 🛡️ With no trusted proxy, a forged `X-Forwarded-For` moves nobody into or
/// out of a block: `client_ip` matches the socket peer.
#[tokio::test]
async fn test_client_ip_abort_ignores_forwarded_headers_from_an_untrusted_peer() {
    let mut server = TestServer::new_pingclairfile(&client_ip_block_pingclairfile(""));
    assert!(server.wait_until_ready().await, "server failed to start");

    assert_eq!(
        fetch(&server, "/page", Some("203.0.113.9"))
            .await
            .as_deref(),
        Some("served"),
        "an untrusted peer must not be able to claim a blocked address"
    );
    assert_eq!(
        fetch(&server, "/loopback", Some("198.51.100.7")).await,
        None,
        "an untrusted peer must not be able to talk its way out of a block"
    );
}
