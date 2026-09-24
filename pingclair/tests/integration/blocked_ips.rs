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
