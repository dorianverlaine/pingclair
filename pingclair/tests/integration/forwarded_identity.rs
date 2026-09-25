// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 The client address a trusted proxy's forwarding headers resolve to.
//!
//! The test client connects from loopback and loopback is a trusted proxy, so
//! whatever the client writes into `X-Forwarded-For` and `Forwarded` is read
//! as a proxy's report. The site answers with `{client_ip}`, which is the
//! verified address, so each response says exactly which identity won.

use super::{TestServer, no_proxy_client};

/// 🧾 A site that trusts loopback and echoes the verified client address.
fn echo_identity_server() -> TestServer {
    let config = r#"
        {
            admin off
            servers {
                trusted_proxies static 127.0.0.1/32
            }
        }

        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            @addresses path /addresses
            respond @addresses "{remote_host} {http.request.remote.host} {client_ip} {http.request.client_ip} {remote_port}"

            respond "{client_ip}"
        }
    "#;
    TestServer::new_pingclairfile(config)
}

/// 🧹 A trailing comma is an empty list element, which RFC 9110 §5.6.1.2 says
/// a recipient must ignore. Next to a valid `Forwarded` it used to fail the
/// `X-Forwarded-For` parse and drop both headers, so the origin saw loopback.
#[tokio::test]
async fn test_empty_list_elements_keep_the_forwarded_client() {
    let mut server = echo_identity_server();
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();
    let url = server.url(0, "/whoami");

    for (xff, forwarded) in [
        ("203.0.113.7,", "for=203.0.113.7"),
        ("203.0.113.7", "for=203.0.113.7,"),
        ("203.0.113.7", "for=203.0.113.7"),
    ] {
        let body = client
            .get(&url)
            .header("X-Forwarded-For", xff)
            .header("Forwarded", forwarded)
            .send()
            .await
            .expect("request")
            .text()
            .await
            .expect("body");
        assert_eq!(
            body, "203.0.113.7",
            "X-Forwarded-For: {xff} / Forwarded: {forwarded}"
        );
    }
}

/// 🧭 One header failing to parse is not the two headers disagreeing. A
/// malformed `X-Forwarded-For` used to discard a valid `Forwarded` beside it,
/// and a `Forwarded` hop that hid its address (`for=unknown`, `for=_hidden`)
/// made the whole field unreadable. Each now leaves the other header usable,
/// while a hidden hop still stops the walk: nothing to its left is verifiable.
#[tokio::test]
async fn test_an_unreadable_header_leaves_the_other_one_usable() {
    let mut server = echo_identity_server();
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();
    let url = server.url(0, "/whoami");

    for (xff, forwarded, expected) in [
        // 🔎 A parse failure on one side, a valid chain on the other.
        (
            Some("203.0.113.7, not-an-address"),
            Some("for=203.0.113.7"),
            "203.0.113.7",
        ),
        (
            Some("203.0.113.7"),
            Some("for=not-an-address"),
            "203.0.113.7",
        ),
        // 🙈 A hop that hid its address, next to a header that names it.
        (Some("203.0.113.7"), Some("for=_hidden"), "203.0.113.7"),
        (Some("203.0.113.7"), Some("by=_edge"), "203.0.113.7"),
        // 🛡️ The walk stops at a hidden hop instead of trusting what lies
        // beyond it, and with nothing else sent the peer stands.
        (None, Some("for=203.0.113.7, for=unknown"), "127.0.0.1"),
        // 🚫 Two readable headers naming different clients still fail closed.
        (Some("203.0.113.7"), Some("for=198.51.100.9"), "127.0.0.1"),
    ] {
        let mut request = client.get(&url);
        if let Some(xff) = xff {
            request = request.header("X-Forwarded-For", xff);
        }
        if let Some(forwarded) = forwarded {
            request = request.header("Forwarded", forwarded);
        }
        let body = request
            .send()
            .await
            .expect("request")
            .text()
            .await
            .expect("body");
        assert_eq!(
            body, expected,
            "X-Forwarded-For: {xff:?} / Forwarded: {forwarded:?}"
        );
    }
}

/// 🔌 `{remote_host}` is the connection's peer and `{client_ip}` the client a
/// trusted proxy vouched for. Both used to print the forwarded client, so a
/// log line behind a load balancer could not name the balancer at all.
#[tokio::test]
async fn test_remote_host_is_the_peer_and_client_ip_the_forwarded_client() {
    let mut server = echo_identity_server();
    assert!(server.wait_until_ready().await, "server failed to start");
    let body = no_proxy_client()
        .get(server.url(0, "/addresses"))
        .header("X-Forwarded-For", "203.0.113.7")
        .send()
        .await
        .expect("request")
        .text()
        .await
        .expect("body");

    let fields: Vec<&str> = body.split(' ').collect();
    assert_eq!(
        fields[..4],
        ["127.0.0.1", "127.0.0.1", "203.0.113.7", "203.0.113.7"],
        "{body}"
    );
    // 🔌 The port is the client socket's ephemeral port, so only its shape is
    // knowable ahead of time.
    assert!(
        fields[4].parse::<u16>().is_ok_and(|port| port != 0),
        "{body}"
    );
}
