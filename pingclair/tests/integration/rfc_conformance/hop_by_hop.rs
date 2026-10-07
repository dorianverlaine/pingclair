// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔗 Hop-by-hop fields: the ones that belong to a single connection.
//!
//! RFC 9110 §7.6.1 makes this a requirement rather than a preference: an
//! intermediary **MUST** remove the fields a message names in its `Connection`
//! header before forwarding it, because those fields are addressed to this hop.
//! The fixed list of hop-by-hop names is only half the rule — the other half is
//! whatever the sender listed.

use super::{ScriptedUpstream, TestServer, raw_http1, site};
use std::time::Duration;

/// 🚫 A field named in the origin's `Connection` does not reach the client.
///
/// The origin here answers with `Connection: X-Listed` and `X-Listed:
/// should-not-survive`. The fixed hop-by-hop list is already stripped, so the
/// only way this test fails is by forwarding the *listed* name — which is the
/// half that changes per deployment and the half a cache or a smuggling chain
/// can use.
#[tokio::test]
async fn test_connection_listed_field_is_not_forwarded() {
    let body = b"hello text body\n".repeat(400);
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: X-Listed\r\n\
         X-Listed: should-not-survive\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let upstream = ScriptedUpstream::start(
        vec![[head.as_bytes(), body.as_slice()].concat()],
        Duration::ZERO,
    )
    .await;
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "reverse_proxy 127.0.0.1:{}",
        upstream.address.port()
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, _) = raw_http1(
        &server,
        b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    )
    .await;
    server.stop();

    assert!(head.starts_with("http/1.1 200"), "{head}");
    assert!(
        !head.contains("x-listed"),
        "RFC 9110 §7.6.1 requires the listed field to be removed: {head}"
    );
}
