// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📏 A body that ends before its declared length is malformed (RFC 9114 §4.1.2).

use super::*;

/// 🚫 A proxied request that declares ten bytes and sends five is a stream error.
///
/// An application-level `400` looked to the client exactly like a site that
/// chose to refuse the body; the RFC asks for `H3_MESSAGE_ERROR`, which is what
/// the header-framing path already sends (#237).
#[tokio::test]
async fn h3_a_short_proxied_body_resets_with_message_error() {
    let (origin, _heads, _hits) =
        spawn_scripted_upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
    let server = spawn_h3_from_pingclairfile(&format!(
        ":443 {{\n reverse_proxy 127.0.0.1:{}\n}}",
        origin.port()
    ))
    .await;

    let outcome = h3_attempt(
        H3Attempt {
            method: "POST",
            extra_headers: &[("content-length", "10")],
            body: b"12345",
            ..H3Attempt::to(server, "/")
        },
        None,
    )
    .await
    .map(|response| response.status);
    assert_eq!(outcome, Err("stream reset with code 270".to_string()));
}

/// 🚫 The FastCGI path resets the same way.
///
/// PHP-FPM reads exactly `CONTENT_LENGTH` bytes from STDIN; a body that ends
/// early is the client's protocol error, not this hop's answer to give.
#[tokio::test]
async fn h3_a_short_fastcgi_body_resets_with_message_error() {
    let (responder, _task) = spawn_fastcgi_responder(200, b"ok".to_vec()).await;
    let server = spawn_h3_from_pingclairfile(&format!(
        ":443 {{\n reverse_proxy {responder} {{\n  transport fastcgi\n }}\n}}"
    ))
    .await;

    let outcome = h3_attempt(
        H3Attempt {
            method: "POST",
            extra_headers: &[("content-length", "10")],
            body: b"12345",
            ..H3Attempt::to(server, "/")
        },
        None,
    )
    .await
    .map(|response| response.status);
    assert_eq!(outcome, Err("stream reset with code 270".to_string()));
}
