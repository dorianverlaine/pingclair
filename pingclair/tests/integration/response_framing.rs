// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧾 Locally generated responses follow their status code's content rules.
//!
//! A 204 has no content and may not say how long its content is (RFC 9110
//! §8.6, §15.3.5). The handlers that build local responses set
//! `Content-Length` from whatever body they were given, so these tests pin the
//! rule where the response leaves the server, on each transport.

use super::{TestServer, read_http1_to_end};
use tokio::io::AsyncWriteExt;

/// 🧾 A Pingclairfile with a readiness route in front of `body`.
fn site(body: &str) -> String {
    format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            {body}
        }}
        "#
    )
}

/// 🔌 Sends one raw HTTP/1.1 request and returns the header block and
/// whatever followed it before the server closed the connection.
async fn raw_http1(server: &TestServer, request: &[u8]) -> (String, Vec<u8>) {
    let mut stream = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    stream.write_all(request).await.unwrap();
    let response = read_http1_to_end(&mut stream).await;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("a complete response head");
    (
        String::from_utf8_lossy(&response[..split]).to_ascii_lowercase(),
        response[split + 4..].to_vec(),
    )
}

/// 🚫 `respond "x" 204` over HTTP/1.1 sends neither `Content-Length` nor
/// the byte.
///
/// Before the fix the header said `Content-Length: 1` while Pingora (rightly)
/// dropped the byte, so the response described content it never sent.
#[tokio::test]
async fn test_h1_respond_204_carries_no_content_length() {
    let mut server = TestServer::new_pingclairfile(&site(r#"respond "x" 204"#));
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, body) = raw_http1(
        &server,
        b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    )
    .await;
    server.stop();

    assert!(head.starts_with("http/1.1 204"), "{head}");
    assert!(!head.contains("\r\ncontent-length:"), "{head}");
    assert!(body.is_empty(), "a 204 carries no content: {body:?}");
}

/// 🚫 The CORS preflight's 204 carries no `Content-Length` either.
///
/// Every browser preflight goes through this response, and it used to answer
/// `204 No Content` with `Content-Length: 0`.
#[tokio::test]
async fn test_h1_cors_preflight_204_carries_no_content_length() {
    let mut server = TestServer::new_pingclairfile(&site(
        r#"cors https://app.example
            respond "ok""#,
    ));
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, body) = raw_http1(
        &server,
        b"OPTIONS / HTTP/1.1\r\nHost: test\r\nOrigin: https://app.example\r\n\
          Access-Control-Request-Method: GET\r\nConnection: close\r\n\r\n",
    )
    .await;
    server.stop();

    assert!(head.starts_with("http/1.1 204"), "{head}");
    assert!(!head.contains("\r\ncontent-length:"), "{head}");
    assert!(body.is_empty(), "a 204 carries no content: {body:?}");
}

/// 🚫 `respond "x" 204` over HTTP/2 sends no DATA and no `Content-Length`.
///
/// HTTP/2 has no transport rule that drops the byte the way HTTP/1.1 does, so
/// this is the transport where the handler's body actually reached the wire.
#[tokio::test]
async fn test_h2_respond_204_carries_no_content() {
    let mut server = TestServer::new_pingclairfile(&site(r#"respond "x" 204"#));
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = reqwest::Client::builder()
        .no_proxy()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let response = client.get(server.url(0, "/")).send().await.unwrap();
    let status = response.status().as_u16();
    let content_length = response.headers().get("content-length").cloned();
    let body = response.bytes().await.unwrap();
    server.stop();

    assert_eq!((status, content_length, body.len()), (204, None, 0));
}
