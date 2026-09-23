// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧾 The connection's first bytes decide which protocol it speaks — and a
//! request that is shorter than the h2c preface must still be answered.
//!
//! 🛡️ Detecting prior-knowledge HTTP/2 means reading the client preface, which
//! is 24 bytes. Asking for all 24 at once waits for bytes that a short request
//! will never send: `GET / HTTP/1.0\r\n\r\n` is 18 bytes and *complete*, so the
//! client waited for a response while the server waited for the rest of a
//! preface that was never coming. Nothing was answered and no socket closed —
//! the client sat there until its own timeout.
//!
//! These tests pin both halves of the contract: short and malformed requests
//! get an answer, and a real preface still opens an HTTP/2 connection.
//!
//! 📌 The three-second deadline in `read_one_response` is what makes the first
//! half a regression test rather than a description: the server used to send
//! nothing at all for these requests, and a test that waits for a response it
//! never gets is exactly how that reads from a client's side.

use super::TestServer;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 🧾 A Pingclairfile with a readiness route in front of a plain `respond`.
///
/// The listener is plaintext, which is what enables the h2c check in the first
/// place (`server_options.h2c = !is_https`), and `respond` keeps the answer
/// independent of any upstream.
fn site() -> String {
    r#"
    {
        admin off
    }

    :__PINGCLAIR_TEST_PORT__ {
        @readiness path __PINGCLAIR_TEST_READINESS_PATH__
        respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

        respond "ok"
    }
    "#
    .to_string()
}

/// ✅ Whether `bytes` already carry a whole response: the head, plus the body
/// its `Content-Length` promises. A connection that stays open afterwards is
/// the keep-alive case, not a missing response — which is why the reader below
/// cannot simply wait for EOF the way `read_http1_to_end` does.
fn response_is_complete(bytes: &[u8]) -> bool {
    let Some(head_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&bytes[..head_end]).to_ascii_lowercase();
    let length = head
        .split("\r\n")
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    bytes.len() >= head_end + 4 + length
}

/// 🔌 Sends raw bytes on a fresh connection and returns the head and body.
///
/// 📌 The deadline is the assertion: for the requests in this module the server
/// used to answer nothing and close nothing, so a reader that waits three
/// seconds is testing the same thing the client in the issue experienced.
async fn raw_exchange(server: &TestServer, request: &[u8]) -> (String, Vec<u8>) {
    let mut stream = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    stream.write_all(request).await.unwrap();

    let mut response = Vec::new();
    let mut chunk = [0u8; 1024];
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            // 📌 Checked before the read, not after: a request answered on a
            // keep-alive connection would otherwise wait here for a byte that
            // is never coming, and a correct response would read as a hang.
            if response_is_complete(&response) {
                break;
            }
            let read = stream.read(&mut chunk).await.expect("response read failed");
            if read == 0 {
                break;
            }
            response.extend_from_slice(&chunk[..read]);
        }
    })
    .await
    .expect("no HTTP/1 response within three seconds");

    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("a complete response head");
    (
        String::from_utf8_lossy(&response[..split]).to_ascii_lowercase(),
        response[split + 4..].to_vec(),
    )
}

/// 🚫 An HTTP/1.1 request with no `Host` is refused, not ignored.
///
/// 18 bytes: complete, and one byte into the preface at most. Caddy answers
/// this request with `400 Bad Request: missing required Host header`, and the
/// status is what a client branches on.
#[tokio::test]
async fn test_short_request_without_host_is_refused_not_ignored() {
    let mut server = TestServer::new_pingclairfile(&site());
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, _) = raw_exchange(&server, b"GET / HTTP/1.1\r\n\r\n").await;
    server.stop();

    assert!(head.starts_with("http/1.1 400"), "{head}");
}

/// 🚫 A request line with no version is refused, not ignored.
///
/// This one is 19 bytes and starts with an illegal request line, so Pingora's
/// own parser rejects it; the test exists because the h2c check runs before
/// that parser and used to stop the bytes from ever reaching it.
#[tokio::test]
async fn test_request_without_a_version_is_refused_not_ignored() {
    let mut server = TestServer::new_pingclairfile(&site());
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, _) = raw_exchange(&server, b"GET /\r\nHost: x\r\n\r\n").await;
    server.stop();

    assert!(head.starts_with("http/1.1 400"), "{head}");
}

/// 👍 HTTP/1.0 predates `Host` and is served without one.
///
/// 📌 Caddy answers `HTTP/1.0 200 OK` here and this build answers `HTTP/1.1
/// 200 OK`; the status and the body are what this test holds, and the version
/// line is a known difference rather than one this test should enshrine.
#[tokio::test]
async fn test_http10_request_without_host_is_served() {
    let mut server = TestServer::new_pingclairfile(&site());
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, body) = raw_exchange(&server, b"GET / HTTP/1.0\r\n\r\n").await;
    server.stop();

    assert!(head.starts_with("http/1.1 200"), "{head}");
    assert_eq!(body, b"ok");
}

/// 🔁 The short-request fix must not swallow a real h2c preface.
///
/// The check now reads the preface one byte at a time and rewinds each peek, so
/// this test is the other half of that change: a client that really does open
/// with the preface must still be handed to the HTTP/2 handshake. A server
/// answers the preface with a SETTINGS frame, which is what makes this
/// observable on the wire.
#[tokio::test]
async fn test_h2c_preface_still_opens_an_http2_connection() {
    let mut server = TestServer::new_pingclairfile(&site());
    assert!(server.wait_until_ready().await, "server failed to start");

    let mut stream = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    stream
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    // An empty SETTINGS frame completes the client preface (RFC 9113 §3.4).
    stream
        .write_all(&[0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await
        .unwrap();

    let mut frame = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut frame))
        .await
        .expect("the server answered the h2c preface with a frame")
        .unwrap();
    server.stop();

    assert_eq!(frame[3], 0x04, "the first frame is SETTINGS: {frame:?}");
    assert_eq!(
        &frame[5..9],
        &[0, 0, 0, 0],
        "SETTINGS opens stream 0: {frame:?}"
    );
}
