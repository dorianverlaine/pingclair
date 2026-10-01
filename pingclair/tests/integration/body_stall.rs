// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ⏱️ A request body that never arrives is answered, not waited on forever.
//!
//! The client announces a body of nearly a terabyte and sends none of it. A
//! `respond` route reads the announced body before answering, and with no
//! timeout configured that read had no end: no response, and a connection held
//! for as long as the client liked. With the 1 MiB default ceiling gone, no
//! other check stops this request before the read.
//!
//! Both tests take about a minute, because the default is the thing under test.

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::TestServer;

/// 🧾 A site that answers everything locally and configures no timeout.
const SITE: &str = r#"
    {
        admin off
    }

    :__PINGCLAIR_TEST_PORT__ {
        @readiness path __PINGCLAIR_TEST_READINESS_PATH__
        respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

        respond "ok" 200
    }
"#;

/// 📏 The announced body length; none of it is ever sent.
const ANNOUNCED: &str = "999999999999";

/// ⏱️ Whether a stall was answered `408` inside the window around the 60 s
/// default, as one value so a failure shows both halves.
fn answered_at_default(status: u16, waited: Duration) -> (u16, bool) {
    (status, (55.0..70.0).contains(&waited.as_secs_f64()))
}

/// ⏱️ HTTP/1.1: Pingora's own per-read timer, which had no value to use.
#[tokio::test]
async fn test_a_body_that_never_arrives_is_answered_at_the_default() {
    let mut server = TestServer::new_pingclairfile(SITE);
    assert!(server.wait_until_ready().await, "server failed to start");

    let mut stream = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    let head = format!("POST / HTTP/1.1\r\nHost: test\r\nContent-Length: {ANNOUNCED}\r\n\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    let started = Instant::now();
    let mut response = Vec::new();
    let read =
        tokio::time::timeout(Duration::from_secs(90), stream.read_to_end(&mut response)).await;
    let waited = started.elapsed();

    assert!(read.is_ok(), "the stalled request was still held at 90 s");
    let status = String::from_utf8_lossy(&response)
        .strip_prefix("HTTP/1.1 ")
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    assert_eq!(
        answered_at_default(status, waited),
        (408, true),
        "answered after {waited:?}"
    );
}

/// ⏱️ HTTP/2 (h2c): Pingora ignores a read timeout on an HTTP/2 stream, so
/// this one needs its own timer and fails differently without it.
#[tokio::test]
async fn test_an_h2_body_that_never_arrives_is_answered_at_the_default() {
    let mut server = TestServer::new_pingclairfile(SITE);
    assert!(server.wait_until_ready().await, "server failed to start");

    let downstream = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    let (mut client, connection) = h2::client::handshake(downstream).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("http://{}/", server.address(0)))
        .header(http::header::CONTENT_LENGTH, ANNOUNCED)
        .body(())
        .unwrap();
    // 📌 The send half stays open and silent: no DATA, no end of stream.
    let (response, _send) = client.send_request(request, false).unwrap();
    let started = Instant::now();
    let response = tokio::time::timeout(Duration::from_secs(90), response).await;
    let waited = started.elapsed();

    let response = response
        .expect("the stalled stream was still held at 90 s")
        .unwrap();
    assert_eq!(
        answered_at_default(response.status().as_u16(), waited),
        (408, true),
        "answered after {waited:?}"
    );
}
