// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ⏱️ An HTTP/2 upload that stops halfway is let go of when it goes to an
//! upstream, not only when a local handler reads it.
//!
//! Pingora's read timeout does nothing on an HTTP/2 stream, so a proxied or
//! FastCGI request body that stopped arriving was waited on forever, even with
//! `limits { body_timeout }` set: the stream, the upstream connection and a
//! FastCGI worker were all held for as long as the client liked. Each test
//! sends ten bytes of a hundred-byte body over h2c and then nothing.

use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;

use super::TestServer;

/// 🧾 A site whose route is written by the caller, with a two-second body
/// pause so the test does not wait out the one-minute default.
fn site(route: &str) -> String {
    site_with_limits("body_timeout 2s", route)
}

/// 🧾 A site with the caller's `limits` body and route.
fn site_with_limits(limits: &str, route: &str) -> String {
    format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            limits {{
                {limits}
            }}

            {route}
        }}
        "#
    )
}

/// 🕳️ An upstream that accepts connections and reads them forever without
/// answering, like an origin still waiting for the rest of an upload.
async fn spawn_patient_upstream() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut sink = [0u8; 4096];
                while matches!(stream.read(&mut sink).await, Ok(read) if read > 0) {}
            });
        }
    });
    port
}

/// ⏱️ How the stalled stream ended, and whether it ended near the deadline.
#[derive(Debug, PartialEq)]
enum Ended {
    /// The server answered with this status.
    Answered(u16, bool),
    /// The server reset the stream with this reason.
    Reset(h2::Reason, bool),
    /// Nothing had happened by the give-up time.
    StillOpen,
}

/// 🐌 Sends ten bytes of a hundred-byte body over h2c, keeps the stream open,
/// and reports how the server ended it.
async fn stall_an_upload(server: &TestServer) -> Ended {
    let downstream = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    let (mut client, connection) = h2::client::handshake(downstream).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("http://{}/upload.php", server.address(0)))
        .header(http::header::CONTENT_LENGTH, "100")
        .body(())
        .unwrap();
    let (response, mut send) = client.send_request(request, false).unwrap();
    send.send_data(bytes::Bytes::from_static(&[b'x'; 10]), false)
        .unwrap();
    // 📌 `send` stays alive and silent: no more DATA, no end of stream.
    let started = Instant::now();
    let response = tokio::time::timeout(Duration::from_secs(10), response).await;
    let near = (1.5..5.0).contains(&started.elapsed().as_secs_f64());
    match response {
        Err(_) => Ended::StillOpen,
        Ok(Ok(response)) => Ended::Answered(response.status().as_u16(), near),
        Ok(Err(error)) => Ended::Reset(error.reason().unwrap_or(h2::Reason::NO_ERROR), near),
    }
}

/// ⏱️ A proxied upload: Pingora reads it inside its own proxy loop, which
/// has no timer for HTTP/2, so the stream is reset at the pause instead.
#[tokio::test]
async fn test_a_proxied_h2_upload_that_stops_is_let_go() {
    let upstream = spawn_patient_upstream().await;
    let mut server =
        TestServer::new_pingclairfile(&site(&format!("reverse_proxy 127.0.0.1:{upstream}")));
    assert!(server.wait_until_ready().await, "server failed to start");

    assert_eq!(
        stall_an_upload(&server).await,
        Ended::Reset(h2::Reason::CANCEL, true)
    );
}

/// ⏱️ A FastCGI upload: this server reads that body itself, so it answers
/// `408` the way HTTP/1 does.
#[tokio::test]
async fn test_a_fastcgi_h2_upload_that_stops_is_answered_408() {
    let upstream = spawn_patient_upstream().await;
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "reverse_proxy 127.0.0.1:{upstream} {{\n transport fastcgi\n }}"
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    assert_eq!(stall_an_upload(&server).await, Ended::Answered(408, true));
}

/// 🌊 An immediate-flush route is a long connection, so its upload keeps the
/// `long_connections` idle timeout instead of the ordinary body pause, as on
/// HTTP/1. `off` means a quiet client stream is healthy and is never cut.
#[tokio::test]
async fn test_a_quiet_h2_stream_on_a_long_connection_keeps_idle_timeout_off() {
    let upstream = spawn_patient_upstream().await;
    let mut server = TestServer::new_pingclairfile(&site_with_limits(
        "body_timeout 2s\n long_connections {\n idle_timeout off\n }",
        &format!("reverse_proxy 127.0.0.1:{upstream} {{\n flush_interval -1\n }}"),
    ));
    assert!(server.wait_until_ready().await, "server failed to start");

    assert_eq!(stall_an_upload(&server).await, Ended::StillOpen);
}
