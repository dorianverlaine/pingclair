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

use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

/// 📮 An upstream that reads one request with a `Content-Length` body and
/// answers `200 ok`, so a test can see an upload arrive in full.
async fn spawn_answering_upstream() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let Ok(read @ 1..) = stream.read(&mut chunk).await else {
                        return;
                    };
                    seen.extend_from_slice(&chunk[..read]);
                    let text = String::from_utf8_lossy(&seen).to_ascii_lowercase();
                    let Some(head_end) = text.find("\r\n\r\n") else {
                        continue;
                    };
                    let length = text[..head_end]
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if seen.len() >= head_end + 4 + length {
                        break;
                    }
                }
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
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
    upload(server, 100, 10).await
}

/// 📤 Announces `announced` body bytes over h2c, sends `sent` of them at
/// once, ending the stream only when that is all of them, and reports how
/// the server ended the request.
async fn upload(server: &TestServer, announced: usize, sent: usize) -> Ended {
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
        .header(http::header::CONTENT_LENGTH, announced)
        .body(())
        .unwrap();
    let (response, mut send) = client.send_request(request, false).unwrap();
    send.send_data(bytes::Bytes::from(vec![b'x'; sent]), sent == announced)
        .unwrap();
    // 📌 `send` stays alive: a short body is followed by silence, not by an
    // end of stream.
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

/// 🐢 Pacing an upload to `upload_bytes_per_sec` is this server waiting, not
/// the client: a whole body sent at once and slowed to five seconds by the
/// rate limit must arrive, not be taken for a two-second stall.
#[tokio::test]
async fn test_a_paced_h2_upload_is_not_taken_for_a_stall() {
    let upstream = spawn_answering_upstream().await;
    let mut server = TestServer::new_pingclairfile(&site_with_limits(
        "body_timeout 2s\n upload_bytes_per_sec 1000",
        &format!("reverse_proxy 127.0.0.1:{upstream}"),
    ));
    assert!(server.wait_until_ready().await, "server failed to start");

    let ended = upload(&server, 5000, 5000).await;
    assert!(matches!(ended, Ended::Answered(200, _)), "{ended:?}");
}
