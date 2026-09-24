// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📥 What a route's `request_body` does to the request it receives.
//!
//! `max_size` was the only subdirective this build implemented, so the other
//! three — `read_timeout`, `write_timeout` and `set` — were refused by name and
//! every configuration that used them failed to load. Each test here pins one
//! of them to an observable a client or an origin can see: the bytes an
//! upstream actually receives, and how long a stalled upload is allowed to
//! stall. A directive that parses but does nothing would pass no test in this
//! file.
//!
//! 📌 `set` is a body *substitution*, so its assertions are made at the origin:
//! the only proof the body changed is what arrived there — the length it
//! declared and the bytes it sent.
//!
//! 🌊 The large-upload case is here for the same reason: a replacement is the
//! shape that invites "read the body, then swap it", and a twenty-mebibyte
//! upload is what makes that mistake visible.

use super::TestServer;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 🔬 An origin that records the request line, the framing and the body, then
/// answers `ok`. The recorded text is what the tests assert on.
///
/// The body it reads is bounded by the length the request declares, so a
/// request that declares 20 MiB and sends 4 bytes cannot make this allocate
/// 20 MiB: it reads what arrives and reports the length it was promised.
async fn spawn_recording_origin() -> (
    std::net::SocketAddr,
    std::sync::Arc<tokio::sync::Mutex<Vec<String>>>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let log = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let recorder = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let recorder = recorder.clone();
            tokio::spawn(async move {
                // 🧾 Read the head, then exactly the length it declares. A
                // replacement is written as the request's final chunk and can
                // land in a segment of its own, so a single read would report
                // the head with an empty body and look like a server bug.
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 16 * 1024];
                // 📌 How many bytes this fixture still wants, once the head has
                // named a length. `None` until then, because the length is what
                // the head is for.
                let mut want: Option<usize> = None;
                loop {
                    let Ok(read) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                    if want.is_none()
                        && let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n")
                    {
                        let head = String::from_utf8_lossy(&buffer[..end]).to_string();
                        let declared = head
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())?
                            })
                            .unwrap_or(0);
                        // 🔒 Bounded by this fixture's own ceiling as well as by
                        // the declared length. These requests declare four or
                        // five bytes; the cap exists so that a server which
                        // forwards a twenty-mebibyte upload fails an assertion
                        // here instead of allocating twenty mebibytes in the
                        // test that was supposed to catch it.
                        want = Some(end + 4 + declared.min(64 * 1024));
                    }
                    if want.is_some_and(|total| buffer.len() >= total) {
                        break;
                    }
                }
                let received = String::from_utf8_lossy(&buffer).to_string();
                let (head, body) = received.split_once("\r\n\r\n").unwrap_or((&received, ""));
                let declared = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().to_string())
                    })
                    .unwrap_or_else(|| "-".to_string());
                // 🧾 The body is truncated on purpose. `set` never sends the
                // client's upload, so the assertion is about the replacement's
                // bytes, and the truncation keeps a bug that *does* forward the
                // upload from turning into a 20 MiB string in the log.
                let body = if body.len() > 128 { &body[..128] } else { body };
                recorder
                    .lock()
                    .await
                    .push(format!("content-length={declared} body={body}"));
                let answer = b"ok";
                let _ = stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\nok",
                            answer.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            });
        }
    });
    (address, log)
}

/// 🧾 A plaintext site that proxies everything to `upstream`, with the
/// `request_body` block the test is about written into it verbatim.
fn site(upstream: std::net::SocketAddr, request_body: &str) -> String {
    format!(
        r#"
    {{
        admin off
    }}

    :__PINGCLAIR_TEST_PORT__ {{
        @readiness path __PINGCLAIR_TEST_READINESS_PATH__
        respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

        {request_body}

        reverse_proxy 127.0.0.1:{}
    }}
    "#,
        upstream.port()
    )
}

/// 🧾 `set` replaces the body the origin receives, and declares its length.
#[tokio::test]
async fn test_pingclairfile_request_body_set_replaces_what_the_origin_receives() {
    let (upstream, recorded) = spawn_recording_origin().await;
    let mut server = TestServer::new_pingclairfile(&site(
        upstream,
        "request_body {\n            set \"hello\"\n        }",
    ));
    assert!(server.wait_until_ready().await, "server never became ready");

    let client = super::no_proxy_client();
    let response = client
        .post(server.url(0, "/"))
        .body("original body")
        .send()
        .await
        .expect("the proxied request must complete");
    assert_eq!(response.status(), 200);

    let log = recorded.lock().await.clone();
    assert_eq!(
        log,
        vec!["content-length=5 body=hello".to_string()],
        "the origin must receive the replacement, not the 13 bytes the client sent"
    );
    server.stop();
}

/// 🧾 The replacement is a template: placeholders are expanded for the request
/// that arrived, and the declared length follows the expansion.
#[tokio::test]
async fn test_pingclairfile_request_body_set_expands_placeholders() {
    let (upstream, recorded) = spawn_recording_origin().await;
    let mut server = TestServer::new_pingclairfile(&site(
        upstream,
        "request_body {\n            set \"method={http.request.method}\"\n        }",
    ));
    assert!(server.wait_until_ready().await, "server never became ready");

    let client = super::no_proxy_client();
    let response = client
        .post(server.url(0, "/"))
        .body("ignored")
        .send()
        .await
        .expect("the proxied request must complete");
    assert_eq!(response.status(), 200);

    let log = recorded.lock().await.clone();
    assert_eq!(
        log,
        vec!["content-length=11 body=method=POST".to_string()],
        "`{{http.request.method}}` must expand, and the length must be the expanded one"
    );
    server.stop();
}

/// 🌊 A twenty-mebibyte upload against a four-byte replacement.
///
/// The origin receiving four bytes is the assertion that matters: it can only
/// happen if the upload was discarded as it arrived rather than read into
/// memory and then swapped. The declared length is the replacement's, which is
/// the half a naive implementation gets wrong — forwarding the client's
/// `Content-Length` while sending different bytes hangs the origin.
#[tokio::test]
async fn test_pingclairfile_request_body_set_discards_a_large_upload_chunk_by_chunk() {
    const UPLOAD: usize = 20 * 1024 * 1024;
    let (upstream, recorded) = spawn_recording_origin().await;
    let mut server = TestServer::new_pingclairfile(&site(
        upstream,
        "request_body {\n            set \"tiny\"\n        }",
    ));
    assert!(server.wait_until_ready().await, "server never became ready");

    let client = super::no_proxy_client();
    let response = client
        .post(server.url(0, "/"))
        .body(vec![b'x'; UPLOAD])
        .send()
        .await
        .expect("the proxied request must complete");
    assert_eq!(response.status(), 200);

    let log = recorded.lock().await.clone();
    assert_eq!(
        log,
        vec!["content-length=4 body=tiny".to_string()],
        "a 20 MiB upload must reach the origin as the 4-byte replacement"
    );
    server.stop();
}

/// ⏱️ `read_timeout` bounds a stalled upload; without it the same client waits.
///
/// 📌 Both halves are asserted, because the deadline is the only thing that can
/// explain a response here: the site declares no `limits`, so nothing else in
/// the configuration is armed to answer at two seconds. Without the control the
/// test would pass for a server that drops every stalled upload immediately.
#[tokio::test]
async fn test_pingclairfile_request_body_read_timeout_cuts_a_stalled_upload() {
    let (upstream, _recorded) = spawn_recording_origin().await;

    // ⏱️ Half one: a stalled upload is answered once the deadline passes.
    let mut server = TestServer::new_pingclairfile(&site(
        upstream,
        "request_body {\n            read_timeout 1s\n        }",
    ));
    assert!(server.wait_until_ready().await, "server never became ready");
    let address = server.address(0);

    let mut stalled = tokio::net::TcpStream::connect(address).await.unwrap();
    stalled
        .write_all(
            b"POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 65536\r\nConnection: close\r\n\r\nab",
        )
        .await
        .unwrap();
    let started = Instant::now();
    let response = read_within(&mut stalled, Duration::from_secs(8)).await;
    let elapsed = started.elapsed();
    assert!(
        response.starts_with(b"HTTP/1.1 408"),
        "a stalled upload must be answered with 408, got: {:?}",
        String::from_utf8_lossy(&response)
    );
    assert!(
        elapsed < Duration::from_secs(8),
        "the deadline must fire on its own, not at the test's own limit: {elapsed:?}"
    );
    server.stop();

    // ⏱️ Half two: the same client, the same stall, no deadline declared.
    let mut server = TestServer::new_pingclairfile(&site(upstream, ""));
    assert!(server.wait_until_ready().await, "server never became ready");
    let address = server.address(0);
    let mut stalled = tokio::net::TcpStream::connect(address).await.unwrap();
    stalled
        .write_all(
            b"POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 65536\r\nConnection: close\r\n\r\nab",
        )
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(3), stalled.read(&mut [0u8; 64]))
            .await
            .is_err(),
        "nothing bounds a stalled body without `read_timeout`, so no answer may arrive"
    );
    server.stop();
}

/// ⏱️ Reads an HTTP/1 response with a caller-chosen ceiling.
///
/// The shared `read_http1_to_end` gives up after three seconds, which is the
/// right ceiling for a rejection that should be immediate and the wrong one for
/// a test that is *about* waiting: it would turn a deadline that never fired
/// into a panic about the response hanging rather than an assertion about the
/// status.
async fn read_within(stream: &mut tokio::net::TcpStream, ceiling: Duration) -> Vec<u8> {
    tokio::time::timeout(ceiling, async {
        let mut response = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) => break,
                Ok(read) => response.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                Err(error) => panic!("HTTP/1 response read failed: {error}"),
            }
        }
        response
    })
    .await
    .unwrap_or_default()
}
