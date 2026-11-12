// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚪 An upstream that stops reading ends the request at its write budget.
//!
//! The write timeout itself already fires inside Pingora. The defect this pins
//! is what happens next: the proxy kept waiting for a response the stalled
//! origin could not send, so the client received nothing and could hold the
//! request open indefinitely.

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{TestServer, read_until_marker};

/// 📤 Enough bytes to fill the loopback send and receive buffers.
const BODY_BYTES: usize = 8 * 1024 * 1024;

#[tokio::test]
async fn test_an_upstream_that_never_reads_ends_at_the_write_timeout() {
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let (release_upstream, wait_for_release) = tokio::sync::oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(2)).await;
        // 📌 Keep the connection open without reading another byte, so only the
        // proxy's write budget can end the client's wait.
        let _ = wait_for_release.await;
    });

    let config = format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            reverse_proxy http://{upstream_address} {{
                transport http {{
                    write_timeout 700ms
                }}
            }}
        }}
        "#
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    let (mut reader, mut writer) = client.into_split();
    writer
        .write_all(
            format!("POST /hang HTTP/1.1\r\nHost: test\r\nContent-Length: {BODY_BYTES}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();

    let upload = tokio::spawn(async move {
        let chunk = vec![b'u'; 64 * 1024];
        let mut sent = 0;
        while sent < BODY_BYTES {
            if writer.write_all(&chunk).await.is_err() {
                break;
            }
            sent += chunk.len();
        }
    });

    let started = Instant::now();
    let mut response = Vec::new();
    let read =
        tokio::time::timeout(Duration::from_secs(5), reader.read_to_end(&mut response)).await;
    let elapsed = started.elapsed();
    upload.abort();
    let _ = release_upstream.send(());
    upstream_task.await.unwrap();
    server.stop();

    assert!(
        read.is_ok(),
        "the client was still waiting after the 700ms write budget"
    );
    let status = String::from_utf8_lossy(&response)
        .strip_prefix("HTTP/1.1 ")
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    assert_eq!(
        status,
        504,
        "expected a gateway timeout, got {}",
        String::from_utf8_lossy(&response)
    );
    assert!(
        (Duration::from_millis(500)..Duration::from_secs(3)).contains(&elapsed),
        "the write budget answered after {elapsed:?}"
    );
}

/// 📬 A complete upstream answer that arrived before the write failed still
/// wins. The fix must not turn every upload write failure into a synthetic
/// gateway timeout when the origin already supplied the response.
#[tokio::test]
async fn test_an_upstream_answer_that_arrived_first_is_not_replaced() {
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(2)).await;
        stream
            .write_all(
                b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });

    let config = format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            reverse_proxy http://{upstream_address} {{
                transport http {{
                    write_timeout 700ms
                }}
            }}
        }}
        "#
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    let (mut reader, mut writer) = client.into_split();
    writer
        .write_all(
            format!(
                "POST /too-large HTTP/1.1\r\nHost: test\r\nContent-Length: {BODY_BYTES}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    // ⏱️ Let the upstream's complete answer reach Pingora before the client
    // starts the body that will fail. This test is specifically about response
    // precedence, not about which side wins an immediate close race.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let upload = tokio::spawn(async move {
        let chunk = vec![b'u'; 64 * 1024];
        while writer.write_all(&chunk).await.is_ok() {}
    });

    let mut response = Vec::new();
    let read =
        tokio::time::timeout(Duration::from_secs(5), reader.read_to_end(&mut response)).await;
    upload.abort();
    upstream_task.await.unwrap();
    server.stop();

    assert!(
        read.is_ok(),
        "the client was still waiting after the origin answered"
    );
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 413 "),
        "the origin's complete answer must win: {response}"
    );
}
