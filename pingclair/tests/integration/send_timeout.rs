// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📮 The downstream write timeout: a stalled reader is cut, a slow one is not.
//!
//! The bound is per write, not over the whole response (the reference's
//! `send_timeout`, 60 s by default here). The two cases below are the whole
//! contract: a client that stops reading gives up the connection, and one that
//! reads slowly keeps it.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

use super::{TestServer, no_proxy_client};

/// 📦 A site serving `bytes` from a file, under the given write timeout.
fn payload_site(bytes: usize, send_timeout: &str) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("payload.bin"), vec![b'x'; bytes]).unwrap();
    let config = format!(
        r#"
HTTPListener(on: "__PINGCLAIR_TEST_LISTEN__") {{
    Site(host: "*") {{
        Route(when: .path(exact: "__PINGCLAIR_TEST_READINESS_PATH__")) {{
            Respond(body: "__PINGCLAIR_TEST_READINESS_TOKEN__")
        }}
        Fallback {{ ServeFiles(root: "{}") }}
    }}
}}
.limits(sendTimeout: {send_timeout})
"#,
        dir.path().display()
    );
    (dir, config)
}

/// 🚫 A reader that stops reading is cut, and the process stays up.
#[tokio::test]
async fn a_stalled_reader_loses_the_connection() {
    let (_dir, config) = payload_site(4 * 1024 * 1024, ".seconds(1)");
    let mut server = TestServer::new_native(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    // 📏 A deliberately tiny receive buffer: without it the loopback socket
    // buffers swallow the whole payload and no write ever stalls, so the test
    // would prove nothing about the bound.
    let stream = TcpSocket::new_v4().unwrap();
    stream.set_recv_buffer_size(4096).unwrap();
    let mut stream = stream.connect(server.address(0)).await.unwrap();
    stream
        .write_all(b"GET /payload.bin HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    // 🛑 Not reading: the socket buffers fill, the next write stalls, and the
    // one-second bound ends the connection. What the client can still read
    // afterwards is whatever the kernel buffered before the cut — the point is
    // that draining reaches an end without the payload.
    tokio::time::sleep(Duration::from_secs(4)).await;
    let mut seen = 0usize;
    let mut buffer = [0u8; 64 * 1024];
    let drained = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => seen += read,
            }
        }
    })
    .await;
    assert!(
        drained.is_ok(),
        "the connection must end once the reader stalls"
    );
    assert!(
        seen < 4 * 1024 * 1024,
        "a stalled reader must not receive the whole payload: {seen} bytes"
    );

    // 🩺 The server itself is untouched: the refusal was one connection, and
    // the next request is answered (a 404 for the directory is fine).
    let probe = no_proxy_client()
        .get(server.url(0, "/payload.bin"))
        .send()
        .await
        .unwrap();
    assert_eq!(probe.status(), 200);
}

/// 🐢 A reader that keeps reading keeps the connection, however slowly.
#[tokio::test]
async fn a_slow_reader_is_not_cut() {
    const BYTES: usize = 2 * 1024 * 1024;
    let (_dir, config) = payload_site(BYTES, ".seconds(1)");
    let mut server = TestServer::new_native(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let mut stream = TcpStream::connect(server.address(0)).await.unwrap();
    stream
        .write_all(b"GET /payload.bin HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    // 📉 64 KiB every 100 ms: far below the bound's threshold between writes,
    // and far above "the client went away".
    let mut seen = 0usize;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = stream.read(&mut buffer).await.unwrap();
        if read == 0 {
            break;
        }
        seen += read;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        seen >= BYTES,
        "headers plus payload must arrive in full: {seen} of {BYTES}"
    );
}

/// 🔌 `sendTimeout: .milliseconds(0)` turns the bound off.
///
/// The control for the first test: the same stall, the same window, and the
/// connection is still open — so the cut there came from the bound and not
/// from something else in the stack.
#[tokio::test]
async fn send_timeout_zero_keeps_the_connection_open() {
    let (_dir, config) = payload_site(4 * 1024 * 1024, ".milliseconds(0)");
    let mut server = TestServer::new_native(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let socket = TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(4096).unwrap();
    let mut stream = socket.connect(server.address(0)).await.unwrap();
    stream
        .write_all(b"GET /payload.bin HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(4)).await;
    let mut seen = 0usize;
    let mut buffer = [0u8; 64 * 1024];
    let drained = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => seen += read,
            }
        }
    })
    .await;
    assert!(drained.is_ok(), "the drain must end");
    assert!(
        seen >= 4 * 1024 * 1024,
        "with the bound off the payload is not cut: {seen} bytes"
    );
}
