// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔌 A WebSocket handshake is recognised however the client spells its lists.
//!
//! `Connection` is a list field, so a client may split it over several field
//! lines. The upgrade probe used to read only the first line, and a request
//! it misread had its handshake stripped before reaching the origin.

use super::{TestServer, read_until_marker};
use tokio::io::AsyncWriteExt;

/// 🔌 A tunnel that loses one direction keeps the other until it ends.
///
/// RFC 9110 §15.2.2 says a `101` hands the connection to the upgraded protocol
/// rather than to HTTP, and RFC 9293 §3.6.1 lets a host keep sending in the
/// open direction after it reads a FIN: the tunnel is a byte pipe, and one
/// side finishing its own sending is not the end of the conversation. An
/// origin that speaks first after the client half-closes — a WebSocket close
/// frame, a last stream chunk — would otherwise be dropped silently.
#[tokio::test]
#[ignore = "pingora-proxy 0.9.0 ends an upgraded exchange when the request side \
            finishes (`if request_done && client_session.was_upgraded()` sets \
            response_done), and the tunnel loop has no embedder hook"]
async fn test_a_half_closed_upgrade_still_carries_the_origins_bytes() {
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let _ =
            read_until_marker(&mut stream, b"\r\n\r\n", std::time::Duration::from_secs(2)).await;
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .unwrap();
        // 🕰️ The client's FIN arrives while the origin is idle, so the payload
        // below is written to a connection the client has half-closed.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let written = stream.write_all(b"BACKEND-AFTER-CLIENT-FIN").await.is_ok();
        let _ = stream.shutdown().await;
        written
    });

    let config = format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            reverse_proxy http://{upstream_address}
        }}
        "#
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let mut client = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    client
        .write_all(
            format!(
                "GET /socket HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
                server.address(0)
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let response =
        read_until_marker(&mut client, b"\r\n\r\n", std::time::Duration::from_secs(2)).await;
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 101 "),
        "the tunnel must open before the half-close: {}",
        String::from_utf8_lossy(&response)
    );

    // 📤 The client has finished talking and closes its own sending only.
    client.shutdown().await.unwrap();
    let mut received = Vec::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::io::AsyncReadExt::read_to_end(&mut client, &mut received),
    )
    .await;
    let written = upstream_task.await.unwrap();
    server.stop();

    assert!(
        written,
        "the origin must still be able to write after the FIN"
    );
    assert!(
        read.is_ok(),
        "the client's read must end when the tunnel does, not hang"
    );
    assert_eq!(
        String::from_utf8_lossy(&received),
        "BACKEND-AFTER-CLIENT-FIN",
        "the bytes the origin wrote after the half-close must reach the client"
    );
}

/// 🔌 `Connection: keep-alive` then `Connection: Upgrade` still reaches the
/// origin as a handshake and gets its `101`.
///
/// 📌 Not also `Upgrade: websocket, h2c`: Pingora 0.9's own upstream
/// sanitiser (`is_websocket_upgrade_request` in `pingora-proxy`
/// `proxy_common.rs`, checked 2026-09-23) compares the whole first `Upgrade`
/// value with `websocket` and strips anything else, before this proxy's
/// filter runs.
#[tokio::test]
async fn test_websocket_upgrade_with_split_connection_reaches_the_origin() {
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let request =
            read_until_marker(&mut stream, b"\r\n\r\n", std::time::Duration::from_secs(2)).await;
        let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .unwrap();
        request
    });

    let config = format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            reverse_proxy http://{upstream_address}
        }}
        "#
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let mut client = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    client
        .write_all(
            format!(
                "GET /socket HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
                server.address(0)
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let response =
        read_until_marker(&mut client, b"\r\n\r\n", std::time::Duration::from_secs(2)).await;
    let response = String::from_utf8_lossy(&response).into_owned();
    let request = upstream_task.await.unwrap();
    let connection_names_upgrade = request
        .lines()
        .filter_map(|line| line.strip_prefix("connection:"))
        .any(|value| value.split(',').any(|token| token.trim() == "upgrade"));
    assert!(
        request.contains("\r\nupgrade: websocket\r\n") && connection_names_upgrade,
        "the handshake must reach the origin: {request}"
    );
    assert!(
        response.starts_with("HTTP/1.1 101"),
        "unexpected upgrade response: {response}"
    );
}
