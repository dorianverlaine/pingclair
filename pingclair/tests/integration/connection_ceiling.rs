// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚪 A configured `max_connections` is the listener's real ceiling.
//!
//! Parsing the knob is not evidence that it reaches `ResourceGuardedProxy`.
//! This holds one keep-alive connection open, asks for a second, and checks
//! that the second receives the documented 503 before the first is released.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{TestServer, read_until_marker};

async fn send_get(stream: &mut tokio::net::TcpStream, connection: &str) -> String {
    stream
        .write_all(
            format!("GET / HTTP/1.1\r\nHost: limit.test\r\nConnection: {connection}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .expect("write the request");
    String::from_utf8_lossy(&read_until_marker(stream, b"\r\n\r\n", Duration::from_secs(5)).await)
        .into_owned()
}

#[tokio::test]
async fn max_connections_is_enforced_from_the_configuration_file() {
    let config = r#"
        {
            admin off
        }

        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            limits {
                max_connections 1
            }
            respond "ok"
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");

    // The readiness client may still be dropping its keep-alive connection.
    // Retry until the one configured slot is actually free; otherwise the
    // test measures that probe rather than the held connection below.
    let mut held = None;
    for _ in 0..100 {
        let mut stream = tokio::net::TcpStream::connect(server.address(0))
            .await
            .expect("open the held connection");
        let first = send_get(&mut stream, "keep-alive").await;
        if first.starts_with("HTTP/1.1 200") {
            held = Some(stream);
            break;
        }
        drop(stream);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let held = held.expect("the configured slot never became available");

    let mut rejected = tokio::net::TcpStream::connect(server.address(0))
        .await
        .expect("connect the second client");
    let second = send_get(&mut rejected, "close").await;
    assert!(
        second.starts_with("HTTP/1.1 503") && second.contains("Connection limit"),
        "the configured ceiling must answer the excess connection: {second}"
    );
    let mut tail = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), rejected.read_to_end(&mut tail)).await;

    drop(held);
    let mut third = String::new();
    for _ in 0..100 {
        let mut next = tokio::net::TcpStream::connect(server.address(0))
            .await
            .expect("connect after releasing the slot");
        third = send_get(&mut next, "close").await;
        if third.starts_with("HTTP/1.1 200") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        third.starts_with("HTTP/1.1 200"),
        "the released slot must admit the next connection: {third}"
    );
}
