// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔁 A keepalive connection is retired after its configured request count.
//!
//! The bound is the reference's `keepalive_requests`: N requests on one
//! connection, then the N+1-th never happens. The tests below pin both the
//! configured number and the default the reference itself runs with.

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use super::TestServer;

/// 🔌 A site answering `ok`, with `keepaliveRequests:` when one is given.
fn responding_site(keepalive_requests: Option<u32>) -> String {
    let limits = keepalive_requests
        .map(|value| format!("\n.limits(keepaliveRequests: {value})\n"))
        .unwrap_or_default();
    format!(
        r#"
HTTPListener(on: "__PINGCLAIR_TEST_LISTEN__") {{
    Site(host: "*") {{
        Route(when: .path(exact: "__PINGCLAIR_TEST_READINESS_PATH__")) {{
            Respond(body: "__PINGCLAIR_TEST_READINESS_TOKEN__")
        }}
        Fallback {{ Respond(body: "ok") }}
    }}
}}
{limits}"#
    )
}

/// 📥 Reads one full HTTP/1 response and returns its head.
async fn read_response(reader: &mut BufReader<OwnedReadHalf>) -> String {
    let mut head = String::new();
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).await.unwrap();
        assert!(
            read > 0,
            "the connection closed before a complete header arrived: {head}"
        );
        if line == "\r\n" {
            break;
        }
        head.push_str(&line);
    }
    let content_length: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .expect("the response names its body length")
        .parse()
        .unwrap();
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).await.unwrap();
    head
}

async fn get(writer: &mut OwnedWriteHalf) {
    writer
        .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        .await
        .unwrap();
}

/// 🚦 Two requests are served; the second says the connection ends there.
#[tokio::test]
async fn keepalive_requests_retires_the_connection_after_the_bound() {
    let config = responding_site(Some(2));
    let mut server = TestServer::new_native(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let stream = TcpStream::connect(server.address(0)).await.unwrap();
    let (read_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    get(&mut writer).await;
    let first = read_response(&mut reader).await;
    assert!(
        !first.contains("Connection: close"),
        "the first request must keep the connection: {first}"
    );

    get(&mut writer).await;
    let second = read_response(&mut reader).await;
    assert!(
        second.contains("Connection: close"),
        "the second request is the last one the bound allows: {second}"
    );

    let mut trailing = [0u8; 1];
    let read = reader.read(&mut trailing).await.unwrap_or(0);
    assert_eq!(read, 0, "the connection must be closed after its bound");
}

/// 🔢 Without a written bound, the connection serves the reference's 1000.
#[tokio::test]
async fn the_default_bound_is_the_references_thousand_requests() {
    let config = responding_site(None);
    let mut server = TestServer::new_native(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let stream = TcpStream::connect(server.address(0)).await.unwrap();
    let (read_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    for served in 1..1000 {
        get(&mut writer).await;
        let head = read_response(&mut reader).await;
        assert!(
            !head.contains("Connection: close"),
            "request {served} must keep the connection: {head}"
        );
    }

    get(&mut writer).await;
    let last = read_response(&mut reader).await;
    assert!(
        last.contains("Connection: close"),
        "the thousandth request is the last one: {last}"
    );
    let mut trailing = [0u8; 1];
    let read = reader.read(&mut trailing).await.unwrap_or(0);
    assert_eq!(read, 0, "the connection must be closed after its bound");
}
