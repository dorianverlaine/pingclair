// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔌 `CONNECT` on HTTP/1.1 (RFC 9110 §9.3.6).
//!
//! This server is a reverse proxy and opens no tunnels. Pingora used to refuse
//! `CONNECT` before any hook ran, with a bare 405 that named no allowed methods
//! and left no access-log line, while HTTP/3 answered 501. Now both transports
//! answer 405 with `Allow`, and the refusal is logged like any other request.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::TestServer;

/// 🔌 A `CONNECT` gets 405 with `Allow`, closes the connection, never reaches
/// the site's handler, and appears in the access log.
#[tokio::test]
async fn test_connect_is_refused_with_allow_and_logged() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("access.log");
    let config = format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            log {{
                output file {log}
                format json
            }}

            respond "origin" 200
        }}
        "#,
        log = log.display(),
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let url = server.url(0, "/");
    let address = url
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();

    let mut stream = tokio::net::TcpStream::connect(&address).await.unwrap();
    stream
        .write_all(b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
        .await
        .unwrap();
    // 🔌 Reading to the end also proves the connection closes: a tunnel
    // client's next bytes must never be parsed as another request.
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("the connection must close after a refused CONNECT")
        .unwrap();
    let response = String::from_utf8_lossy(&response).to_ascii_lowercase();
    assert!(
        response.starts_with("http/1.1 405"),
        "CONNECT must be refused with 405: {response}"
    );
    assert!(
        response.contains("\r\nallow: get, head, post, put, patch, delete, options\r\n"),
        "the 405 must name the methods this server serves: {response}"
    );
    assert!(
        !response.contains("origin"),
        "CONNECT must not reach the site's handler: {response}"
    );

    // 🕰️ The writer thread owns the sink, so the line lands shortly after.
    let mut logged = false;
    for _ in 0..50 {
        logged = std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .any(|line| line.contains("\"CONNECT\"") && line.contains("405"));
        if logged {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(logged, "the refused CONNECT must appear in the access log");
}
