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

/// 🔌 A `CONNECT` whose authority names no site gets the same refusal as one
/// that does, on HTTP/1.1 and on HTTP/2, and a target without a usable port is
/// a 400 (RFC 9110 §9.3.6).
///
/// The host-specific site is the point. An unmatched `CONNECT` used to get the
/// no-matching-site `200`, which told the client its tunnel was open, and on
/// HTTP/1.1 the bytes it then sent were served as the next request
/// (pingclair#283, RFC 9931 §8).
#[tokio::test]
async fn test_unmatched_connect_gets_the_matched_refusal() {
    let config = r#"
        {
            admin off
        }

        http://127.0.0.1:__PINGCLAIR_TEST_PORT__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "site-body" 200
        }
        "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");

    // 🔌 HTTP/1.1: each answer must be the only response on its connection,
    // whatever follows the `CONNECT` on the wire.
    let mut h1 = Vec::new();
    for (target, matched) in [
        ("elsewhere.test:443", false),
        ("elsewhere.test", false),
        ("127.0.0.1:443", true),
        ("127.0.0.1", true),
    ] {
        let mut stream = tokio::net::TcpStream::connect(server.address(0))
            .await
            .unwrap();
        stream
            .write_all(
                format!(
                    "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n\
                     GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
            .await
            .expect("the connection must close after a refused CONNECT")
            .unwrap();
        let response = String::from_utf8_lossy(&response).to_ascii_lowercase();
        h1.push((
            target,
            matched,
            response.get(..12).unwrap_or_default().to_string(),
            response.matches("http/1.1 ").count(),
            response.contains("site-body"),
        ));
    }
    assert_eq!(
        h1,
        [
            ("elsewhere.test:443", false, "http/1.1 405".into(), 1, false),
            ("elsewhere.test", false, "http/1.1 400".into(), 1, false),
            ("127.0.0.1:443", true, "http/1.1 405".into(), 1, false),
            ("127.0.0.1", true, "http/1.1 400".into(), 1, false),
        ]
    );

    // 🛰️ HTTP/2 without `:protocol` is the same request, and must not hear
    // that a tunnel is open either.
    let stream = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    let (mut client, connection) = h2::client::handshake(stream).await.unwrap();
    let driver = tokio::spawn(connection);
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("elsewhere.test:443")
        .body(())
        .unwrap();
    let (response, _) = client.send_request(request, true).unwrap();
    let status = response.await.unwrap().status().as_u16();
    driver.abort();
    server.stop();
    assert_eq!(status, 405, "an unmatched HTTP/2 CONNECT must be refused");
}
