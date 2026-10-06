// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚫 Malformed HTTP/1 input must receive an answer and release its connection.

use super::{TestServer, read_http1_to_end};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn site() -> &'static str {
    r#"
    {
        admin off
    }
    :__PINGCLAIR_TEST_PORT__ {
        @ready path __PINGCLAIR_TEST_READINESS_PATH__
        respond @ready "__PINGCLAIR_TEST_READINESS_TOKEN__"
        respond "ok"
    }
    "#
}

async fn closed_exchange(server: &TestServer, request: &[u8]) -> (u16, String, Vec<u8>) {
    let mut stream = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    stream.write_all(request).await.unwrap();
    let response = read_http1_to_end(&mut stream).await;
    let split = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .expect("complete response header before EOF");
    let head = String::from_utf8_lossy(&response[..split]).to_ascii_lowercase();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, head, response[split + 4..].to_vec())
}

#[tokio::test]
async fn test_short_h1_requests_answer_and_close() {
    let mut server = TestServer::new_pingclairfile(site());
    assert!(server.wait_until_ready().await, "server failed to start");
    for (request, expected) in [
        (b"GET /\r\nHost: x\r\n\r\n".as_slice(), 400),
        (b"GET / HTTP/1.1\r\n\r\n".as_slice(), 400),
        (b"GET / HTTP/1.0\r\n\r\n".as_slice(), 200),
    ] {
        let (status, head, body) = closed_exchange(&server, request).await;
        assert_eq!(status, expected, "{request:?}: {head}");
        if status == 200 {
            assert!(head.starts_with("http/1.0 200"), "{head}");
            assert_eq!(body, b"ok");
        }
    }
    server.stop();
}

#[tokio::test]
async fn test_raw_space_in_request_target_is_refused_and_closed() {
    let mut server = TestServer::new_pingclairfile(site());
    assert!(server.wait_until_ready().await, "server failed to start");
    for request in [
        b"GET /a b HTTP/1.1\r\nHost: x\r\n\r\n".as_slice(),
        b"GET /a\tb HTTP/1.1\r\nHost: x\r\n\r\n".as_slice(),
    ] {
        let (status, head, _) = closed_exchange(&server, request).await;
        assert_eq!(status, 400, "{request:?}: {head}");
    }
    let (status, _, body) = closed_exchange(
        &server,
        b"GET /a%20b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!((status, body), (200, b"ok".to_vec()));
    server.stop();
}

#[tokio::test]
async fn test_malformed_chunked_body_is_a_client_error_and_closed() {
    let mut server = TestServer::new_pingclairfile(site());
    assert!(server.wait_until_ready().await, "server failed to start");
    for body in [
        b"zz\r\nhello\r\n0\r\n\r\n".as_slice(),
        b"5\nhello\n0\n\n".as_slice(),
    ] {
        let mut request =
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        request.extend_from_slice(body);
        let (status, head, body) = closed_exchange(&server, &request).await;
        assert_eq!((status, body), (400, b"400 Bad Request".to_vec()), "{head}");
        assert!(head.contains("\r\nconnection: close"), "{head}");
    }
    server.stop();
}

#[tokio::test]
async fn test_remaining_h1_parser_decisions_match_go() {
    let config = site().replace("respond \"ok\"", "respond \"{host}\"");
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");
    for (request, expected_status, expected_body) in [
        (
            b"GET http://example.com/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".as_slice(),
            200,
            b"example.com".as_slice(),
        ),
        (
            b"GET / HTTP/1.1\r\nHost: x\r\nX-A: one\r\n two\r\nConnection: close\r\n\r\n"
                .as_slice(),
            200,
            b"x".as_slice(),
        ),
        (
            b"\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n".as_slice(),
            400,
            b"400 Bad Request".as_slice(),
        ),
        (
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\nhello".as_slice(),
            501,
            b"501 Not Implemented".as_slice(),
        ),
        (
            b"GET / HTTP/9.9\r\nHost: x\r\n\r\n".as_slice(),
            505,
            b"505 HTTP Version Not Supported".as_slice(),
        ),
        (
            b"GET / HTTP/1.2\r\nHost: x\r\nConnection: close\r\n\r\n".as_slice(),
            200,
            b"x".as_slice(),
        ),
        (
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".as_slice(),
            405,
            b"".as_slice(),
        ),
    ] {
        let (status, head, body) = closed_exchange(&server, request).await;
        assert_eq!(
            (status, body),
            (expected_status, expected_body.to_vec()),
            "{request:?}: {head}"
        );
    }
    // 🌊 Unfolding must leave overread body bytes in place for the chunk parser.
    let (status, _, body) = closed_exchange(&server,
        b"POST / HTTP/1.1\r\nHost: x\r\nX-A: one\r\n two\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n").await;
    assert_eq!((status, body), (200, b"x".to_vec()));
    // 🛡️ Absolute form cannot hide an invalid original Host or duplicate fields.
    for request in [
        b"GET http://example.com/ HTTP/1.1\r\nHost: a/b\r\n\r\n".as_slice(),
        b"GET http://example.com/ HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n".as_slice(),
        b"GET http://user@example.com/ HTTP/1.1\r\nHost: x\r\n\r\n".as_slice(),
        b"GET http://example.com/ HTTP/1.1\r\nHost: \x0bx\r\n\r\n".as_slice(),
    ] {
        let (status, head, _) = closed_exchange(&server, request).await;
        assert_eq!(status, 400, "{head}");
    }
    server.stop();
}

#[tokio::test]
async fn test_malformed_host_characters_are_refused_and_closed() {
    let mut server = TestServer::new_pingclairfile(site());
    assert!(server.wait_until_ready().await, "server failed to start");
    for host in [
        "a/b", "a\\b", "a?b", "a#b", "a@b", "bad host", "a\"b", "a<b", "a>b", "a^b", "a`b", "a{b",
        "a|b", "a}b",
    ] {
        let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
        let (status, head, _) = closed_exchange(&server, request.as_bytes()).await;
        assert_eq!(status, 400, "Host {host:?}: {head}");
    }
    for host in [
        "example.test:80",
        "[::1]:80",
        "[fe80::1%25en0]:80",
        "a_b",
        "a,b",
    ] {
        let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        let (status, head, body) = closed_exchange(&server, request.as_bytes()).await;
        assert_eq!(
            (status, body),
            (200, b"ok".to_vec()),
            "Host {host:?}: {head}"
        );
    }
    server.stop();
}

#[tokio::test]
async fn test_empty_host_retains_its_measured_keepalive_exception() {
    let mut server = TestServer::new_pingclairfile(site());
    assert!(server.wait_until_ready().await, "server failed to start");
    let mut stream = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: \r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let mut bytes = [0u8; 1024];
        while !super::request_framing::response_is_complete(&response) {
            let read = stream.read(&mut bytes).await.unwrap();
            assert_ne!(read, 0, "empty Host closed before a complete 400");
            response.extend_from_slice(&bytes[..read]);
        }
    })
    .await
    .unwrap();
    let first = String::from_utf8_lossy(&response).to_ascii_lowercase();
    assert!(first.starts_with("http/1.1 400"), "{first}");
    assert!(first.contains("\r\nconnection: keep-alive"), "{first}");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_http1_to_end(&mut stream).await;
    let second = String::from_utf8_lossy(&response);
    assert!(second.starts_with("HTTP/1.1 200"), "{second}");
    assert!(second.ends_with("\r\n\r\nok"), "{second}");
    server.stop();
}
