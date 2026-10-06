// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚫 Malformed HTTP/1 input must receive an answer and release its connection.

use super::{TestServer, read_http1_to_end};
use tokio::io::AsyncWriteExt;

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
