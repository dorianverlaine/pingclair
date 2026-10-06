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
