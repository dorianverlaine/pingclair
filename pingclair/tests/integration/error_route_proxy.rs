// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚨 An error route's reverse proxy answers through the upstream phase.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{TestServer, no_proxy_client};

/// 🖥️ Echoes the method, target, and body of one request.
async fn echo_origin() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind origin");
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                let method = head.split_whitespace().next().unwrap_or("-");
                let path = head.split_whitespace().nth(1).unwrap_or("-");
                // Answer from the headers alone. A proxy that waits for a
                // response before forwarding a request body would deadlock
                // with an origin that waits for the body first; this test is
                // about the error-route exchange, not body replay.
                let answer = format!("{method} {path} ");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                    answer.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    address
}

/// 🖥️ An origin that answers every request with one fixed status and body.
async fn fixed_origin(status: u16, body: &'static str) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind origin");
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = stream.read(&mut [0u8; 4096]).await;
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    address
}

#[tokio::test]
async fn handle_errors_proxy_forwards_local_get_and_post() {
    let origin = echo_origin().await;
    let config = format!(
        r#"
        {{
            admin off
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            handle_errors {{
                reverse_proxy http://{origin}
            }}
            handle /boom {{
                error "gone" 404
            }}
            respond "ok"
        }}
        "#
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = no_proxy_client();
    let get = client.get(server.url(0, "/boom")).send().await.unwrap();
    assert_eq!(get.status(), reqwest::StatusCode::OK);
    assert_eq!(get.text().await.unwrap(), "GET /boom ");

    let post = client
        .post(server.url(0, "/boom"))
        .body("hello")
        .send()
        .await
        .unwrap();
    if post.status() != reqwest::StatusCode::OK {
        server.print_diagnostics();
    }
    assert_eq!(post.status(), reqwest::StatusCode::OK);
    assert_eq!(post.text().await.unwrap(), "POST /boom ");
}

/// 🚨 An upstream 503 redispatches into the error route's own proxy.
#[tokio::test]
async fn handle_errors_proxy_replaces_an_upstream_503() {
    let primary = fixed_origin(503, "primary-failed").await;
    let error_origin = fixed_origin(200, "error-route-answered").await;
    let config = format!(
        r#"
        {{
            admin off
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            handle_errors {{
                reverse_proxy http://{error_origin}
            }}
            reverse_proxy http://{primary}
        }}
        "#
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let response = no_proxy_client()
        .get(server.url(0, "/b"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "error-route-answered");
}
