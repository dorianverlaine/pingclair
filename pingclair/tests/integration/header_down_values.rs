// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🗄️ A proxy's `header_down` values resolve against the request, like every
//! other response-side value.

use super::{TestServer, read_until_marker};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// 🪞 An origin that answers a request with its own request head.
async fn echo_origin(requests: usize) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let origin = tokio::spawn(async move {
        for _ in 0..requests {
            let (mut stream, _) = listener.accept().await.unwrap();
            let head = read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(2)).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                head.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(&head).await.unwrap();
        }
    });
    (address, origin)
}

/// 🗄️ A proxy's `header_down` resolves against the request: `{host}` used to
/// be written to the client verbatim (the one path that stored its text
/// ready-made), which this pins for the Caddyfile spelling too.
#[tokio::test]
async fn proxy_header_down_values_resolve_against_the_request() {
    let (address, origin) = echo_origin(1).await;
    let source = format!(
        r#"
        {{
            admin off
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            reverse_proxy {address} {{
                header_down X-Test "{{host}}"
                header_down X-Plain "literal"
            }}
        }}
        "#
    );
    let mut server = TestServer::new_pingclairfile(&source);
    assert!(server.wait_until_ready().await, "server failed to start");

    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(server.url(0, "/"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers()["x-test"], "127.0.0.1");
    assert_eq!(response.headers()["x-plain"], "literal");
    origin.await.unwrap();
}
