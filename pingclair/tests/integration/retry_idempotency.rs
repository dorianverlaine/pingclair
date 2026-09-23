// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔁 A retry after the origin has answered repeats only idempotent methods.
//!
//! Once an origin has seen a request, a retry is a second copy of it. An empty
//! body does not make that safe: `POST /orders/submit` with no body can still
//! place an order, and repeating it places two. The server here is configured
//! with a Pingclairfile that explicitly names `POST` in `lb_retry_match`, which
//! still loads — it just cannot make a POST happen twice.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{TestServer, no_proxy_client};

/// 🎛️ An origin that answers every request with a 503 and counts them by
/// method into shared counters, so a test can tell "retried" from "answered
/// once" across every backend of the route.
async fn spawn_unavailable_origin(
    post_counter: Arc<AtomicUsize>,
    get_counter: Arc<AtomicUsize>,
) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let (posts, gets) = (Arc::clone(&post_counter), Arc::clone(&get_counter));
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 16384];
                let Ok(read) = stream.read(&mut buffer).await else {
                    return;
                };
                if buffer[..read].starts_with(b"POST ") {
                    posts.fetch_add(1, Ordering::SeqCst);
                } else {
                    gets.fetch_add(1, Ordering::SeqCst);
                }
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            });
        }
    });
    address
}

/// 🛡️ A bodyless POST that a retry rule names is still sent only once.
///
/// The GET beside it is the control: the same rule, the same origin, the same
/// 503, and it is retried. Without it, "never retry anything" would pass.
#[tokio::test]
async fn test_named_bodyless_post_is_not_repeated_after_an_upstream_status() {
    // 🔁 Two backends, because a redispatch excludes the one that just failed:
    // with only one, a retry has nowhere to go and the test could not observe it.
    let posts = Arc::new(AtomicUsize::new(0));
    let gets = Arc::new(AtomicUsize::new(0));
    let first = spawn_unavailable_origin(Arc::clone(&posts), Arc::clone(&gets)).await;
    let second = spawn_unavailable_origin(Arc::clone(&posts), Arc::clone(&gets)).await;
    let config = format!(
        r#"
        {{
            admin off
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            reverse_proxy http://{first} http://{second} {{
                lb_retries 3
                lb_retry_match {{
                    method POST GET
                }}
            }}
        }}
        "#
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let response = client
        .post(server.url(0, "/orders/submit"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(
        posts.load(Ordering::SeqCst),
        1,
        "a POST the origin had already answered was sent to it again"
    );

    let response = client.get(server.url(0, "/orders")).send().await.unwrap();
    assert_eq!(response.status(), 503);
    assert!(
        gets.load(Ordering::SeqCst) >= 2,
        "the control GET was not retried, so this test proves nothing about POST"
    );
}
