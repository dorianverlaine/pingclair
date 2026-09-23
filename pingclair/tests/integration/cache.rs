// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🗄️ What the response cache stores, and how long each entry lives.
//!
//! Every server here is configured with a Pingclairfile `cache { ttl }` block,
//! so the DSL adapter is on the path a real configuration takes. The tests ask
//! two questions: was a response stored at all, and — where it matters — did it
//! stop being served once its lifetime ran out. "Stored" alone is how a 503 got
//! pinned in cache for a whole route `ttl` without any test noticing.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{TestServer, no_proxy_client, origin_hits_for_two_requests};

/// 🗄️ Builds a Pingclairfile whose one route proxies to `upstream` and caches
/// for `ttl`, written exactly as an operator would write it.
fn cache_pingclairfile(upstream: SocketAddr, ttl: &str) -> String {
    format!(
        r#"
        {{
            admin off
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            reverse_proxy http://{upstream} {{
                cache {{
                    ttl {ttl}
                }}
            }}
        }}
        "#
    )
}

/// 🎛️ An origin whose status and caching headers are chosen by the path.
///
/// `/<status>/<headers>` answers with that status and the header set named by
/// the second segment, so each test states the exact response it is about in
/// the URL it requests. The body is a per-request counter, which is what lets
/// "served from cache" be told apart from "the origin answered the same way".
async fn spawn_status_origin() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 16384];
                loop {
                    let read = match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => read,
                    };
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let mut segments = path.trim_start_matches('/').split('/');
                    let status = segments.next().unwrap_or("200");
                    let headers = match segments.next().unwrap_or("none") {
                        "max-age" => "Cache-Control: max-age=300\r\n",
                        _ => "",
                    };

                    let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    let body = format!("origin-{n}");
                    let response = format!(
                        "HTTP/1.1 {status} Scripted\r\nContent-Length: {}\r\n{headers}Connection: keep-alive\r\n\r\n{body}",
                        body.len(),
                    );
                    if stream.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (address, hits)
}

/// 🚫 A status a cache must never store reaches the origin every time, even
/// when the origin claims a lifetime for it.
///
/// RFC 6585 forbids storing 428, 429, 431 and 511 unconditionally. 206 is
/// refused because this cache does not assemble ranges. Each row carries
/// `max-age=300`, which is the case that used to slip through: the freshness
/// directive alone was enough to store a "too many requests" page.
#[tokio::test]
async fn test_statuses_a_cache_must_not_store_are_refused_despite_max_age() {
    let (origin, hits) = spawn_status_origin().await;
    let mut server = TestServer::new_pingclairfile(&cache_pingclairfile(origin, "60s"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    // 🩺 The control: the same headers on a 200 are stored. Without it every
    // row below would also pass against a cache that never stores anything.
    assert_eq!(
        origin_hits_for_two_requests(&server, &client, &hits, "/200/max-age").await,
        1,
        "the control case must be cached, or the rest of this test proves nothing"
    );

    for status in [206, 428, 429, 431, 511] {
        assert_eq!(
            origin_hits_for_two_requests(&server, &client, &hits, &format!("/{status}/max-age"))
                .await,
            2,
            "a {status} must not be stored, whatever its Cache-Control says"
        );
    }
}
