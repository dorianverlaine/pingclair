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

use super::response_pipeline::{gunzip, proxy_pingclairfile, spawn_scripted_origin};
use super::{TestServer, no_proxy_client, origin_hits_for_two_requests};

/// 🗄️ Builds a Pingclairfile whose one route proxies to `upstream` and caches
/// for `ttl`, written exactly as an operator would write it.
pub(super) fn cache_pingclairfile(upstream: SocketAddr, ttl: &str) -> String {
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

/// 🗄️ The cache keeps origin bytes, while `encode gzip` decides each client's
/// representation on the way out. A gzip miss must not poison an identity hit.
#[tokio::test]
async fn test_cached_entry_is_stored_uncompressed_and_encoded_per_client() {
    let body = "cacheable and compressible text ".repeat(64);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let (origin, hits) = spawn_scripted_origin(response.into_bytes()).await;
    let mut server =
        TestServer::new_pingclairfile(&proxy_pingclairfile(origin, "cache {\n ttl 60s\n }"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let miss = client
        .get(server.url(0, "/page"))
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(miss.status(), 200);
    assert_eq!(miss.headers().get("content-encoding").unwrap(), "gzip");
    assert_eq!(gunzip(&miss.bytes().await.unwrap()), body);

    let identity_hit = client
        .get(server.url(0, "/page"))
        .header("Accept-Encoding", "identity")
        .send()
        .await
        .unwrap();
    assert_eq!(identity_hit.status(), 200);
    assert!(identity_hit.headers().get("content-encoding").is_none());
    assert_eq!(identity_hit.text().await.unwrap(), body);

    let gzip_hit = client
        .get(server.url(0, "/page"))
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(gzip_hit.status(), 200);
    assert_eq!(gzip_hit.headers().get("content-encoding").unwrap(), "gzip");
    assert_eq!(gunzip(&gzip_hit.bytes().await.unwrap()), body);

    assert_eq!(hits.load(Ordering::SeqCst), 1, "later replies must be hits");
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
                        "bad-max-age" => "Cache-Control: max-age=abc\r\n",
                        "bare-max-age" => "Cache-Control: max-age\r\n",
                        "two-expires" => {
                            "Expires: Thu, 01 Jan 2099 00:00:00 GMT\r\n\
                             Expires: Fri, 02 Jan 2099 00:00:00 GMT\r\n"
                        }
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

/// 🔢 Counts the origin requests behind `requests` sequential GETs for `path`.
async fn origin_hits_for(
    server: &TestServer,
    client: &reqwest::Client,
    hits: &AtomicUsize,
    path: &str,
    requests: usize,
) -> usize {
    let before = hits.load(Ordering::SeqCst);
    for _ in 0..requests {
        let response = client.get(server.url(0, path)).send().await.unwrap();
        let _ = response.bytes().await.unwrap();
    }
    hits.load(Ordering::SeqCst) - before
}

/// 🚫 A server error that states no lifetime is never stored.
///
/// The route asks for a minute. That minute is the operator's answer for
/// content, not for failures: holding an unannounced 503 for it would pin one
/// upstream hiccup in front of every visitor until the `ttl` ran out.
#[tokio::test]
async fn test_server_errors_without_a_stated_lifetime_are_not_stored() {
    let (origin, hits) = spawn_status_origin().await;
    let mut server = TestServer::new_pingclairfile(&cache_pingclairfile(origin, "60s"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    for status in [500, 502, 503, 504] {
        assert_eq!(
            origin_hits_for(&server, &client, &hits, &format!("/{status}/none"), 2).await,
            2,
            "a {status} with no caching headers must not be stored"
        );
    }
}

/// ⏳ A success the origin said nothing about lives exactly the route's `ttl`.
///
/// Two claims, both needed: it is served from cache inside the `ttl`, and the
/// origin is asked again once the `ttl` has passed.
#[tokio::test]
async fn test_a_silent_success_lives_for_the_route_ttl() {
    let (origin, hits) = spawn_status_origin().await;
    let mut server = TestServer::new_pingclairfile(&cache_pingclairfile(origin, "1s"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    assert_eq!(
        origin_hits_for(&server, &client, &hits, "/200/none", 2).await,
        1,
        "inside the ttl the second request must be a cache hit"
    );
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    assert_eq!(
        origin_hits_for(&server, &client, &hits, "/200/none", 1).await,
        1,
        "after the ttl the entry must be stale and the origin asked again"
    );
}

/// 🩹 A silent not-found lives ten seconds, not the route's `ttl`.
///
/// The route asks for a minute; a missing page held that long would hide a
/// newly published page for a minute. The short lifetime is the point.
#[tokio::test]
async fn test_a_silent_not_found_lives_seconds_not_the_route_ttl() {
    let (origin, hits) = spawn_status_origin().await;
    let mut server = TestServer::new_pingclairfile(&cache_pingclairfile(origin, "60s"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    assert_eq!(
        origin_hits_for(&server, &client, &hits, "/404/none", 2).await,
        1,
        "a repeated 404 must be absorbed by the cache"
    );
    tokio::time::sleep(std::time::Duration::from_millis(11_000)).await;
    assert_eq!(
        origin_hits_for(&server, &client, &hits, "/404/none", 1).await,
        1,
        "after ten seconds the 404 must be stale, even though the ttl is a minute"
    );
}

/// 📜 An unusable `max-age` does not set the route's `ttl` aside.
///
/// `max-age=abc` and a bare `max-age` state no lifetime anyone can use, so the
/// route's one-second `ttl` has to answer. It used to be skipped because the
/// token was present, leaving the entry alive for a 60-second placeholder
/// nobody configured.
#[tokio::test]
async fn test_an_unusable_max_age_falls_back_to_the_route_ttl() {
    let (origin, hits) = spawn_status_origin().await;
    let mut server = TestServer::new_pingclairfile(&cache_pingclairfile(origin, "1s"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    for path in ["/200/bad-max-age", "/200/bare-max-age"] {
        assert_eq!(
            origin_hits_for(&server, &client, &hits, path, 2).await,
            1,
            "{path} must still be cached, for the route's ttl"
        );
    }
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    for path in ["/200/bad-max-age", "/200/bare-max-age"] {
        assert_eq!(
            origin_hits_for(&server, &client, &hits, path, 1).await,
            1,
            "{path} must be stale once the route's ttl has passed"
        );
    }
}

/// 🔁 Two `Expires` lines make the response stale on arrival.
///
/// RFC 9111 §4.2.1 allows either the first value or "stale" here. This cache
/// chooses stale, so each request is rechecked with the origin, rather than
/// the response living a default lifetime neither answer allows.
#[tokio::test]
async fn test_conflicting_expires_is_treated_as_stale() {
    let (origin, hits) = spawn_status_origin().await;
    let mut server = TestServer::new_pingclairfile(&cache_pingclairfile(origin, "60s"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    assert_eq!(
        origin_hits_for(&server, &client, &hits, "/200/two-expires", 2).await,
        2,
        "a response with two Expires lines must be rechecked on every reuse"
    );
}
