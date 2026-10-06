// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ⏳ A shared cache carries the origin's age instead of restarting its clock.

use super::cache::cache_pingclairfile;
use super::response_pipeline::spawn_scripted_origin;
use super::{TestServer, no_proxy_client, origin_hits_for_two_requests};
use std::sync::atomic::Ordering;

#[tokio::test]
async fn test_upstream_age_and_date_reduce_cache_freshness() {
    for headers in [
        "Cache-Control: max-age=60\r\nAge: 61\r\n",
        "Cache-Control: max-age=60\r\nDate: Tue, 01 Jan 2019 00:00:00 GMT\r\n",
        "Age: 61\r\n",
    ] {
        let (origin, hits) = spawn_scripted_origin(
            format!(
                "HTTP/1.1 200 OK\r\n{headers}Content-Length: 5\r\nConnection: close\r\n\r\nhello"
            )
            .into_bytes(),
        )
        .await;
        let mut server = TestServer::new_pingclairfile(&cache_pingclairfile(origin, "60s"));
        assert!(server.wait_until_ready().await);
        assert_eq!(
            origin_hits_for_two_requests(&server, &no_proxy_client(), &hits, "/old").await,
            2,
            "an already-aged response was reused as fresh: {headers}"
        );
    }
}

#[tokio::test]
async fn test_cache_hits_include_upstream_age() {
    let (origin, hits) = spawn_scripted_origin(
        b"HTTP/1.1 200 OK\r\nCache-Control: max-age=60\r\nAge: 57\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello".to_vec()
    ).await;
    let mut server = TestServer::new_pingclairfile(&cache_pingclairfile(origin, "60s"));
    assert!(server.wait_until_ready().await);
    let client = no_proxy_client();
    for _ in 0..2 {
        let response = client.get(server.url(0, "/fresh")).send().await.unwrap();
        let age = response.headers()["age"]
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert!(age >= 57, "a hit discarded the upstream Age: {age}");
        assert_eq!(response.text().await.unwrap(), "hello");
    }
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "a response with remaining freshness must still be cached"
    );
}

/// ⏳ Time waiting for an upstream header consumes the origin's stated lifetime.
#[tokio::test]
async fn test_upstream_response_delay_consumes_freshness() {
    use std::sync::{Arc, atomic::AtomicUsize};
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let counter = counter.clone();
            tokio::spawn(async move {
                super::read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(5)).await;
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(1100)).await;
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nCache-Control: max-age=1\r\nAge: 0\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello").await;
            });
        }
    });
    let mut server = TestServer::new_pingclairfile(&cache_pingclairfile(origin, "60s"));
    assert!(server.wait_until_ready().await);
    assert_eq!(
        origin_hits_for_two_requests(&server, &no_proxy_client(), &hits, "/slow").await,
        2
    );
}

/// 🔁 A 304 supplies the clock for cache hits and unstored validations.
#[tokio::test]
async fn test_revalidated_response_keeps_its_new_upstream_age() {
    use std::sync::{Arc, atomic::AtomicUsize};
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    for (cache_control, upstream_age, requests) in [
        ("max-age=60", 50u64, 3),
        ("no-store", 50, 2),
        ("max-age=60", 1 << 31, 2),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let counter = counter.clone();
                tokio::spawn(async move {
                    super::read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(5))
                        .await;
                    let first = counter.fetch_add(1, Ordering::SeqCst) == 0;
                    let response = if first {
                        b"HTTP/1.1 200 OK\r\nCache-Control: max-age=0\r\nAge: 10\r\nETag: \"v1\"\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello".to_vec()
                    } else {
                        format!("HTTP/1.1 304 Not Modified\r\nCache-Control: {cache_control}\r\nAge: {upstream_age}\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n").into_bytes()
                    };
                    let _ = stream.write_all(&response).await;
                });
            }
        });
        let mut server = TestServer::new_pingclairfile(&cache_pingclairfile(origin, "60s"));
        assert!(server.wait_until_ready().await);
        let client = no_proxy_client();
        for index in 0..requests {
            let response = client
                .get(server.url(0, "/revalidated"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            if index > 0 {
                let age = response.headers()["age"]
                    .to_str()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap();
                assert!(age >= upstream_age, "revalidation reset Age to {age}");
            }
            assert_eq!(response.text().await.unwrap(), "hello");
        }
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }
}

/// 🧮 A saturated upstream age must not become a metadata serialization failure.
#[tokio::test]
async fn test_extreme_upstream_age_remains_an_uncached_response() {
    let (origin, hits) = spawn_scripted_origin(
        b"HTTP/1.1 200 OK\r\nCache-Control: max-age=60\r\nAge: 184467440737095516160\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello".to_vec()
    ).await;
    let mut server = TestServer::new_pingclairfile(&cache_pingclairfile(origin, "60s"));
    assert!(server.wait_until_ready().await);
    assert_eq!(
        origin_hits_for_two_requests(&server, &no_proxy_client(), &hits, "/extreme").await,
        2
    );
}
