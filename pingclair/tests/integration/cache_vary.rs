// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🗄️ Every response Vary line and every nominated request field affect reuse.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{TestServer, cache::cache_pingclairfile, no_proxy_client};

/// 🧪 Counts origin visits while sending the exact Vary spelling under test.
async fn fixture(vary: &'static [u8]) -> (TestServer, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buffer = [0; 1024];
                while head.len() < 16 * 1024 && !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    let read = stream.read(&mut buffer).await.unwrap();
                    if read == 0 {
                        return;
                    }
                    head.extend_from_slice(&buffer[..read]);
                }
                let body = format!("origin-{}", counter.fetch_add(1, Ordering::SeqCst));
                let mut response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nCache-Control: max-age=300\r\n",
                    body.len()
                )
                .into_bytes();
                response.extend_from_slice(vary);
                response.extend_from_slice(b"Connection: close\r\n\r\n");
                response.extend_from_slice(body.as_bytes());
                stream.write_all(&response).await.unwrap();
            });
        }
    });
    let mut server = TestServer::new_pingclairfile(&cache_pingclairfile(address, "30s"));
    assert!(server.wait_until_ready().await);
    (server, hits)
}

/// 🔑 Identical first lines do not make differing later lines interchangeable.
async fn assert_distinct_variants(vary: &'static [u8]) {
    let (server, hits) = fixture(vary).await;
    let client = no_proxy_client();
    let fetch = async |languages: &[&str]| {
        let mut request = client.get(server.url(0, "/variant"));
        for language in languages {
            request = request.header("accept-language", *language);
        }
        request.send().await.unwrap().text().await.unwrap()
    };
    let english = fetch(&["en"]).await;
    let french = fetch(&["fr"]).await;
    let bilingual = fetch(&["en", "fr"]).await;
    assert_ne!(english, french, "the second Vary line must affect reuse");
    assert_ne!(
        english, bilingual,
        "the second request line must affect reuse"
    );
    assert_ne!(french, bilingual);
    assert_eq!(fetch(&["en"]).await, english);
    assert_eq!(fetch(&["fr"]).await, french);
    assert_eq!(fetch(&["en", "fr"]).await, bilingual);
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn every_vary_field_line_separates_cached_responses() {
    assert_distinct_variants(b"Vary: Accept-Encoding\r\nVary: Accept-Language\r\n").await;
}

#[tokio::test]
async fn every_request_field_line_separates_cached_responses() {
    assert_distinct_variants(b"Vary: Accept-Encoding, Accept-Language\r\n").await;
}

/// 🚫 An unreadable or wildcard later Vary line cannot become an ordinary hit.
#[tokio::test]
async fn invalid_or_wildcard_vary_is_not_stored() {
    for vary in [
        &b"Vary: Accept-Encoding\r\nVary: *\r\n"[..],
        &b"Vary: Accept-Encoding\r\nVary: \xff\r\n"[..],
        &b"Vary: Accept-Encoding\r\nVary: bad name\r\n"[..],
    ] {
        let (server, hits) = fixture(vary).await;
        let client = no_proxy_client();
        for _ in 0..2 {
            let response = client.get(server.url(0, "/invalid")).send().await.unwrap();
            assert_eq!(response.status(), 200);
            response.bytes().await.unwrap();
        }
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }
}
