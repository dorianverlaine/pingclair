// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧬 The H1/H2 response pipeline decides per *final* response, not per request.
//!
//! 📌 Every test here fails the same way when the rule breaks: something that
//! belongs to one response (a compressor, a health verdict) is decided by a
//! different one — the stored copy in the cache, or an informational `103`
//! that arrived before the real answer.

use super::{TestServer, no_proxy_client, read_until_marker};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// 🧪 Starts an origin that answers every connection with `response` and
/// counts how many requests reached it.
async fn spawn_scripted_origin(response: Vec<u8>) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let response = Arc::new(response);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let counter = counter.clone();
            let response = response.clone();
            tokio::spawn(async move {
                read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(5)).await;
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (address, hits)
}

/// 📄 A single proxied site; `options` goes inside the `reverse_proxy` block.
fn proxy_pingclairfile(upstream: SocketAddr, options: &str) -> String {
    format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            reverse_proxy {upstream} {{
                {options}
            }}
        }}
        "#
    )
}

fn gunzip(bytes: &[u8]) -> String {
    use std::io::Read;
    let mut decoded = String::new();
    flate2::read::GzDecoder::new(bytes)
        .read_to_string(&mut decoded)
        .expect("the body must be valid gzip");
    decoded
}

/// 🗄️ A cached entry holds the origin's bytes, and compression is applied per
/// client on the way out.
///
/// The failure this guards: the body was compressed before the cache saw it,
/// while the headers were rewritten after, so the store held gzip bytes under
/// the origin's identity headers — including a `Content-Length` describing the
/// uncompressed body. A later client that never asked for gzip got gzip.
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
    let miss_bytes = miss.bytes().await.unwrap();
    assert_eq!(gunzip(&miss_bytes), body);

    let identity_hit = client.get(server.url(0, "/page")).send().await.unwrap();
    assert_eq!(identity_hit.status(), 200);
    assert!(
        identity_hit.headers().get("content-encoding").is_none(),
        "a client that asked for no coding must not be told about one"
    );
    assert_eq!(identity_hit.text().await.unwrap(), body);

    let gzip_hit = client
        .get(server.url(0, "/page"))
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(gzip_hit.headers().get("content-encoding").unwrap(), "gzip");
    assert_eq!(gunzip(&gzip_hit.bytes().await.unwrap()), body);

    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "both later requests must have been cache hits"
    );
}
