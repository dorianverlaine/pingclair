// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔐 Fields an origin keeps out of a shared copy with `private="…"` or
//! `no-cache="…"`.
//!
//! RFC 9111 lets an origin say "store this response, but not these fields".
//! The cache honours that by removing the named fields from the stored copy.
//! Each test here names one way that removal can go wrong: a field that comes
//! back on a later path through the cache, or a field whose removal takes away
//! what kept two visitors' responses apart.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::cache::cache_pingclairfile;
use super::{TestServer, no_proxy_client};

/// 🎛️ An origin whose caching headers are chosen by the path, and whose body
/// is the request's `X-Account` (or `shared` without one).
///
/// - `/vary-private`: `Vary: X-Account` and `Cache-Control: private="Vary"`.
/// - `/no-cache-field`: `Cache-Control: no-cache="X-User-Token"` and a token.
/// - `/two-expires`: two `Expires` lines, `private="X-User-Token"`, a token and
///   an `ETag`; a request carrying `If-None-Match` is answered `304`.
async fn spawn_account_origin() -> (SocketAddr, Arc<AtomicUsize>) {
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
                    counter.fetch_add(1, Ordering::SeqCst);
                    let request = String::from_utf8_lossy(&buffer[..read]).to_string();
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_string();
                    let header = |name: &str| {
                        request.lines().find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            key.trim()
                                .eq_ignore_ascii_case(name)
                                .then(|| value.trim().to_string())
                        })
                    };
                    let body = header("x-account").unwrap_or_else(|| "shared".into());
                    let (status, headers) = match path.as_str() {
                        "/vary-private" => (
                            "200 OK",
                            "Vary: X-Account\r\nCache-Control: private=\"Vary\"\r\n",
                        ),
                        "/no-cache-field" => (
                            "200 OK",
                            "Cache-Control: no-cache=\"X-User-Token\"\r\n\
                             X-User-Token: first-visitor-secret\r\n",
                        ),
                        _ if header("if-none-match").is_some() => {
                            ("304 Not Modified", "ETag: \"v1\"\r\n")
                        }
                        _ => (
                            "200 OK",
                            "ETag: \"v1\"\r\n\
                             Expires: Thu, 01 Jan 2099 00:00:00 GMT\r\n\
                             Expires: Fri, 02 Jan 2099 00:00:00 GMT\r\n\
                             Cache-Control: private=\"X-User-Token\"\r\n\
                             X-User-Token: first-visitor-secret\r\n",
                        ),
                    };
                    let body = if status.starts_with("304") { "" } else { &body };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\n{headers}\
                         Connection: keep-alive\r\n\r\n{body}",
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

/// 🔀 `private="Vary"` must not erase what keeps two accounts apart.
///
/// The stored copy loses the `Vary` field, and the variance key used to be
/// computed from that stored copy — so it saw no `Vary` at all, and the second
/// account was served the first account's page.
#[tokio::test]
async fn test_private_vary_does_not_merge_two_accounts() {
    let (origin, _hits) = spawn_account_origin().await;
    let mut server = TestServer::new_pingclairfile(&cache_pingclairfile(origin, "60s"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let mut bodies = Vec::new();
    for account in ["alice", "bob"] {
        let response = client
            .get(server.url(0, "/vary-private"))
            .header("X-Account", account)
            .send()
            .await
            .unwrap();
        bodies.push(response.text().await.unwrap());
    }
    assert_eq!(bodies, ["alice", "bob"]);
}

/// 🔐 A field named by `no-cache="…"`, or stripped from a response stored
/// stale because of two `Expires` lines, is not served from the stored copy.
///
/// The `Expires` case reaches the stored copy through revalidation: the origin
/// answers `304`, and the response is assembled from what was stored.
#[tokio::test]
async fn test_stripped_fields_stay_stripped_on_every_stored_path() {
    let (origin, hits) = spawn_account_origin().await;
    let mut server = TestServer::new_pingclairfile(&cache_pingclairfile(origin, "60s"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let mut seen = Vec::new();
    for path in ["/no-cache-field", "/two-expires"] {
        let before = hits.load(Ordering::SeqCst);
        let miss = client.get(server.url(0, path)).send().await.unwrap();
        let _ = miss.text().await.unwrap();
        let reuse = client.get(server.url(0, path)).send().await.unwrap();
        seen.push((
            path,
            reuse.status().as_u16(),
            reuse.headers().get("x-user-token").cloned(),
            hits.load(Ordering::SeqCst) - before,
        ));
        let _ = reuse.text().await.unwrap();
    }

    // 🎯 `no-cache="…"` is stored fresh, so its reuse is a pure hit; the
    // `Expires` conflict is stored stale, so its reuse is one `304` round trip.
    assert_eq!(
        seen,
        [
            ("/no-cache-field", 200, None, 1),
            ("/two-expires", 200, None, 2)
        ]
    );
}
