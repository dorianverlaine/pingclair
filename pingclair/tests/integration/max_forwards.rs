// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 `TRACE` and `Max-Forwards` on HTTP/1.1 (RFC 9110 §7.6.2).
//!
//! `Max-Forwards` is a hop budget: each proxy spends one, and the hop that
//! receives zero answers instead of forwarding. `TRACE` is refused outright,
//! because reflecting it would echo `Cookie` and `Authorization` back. The
//! origin here counts what reaches it, so "answered locally" means the origin
//! never saw the request.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{TestServer, no_proxy_client};

/// 🎛️ An origin that counts requests and answers with the `Max-Forwards`
/// value it received, or `none`.
async fn spawn_recording_origin(hits: Arc<AtomicUsize>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let hits = Arc::clone(&hits);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 16384];
                let Ok(read) = stream.read(&mut buffer).await else {
                    return;
                };
                hits.fetch_add(1, Ordering::SeqCst);
                let head = String::from_utf8_lossy(&buffer[..read]).to_string();
                let value = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("max-forwards")
                            .then(|| value.trim().to_string())
                    })
                    .unwrap_or_else(|| "none".to_string());
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{value}",
                    value.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    address
}

/// 🧭 `TRACE` is refused and a spent `OPTIONS` is answered here, neither one
/// reaching the origin; a live `OPTIONS` budget arrives one smaller.
#[tokio::test]
async fn test_max_forwards_is_checked_and_spent() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_recording_origin(Arc::clone(&hits)).await;
    let config = format!(
        r#"
        {{
            admin off
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            reverse_proxy http://{origin}
        }}
        "#
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();
    let url = server.url(0, "/probe");

    for (method, max_forwards, status) in [
        (reqwest::Method::TRACE, None, 405),
        (reqwest::Method::TRACE, Some("3"), 405),
        (reqwest::Method::OPTIONS, Some("0"), 200),
    ] {
        let mut request = client.request(method.clone(), &url);
        if let Some(value) = max_forwards {
            request = request.header("Max-Forwards", value);
        }
        let response = request.send().await.expect("request");
        let allow = response
            .headers()
            .get("allow")
            .map(|value| value.to_str().unwrap().to_string());
        assert_eq!(
            (response.status().as_u16(), allow.as_deref()),
            (status, Some("GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")),
            "{method} with Max-Forwards {max_forwards:?}"
        );
    }
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "nothing may reach the origin"
    );

    let forwarded = client
        .request(reqwest::Method::OPTIONS, &url)
        .header("Max-Forwards", "5")
        .send()
        .await
        .expect("request");
    assert_eq!(forwarded.status(), 200);
    assert_eq!(forwarded.text().await.unwrap(), "4");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}
