// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🏷️ A 502 this proxy wrote says so (RFC 9209 `Proxy-Status`).
//!
//! 📌 Without the field, "the origin answered 502" and "this proxy could not
//! reach the origin" look identical to anyone reading the response. Each test
//! pins one side of that line: a generated error names this hop and why, and
//! a forwarded error is passed through untouched.

use super::TestServer;
use super::no_proxy_client;
use super::response_pipeline::spawn_scripted_origin;
use std::net::SocketAddr;

/// 🧾 A site that proxies everything to `upstream` with `transport` options.
fn proxy_site(upstream: SocketAddr, transport: &str) -> String {
    format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            reverse_proxy {upstream} {{
                transport http {{
                    {transport}
                }}
            }}
        }}
        "#
    )
}

/// 🔌 An address nothing listens on: bound once for a free port, then closed.
fn refused_address() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

/// ⌛ An origin that accepts connections and never answers them.
async fn silent_origin() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        // 🪝 Held rather than dropped, so the proxy sees silence, not a reset.
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    address
}

/// 🔌 A refused connection produces a 502 that names this hop and the cause.
#[tokio::test]
async fn test_refused_upstream_502_carries_proxy_status() {
    let mut server = TestServer::new_pingclairfile(&proxy_site(refused_address(), ""));
    assert!(server.wait_until_ready().await, "server failed to start");

    let reply = no_proxy_client()
        .get(server.url(0, "/"))
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), 502);
    assert_eq!(
        reply.headers().get("proxy-status").unwrap(),
        "pingclair; error=connection_refused"
    );
}

/// ⌛ An origin that never sends response headers produces a 504 that says
/// the response timed out, not that the connection failed.
#[tokio::test]
async fn test_upstream_response_timeout_carries_proxy_status() {
    let origin = silent_origin().await;
    let mut server =
        TestServer::new_pingclairfile(&proxy_site(origin, "response_header_timeout 300ms"));
    assert!(server.wait_until_ready().await, "server failed to start");

    let reply = no_proxy_client()
        .get(server.url(0, "/"))
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), 504);
    assert_eq!(
        reply.headers().get("proxy-status").unwrap(),
        "pingclair; error=http_response_timeout"
    );
}

/// 🚫 A 502 the origin sent itself is forwarded without a member from this
/// hop, because this hop did not generate it.
#[tokio::test]
async fn test_forwarded_upstream_502_carries_no_proxy_status() {
    let (origin, _hits) = spawn_scripted_origin(
        b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
    )
    .await;
    let mut server = TestServer::new_pingclairfile(&proxy_site(origin, ""));
    assert!(server.wait_until_ready().await, "server failed to start");

    let reply = no_proxy_client()
        .get(server.url(0, "/"))
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), 502);
    assert_eq!(reply.headers().get("proxy-status"), None);
}
