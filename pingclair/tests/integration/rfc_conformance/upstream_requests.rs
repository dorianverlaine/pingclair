// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ➡️ Requests this server generates towards an upstream.
//!
//! A proxy is a client too, so the same clauses that bind a browser bind the
//! probes and the forwarded request line: the target must be the one the client
//! asked for (RFC 3986 §6.2.2.3 names the normalization algorithm), and the
//! `Host` field must carry the authority the connection was made to
//! (RFC 9112 §3.2).

use super::{ScriptedUpstream, TestServer, site};
use std::time::Duration;

/// 🧭 The forwarded path keeps its interior empty segments.
///
/// RFC 3986 §6.2.2.3 points at `remove_dot_segments` (§5.2.4), which removes
/// complete `.` and `..` segments and leaves empty ones alone — §3.3 makes an
/// empty segment a segment. Collapsing `//` is a second, different rule, and it
/// rewrites the resource the client asked for: an upstream that signs or keys on
/// the raw target (SigV4, S3-style names, raw-path ACLs) sees a URL nobody
/// requested.
#[tokio::test]
#[ignore = "pingclair#275 — `/a//b` reaches the upstream as `/a/b`"]
async fn test_forwarded_path_keeps_interior_empty_segments() {
    let upstream = ScriptedUpstream::start(
        vec![b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()],
        Duration::ZERO,
    )
    .await;
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "reverse_proxy 127.0.0.1:{}",
        upstream.address.port()
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    let mut stream = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::write_all(
        &mut stream,
        b"GET /a//b HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let _ = super::read_http1_to_end(&mut stream).await;
    let head = upstream.request_head().await;
    server.stop();

    assert!(
        head.starts_with("GET /a//b "),
        "the request line must be the one the client sent: {head:?}"
    );
}

/// 🏷️ A health probe's `Host` carries the authority, port included.
///
/// RFC 9112 §3.2: a client "MUST send a field value for Host that is identical to
/// that authority component", and RFC 9110 §7.1 puts a non-default port in the
/// authority. A probe is a client request, and the backend most likely to care is
/// exactly the one behind a port-qualified vhost — where a probe with a bare
/// hostname 404s and the pool is retired while the application is healthy.
#[tokio::test]
#[ignore = "pingclair#271 — the probe sends `Host: 127.0.0.1` with no port"]
async fn test_health_probe_host_carries_the_authority() {
    let upstream = ScriptedUpstream::start(
        vec![b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()],
        Duration::ZERO,
    )
    .await;
    let port = upstream.address.port();
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "reverse_proxy 127.0.0.1:{port} {{\n                health_uri /healthz\n                health_interval 1s\n            }}"
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    // One interval is enough for a probe; the loop keeps the check honest if the
    // first tick lands before the pool is ready.
    let mut head = String::new();
    for _ in 0..40 {
        head = upstream.request_head().await;
        if !head.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    server.stop();

    let host = head
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("host:"))
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    assert_eq!(
        host,
        format!("host: 127.0.0.1:{port}"),
        "the probe's Host must be the authority it dialled: {head:?}"
    );
}

/// ✅ The probe target is the configured `health_uri`.
///
/// The net under the ignored check above: whatever the authority becomes, the
/// probe must still be a request to the path the operator configured. A fix for
/// the `Host` field that broke the probe shape would show up here.
#[tokio::test]
async fn test_health_probe_uses_the_configured_uri() {
    let upstream = ScriptedUpstream::start(
        vec![b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()],
        Duration::ZERO,
    )
    .await;
    let port = upstream.address.port();
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "reverse_proxy 127.0.0.1:{port} {{\n                health_uri /healthz\n                health_interval 1s\n            }}"
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    let mut head = String::new();
    for _ in 0..40 {
        head = upstream.request_head().await;
        if !head.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    server.stop();

    assert!(
        head.starts_with("GET /healthz "),
        "the probe must ask for the configured path: {head:?}"
    );
}
