// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🤝 Cross-server parity: properties wanted because Caddy or nginx has them,
//! not because a clause of an RFC demands them.
//!
//! They live in this tree deliberately. The authority order here is
//! RFC > Caddy > nginx, so "we differ from Caddy" is still a finding — just a
//! lower-priority one than a protocol violation. A test is the cheapest way to
//! record that the difference was seen rather than missed, and the doc comment
//! says plainly which server it is measured against.

use super::{ScriptedUpstream, TestServer, raw_http1, site};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 🧩 An unknown `{placeholder}` is left as written.
///
/// Caddy's replacer keeps a name it does not know, which is why a body
/// containing literal braces — JSON, JavaScript, documentation — survives it.
/// Replacing the unknown name with nothing is the one answer that silently
/// changes content the operator wrote.
#[tokio::test]
#[ignore = "pingclair#260 — the unknown placeholder is replaced with nothing"]
async fn test_unknown_placeholder_is_preserved() {
    let mut server = TestServer::new_pingclairfile(&site(r#"respond "open {brace} close""#));
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, body) = raw_http1(
        &server,
        b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    )
    .await;
    server.stop();

    assert!(head.starts_with("http/1.1 200"), "{head}");
    assert_eq!(
        body, b"open {brace} close",
        "text the operator wrote must not be rewritten"
    );
}

/// 🗜️ A ranged request for a precompressed file ranges over the compressed
/// representation.
///
/// Caddy answers `206` with `Content-Encoding: gzip` and a `Content-Range` over
/// the sidecar's length, so the representation a client negotiated is the one it
/// ranges over. This is a parity choice rather than an RFC requirement — nginx's
/// `gzip_static` serves the identity file for ranges — but it has to be a choice,
/// which is what this test records.
#[tokio::test]
#[ignore = "pingclair#254 — the identity representation is served instead"]
async fn test_precompressed_range_uses_the_compressed_representation() {
    use std::io::Write;

    let root = tempfile::tempdir().unwrap();
    let body = b"0123456789".repeat(200);
    std::fs::write(root.path().join("range.txt"), &body).unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&body).unwrap();
    let compressed = encoder.finish().unwrap();
    std::fs::write(root.path().join("range.txt.gz"), &compressed).unwrap();

    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "root * {}\n            file_server {{\n                precompressed gzip\n            }}",
        root.path().display()
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, _) = raw_http1(
        &server,
        b"GET /range.txt HTTP/1.1\r\nHost: test\r\nAccept-Encoding: gzip\r\n\
          Range: bytes=0-9\r\nConnection: close\r\n\r\n",
    )
    .await;
    server.stop();

    assert!(head.starts_with("http/1.1 206"), "{head}");
    assert!(
        head.contains("\r\ncontent-encoding: gzip"),
        "the negotiated representation is the one a range applies to: {head}"
    );
    assert!(
        head.contains(&format!("/{}", compressed.len())),
        "the range describes the sidecar, not the original: {head}"
    );
}

/// 🌊 A response with a known length still leaves the proxy as it is produced.
///
/// Caddy and nginx both stream a body whose length is declared; this check asks
/// the same of Pingclair, because a bounded event stream that declares its length
/// is otherwise silent until it ends. The origin here writes one event, waits,
/// then writes a second, and the assertion is about the first event's *arrival*
/// rather than the response's contents.
#[tokio::test]
#[ignore = "pingclair#247 — H1 holds a known-length body until it ends"]
async fn test_known_length_body_arrives_before_it_ends() {
    let events = b"data: one\n\ndata: two\n\n";
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n",
        events.len()
    );
    let first = [head.as_bytes(), b"data: one\n\n"].concat();
    let upstream = ScriptedUpstream::start(
        vec![first, b"data: two\n\n".to_vec()],
        Duration::from_millis(700),
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
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let first_event_arrived = tokio::time::timeout(Duration::from_millis(400), async {
        let mut seen = Vec::new();
        loop {
            let mut chunk = [0u8; 1024];
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return false,
                Ok(read) => {
                    seen.extend_from_slice(&chunk[..read]);
                    if seen.windows(9).any(|window| window == b"data: one") {
                        return true;
                    }
                }
            }
        }
    })
    .await;
    server.stop();

    assert_eq!(
        first_event_arrived,
        Ok(true),
        "a body produced incrementally must leave the proxy incrementally"
    );
}

/// 🧯 A truncated upstream still answers an HTTP/2 client.
///
/// Caddy's fix for this (caddyserver/caddy#7845) passes along the response head
/// it already formed; a stream reset with no status at all leaves the client —
/// and the operator reading the access log — with nothing to act on.
#[tokio::test]
#[ignore = "pingclair#249 — the H2 client receives a stream reset and no response"]
async fn test_truncated_upstream_answers_an_h2_client() {
    let upstream = ScriptedUpstream::start(
        vec![
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100\r\n\r\n0123456789"
                .to_vec(),
        ],
        Duration::ZERO,
    )
    .await;
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "reverse_proxy 127.0.0.1:{}",
        upstream.address.port()
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = reqwest::Client::builder()
        .no_proxy()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    // Whether the reset beats the response is a race inside the proxy, so one
    // request can pass by luck: whatever the scheduler does, no attempt may end
    // in a bare reset.
    let mut outcomes = Vec::new();
    for _ in 0..5 {
        outcomes.push(match client.get(server.url(0, "/")).send().await {
            Ok(response) => Ok(response.status().as_u16()),
            Err(error) => Err(error.to_string()),
        });
    }
    server.stop();

    for outcome in &outcomes {
        match outcome {
            Ok(status) => assert!(
                (200..600).contains(status),
                "the client must receive a status: {outcomes:?}"
            ),
            Err(error) => panic!("the client must not be left with a bare stream reset: {error}"),
        }
    }
}

/// ⚖️ A zero weight means the upstream is not chosen.
///
/// No RFC clause covers load-balancer weights, so this is a parity check against
/// Caddy (which excludes a zero-weight upstream, caddyserver/caddy#6357) *and* the
/// repository's own fail-closed rule: an operator draining a backend for a
/// cutover is entitled to have the configuration mean what it says, and a
/// silently clamped weight is the one answer that satisfies neither reading.
#[tokio::test]
#[ignore = "pingclair#266 — weight 0 is clamped to 1 and the drained backend keeps serving"]
async fn test_zero_weight_upstream_receives_no_traffic() {
    let drained = ScriptedUpstream::start(
        vec![b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()],
        Duration::ZERO,
    )
    .await;
    let live = ScriptedUpstream::start(
        vec![b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()],
        Duration::ZERO,
    )
    .await;
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "reverse_proxy 127.0.0.1:{} 127.0.0.1:{} {{\n                lb_policy weighted_round_robin 0 1\n            }}",
        drained.address.port(),
        live.address.port()
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    for _ in 0..6 {
        let _ = client.get(server.url(0, "/")).send().await;
    }
    let drained_head = drained.request_head().await;
    let live_head = live.request_head().await;
    server.stop();

    assert!(
        live_head.contains("GET /"),
        "the weighted upstream must receive traffic: {live_head:?}"
    );
    assert!(
        drained_head.is_empty(),
        "a zero-weight upstream must not be selected: {drained_head:?}"
    );
}

/// 🍪 Every `+Set-Cookie` written in one `header` block is sent.
///
/// Multiple cookies cannot be folded into one field (RFC 6265 §3 forbids it) and
/// repeated fields are ordinary HTTP (RFC 9110 §5.3), so a site that configures
/// two cookies has no way to express itself if the compiled shape keeps one value
/// per name. Caddy's block form emits both.
#[tokio::test]
#[ignore = "pingclair#276 — the second +Set-Cookie replaces the first inside one block"]
async fn test_header_block_keeps_every_set_cookie() {
    let mut server = TestServer::new_pingclairfile(&site(
        "header {\n                +Set-Cookie \"a=1; Path=/\"\n                +Set-Cookie \"b=2; Path=/\"\n            }\n            respond \"ok\"",
    ));
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, _) = raw_http1(
        &server,
        b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    )
    .await;
    server.stop();

    let cookies = head
        .lines()
        .filter(|line| line.starts_with("set-cookie:"))
        .count();
    assert_eq!(cookies, 2, "both configured cookies must be sent: {head}");
}

/// ✅ `header X v` produces one field line, even when the origin sent its own.
///
/// This is the recorded decision from pingclair#272: Caddy keeps both values,
/// this server replaces, and the verb says what it does. The test exists so the
/// choice is visible to whoever next reads the compatibility note.
#[tokio::test]
async fn test_header_set_yields_one_field_line() {
    let upstream = ScriptedUpstream::start(
        vec![b"HTTP/1.1 200 OK\r\nX-Test: from-origin\r\nContent-Length: 2\r\n\r\nok".to_vec()],
        Duration::ZERO,
    )
    .await;
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "reverse_proxy 127.0.0.1:{}",
        upstream.address.port()
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, _) = raw_http1(
        &server,
        b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    )
    .await;
    server.stop();

    let values = head
        .lines()
        .filter(|line| line.starts_with("x-test:"))
        .count();
    assert_eq!(values, 1, "one configured value, one field line: {head}");
}

/// 🧭 `uri` resolves placeholders in every operand, not just `replace`.
///
/// A Caddyfile that migrates cleanly and then strips nothing sends traffic to a
/// path the operator did not write — and `validate` says the file is fine. Caddy
/// resolves these operands, so a `strip_prefix` containing a named-matcher
/// capture is a directive that either works or should be refused.
#[tokio::test]
async fn test_uri_strip_prefix_resolves_placeholders() {
    let upstream = ScriptedUpstream::start(
        vec![b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()],
        Duration::ZERO,
    )
    .await;
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "@m {{\n                path_regexp sample ^/api/static/([^/]+)/.*$\n            }}\n            handle @m {{\n                uri strip_prefix /api/static/{{re.sample.1}}\n                reverse_proxy 127.0.0.1:{}\n            }}",
        upstream.address.port()
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    let mut stream = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::write_all(
        &mut stream,
        b"GET /api/static/plain/icon.jpg HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let _ = super::read_http1_to_end(&mut stream).await;
    let head = upstream.request_head().await;
    server.stop();

    assert!(
        head.starts_with("GET /icon.jpg "),
        "the captured prefix must be stripped: {head:?}"
    );
}

/// 📝 An origin that keeps every byte it was sent, body and trailer included.
///
/// The shared helper in this tree records only the request head, because every
/// other check here is about a header. A trailer question is about the body, so
/// this one reads on for a moment after the head and hands back the whole
/// transcript.
async fn recording_origin() -> (
    std::net::SocketAddr,
    std::sync::Arc<tokio::sync::Mutex<Vec<u8>>>,
) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind a recording origin");
    let address = listener.local_addr().expect("origin address");
    let transcript = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let recorder = std::sync::Arc::clone(&transcript);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let recorder = std::sync::Arc::clone(&recorder);
            tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut chunk = [0u8; 4096];
                // A short read window rather than a framing parser: the question
                // is whether the trailer bytes arrived at all, and a proxy that
                // drops them sends nothing to wait for.
                let _ = tokio::time::timeout(Duration::from_millis(400), async {
                    loop {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(read) => {
                                seen.extend_from_slice(&chunk[..read]);
                                if seen.ends_with(b"\r\n\r\n") && seen.len() > 8 {
                                    break;
                                }
                            }
                        }
                    }
                })
                .await;
                recorder.lock().await.extend_from_slice(&seen);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (address, transcript)
}

/// 🧾 An undeclared request trailer is forwarded or refused, never dropped.
///
/// RFC 9112 §7.1.2 makes the trailer section part of the chunked body, so a proxy
/// that forwards the body without it forwards a different message — and the
/// client is told `200 OK`. `aws-chunked` uploads put a checksum there and
/// announce it with `x-amz-trailer` rather than `Trailer:`, so the quiet path is
/// the one real clients take.
#[tokio::test]
#[ignore = "pingclair#257 — the trailer is dropped and the request is answered 200"]
async fn test_undeclared_request_trailer_is_not_silently_dropped() {
    let (address, transcript) = recording_origin().await;
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "reverse_proxy 127.0.0.1:{}",
        address.port()
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, _) = raw_http1(
        &server,
        b"POST /upload HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n\
          Content-Type: text/plain\r\nConnection: close\r\n\r\n\
          5\r\nhello\r\n0\r\nx-amz-checksum-crc64nvme: abc123\r\n\r\n",
    )
    .await;
    let seen = transcript.lock().await.clone();
    server.stop();

    let forwarded = seen
        .windows(25)
        .any(|window| window == b"x-amz-checksum-crc64nvme: ");
    let refused = !head.starts_with("http/1.1 2");
    assert!(
        forwarded || refused,
        "the trailer must reach the origin or the request must be refused: head={head:?} seen={:?}",
        String::from_utf8_lossy(&seen)
    );
}

/// 🩺 A backend that keeps failing in the response phase stops being chosen.
///
/// No RFC clause covers load-balancer health, so this is the repository's own
/// fail-closed rule plus Caddy/nginx parity: nginx ejects after `max_fails`
/// within `fail_timeout`, Caddy lets the operator configure `max_fails` and
/// `fail_duration`, and here the directives are refused at load — which makes the
/// default behaviour the only behaviour, and a permanently failing backend the
/// operator cannot retire. The check asks for the modest version: after a first
/// failure, stop sending it new traffic.
#[tokio::test]
#[ignore = "pingclair#262 — a truncating backend is chosen forever"]
async fn test_a_truncating_backend_stops_receiving_traffic() {
    let truncating = ScriptedUpstream::start(
        vec![
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100\r\n\r\n0123456789"
                .to_vec(),
        ],
        Duration::ZERO,
    )
    .await;
    let healthy = ScriptedUpstream::start(
        vec![b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()],
        Duration::ZERO,
    )
    .await;
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "reverse_proxy 127.0.0.1:{} 127.0.0.1:{}",
        truncating.address.port(),
        healthy.address.port()
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    for _ in 0..6 {
        let _ = client.get(server.url(0, "/")).send().await;
    }
    let bad = truncating.request_head().await;
    let good = healthy.request_head().await;
    server.stop();

    assert!(
        good.contains("GET /"),
        "the healthy backend must keep serving: {good:?}"
    );
    let bad_requests = bad.matches("GET /").count();
    assert!(
        bad_requests <= 1,
        "a backend that fails every response must be retired after the first: {bad_requests} requests"
    );
}
