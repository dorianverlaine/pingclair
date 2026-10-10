// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🤝 Cross-server parity: properties wanted because another server has them,
//! not because a clause of an RFC demands them.
//!
//! They live in this tree deliberately: a difference from the semantic
//! reference (nginx, per `docs/guardrails/config.md`) is a finding — just a
//! lower-priority one than a protocol violation — and a test is the cheapest
//! way to record that it was seen rather than missed. Each doc comment says
//! which server the expectation below was measured against; the ones recorded
//! while Caddy was the reference are re-based one at a time, and say so until
//! they are.

use super::{ScriptedUpstream, TestServer, raw_http1, site};
use crate::{no_proxy_client, read_until_marker};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 🧩 An unknown `{placeholder}` is left as written.
///
/// Caddy's replacer keeps a name it does not know, which is why a body
/// containing literal braces — JSON, JavaScript, documentation — survives it.
/// Replacing the unknown name with nothing is the one answer that silently
/// changes content the operator wrote.
///
/// 📌 This is the **frozen Caddyfile dialect's** replacer rule, not a decision
/// about new surface: the native language has no interpolation in literals
/// (`Format` carries dynamic values), so nothing here constrains it.
#[tokio::test]
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
/// ranges over. The first version of this comment claimed nginx does the
/// opposite; a measurement against 1.31.6 refuted it — `gzip_static on` answers
/// `206`, `Content-Encoding: gzip`, `Content-Range: bytes 0-9/56` over a 56-byte
/// sidecar — and the source says the same thing:
/// `ngx_http_gzip_static_module.c:250` sets `r->allow_ranges = 1` on the sidecar
/// it serves. Both references do what this test pins.
#[tokio::test]
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
///
/// ⏳ Re-base owed: measured against Caddy so far. nginx's h2 side of this —
/// whether the status reaches the client before the stream is reset — has not
/// been compared yet; the differential harness in `pingclair-tests` is where
/// that measurement belongs.
#[tokio::test]
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

/// 🧯 A truncated flushing route must not read as a complete HTTP/1.1
/// response.
///
/// This is the same origin break the HTTP/2 test above pins: the origin
/// declares 1 MiB, writes 256 KiB and hangs up. A route that asked for
/// immediate flushing drops the length so each chunk leaves as it is written
/// (#247), and a response whose head declares neither `Content-Length` nor
/// `Transfer-Encoding` is delimited by the close — which turns the very break
/// the client must notice into a clean end. Caddy relays the head it formed
/// with chunked framing instead, so the missing terminating chunk stays
/// visible.
///
/// 📌 nginx shares the rule that decides this: a proxied response whose length
/// is unknown to it is framed chunked to an HTTP/1.1 client, so a break before
/// the terminating chunk stays visible there too.
#[tokio::test]
async fn test_truncated_flushing_response_is_not_a_clean_h1_end() {
    let upstream = ScriptedUpstream::start(
        vec![
            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
              Content-Length: 1048576\r\n\r\n"
                .to_vec(),
            vec![b'x'; 256 * 1024],
        ],
        Duration::ZERO,
    )
    .await;
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "reverse_proxy 127.0.0.1:{} {{\n                flush_interval -1\n            }}",
        upstream.address.port()
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = no_proxy_client();
    let outcome = async {
        let response = client.get(server.url(0, "/")).send().await?;
        let status = response.status();
        let body = response.bytes().await?;
        Ok::<_, reqwest::Error>((status, body.len()))
    }
    .await;
    server.stop();

    match outcome {
        // The break reached the client — a failed body read is the signal.
        Err(_) => {}
        Ok((status, bytes)) => panic!(
            "the origin stopped 768 KiB short, yet the client read a complete \
             response: {status} {bytes} bytes"
        ),
    }
}

/// 🔁 A flushing route keeps its HTTP/1.1 connection for the next request.
///
/// `flush_interval -1` drops the length so chunks leave as they are written
/// (#247). A lengthless HTTP/1.1 response is close-delimited unless its head
/// says chunked, and a close-delimited response ends the connection: without
/// that framing every proxied response would pay a fresh TCP and TLS
/// handshake. Caddy and nginx both frame it as chunked and keep the
/// connection, and the second request on this one is the check.
#[tokio::test]
async fn test_flushing_route_keeps_its_h1_connection() {
    let upstream = ScriptedUpstream::start(
        vec![
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"
                .to_vec(),
        ],
        Duration::ZERO,
    )
    .await;
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "reverse_proxy 127.0.0.1:{} {{\n                flush_interval -1\n            }}",
        upstream.address.port()
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    let mut stream = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    stream
        .write_all(b"GET /one HTTP/1.1\r\nHost: test\r\n\r\n")
        .await
        .unwrap();
    let first = read_until_marker(&mut stream, b"hello", Duration::from_secs(5)).await;
    stream
        .write_all(b"GET /two HTTP/1.1\r\nHost: test\r\n\r\n")
        .await
        .unwrap();
    let second = read_until_marker(&mut stream, b"hello", Duration::from_secs(5)).await;
    server.stop();

    let first_head = String::from_utf8_lossy(&first).to_ascii_lowercase();
    assert!(
        first_head.contains("transfer-encoding: chunked"),
        "a lengthless HTTP/1.1 response must frame its body, not lean on the \
         close: {first_head}"
    );
    assert!(
        second
            .windows(b"HTTP/1.1 200".len())
            .any(|window| window == b"HTTP/1.1 200"),
        "the second response must arrive on the same connection"
    );
}

/// ⚖️ A zero weight means the upstream is not chosen.
///
/// No RFC clause covers load-balancer weights, so this is a parity check against
/// Caddy (which excludes a zero-weight upstream, caddyserver/caddy#6357) *and* the
/// repository's own fail-closed rule: an operator draining a backend for a
/// cutover is entitled to have the configuration mean what it says, and a
/// silently clamped weight is the one answer that satisfies neither reading.
///
/// 📌 nginx agrees, from the source: `ngx_http_upstream_round_robin.c:190–192`
/// copies `weight` into `effective_weight`, so a zero-weight peer never wins a
/// round — the same exclusion, reached by the same reading of the number.
#[tokio::test]
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

/// 🏷️ An upstream's `Server` field line reaches the client unchanged, and a
/// response this server wrote itself carries ours.
///
/// Caddy sets its own `Server` before the handler chain runs
/// (`modules/caddyhttp/server.go`) and its proxy then copies the upstream's
/// headers over it, so what a client sees is the origin's product string when
/// there is one and `Caddy` when there is not. This server inserted
/// `Pingclair` over whatever arrived, which is why monitoring that identifies
/// an origin, or a mixed fleet comparing nodes, saw something different
/// (#159).
///
/// 📌 nginx does the same two things: its upstream header table copies `Server`
/// into the response (`ngx_http_upstream.c:240–244`), and a locally generated
/// response carries its own product string (measured: `Server: nginx/1.31.6`).
#[tokio::test]
async fn test_the_upstreams_server_header_survives_the_proxy() {
    let upstream = ScriptedUpstream::start(
        vec![
            b"HTTP/1.1 200 OK\r\nServer: audit-upstream/u1\r\nContent-Length: 2\r\n\r\nok".to_vec(),
        ],
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

    let identifications: Vec<String> = head
        .lines()
        .filter(|line| line.to_ascii_lowercase().starts_with("server:"))
        .map(|line| line.trim().to_ascii_lowercase())
        .collect();
    assert_eq!(
        identifications,
        vec!["server: audit-upstream/u1".to_string()],
        "the origin's own product string must survive: {head}"
    );
    // 🤝 `Via` still names *this* intermediary, appended to whatever chain the
    // request already crossed — the token is our product name because that is
    // what the field is for (RFC 9110 §7.6.3).
    let via = head
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("via:"))
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(via.contains("1.1 pingclair"), "got: {via:?} in {head}");
}

/// 🏷️ A response this server produced itself still says so.
#[tokio::test]
async fn test_a_local_response_carries_our_server_header() {
    let mut server = TestServer::new_pingclairfile(&site(r#"respond "local""#));
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, _) = raw_http1(
        &server,
        b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    )
    .await;
    server.stop();

    let identifications: Vec<String> = head
        .lines()
        .filter(|line| line.to_ascii_lowercase().starts_with("server:"))
        .map(|line| line.trim().to_ascii_lowercase())
        .collect();
    assert_eq!(identifications, vec!["server: pingclair".to_string()]);
}

/// ✅ `header X v` produces one field line, even when the origin sent its own.
///
/// This is the recorded decision from pingclair#272: Caddy keeps both values,
/// this server replaces, and the verb says what it does. nginx keeps both too
/// (`ngx_http_add_header`, `ngx_http_headers_filter_module.c:568`, pushes onto
/// the response without touching the upstream's), and replacing a field there
/// takes `proxy_hide_header` plus `add_header` — so the difference is kept on
/// purpose rather than by accident. The test exists so the choice is visible to
/// whoever next reads the compatibility note.
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
///
/// 📌 nginx's model for when #257 is fixed: it reads request trailers and does
/// not forward them by default — `proxy_pass_trailers on` is the opt-in
/// (`ngx_http_proxy_module.c:385`, since 1.27.2) — and nginx/nginx#778 is the
/// same silent-drop report this test pins. So the reference agrees that
/// forwarding is opt-in; what it does not settle is what the *declared* case
/// should answer, which is ours to decide.
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
/// within `fail_timeout`, and Caddy lets the operator configure `max_fails`
/// and `fail_duration` — both of which are honoured now. The check asks for
/// the modest version: after a first failure, stop sending it new traffic.
#[tokio::test]
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
