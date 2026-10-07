// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧾 Response framing: the length a response declares and the bytes it sends.
//!
//! A mismatch is worse than it sounds. On HTTP/1.1 the connection can absorb it
//! (the writer truncates, or the close delimits the body), but HTTP/2 and HTTP/3
//! carry the length in a field the client is required to check, so the client —
//! not the server — is where the failure lands.

use super::{ScriptedUpstream, TestServer, raw_http1, site};
use std::time::Duration;

/// 🚫 A `Content-Length` this server cannot honour is not written.
///
/// RFC 9110 §8.6: a sender "MUST NOT" send a `Content-Length` that differs from
/// the message content, and RFC 9113 §8.1.1 makes a client treat the mismatch as
/// a stream error. Refusing the configuration, dropping the operator-set field,
/// or rewriting it from the body are all acceptable answers; sending the pair as
/// written is not, because the client pays for it with a reset connection.
#[tokio::test]
async fn test_h2_declared_length_matches_the_body() {
    let mut server = TestServer::new_pingclairfile(&site(
        "handle /cl/* {\n                header Content-Length \"3\"\n                respond \"0123456789\"\n            }",
    ));
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = reqwest::Client::builder()
        .no_proxy()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let response = match client.get(server.url(0, "/cl/x")).send().await {
        Ok(response) => response,
        Err(error) => {
            server.stop();
            panic!("an HTTP/2 response must be readable rather than reset: {error}");
        }
    };
    let declared: usize = response
        .headers()
        .get("content-length")
        .expect("the response declares a length")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let body = match response.bytes().await {
        Ok(body) => body,
        Err(error) => {
            server.stop();
            panic!("the declared length and the body must agree: {error}");
        }
    };
    server.stop();

    assert_eq!(
        body.len(),
        declared,
        "RFC 9110 §8.6 forbids announcing a length the body does not have"
    );
}

/// ✅ A proxied body keeps the length its origin declared.
///
/// The net under the ignored check above: this is the ordinary path — an origin
/// that states a length and sends exactly that many bytes — and no later change
/// to length handling may break it.
#[tokio::test]
async fn test_proxied_body_length_matches_its_header() {
    let upstream = ScriptedUpstream::start(
        vec![b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec()],
        Duration::ZERO,
    )
    .await;
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "reverse_proxy 127.0.0.1:{}",
        upstream.address.port()
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, body) = raw_http1(
        &server,
        b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    )
    .await;
    server.stop();

    assert!(head.starts_with("http/1.1 200"), "{head}");
    assert!(head.contains("\r\ncontent-length: 5"), "{head}");
    assert_eq!(body, b"hello", "the body must be exactly what was declared");
}

/// 🚫 A proxied `204` carries no `Content-Length`.
///
/// RFC 9110 §8.6: "A server MUST NOT send a Content-Length header field in any
/// response with a status code of 1xx (Informational) or 204 (No Content)". The
/// field is the origin's mistake to make; forwarding it makes it ours, and an
/// HTTP/1.1 client that believes the announced length on a bodiless status waits
/// for bytes that never arrive.
#[tokio::test]
async fn test_proxied_204_carries_no_content_length() {
    let upstream = ScriptedUpstream::start(
        vec![b"HTTP/1.1 204 No Content\r\nContent-Length: 42\r\n\r\n".to_vec()],
        Duration::ZERO,
    )
    .await;
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "reverse_proxy 127.0.0.1:{}",
        upstream.address.port()
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, body) = raw_http1(
        &server,
        b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    )
    .await;
    server.stop();

    assert!(head.starts_with("http/1.1 204"), "{head}");
    assert!(
        !head.contains("\r\ncontent-length:"),
        "RFC 9110 §8.6 forbids a length on a 204: {head}"
    );
    assert!(body.is_empty(), "a 204 carries no content: {body:?}");
}

/// 🏷️ A configured `ETag` is the validator that decides a conditional request.
///
/// RFC 9110 §13.1.2 compares `If-None-Match` against "the entity tag of the
/// selected representation", and §8.8.3 makes the `ETag` field that tag's only
/// carrier. A server that advertises one tag and compares another makes its own
/// advertisement useless — the client is told which version it holds and then
/// answered as if it had said something else.
#[tokio::test]
#[ignore = "pingclair#265 — the advertised tag never revalidates; an internal tag nobody saw does"]
async fn test_configured_etag_is_the_validator() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("file.txt"), b"payload\n").unwrap();
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "root * {}\n            header Etag \"\\\"probe-tag\\\"\"\n            file_server",
        root.path().display()
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, _) = raw_http1(
        &server,
        b"GET /file.txt HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(head.contains("etag: \"probe-tag\""), "{head}");

    let (conditional, _) = raw_http1(
        &server,
        b"GET /file.txt HTTP/1.1\r\nHost: test\r\nIf-None-Match: \"probe-tag\"\r\n\
          Connection: close\r\n\r\n",
    )
    .await;
    server.stop();

    assert!(
        conditional.starts_with("http/1.1 304"),
        "the tag the client was given must be the one that matches: {conditional}"
    );
}

/// 📏 A `HEAD` describes the response the same request would get with `GET`.
///
/// RFC 9110 §9.3.2 asks for the same header fields, and §8.6 requires a
/// `Content-Length` to state the length of the content *this* response carries.
/// When the `GET` is compressed and the `HEAD` announces the identity length, a
/// client that sizes a download with `HEAD` is told a number that no response
/// will ever have.
#[tokio::test]
#[ignore = "pingclair#264 — the HEAD announces the identity length while the GET is gzip"]
async fn test_head_describes_the_same_response_as_get() {
    let body = b"hello text body\n".repeat(400);
    let upstream = ScriptedUpstream::start(
        vec![
            [
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
                body.as_slice(),
            ]
            .concat(),
        ],
        Duration::ZERO,
    )
    .await;
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "encode gzip\n            reverse_proxy 127.0.0.1:{}",
        upstream.address.port()
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    let (get_head, get_body) = raw_http1(
        &server,
        b"GET / HTTP/1.1\r\nHost: test\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    )
    .await;
    let (head_head, _) = raw_http1(
        &server,
        b"HEAD / HTTP/1.1\r\nHost: test\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    )
    .await;
    server.stop();

    assert!(get_head.contains("content-encoding: gzip"), "{get_head}");
    let declared = head_head
        .lines()
        .find(|line| line.starts_with("content-length:"))
        .map(|line| {
            line.trim_start_matches("content-length:")
                .trim()
                .to_string()
        });
    if let Some(declared) = declared {
        assert_eq!(
            declared.parse::<usize>().unwrap(),
            get_body.len(),
            "a HEAD may not announce a length no GET would send: {head_head}"
        );
    }
}

/// 🧾 A declared upstream trailer is not a gateway error.
///
/// RFC 9110 §15.6.3 reserves `502` for an *invalid* response from the upstream,
/// and RFC 9112 §7.1.2 makes the trailer section part of the chunked coding. An
/// origin that announces a trailer and then omits it is still answering validly,
/// so the client should see the origin's status — and the same bytes already
/// relay when the origin forgets to announce them, which is the tell that this is
/// a policy trigger rather than a parsing limit.
#[tokio::test]
async fn test_declared_upstream_trailer_is_not_a_gateway_error() {
    let upstream = ScriptedUpstream::start(
        vec![
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\
               Trailer: X-Checksum\r\n\r\n5\r\nhello\r\n0\r\nX-Checksum: abc123\r\n\r\n"
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

    let (head, _) = raw_http1(
        &server,
        b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    )
    .await;
    server.stop();

    assert!(
        head.starts_with("http/1.1 200"),
        "a valid chunked response must not become a 502: {head}"
    );
}

/// 🧱 An HTTP/1.0 client is not sent HTTP/1.1 framing.
///
/// RFC 9112 §6.1: "A server MUST NOT send a response containing Transfer-Encoding
/// unless the corresponding request indicates HTTP/1.1 (or later minor
/// revisions)", and §2.3 asks that a message sent to an HTTP/1.0 recipient be
/// interpretable as valid HTTP/1.0. An unknown-length body therefore reaches a
/// 1.0 client as `Content-Length` or as a close-delimited body — never as chunk
/// sizes the client will read as content.
#[tokio::test]
async fn test_http10_client_is_not_sent_chunked_framing() {
    let upstream = ScriptedUpstream::start(
        vec![
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n\
               5\r\nhello\r\n0\r\n\r\n"
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

    let (head, body) = raw_http1(&server, b"GET / HTTP/1.0\r\nHost: test\r\n\r\n").await;
    server.stop();

    assert!(
        head.starts_with("http/1.0 200"),
        "an HTTP/1.0 request gets an HTTP/1.0 status line: {head}"
    );
    assert!(
        !head.contains("transfer-encoding"),
        "RFC 9112 §6.1 forbids chunked framing for an HTTP/1.0 client: {head}"
    );
    assert_eq!(
        body, b"hello",
        "the body is delimited by the close, with no chunk-size lines in it"
    );
}
