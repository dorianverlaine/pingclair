// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧱 Request framing: what a message's own bytes say about its body.
//!
//! These rules are decided before any handler runs, which is exactly why they
//! matter: two ends that resolve an ambiguous message differently disagree about
//! where one request stops and the next begins.

use super::{TestServer, closed_port, raw_http1, site};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// 🧱 A message with both framings is resolved to chunked and the connection ends.
///
/// RFC 9112 §6.1 gives a server two options and one obligation: it "MAY reject a
/// request that contains both Content-Length and Transfer-Encoding or process
/// such a request in accordance with the Transfer-Encoding alone. Regardless, the
/// server MUST close the connection after responding to such a request to avoid
/// the potential attacks."
///
/// So a `400` is *not* required — that was this test's first draft, borrowed from
/// Go's behaviour rather than from the clause. What is required is the close: a
/// chunked body followed by more bytes is the request-smuggling shape, and a
/// keep-alive connection after it hands those bytes to the next request.
#[tokio::test]
async fn test_cl_and_te_together_end_the_connection() {
    let mut server = TestServer::new_pingclairfile(&site(r#"respond "answered""#));
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, _) = raw_http1(
        &server,
        b"POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\n\
          Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n\
          GET /second HTTP/1.1\r\nHost: test\r\n\r\n",
    )
    .await;
    server.stop();

    // Either answer satisfies the clause; a second response does not.
    assert!(
        head.starts_with("http/1.1 4") || head.starts_with("http/1.1 2"),
        "the request must be refused or processed with the Transfer-Encoding alone: {head}"
    );
    assert_eq!(
        head.matches("http/1.1 ").count(),
        1,
        "the connection must end after this response — no second request may be served: {head}"
    );
}

/// 📥 A request that says nothing about a body still reaches FastCGI.
///
/// RFC 9112 §6.3: a request with neither `Content-Length` nor
/// `Transfer-Encoding` has no body. Its absence is not an error, so answering
/// 411 — RFC 9110 §15.5.12, "the server refuses to accept the request without a
/// defined Content-Length" — invents a refusal the client did not earn. A
/// bodyless `POST` or `DELETE` is ordinary traffic.
#[tokio::test]
async fn test_bodyless_post_reaches_fastcgi() {
    let port = closed_port();
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "handle /php/* {{\n                php_fastcgi 127.0.0.1:{port}\n            }}"
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, _) = raw_http1(
        &server,
        b"POST /php/x HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    )
    .await;
    server.stop();

    // 502 is the honest answer for an origin that is not listening: it proves
    // the request was carried to the dial instead of being refused here.
    assert!(
        !head.starts_with("http/1.1 411"),
        "a bodyless request has a defined (empty) body: {head}"
    );
}

/// 🧱 A chunked body reaches FastCGI with a length the server measured.
///
/// Chunked framing defines a length by construction (RFC 9112 §7.1), so 411
/// cannot be the right answer to it: the request does have a defined length and
/// the server only has to read it. Caddy reached the same conclusion in 2.9.1 by
/// buffering FastCGI bodies by default (caddyserver/caddy#6759).
#[tokio::test]
async fn test_chunked_post_reaches_fastcgi() {
    let port = closed_port();
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "handle /php/* {{\n                php_fastcgi 127.0.0.1:{port}\n            }}"
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, _) = raw_http1(
        &server,
        b"POST /php/x HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n\
          Connection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    )
    .await;
    server.stop();

    assert!(
        !head.starts_with("http/1.1 411"),
        "chunked framing gives the request a defined length: {head}"
    );
}

/// ✅ A request that declares `Content-Length: 0` is not lengthless.
///
/// The net under the two ignored checks above: this shape is already handled —
/// it reaches the dial and answers 502 for an origin that is not listening — and
/// it must stay that way when the lengthless cases are fixed.
#[tokio::test]
async fn test_zero_length_post_reaches_fastcgi() {
    let port = closed_port();
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "handle /php/* {{\n                php_fastcgi 127.0.0.1:{port}\n            }}"
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, _) = raw_http1(
        &server,
        b"POST /php/x HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\
          Connection: close\r\n\r\n",
    )
    .await;
    server.stop();

    assert!(
        head.starts_with("http/1.1 502"),
        "a declared length of zero must reach the dial: {head}"
    );
}

/// 🚫 An invalid HTTP/2 connection preface ends the connection.
///
/// RFC 9113 §3.4 requires an invalid preface to be treated as a connection error
/// and explicitly allows the `GOAWAY` to be omitted ("since an invalid preface
/// indicates that the peer is not using HTTP/2"). `h2spec` 3.5/2 reports the
/// omission as a failure; this check pins the half the RFC demands — the TCP
/// connection ends rather than the server waiting for a client that is not
/// speaking its protocol.
#[tokio::test]
async fn test_invalid_h2_preface_terminates_the_connection() {
    use tokio::io::AsyncReadExt;

    let mut server = TestServer::new_pingclairfile(&site(r#"respond "ok""#));
    assert!(server.wait_until_ready().await, "server failed to start");

    let mut stream = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    // The preface starts correctly and then diverges, which is the shape h2spec
    // sends: enough for the listener to commit to HTTP/2, then a violation.
    stream
        .write_all(b"PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n")
        .await
        .unwrap();
    let ended = tokio::time::timeout(Duration::from_secs(3), async {
        let mut buffer = [0u8; 256];
        loop {
            match stream.read(&mut buffer).await {
                // A close, a reset, or a GOAWAY followed by either: all three
                // satisfy the clause.
                Ok(0) | Err(_) => return true,
                Ok(_) => continue,
            }
        }
    })
    .await;
    server.stop();

    assert_eq!(
        ended,
        Ok(true),
        "an invalid connection preface must end the connection"
    );
}

/// 🚫 A `CONNECT` this server will not tunnel does not get a 2xx, and the
/// connection does not survive it.
///
/// RFC 9110 §9.3.6 makes a 2xx to `CONNECT` mean "switch to tunnel mode
/// immediately", and data after the header section then belongs to the tunnelled
/// protocol — so answering 2xx without tunnelling hands the next request on the
/// connection to whoever wrote those bytes (RFC 9110 §11.2). §8.6 forbids a
/// `Content-Length` in that 2xx, and RFC 9931 §8 (March 2026, *Updates: 9112*)
/// requires the connection to be closed when a `CONNECT` is rejected, with or
/// without a `close` connection option.
///
/// The host-specific fixture is the point: a matched site always refused
/// `CONNECT` (405, `Allow`, close), while the no-matching-site path answered 200
/// until pingclair#283.
#[tokio::test]
async fn test_unmatched_connect_is_refused_and_ends_the_connection() {
    let fixture = r#"
        {
            admin off
        }

        http://127.0.0.1:__PINGCLAIR_TEST_PORT__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "site-body" 200
        }
        "#;
    let mut server = TestServer::new_pingclairfile(fixture);
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, _) = raw_http1(
        &server,
        b"CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n\
          GET /second HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    .await;
    server.stop();

    assert!(
        !head.starts_with("http/1.1 2"),
        "a CONNECT that is not tunnelled must not be answered successfully: {head}"
    );
    assert_eq!(
        head.matches("http/1.1 ").count(),
        1,
        "the bytes behind the CONNECT are not a request: {head}"
    );
}
