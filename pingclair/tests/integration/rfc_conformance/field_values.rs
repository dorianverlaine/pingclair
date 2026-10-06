// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🏷️ Field values: which bytes are allowed to cross the wire.
//!
//! RFC 9110 §5.5 forbids CR, LF and NUL inside a field value. RFC 9113 §8.2.1
//! and RFC 9114 §10.3 add that a value must not start or end with SP or HTAB.
//! Both are rules about what a *sender* may produce, so they bind this server for
//! every field it generates — whether the value came from a configuration file
//! or from an upstream it is proxying.

use super::{ScriptedUpstream, TestServer, raw_http1, site};
use std::time::Duration;

/// 🚫 A configured value containing CR/LF never becomes an extra field line.
///
/// RFC 9110 §5.5 is written for the recipient, and this test now follows the
/// clause rather than the first draft's paraphrase: "Field values containing CR,
/// LF, or NUL characters are invalid and dangerous... a recipient of CR, LF, or
/// NUL within a field value MUST either reject the message or replace each of
/// those characters with SP before further processing or forwarding of that
/// message."
///
/// So refusing the configuration, answering with the characters replaced by SP,
/// and rejecting the message outright all satisfy it. What does not is letting
/// the CR/LF become a field separator — that is the injection the clause exists
/// to stop, and the H3 path is where it happens today (issue #255; the H1/H2
/// path here refuses the message, which the clause permits).
#[tokio::test]
async fn test_configured_field_value_with_crlf_never_becomes_a_field_line() {
    let mut server = TestServer::new_pingclairfile(&site(
        "handle /probe/* {\n                header X-Inject \"legit\\r\\nInjected-Header: pwned\"\n                respond \"ok\"\n            }",
    ));
    if !server.wait_until_ready().await {
        // Refusing the configuration is the first of the two permitted answers.
        return;
    }

    let (head, _) = raw_http1(
        &server,
        b"GET /probe/x HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    )
    .await;
    server.stop();

    for line in head.lines() {
        assert!(
            !line.starts_with("injected-header:"),
            "the CR/LF must not become a field separator: {head}"
        );
    }
    // An empty head means the message was rejected, which the clause allows; a
    // head that did arrive must not be a truncated one.
    assert!(
        head.is_empty() || head.starts_with("http/1.1 "),
        "the answer is either a rejection or a complete response: {head:?}"
    );
}

/// 🚫 A padded value is not emitted as a field value.
///
/// RFC 9113 §8.2.1: "A field value MUST NOT start or end with an ASCII
/// whitespace character". A client that enforces it — every strict HTTP/2 and
/// HTTP/3 implementation — treats the response as malformed, so a stray space in
/// a configuration value is not cosmetic. Trimming the value and omitting it are
/// both fine; sending the padding is not.
#[tokio::test]
#[ignore = "pingclair#256 — `x-pad:   padded  ` goes out on H2"]
async fn test_h2_response_field_value_carries_no_padding() {
    let mut server = TestServer::new_pingclairfile(&site(
        "handle /probe/* {\n                header X-Pad \"  padded  \"\n                respond \"ok\"\n            }",
    ));
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = reqwest::Client::builder()
        .no_proxy()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let response = client.get(server.url(0, "/probe/x")).send().await.unwrap();
    let value = response
        .headers()
        .get("x-pad")
        .map(|value| value.to_str().unwrap().to_string());
    server.stop();

    if let Some(value) = value {
        assert_eq!(
            value.trim_matches([' ', '\t']),
            value,
            "a field value must carry no leading or trailing SP/HTAB: {value:?}"
        );
    }
}

/// 🚫 Padding on an incoming request field is not forwarded.
///
/// The same clause, in the direction the client controls: a value that arrives
/// padded over HTTP/2 must either be refused as malformed or have the padding
/// removed before it is passed on, because the origin (or the next proxy) will
/// judge the field it receives. The origin here records the bytes it saw, which
/// is the only place the padding is visible.
#[tokio::test]
#[ignore = "pingclair#256 — the trailing SP is forwarded to the origin"]
async fn test_h2_request_field_padding_is_not_forwarded() {
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

    let client = reqwest::Client::builder()
        .no_proxy()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let _ = client
        .get(server.url(0, "/"))
        .header("x-trail", "val3 ")
        .send()
        .await;
    let head = upstream.request_head().await;
    server.stop();

    let line = head
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("x-trail"))
        .unwrap_or_default()
        .trim_end_matches('\r');
    assert_eq!(
        line, "x-trail: val3",
        "the padding survived the hop: {line:?}"
    );
}

/// 🔑 `alice` / `secret1`, at the cheapest bcrypt cost so the check stays fast.
const ALICE_HASH: &str = "$2y$04$EBGg0.PJo2Qi2WYiMUqXsuB9orpRrMXiABirLM33AHHNb5GzEcipS";

/// 🚫 A realm containing a quote is escaped, not pasted in.
///
/// The parameter is a `quoted-string`: RFC 9110 §11.2 allows a token or a
/// `quoted-string` for any auth-param, §5.6.4 defines `quoted-pair` as the way a
/// `"` travels inside one, and RFC 7617 §2 makes `realm` a required parameter of
/// the Basic challenge. So a `"`
/// inside it must travel as `\"`. Sending it bare produces a field that a strict
/// parser rejects and a lenient one truncates — the client then shows a realm the
/// operator never wrote. Refusing the configuration is the other acceptable
/// answer, and a server that never becomes ready counts as having chosen it.
#[tokio::test]
#[ignore = "pingclair#268 — the realm is interpolated raw and the challenge is malformed"]
async fn test_basic_auth_realm_is_escaped() {
    // The guard is scoped to its own route so the harness's readiness probe is
    // not itself challenged — a 401 on the readiness path would fail the start
    // and skip the assertion, which is how this check first passed for the wrong
    // reason.
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "handle /probe/* {{\n                basic_auth bcrypt \"He said \\\"hi\\\" ok\" {{\n                    alice {ALICE_HASH}\n                }}\n                respond \"secret\"\n            }}"
    )));
    if !server.wait_until_ready().await {
        return;
    }

    let (head, _) = raw_http1(
        &server,
        b"GET /probe/x HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    )
    .await;
    server.stop();

    assert!(head.starts_with("http/1.1 401"), "{head}");
    let challenge = head
        .lines()
        .find(|line| line.starts_with("www-authenticate:"))
        .unwrap_or_else(|| panic!("a 401 carries a challenge: {head}"));
    let value = challenge
        .trim_start_matches("www-authenticate:")
        .trim()
        .to_string();
    assert!(
        value.starts_with("basic realm=\""),
        "the challenge names a realm: {value:?}"
    );
    let inner = value
        .trim_start_matches("basic realm=\"")
        .strip_suffix('"')
        .unwrap_or_else(|| panic!("the realm value is a closed quoted-string: {value:?}"));
    // A quote is legal inside the value only when it is escaped, which is what
    // makes the field parseable at all.
    let mut previous = ' ';
    let unescaped = inner.chars().any(|character| {
        let bare = character == '"' && previous != '\\';
        previous = character;
        bare
    });
    assert!(
        !unescaped,
        "RFC 9110 §5.5 requires a quote in a quoted-string to be escaped: {value:?}"
    );
}
