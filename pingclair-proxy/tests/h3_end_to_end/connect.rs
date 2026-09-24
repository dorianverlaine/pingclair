//! 🔌 `CONNECT` over HTTP/3 (RFC 9114 §4.4, RFC 9110 §9.3.6).
//!
//! A well-formed `CONNECT` carries only `:method` and `:authority`. The parser
//! used to call that shape malformed and reset the stream, while the one
//! nonstandard shape with `:scheme` and `:path` reached a 501. The two are now
//! the other way round: the well-formed request gets the same 405 with `Allow`
//! as HTTP/1.1, and the ill-formed one is reset.

use super::*;

/// 🔌 A §4.4 `CONNECT` gets 405 with `Allow` and never reaches the upstream.
#[tokio::test]
async fn h3_connect_is_refused_with_allow() {
    let (upstream, _heads, hits) = spawn_scripted_upstream(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    )
    .await;
    let server =
        spawn_h3_from_pingclairfile(&format!(":443 {{\n reverse_proxy http://{upstream}\n}}"))
            .await;

    let response = h3_attempt(
        H3Attempt {
            method: "CONNECT",
            ..H3Attempt::to(server, "")
        },
        None,
    )
    .await
    .unwrap();
    let allow = response
        .headers
        .iter()
        .find(|(name, _)| name == "allow")
        .map(|(_, value)| value.as_str());
    assert_eq!(
        (response.status, allow),
        (405, Some("GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"))
    );
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
}

/// 🚫 A `CONNECT` that also sends `:scheme` and `:path` is malformed (§4.4).
#[tokio::test]
async fn h3_connect_with_a_path_resets_with_message_error() {
    let server = spawn_h3_from_pingclairfile(":443 {\n respond \"ok\" 200\n}").await;
    let outcome = h3_attempt(
        H3Attempt {
            method: "CONNECT",
            ..H3Attempt::to(server, "/")
        },
        None,
    )
    .await
    .map(|response| response.status);
    assert_eq!(outcome, Err("stream reset with code 270".to_string()));
}
