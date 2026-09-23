//! 🔪 A response that breaks after it started must end in a reset, not a FIN.
//!
//! Once the headers are on the wire, HTTP/3 has exactly one way left to say
//! "this message is not complete": RESET_STREAM. A FIN says the opposite, so a
//! short body followed by a FIN is a lie the client cannot detect when no
//! `content-length` was sent, and a malformed response (RFC 9114 §4.1.2) when
//! one was.

use super::*;

/// 🔢 `H3_INTERNAL_ERROR` (RFC 9114 §8.1): the upstream failed, not the client.
const H3_INTERNAL_ERROR: u64 = 0x102;

/// 🔪 An upstream that dies mid-body resets the client's stream.
///
/// The upstream announces 100,000 bytes, sends 100, and closes. Before the
/// fix the proxy relayed the 100 bytes and then a clean FIN, so the client
/// saw a finished `200` whose body was a thousandth of its `content-length`.
#[tokio::test]
async fn h3_upstream_failing_mid_body_resets_the_stream() {
    let reply: &'static [u8] = [
        &b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n"[..],
        &[b'x'; 100][..],
    ]
    .concat()
    .leak();
    let (upstream, _, _) = spawn_scripted_upstream(reply).await;
    let server =
        spawn_h3_from_pingclairfile(&format!(":443 {{\n reverse_proxy http://{upstream}\n}}"))
            .await;

    let outcome = h3_get(server, "/").await;
    assert_eq!(
        outcome.map(|response| (response.status, response.body.len())),
        Err(format!("stream reset with code {H3_INTERNAL_ERROR}")),
        "a truncated upstream body must reset the stream, not end it with a FIN"
    );
}
