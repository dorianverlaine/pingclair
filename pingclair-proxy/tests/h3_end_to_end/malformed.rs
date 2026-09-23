//! 🚫 A malformed HTTP/3 request is a stream error, not an application answer.
//!
//! RFC 9114 §4.1.2: malformed requests "MUST be treated as a stream error of
//! type H3_MESSAGE_ERROR". Before the fix every case here got a `400` and a
//! clean FIN, which a client cannot tell apart from a site choosing to refuse.

use super::*;

/// 🔢 `H3_MESSAGE_ERROR` (RFC 9114 §8.1).
const H3_MESSAGE_ERROR: u64 = 0x10e;

/// 🧾 A site that answers `ok` to anything, so any status rather than a reset
/// means the request got through.
async fn spawn_ok_site() -> SocketAddr {
    spawn_h3_from_pingclairfile(":443 {\n respond \"ok\" 200\n}").await
}

/// 🚫 Sends one request and returns the status, or how the stream was reset.
async fn outcome(attempt: H3Attempt<'_>) -> Result<u16, String> {
    h3_attempt(attempt, None)
        .await
        .map(|response| response.status)
}

/// 🔪 The outcome every malformed request must have.
fn message_error() -> Result<u16, String> {
    Err(format!("stream reset with code {H3_MESSAGE_ERROR}"))
}

/// 🔠 A pseudo-header after a regular field (§4.3) is refused by the parser.
///
/// 📌 Not an uppercase name, the more obvious example: quiche's encoder
/// lowercases names before they reach the wire, so this client cannot send one.
#[tokio::test]
async fn h3_misplaced_pseudo_header_resets_with_message_error() {
    let server = spawn_ok_site().await;
    let attempt = H3Attempt {
        extra_headers: &[("foo", "bar"), (":scheme", "https")],
        ..H3Attempt::to(server, "/")
    };
    assert_eq!(outcome(attempt).await, message_error());
}

/// 🛡️ `Transfer-Encoding` is refused by the framing check, which runs after
/// the parser, and must end the same way.
#[tokio::test]
async fn h3_transfer_encoding_resets_with_message_error() {
    let server = spawn_ok_site().await;
    let attempt = H3Attempt {
        extra_headers: &[("transfer-encoding", "chunked")],
        ..H3Attempt::to(server, "/")
    };
    assert_eq!(outcome(attempt).await, message_error());
}

/// 🔤 A `:method` that is not a token used to reach the handler and come back
/// as a `400`.
#[tokio::test]
async fn h3_invalid_method_resets_with_message_error() {
    let server = spawn_ok_site().await;
    let attempt = H3Attempt {
        method: "GE T",
        ..H3Attempt::to(server, "/")
    };
    assert_eq!(outcome(attempt).await, message_error());
}

/// 👍 The control: the same site answers a well-formed request normally.
#[tokio::test]
async fn h3_well_formed_request_is_answered() {
    let server = spawn_ok_site().await;
    assert_eq!(outcome(H3Attempt::to(server, "/")).await, Ok(200));
}
