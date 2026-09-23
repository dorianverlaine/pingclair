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

/// 🔪 A local file that runs out of time mid-body resets the stream instead
/// of growing an error page on its tail.
///
/// Pacing at 128 KiB/s makes a 512 KiB file need four seconds, so three of
/// its 64 KiB chunks leave before the two-second whole-request timeout
/// fires. Before the fix the timeout became a `408` error page sent after the
/// `200` had started: its headers were dropped, its body was appended to the
/// file's bytes, and the stream ended cleanly.
#[tokio::test]
async fn h3_file_timing_out_mid_body_resets_instead_of_appending_an_error_page() {
    let site = tempfile::tempdir().unwrap();
    std::fs::write(site.path().join("big.bin"), vec![b'x'; 512 * 1024]).unwrap();
    let source = format!(
        ":443 {{\n limits {{\n  download_bytes_per_sec 131072\n  request_timeout 2s\n }}\n root * {}\n file_server\n}}",
        site.path().display()
    );
    let compiled = pingclair_config::compile(&source).unwrap();
    let site_config = compiled.servers[0].clone();
    let server = spawn_h3_server_with(|address| ServerConfig {
        listen: vec![address.to_string()],
        ..site_config
    })
    .await;

    let outcome = h3_get(server, "/big.bin").await;
    assert_eq!(
        outcome.map(|response| (response.status, response.body.len())),
        Err(format!("stream reset with code {H3_INTERNAL_ERROR}")),
        "a response that fails after it started must reset, not carry an error page"
    );
}
