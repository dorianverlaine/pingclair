// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔪 A response that fails after it started is abandoned, not extended.
//!
//! Once a status line or HEADERS frame is on the wire, an error page can only
//! be spliced onto the response already in flight. The client must instead
//! see the message break: RST_STREAM on HTTP/2, a closed connection on
//! HTTP/1.1.

use super::TestServer;

/// 🔪 A file whose pacing overruns `request_timeout` resets the H2 stream.
///
/// Pacing at 128 KiB/s makes a 512 KiB file take four seconds, so the
/// two-second whole-request timeout fires partway through the body. Before
/// the fix the proxy still tried to write a `408` error page onto the
/// started stream. In this scenario Pingora then dropped the stream, so the
/// client saw RST_STREAM(CANCEL) — "no longer needed", which blames nobody —
/// rather than INTERNAL_ERROR; the test pins both the code and the absence
/// of error-page bytes.
#[tokio::test]
async fn test_h2_file_timing_out_mid_body_resets_instead_of_appending_an_error_page() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("big.bin"), vec![b'x'; 512 * 1024]).unwrap();
    let config = format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            limits {{
                download_bytes_per_sec 131072
                request_timeout 2s
            }}
            root * {root}
            file_server
        }}
        "#,
        root = root.path().display()
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = reqwest::Client::builder()
        .no_proxy()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let mut response = client.get(server.url(0, "/big.bin")).send().await.unwrap();
    assert_eq!(response.status(), 200, "the file response must start");
    // 🌊 Read chunk by chunk so the bytes that arrived before the failure
    // are still visible when the stream breaks.
    let mut received = Vec::new();
    let ending = loop {
        match response.chunk().await {
            Ok(Some(chunk)) => received.extend_from_slice(&chunk),
            Ok(None) => break "a clean end of stream".to_string(),
            Err(error) => break format!("{error:?}"),
        }
    };
    server.stop();

    assert!(
        !received.windows(7).any(|window| window == b"Timeout"),
        "no error-page bytes may follow the file's bytes"
    );
    assert!(
        ending.contains("INTERNAL_ERROR"),
        "the stream must be reset with INTERNAL_ERROR; ended with {ending}"
    );
}
