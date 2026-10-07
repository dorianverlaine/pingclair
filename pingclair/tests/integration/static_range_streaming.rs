// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌊 The shared file stream must preserve range framing through the real transport.

use super::{TestServer, no_proxy_client};

/// 🗜️ A range over a precompressed sidecar ranges over the sidecar's bytes.
///
/// The sidecar *is* the representation a client negotiated, so a byte range is
/// as well-defined on it as on the identity file — and that is the
/// representation Caddy serves a range from (#254). A client that did not
/// accept the coding still ranges over the identity file, which also keeps the
/// on-the-fly compressor out of range responses: a compressed stream cannot
/// start at an arbitrary offset.
#[tokio::test]
async fn test_a_range_over_a_precompressed_sidecar_ranges_over_the_sidecar() {
    use std::io::Write as _;

    let root = tempfile::tempdir().unwrap();
    let content = "0123456789".repeat(200);
    std::fs::write(root.path().join("range.txt"), &content).unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(content.as_bytes()).unwrap();
    let sidecar = encoder.finish().unwrap();
    std::fs::write(root.path().join("range.txt.gz"), &sidecar).unwrap();

    let mut server = TestServer::new_pingclairfile(&format!(
        r#"
        {{
            admin off
        }}
        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            root * {}
            file_server {{
                precompressed gzip
            }}
        }}
    "#,
        root.path().display()
    ));
    assert!(server.wait_until_ready().await);

    // 🗜️ Control: the full negotiated response is the sidecar, on both servers.
    let full = no_proxy_client()
        .get(server.url(0, "/range.txt"))
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(full.status(), 200);
    assert_eq!(full.headers()["content-encoding"], "gzip");
    let sidecar_etag = full.headers()["etag"].clone();
    assert_eq!(full.bytes().await.unwrap().as_ref(), sidecar.as_slice());

    // 🪟 The range applies to the negotiated representation, byte for byte.
    let ranged = no_proxy_client()
        .get(server.url(0, "/range.txt"))
        .header("Accept-Encoding", "gzip")
        .header("Range", "bytes=0-9")
        .send()
        .await
        .unwrap();
    let ranged_status = ranged.status();
    let ranged_encoding = ranged.headers().get("content-encoding").cloned();
    let ranged_range = ranged.headers()["content-range"].clone();
    let ranged_length = ranged.content_length();
    let ranged_etag = ranged.headers()["etag"].clone();
    let ranged_body = ranged.bytes().await.unwrap();

    assert_eq!(ranged_status, 206);
    assert_eq!(
        ranged_encoding
            .as_ref()
            .and_then(|value| value.to_str().ok()),
        Some("gzip"),
        "the range must be over the representation the client negotiated"
    );
    assert_eq!(
        ranged_range.to_str().unwrap(),
        format!("bytes 0-9/{}", sidecar.len())
    );
    assert_eq!(ranged_length, Some(10));
    assert_eq!(ranged_etag, sidecar_etag, "one representation, one tag");
    assert_eq!(ranged_body.as_ref(), &sidecar[..10]);

    // 🧷 The sidecar's own tag is what gates the range: it resumes the encoded
    // copy, and anything else is ignored in favour of the whole representation.
    let resumed = no_proxy_client()
        .get(server.url(0, "/range.txt"))
        .header("Accept-Encoding", "gzip")
        .header("Range", "bytes=0-9")
        .header("If-Range", &sidecar_etag)
        .send()
        .await
        .unwrap();
    assert_eq!(resumed.status(), 206);
    assert_eq!(
        resumed.headers()["content-range"].to_str().unwrap(),
        format!("bytes 0-9/{}", sidecar.len())
    );
    assert_eq!(resumed.bytes().await.unwrap().as_ref(), &sidecar[..10]);
    let replaced = no_proxy_client()
        .get(server.url(0, "/range.txt"))
        .header("Accept-Encoding", "gzip")
        .header("Range", "bytes=0-9")
        .header("If-Range", "\"a-copy-we-do-not-have\"")
        .send()
        .await
        .unwrap();
    assert_eq!(replaced.status(), 200);
    assert_eq!(replaced.bytes().await.unwrap().as_ref(), sidecar.as_slice());

    // 🏷️ A conditional request against the negotiated representation sees the
    // same tag it was served with.
    let revalidated = no_proxy_client()
        .get(server.url(0, "/range.txt"))
        .header("Accept-Encoding", "gzip")
        .header("If-None-Match", &sidecar_etag)
        .send()
        .await
        .unwrap();
    assert_eq!(revalidated.status(), 304);
    server.stop();
}

#[tokio::test]
async fn test_compressible_static_range_bytes_and_framing() {
    let root = tempfile::tempdir().unwrap();
    let size = 8 * 1024 * 1024;
    std::fs::write(root.path().join("large.txt"), vec![b'x'; size]).unwrap();
    let mut server = TestServer::new_pingclairfile(&format!(
        r#"
        {{
            admin off
        }}
        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            root * {}
            encode gzip
            file_server
        }}
    "#,
        root.path().display()
    ));
    assert!(server.wait_until_ready().await);
    let mut response = no_proxy_client()
        .get(server.url(0, "/large.txt"))
        .header("Accept-Encoding", "gzip")
        .header("Range", "bytes=1-")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 206);
    assert_eq!(
        response.headers()["content-range"],
        format!("bytes 1-{}/{}", size - 1, size)
    );
    assert_eq!(response.content_length(), Some((size - 1) as u64));
    assert!(response.headers().get("content-encoding").is_none());
    let mut total = 0;
    while let Some(chunk) = response.chunk().await.unwrap() {
        assert!(chunk.iter().all(|byte| *byte == b'x'));
        total += chunk.len();
    }
    assert_eq!(total, size - 1);
}
