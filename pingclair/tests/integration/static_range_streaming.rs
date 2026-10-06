// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌊 The shared file stream must preserve range framing through the real transport.

use super::{TestServer, no_proxy_client};

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
