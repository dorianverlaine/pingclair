// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌊 A compressible source must not make an identity range allocate its whole body.

use super::{FileRequest, FileServer, FileServerConfig, ServedResponse};

#[tokio::test]
async fn compressible_ranges_keep_reads_bounded() {
    let root = tempfile::tempdir().unwrap();
    let size = 8 * 1024 * 1024;
    std::fs::write(root.path().join("large.txt"), vec![b'x'; size]).unwrap();
    let server = FileServer::new(FileServerConfig {
        root: root.path().into(),
        compress: true,
        ..FileServerConfig::default()
    });
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::RANGE, "bytes=1-".parse().unwrap());
    let response = server
        .serve_auto(
            "/large.txt",
            "/large.txt",
            FileRequest::new(&http::Method::GET, &headers),
            Some("gzip"),
        )
        .await
        .unwrap()
        .unwrap();
    let ServedResponse::Stream(mut stream) = response else {
        panic!("an identity range must stream even when its source is compressible");
    };
    assert_eq!(stream.status, 206);
    assert_eq!(stream.body_len, (size - 1) as u64);
    assert!(stream.content_encoding.is_none());
    let mut total = 0;
    while let Some(chunk) = stream.read_chunk().unwrap() {
        assert!(chunk.len() <= 64 * 1024);
        assert!(chunk.iter().all(|byte| *byte == b'x'));
        total += chunk.len();
    }
    assert_eq!(total, size - 1);
}
