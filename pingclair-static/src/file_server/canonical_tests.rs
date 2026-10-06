// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔁 Canonical redirects retain request data without changing the origin.

use super::{FileRequest, FileServer, FileServerConfig, ServedResponse};

#[tokio::test]
async fn canonical_redirects_keep_queries_and_safe_paths() {
    let root = tempfile::tempdir().unwrap();
    for directory in ["sub", "sub dir", "\\evil.example"] {
        std::fs::create_dir(root.path().join(directory)).unwrap();
        std::fs::write(root.path().join(directory).join("index.html"), "index").unwrap();
    }
    std::fs::write(root.path().join("plain.txt"), "plain").unwrap();
    let server = FileServer::new(FileServerConfig {
        root: root.path().to_owned(),
        ..FileServerConfig::default()
    });
    for (effective, original, expected) in [
        ("/sub", "//sub", "/sub/"),
        ("/sub", "/sub?x=1&y=2", "/sub/?x=1&y=2"),
        (
            "/sub",
            "//sub?next=//evil.example&x=%2F",
            "/sub/?next=//evil.example&x=%2F",
        ),
        ("/sub", "///sub?", "/sub/?"),
        ("/sub", "/other/%2e/../sub?x=1", "/sub/?x=1"),
        ("/sub", "/other/child/.%2e/../sub?x=1", "/sub/?x=1"),
        ("/sub", "/other/child/%2e%2E/../sub?x=1", "/sub/?x=1"),
        ("/sub", "/./sub?x=1", "/sub/?x=1"),
        ("/sub", "/other/../sub?x=1", "/sub/?x=1"),
        ("/plain.txt/", "//plain.txt/?x=1", "/plain.txt?x=1"),
        ("/sub%20dir", "/sub%20dir?x=%252F", "/sub%20dir/?x=%252F"),
        (
            "/\\evil.example",
            "/\\evil.example?x=1",
            "/%5Cevil.example/?x=1",
        ),
        ("/sub/", "/sub?x=1", "/sub/?x=1"),
    ] {
        let response = server
            .serve_auto(effective, original, FileRequest::plain(), None)
            .await
            .unwrap();
        match response {
            Some(ServedResponse::Redirect(location)) => {
                assert_eq!(location, expected, "{original}")
            }
            _ => panic!("{original}: expected canonical redirect"),
        }
    }
    for (effective, original) in [("/plain.txt", "/sub?x=1"), ("/sub/", "/sub/?x=1")] {
        assert!(!matches!(
            server
                .serve_auto(effective, original, FileRequest::plain(), None)
                .await
                .unwrap(),
            Some(ServedResponse::Redirect(_))
        ));
    }
}
