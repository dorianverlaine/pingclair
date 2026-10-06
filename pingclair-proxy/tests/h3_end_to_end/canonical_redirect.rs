// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔁 HTTP/3 shares the static redirect safety boundary.

use super::*;

#[tokio::test]
async fn h3_canonical_redirect_query_and_origin() {
    let root = tempfile::tempdir().unwrap();
    for directory in ["sub", "sub dir", "\\evil.example"] {
        std::fs::create_dir(root.path().join(directory)).unwrap();
        std::fs::write(root.path().join(directory).join("index.html"), "index").unwrap();
    }
    std::fs::write(root.path().join("plain.txt"), "plain").unwrap();
    let server = spawn_h3_from_pingclairfile(&format!(
        ":443 {{\n root * {}\n try_files {{path}} {{path}}/ /plain.txt\n file_server\n}}",
        root.path().display()
    ))
    .await;
    for (target, expected) in [
        ("/sub?x=1&y=2", "/sub/?x=1&y=2"),
        (
            "//sub?next=//evil.example&x=%2F",
            "/sub/?next=//evil.example&x=%2F",
        ),
        ("///sub?", "/sub/?"),
        ("/./sub?x=1", "/sub/?x=1"),
        ("/other/%2e/../sub?x=1", "/sub/?x=1"),
        ("/other/child/.%2e/../sub?x=1", "/sub/?x=1"),
        ("/other/child/%2e%2E/../sub?x=1", "/sub/?x=1"),
        ("//plain.txt/?x=1", "/plain.txt?x=1"),
        ("/sub%20dir?x=%252F", "/sub%20dir/?x=%252F"),
        ("/\\evil.example?x=1", "/%5Cevil.example/?x=1"),
    ] {
        let response = h3_get(server, target).await.unwrap();
        let location = response
            .headers
            .iter()
            .find(|(name, _)| name == "location")
            .map(|(_, value)| value.as_str());
        assert_eq!(
            (response.status, location, response.body.as_slice()),
            (308, Some(expected), &b""[..]),
            "{target}"
        );
    }
    let response = h3_get(server, "/sub/?x=1").await.unwrap();
    assert_eq!(
        (response.status, response.body.as_slice()),
        (200, &b"index"[..])
    );
}
