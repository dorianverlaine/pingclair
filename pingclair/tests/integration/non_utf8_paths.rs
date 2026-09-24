// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📁 Filenames that are not valid UTF-8, end to end.
//!
//! On Unix a filename is bytes, and a client reaches such a file by spelling
//! those bytes in percent-escapes. Every handler that turns a request into a
//! filename has to carry the bytes through unchanged; a lossy conversion to
//! text anywhere on the way asks the filesystem about a different name.
//!
//! 🐧 Linux only: APFS refuses to create a name that is not valid UTF-8, so on
//! macOS these files cannot exist and the tests could not set themselves up.

use super::{TestServer, no_proxy_client};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;

/// 🧾 A `file_server` site behind one `try_files` line, rooted at `root`.
fn try_files_site(root: &str, candidates: &str) -> TestServer {
    let config = format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            root * {root}
            try_files {candidates}
            file_server
        }}
        "#
    );
    TestServer::new_pingclairfile(&config)
}

/// 📥 Status and body of one GET.
async fn get(server: &TestServer, path: &str) -> (u16, String) {
    let response = no_proxy_client()
        .get(server.url(0, path))
        .send()
        .await
        .expect("request");
    let status = response.status().as_u16();
    (status, response.text().await.expect("body"))
}

/// 🔍 A glob candidate reaches a file whose name is not valid UTF-8.
///
/// The glob results were converted with `to_string_lossy`, so `caf\xE9.js`
/// became `caf\u{FFFD}.js`, the existence probe missed, and the request fell
/// through to a 404 for a file that was sitting in the directory.
#[tokio::test]
async fn test_try_files_glob_reaches_a_non_utf8_name() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("build")).unwrap();
    std::fs::write(
        root.path()
            .join("build")
            .join(OsStr::from_bytes(b"caf\xe9.js")),
        "latin-1 bundle",
    )
    .unwrap();
    let mut server = try_files_site(root.path().to_str().unwrap(), "/build/caf*.js");
    assert!(server.wait_until_ready().await, "server failed to start");

    let response = get(&server, "/anything").await;
    server.stop();

    assert_eq!(response, (200, "latin-1 bundle".to_string()));
}

/// 🔤 `try_files {path}` reaches a file whose name is not valid UTF-8.
///
/// The file server could already serve `/caf%E9.txt`, but the `file` matcher
/// in front of it joined paths as `String` and gave up on the decoded byte
/// `0xE9`, so the canonical single-page-application shape fell through to
/// `/index.html` for a file that exists.
#[tokio::test]
async fn test_try_files_path_reaches_a_non_utf8_name() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("index.html"), "shell").unwrap();
    std::fs::write(
        root.path().join(OsStr::from_bytes(b"caf\xe9.txt")),
        "latin-1",
    )
    .unwrap();
    let mut server = try_files_site(root.path().to_str().unwrap(), "{path} /index.html");
    assert!(server.wait_until_ready().await, "server failed to start");

    let response = get(&server, "/caf%E9.txt").await;
    server.stop();

    assert_eq!(response, (200, "latin-1".to_string()));
}
