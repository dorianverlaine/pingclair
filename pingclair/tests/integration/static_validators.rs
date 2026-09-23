// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🏷️ Static-file validators, end to end: the `ETag` a client receives must
//! be a strong validator it can trust, because `If-Range` resumes a download
//! by trusting it.

use super::{TestServer, no_proxy_client};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 🧾 A `file_server` site with gzip sidecars enabled, rooted at `root`.
fn sidecar_site(root: &str) -> TestServer {
    let config = format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            root * {root}
            file_server {{
                precompressed gzip
            }}

            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
        }}
        "#
    );
    TestServer::new_pingclairfile(&config)
}

/// 🏷️ The `ETag` and `Content-Encoding` one request comes back with.
async fn etag_of(
    server: &TestServer,
    path: &str,
    accept_encoding: &str,
) -> (String, Option<String>) {
    let response = no_proxy_client()
        .get(server.url(0, path))
        .header("Accept-Encoding", accept_encoding)
        .send()
        .await
        .expect("request");
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
    };
    (header("etag").expect("an ETag"), header("content-encoding"))
}

/// 🕰️ Pins a file's mtime to an exact instant, so a test can place two edits
/// inside one second without racing the clock.
fn set_mtime(path: &std::path::Path, at: SystemTime) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(at)
        .unwrap();
}

/// 🏷️ RFC 9110 §8.8.1: the gzip sidecar and the plain file are different
/// bytes, so one strong tag cannot describe both.
#[tokio::test]
async fn test_file_server_etag_differs_per_content_coding() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("app.js"), "plain-source").unwrap();
    std::fs::write(root.path().join("app.js.gz"), "gzip-sidecar").unwrap();
    let mut server = sidecar_site(root.path().to_str().unwrap());
    assert!(server.wait_until_ready().await, "server failed to start");

    let identity = etag_of(&server, "/app.js", "identity").await;
    let gzip = etag_of(&server, "/app.js", "gzip").await;
    server.stop();

    assert_eq!(identity.1, None);
    assert_eq!(gzip.1.as_deref(), Some("gzip"));
    assert!(!identity.0.starts_with("W/"), "the tag must stay strong");
    assert_eq!(
        gzip.0,
        format!("{}-gzip\"", identity.0.trim_end_matches('"')),
        "the gzip body gets its own strong tag"
    );
}

/// 🕰️ Two same-size edits inside one second must not share a tag. With a
/// whole-second mtime they did, and a client resuming a download would have
/// spliced bytes from two different files together.
#[tokio::test]
async fn test_file_server_etag_changes_within_one_second() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("f.txt");
    let second = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let at = |millis: u64| UNIX_EPOCH + Duration::from_secs(second) + Duration::from_millis(millis);
    std::fs::write(&path, "version-A").unwrap();
    set_mtime(&path, at(100));
    let mut server = sidecar_site(root.path().to_str().unwrap());
    assert!(server.wait_until_ready().await, "server failed to start");
    let before = etag_of(&server, "/f.txt", "identity").await.0;

    std::fs::write(&path, "version-B").unwrap();
    set_mtime(&path, at(600));
    let after = etag_of(&server, "/f.txt", "identity").await.0;
    server.stop();

    assert_ne!(before, after, "a same-second, same-size edit kept its ETag");
}
