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

/// 🪟 RFC 9110 §13.1.5: `If-Range` decides whether `Range` applies. A client
/// resuming a download names the version it holds; when that is not the
/// current file, it must get the whole current file (200), never a 206 whose
/// bytes splice onto a different version.
#[tokio::test]
async fn test_file_server_if_range_gates_the_range() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("f.txt");
    std::fs::write(&path, "0123456789").unwrap();
    // 🕰️ An old mtime makes the one-second `Last-Modified` a strong validator.
    set_mtime(&path, SystemTime::now() - Duration::from_secs(60));
    let mut server = sidecar_site(root.path().to_str().unwrap());
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = no_proxy_client();
    let plain = client
        .get(server.url(0, "/f.txt"))
        .send()
        .await
        .expect("request");
    let header = |name: &str| plain.headers()[name].to_str().unwrap().to_string();
    let (etag, last_modified) = (header("etag"), header("last-modified"));

    let mut outcomes = Vec::new();
    for if_range in [
        "\"definitely-not-the-etag\"".to_string(),
        format!("W/{etag}"),
        "Tue, 01 Jan 2002 00:00:00 GMT".to_string(),
        etag.clone(),
        last_modified.clone(),
    ] {
        let response = client
            .get(server.url(0, "/f.txt"))
            .header("Range", "bytes=0-4")
            .header("If-Range", &if_range)
            .send()
            .await
            .expect("request");
        let status = response.status().as_u16();
        outcomes.push((status, response.text().await.unwrap()));
    }
    server.stop();

    let full = (200, "0123456789".to_string());
    let partial = (206, "01234".to_string());
    assert_eq!(
        outcomes,
        [full.clone(), full.clone(), full, partial.clone(), partial],
        "stale tag, weak tag, stale date → 200; current tag, current date → 206"
    );
}

/// 🚫 A sidecar ETag that is not an entity tag is skipped, not served.
///
/// 🤡 The sidecar was trimmed and checked only for emptiness, then turned into
/// a header with `unwrap()`. An embedded line break, which `trim()` leaves in
/// place, panicked the request, and every later one, because the failed
/// metadata entry was never cached. One bad build artifact took the file
/// offline.
#[tokio::test]
async fn test_file_server_skips_a_sidecar_etag_that_is_not_an_entity_tag() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("app.js"), "source").unwrap();
    std::fs::write(root.path().join("app.js.etag"), "\"abc\"\n\"def\"\n").unwrap();
    std::fs::write(root.path().join("ok.js"), "source").unwrap();
    std::fs::write(root.path().join("ok.js.etag"), "\"from-build\"\r\n").unwrap();
    let config = format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            root * {root}
            file_server {{
                etag_file_extensions .etag
            }}

            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
        }}
        "#,
        root = root.path().display()
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let mut outcomes = Vec::new();
    for path in ["/app.js", "/app.js", "/ok.js"] {
        let response = no_proxy_client()
            .get(server.url(0, path))
            .send()
            .await
            .expect("request");
        let status = response.status().as_u16();
        let etag = response.headers()["etag"].to_str().unwrap().to_string();
        let body = response.text().await.unwrap();
        outcomes.push((status, etag == "\"from-build\"", body));
    }
    server.stop();

    // 🎯 The bad sidecar falls back to the derived tag on every request; a
    // good one next to it is still honoured.
    let source = || "source".to_string();
    assert_eq!(
        outcomes,
        [
            (200, false, source()),
            (200, false, source()),
            (200, true, source())
        ]
    );
}
