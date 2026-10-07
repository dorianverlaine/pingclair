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

/// 🕰️ The modification time the filesystem actually stored, in nanoseconds.
///
/// Read back rather than assumed: a coarser timestamp granularity than the
/// caller asked for is the one platform difference that can turn two writes
/// into one validator (#184).
fn mtime_nanos(path: &std::path::Path) -> u128 {
    std::fs::metadata(path)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
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
    // 🗜️ A disk sidecar carries its own tag, never the live encoder's `-gzip-<level>` one.
    assert!(
        !gzip.0.ends_with("-gzip-5\""),
        "a sidecar must not claim the live encoder's tag: {}",
        gzip.0
    );
    assert_ne!(gzip.0, identity.0, "each representation needs its own tag");
}

/// 🏷️ The validator is Caddy's spelling for the same file.
///
/// Caddy derives a static file's tag as
/// `"<base36(mtime_ns)>-<base36(size)>"` (`calculateEtag`,
/// `modules/caddyhttp/fileserver/staticfiles.go`, v2.11.7). A site moved
/// between the two servers therefore keeps the validators its browsers and CDN
/// already stored, instead of re-downloading every file on the day of the
/// switch (#158).
#[tokio::test]
async fn test_file_server_etag_is_caddys_base36_pair() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("gzip.txt");
    std::fs::write(&path, "x".repeat(7200)).unwrap();
    // 🕰️ A whole second, because the digit string below is what Caddy prints
    // for this exact pair: 1_700_000_000 s in nanoseconds is `cwyvpelgpse8`,
    // and 7200 bytes is `5k0`.
    set_mtime(&path, UNIX_EPOCH + Duration::from_secs(1_700_000_000));
    let mut server = sidecar_site(root.path().to_str().unwrap());
    assert!(server.wait_until_ready().await, "server failed to start");

    let etag = etag_of(&server, "/gzip.txt", "identity").await.0;
    server.stop();

    assert_eq!(etag, "\"cwyvpelgpse8-5k0\"");
}

/// 🕰️ Two same-size edits inside one second must not share a tag. With a
/// whole-second mtime they did, and a client resuming a download would have
/// spliced bytes from two different files together.
///
/// 📌 The assertion is against the mtimes the filesystem actually stored, read
/// back between the two requests: a container filesystem with coarse timestamp
/// granularity can land both writes on one instant, and two identical
/// validators are then the *correct* answer — the unit test in
/// `pingclair-static` is where the nanosecond property itself is pinned, and
/// this one is about the file server noticing the change (#184).
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
    let first_mtime = mtime_nanos(&path);

    std::fs::write(&path, "version-B").unwrap();
    set_mtime(&path, at(600));
    let second_mtime = mtime_nanos(&path);
    let after = etag_of(&server, "/f.txt", "identity").await.0;
    server.stop();

    if first_mtime == second_mtime {
        // 🕰️ The filesystem could not tell the two instants apart: identical
        // validators are the correct answer, and the property this test is
        // about cannot be observed here. Say so rather than passing quietly.
        eprintln!(
            "note: this filesystem stored both writes at mtime {first_mtime}; \
             the same-second property is pinned by the unit test instead"
        );
        assert_eq!(before, after);
    } else {
        assert_ne!(
            before, after,
            "a same-second, same-size edit kept its ETag (mtime {first_mtime} -> {second_mtime})"
        );
    }
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

/// 🏷️ A configured `ETag` is the validator, not just a label.
///
/// RFC 9110 §13.1.2 compares `If-None-Match` against "the entity tag of the
/// selected representation", and §8.8.3 makes the `ETag` field that tag's
/// carrier. There is one representation and one tag on the wire, so the tag
/// the client was given is the tag that decides `304` — revalidating against
/// it must not answer `200` while some tag the client never saw answers `304`
/// (#265).
#[tokio::test]
async fn test_a_configured_etag_is_the_validator_the_client_revalidates_with() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("file.txt"), "configured-tag").unwrap();

    let config = format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            root * {root}
            header Etag "\"quoted-hash-9\""
            file_server

            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
        }}
        "#,
        root = root.path().display()
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let served = no_proxy_client()
        .get(server.url(0, "/file.txt"))
        .send()
        .await
        .unwrap();
    let advertised = served.headers()["etag"].to_str().unwrap().to_string();
    assert_eq!(advertised, "\"quoted-hash-9\"");
    served.bytes().await.unwrap();

    let revalidated = no_proxy_client()
        .get(server.url(0, "/file.txt"))
        .header("If-None-Match", &advertised)
        .send()
        .await
        .unwrap();
    let status = revalidated.status().as_u16();
    revalidated.bytes().await.unwrap();

    // 🧷 The same tag gates a resumable range: the client's copy is the version
    // the server described, so the range is honoured rather than ignored.
    let partial = no_proxy_client()
        .get(server.url(0, "/file.txt"))
        .header("Range", "bytes=0-3")
        .header("If-Range", &advertised)
        .send()
        .await
        .unwrap();
    let partial_status = partial.status().as_u16();
    let partial_body = partial.text().await.unwrap();
    server.stop();

    assert_eq!(
        status, 304,
        "the tag the client was given must be the tag that answers 304"
    );
    assert_eq!(
        (partial_status, partial_body.as_str()),
        (206, "conf"),
        "If-Range must trust the tag the client was given"
    );
}
