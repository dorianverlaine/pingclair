// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🏷️ Conditional requests against `file_server`, end to end (RFC 9110 §13).
//!
//! 🤡 The file server sent `ETag` and `Last-Modified` and never read either
//! back: a browser revalidating its cache downloaded the whole file again,
//! and an `If-Match` meant to stop a lost update was ignored.

use super::{TestServer, no_proxy_client};
use std::time::{Duration, SystemTime};

/// 🧾 A `file_server` site with gzip sidecars, rooted at `root`.
fn site(root: &std::path::Path) -> TestServer {
    let config = format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            root * {root}
            header Cache-Control "max-age=60"
            file_server {{
                precompressed gzip
            }}

            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
        }}
        "#,
        root = root.display()
    );
    TestServer::new_pingclairfile(&config)
}

/// 🏷️ What one conditional request came back with: status, `ETag`,
/// `Content-Length`, and the body.
type Outcome = (u16, Option<String>, Option<String>, String);

async fn send(server: &TestServer, fields: &[(&str, &str)]) -> Outcome {
    let mut request = no_proxy_client().get(server.url(0, "/f.txt"));
    for &(name, value) in fields {
        request = request.header(name, value);
    }
    let response = request.send().await.expect("request");
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
    };
    let (etag, length) = (header("etag"), header("content-length"));
    let status = response.status().as_u16();
    (status, etag, length, response.text().await.unwrap())
}

/// 🏷️ The five `If-*` outcomes on `GET`, in the §13.2.2 order, including the
/// per-coding tag: the gzip sidecar's tag revalidates the gzip copy only.
#[tokio::test]
async fn test_file_server_evaluates_preconditions() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("f.txt");
    std::fs::write(&path, "0123456789").unwrap();
    std::fs::write(root.path().join("f.txt.gz"), "gzip-sidecar").unwrap();
    // 🕰️ An old mtime, so the file is not changing under the date checks.
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(60))
        .unwrap();
    let mut server = site(root.path());
    assert!(server.wait_until_ready().await, "server failed to start");

    let identity = [("accept-encoding", "identity")];
    let plain = send(&server, &identity).await;
    let etag = plain.1.clone().expect("an ETag");
    let gzip_etag = send(&server, &[("accept-encoding", "gzip")])
        .await
        .1
        .unwrap();
    let last_modified = no_proxy_client()
        .get(server.url(0, "/f.txt"))
        .send()
        .await
        .unwrap()
        .headers()["last-modified"]
        .to_str()
        .unwrap()
        .to_string();
    let weak = format!("W/{etag}");
    let stale = "\"not-the-etag\"";
    let old_date = "Tue, 01 Jan 2002 00:00:00 GMT";

    let cases: Vec<Vec<(&str, &str)>> = vec![
        vec![("if-none-match", &etag)],
        vec![("if-none-match", &weak)],
        vec![("if-modified-since", &last_modified)],
        vec![
            ("if-none-match", stale),
            ("if-modified-since", &last_modified),
        ],
        vec![("if-match", stale)],
        vec![("if-match", &etag)],
        vec![("if-unmodified-since", old_date)],
        vec![("if-none-match", &gzip_etag), ("accept-encoding", "gzip")],
        vec![("if-none-match", &gzip_etag)],
    ];
    let mut outcomes = Vec::new();
    for mut fields in cases {
        if !fields.iter().any(|(name, _)| *name == "accept-encoding") {
            fields.extend(identity);
        }
        outcomes.push(send(&server, &fields).await);
    }
    // 🧊 A 304 refreshes the cache entry, so it carries the same freshness
    // and variance fields a 200 would (RFC 9110 §15.4.5).
    let revalidated = no_proxy_client()
        .get(server.url(0, "/f.txt"))
        .header("if-none-match", &etag)
        .send()
        .await
        .unwrap();
    let refresh_fields = ["cache-control", "vary", "last-modified"]
        .map(|name| revalidated.headers().get(name).is_some());
    server.stop();

    assert_eq!(revalidated.status(), 304);
    assert_eq!(refresh_fields, [true; 3], "{:?}", revalidated.headers());

    let full = || {
        (
            200,
            Some(etag.clone()),
            Some("10".into()),
            "0123456789".into(),
        )
    };
    let not_modified = |tag: &str| (304, Some(tag.to_string()), None, String::new());
    let failed = (412, None, Some("0".into()), String::new());
    assert_eq!(
        outcomes,
        [
            not_modified(&etag),
            not_modified(&etag),
            not_modified(&etag),
            full(),
            failed.clone(),
            full(),
            failed,
            not_modified(&gzip_etag),
            full(),
        ],
        "match, weak match, date → 304; If-None-Match overrides the date; \
         If-Match and If-Unmodified-Since → 412; a gzip tag matches gzip only"
    );
}
