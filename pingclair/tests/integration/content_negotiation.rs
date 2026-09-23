// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🗜️ `Accept-Encoding` negotiation, end to end: which precompressed sidecar
//! a client receives must follow its quality values, not the substrings of its
//! header.

use super::{TestServer, no_proxy_client};

/// 🧾 A `file_server` site with zstd and gzip sidecars, zstd preferred.
fn sidecar_site(root: &str) -> TestServer {
    let config = format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            root * {root}
            file_server {{
                precompressed zstd gzip
            }}

            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
        }}
        "#
    );
    TestServer::new_pingclairfile(&config)
}

/// 🗂️ Writes `app.js` plus whichever sidecars are named. Each sidecar's bytes
/// are a label rather than real compressed data, so the body says which file
/// answered. The original stays below the live-compression floor, so an
/// unencoded answer is the original and nothing else.
fn write_site(root: &std::path::Path, sidecars: &[&str]) {
    std::fs::write(root.join("app.js"), "original").unwrap();
    for suffix in sidecars {
        std::fs::write(
            root.join(format!("app.js{suffix}")),
            format!("sidecar{suffix}"),
        )
        .unwrap();
    }
}

/// 🏷️ The `Content-Encoding` and body one request comes back with.
async fn fetch(server: &TestServer, accept_encoding: &str) -> (Option<String>, String) {
    let response = no_proxy_client()
        .get(server.url(0, "/app.js"))
        .header("Accept-Encoding", accept_encoding)
        .send()
        .await
        .expect("request");
    let encoding = response
        .headers()
        .get("content-encoding")
        .map(|v| v.to_str().unwrap().to_string());
    (encoding, response.text().await.expect("body"))
}

/// 🚫 #89: `gzip;q=0` is a refusal, and a substring test read it as consent.
/// `*` accepts every coding, and a substring test found none in it.
#[tokio::test]
async fn sidecar_selection_follows_quality_values() {
    let root = tempfile::tempdir().unwrap();
    write_site(root.path(), &[".gz"]);
    let mut server = sidecar_site(root.path().to_str().unwrap());
    assert!(server.wait_until_ready().await, "server failed to start");

    assert_eq!(fetch(&server, "gzip;q=0").await, (None, "original".into()));
    assert_eq!(
        fetch(&server, "*").await,
        (Some("gzip".into()), "sidecar.gz".into())
    );
}

/// 🥇 The client's quality beats the operator's order, and a missing sidecar
/// falls through to the next-ranked one instead of to no coding at all.
#[tokio::test]
async fn sidecar_ranking_prefers_client_quality_then_falls_back() {
    let root = tempfile::tempdir().unwrap();
    write_site(root.path(), &[".zst", ".gz"]);
    let mut server = sidecar_site(root.path().to_str().unwrap());
    assert!(server.wait_until_ready().await, "server failed to start");

    assert_eq!(
        fetch(&server, "zstd;q=0.1, gzip").await,
        (Some("gzip".into()), "sidecar.gz".into())
    );
    assert_eq!(
        fetch(&server, "gzip, zstd").await,
        (Some("zstd".into()), "sidecar.zst".into())
    );

    std::fs::remove_file(root.path().join("app.js.zst")).unwrap();
    assert_eq!(
        fetch(&server, "zstd, gzip;q=0.5").await,
        (Some("gzip".into()), "sidecar.gz".into())
    );
}
