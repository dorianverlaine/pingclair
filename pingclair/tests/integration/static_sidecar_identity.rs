// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🏷️ A sidecar deployment changes its validator even when the source stays put.

use super::{TestServer, no_proxy_client};
use std::time::{Duration, SystemTime};

#[tokio::test]
async fn test_sidecar_replacement_revalidates_its_own_bytes() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("app.txt");
    let sidecar = root.path().join("app.txt.gz");
    std::fs::write(&source, vec![b'x'; 4096]).unwrap();
    let at = SystemTime::now() - Duration::from_secs(120);
    std::fs::File::options()
        .write(true)
        .open(&source)
        .unwrap()
        .set_modified(at)
        .unwrap();
    let config = format!(
        r#"
        {{
            admin off
        }}
        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            root * {}
            encode gzip
            file_server {{
                precompressed gzip
            }}
        }}
    "#,
        root.path().display()
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await);
    let client = no_proxy_client();
    let live = client
        .get(server.url(0, "/app.txt"))
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap();
    let live_tag = live.headers()["etag"].clone();
    assert_eq!(live.headers()["content-encoding"], "gzip");
    let _ = live.bytes().await.unwrap();
    // 🏷️ Equal metadata must still distinguish a disk sidecar from live encoding.
    std::fs::write(&sidecar, vec![b'a'; 4096]).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&sidecar)
        .unwrap()
        .set_modified(at)
        .unwrap();
    let first = client
        .get(server.url(0, "/app.txt"))
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap();
    let first_tag = first.headers()["etag"].clone();
    assert_eq!(first.bytes().await.unwrap().as_ref(), vec![b'a'; 4096]);
    assert_ne!(first_tag, live_tag);
    for size in [4096, 512 * 1024] {
        std::fs::write(&sidecar, vec![b'b'; size]).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&sidecar)
            .unwrap()
            .set_modified(at + Duration::from_secs(size as u64))
            .unwrap();
        let changed = client
            .get(server.url(0, "/app.txt"))
            .header("Accept-Encoding", "gzip")
            .header("If-None-Match", &first_tag)
            .send()
            .await
            .unwrap();
        assert_eq!(changed.status(), 200);
        let tag = changed.headers()["etag"].clone();
        assert_ne!(tag, first_tag);
        assert_eq!(changed.bytes().await.unwrap().as_ref(), vec![b'b'; size]);
        let unchanged = client
            .get(server.url(0, "/app.txt"))
            .header("Accept-Encoding", "gzip")
            .header("If-None-Match", tag)
            .send()
            .await
            .unwrap();
        assert_eq!(unchanged.status(), 304);
    }
}

#[tokio::test]
async fn test_only_sidecar_edits_change_conditional_responses() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("app.txt"), "unchanged source").unwrap();
    let sidecar = root.path().join("app.txt.gz");
    std::fs::write(&sidecar, "sidecar-A").unwrap();
    let mut server = TestServer::new_pingclairfile(&format!(
        r#"
        {{
            admin off
        }}
        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            root * {}
            file_server {{
                precompressed gzip
            }}
        }}
    "#,
        root.path().display()
    ));
    assert!(server.wait_until_ready().await);
    let client = no_proxy_client();
    let first = client
        .get(server.url(0, "/app.txt"))
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap();
    let tag = first.headers()["etag"].clone();
    assert_eq!(first.text().await.unwrap(), "sidecar-A");
    std::fs::write(&sidecar, "sidecar-B").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&sidecar)
        .unwrap()
        .set_modified(SystemTime::now() + Duration::from_secs(1))
        .unwrap();
    let changed = client
        .get(server.url(0, "/app.txt"))
        .header("Accept-Encoding", "gzip")
        .header("If-None-Match", &tag)
        .send()
        .await
        .unwrap();
    assert_eq!(
        changed.status(),
        200,
        "replacing only the sidecar must invalidate its tag"
    );
    assert_ne!(changed.headers()["etag"], tag);
    assert_eq!(changed.text().await.unwrap(), "sidecar-B");
}
