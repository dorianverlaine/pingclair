// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ♻️ Admin readers retain one complete published generation across reloads.

use super::*;
use std::sync::atomic::AtomicUsize;

#[tokio::test]
async fn admin_readers_are_not_refused_during_publication() {
    let mut config = admin_test_pingclairfile("/__admin_reload", "reload");
    for site in 0..64 {
        config.push_str(&format!(
            "http://site{site}.test:__PINGCLAIR_TEST_PORT__ {{\n respond \"reload\"\n}}\n"
        ));
    }
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await);
    let client = no_proxy_client();
    let mut document = client
        .get(server.admin_url("/config/"))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let served = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();
    for _ in 0..32 {
        let stop = stop.clone();
        let served = served.clone();
        let url = server.admin_url("/config/debug");
        workers.push(tokio::spawn(async move {
            let client = no_proxy_client();
            let mut failures = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                let response = client.get(&url).send().await.unwrap();
                if response.status() != 200 {
                    failures.push(response.status());
                } else {
                    assert!(
                        response
                            .json::<serde_json::Value>()
                            .await
                            .unwrap()
                            .is_boolean()
                    );
                    served.fetch_add(1, Ordering::Relaxed);
                }
            }
            failures
        }));
    }
    for reload in 0..64 {
        document["debug"] = serde_json::json!(reload % 2 == 0);
        let response = client
            .post(server.admin_url("/load"))
            .json(&document)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }
    stop.store(true, Ordering::Relaxed);
    let mut failures = Vec::new();
    for worker in workers {
        failures.extend(worker.await.unwrap());
    }
    assert!(served.load(Ordering::Relaxed) > 0);
    assert!(
        failures.is_empty(),
        "admin reads failed across 64 reloads: {failures:?}"
    );
}

/// 🍂 True when the document holds a `file` matcher with an optional field
/// serialized as absent — the sparse shape a `php_fastcgi` expansion produces.
fn has_sparse_file_matcher(node: &serde_json::Value) -> bool {
    match node {
        serde_json::Value::Object(map) => {
            if let Some(file) = map.get("file").and_then(|value| value.as_object())
                && (!file.contains_key("root")
                    || !file.contains_key("try_policy")
                    || !file.contains_key("split_path"))
            {
                return true;
            }
            map.values().any(has_sparse_file_matcher)
        }
        serde_json::Value::Array(items) => items.iter().any(has_sparse_file_matcher),
        _ => false,
    }
}

/// 🐘 A `php_fastcgi` site compiles to a sparse `file` matcher, and loading
/// that document back used to be refused as "a tagged matcher" — the defect
/// behind every Admin `/load` in the 0.2.0 soak while `systemctl reload`
/// applied the very same file.
#[tokio::test]
async fn test_a_php_fastcgi_site_round_trips_through_the_admin_api() {
    let mut server = TestServer::new_pingclairfile(
        r#"
        {
            admin __PINGCLAIR_TEST_ADMIN_LISTEN__
        }

        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            php_fastcgi 127.0.0.1:9000
        }
        "#,
    );
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let mut document = client
        .get(server.admin_url("/config"))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert!(
        has_sparse_file_matcher(&document),
        "the fixture really produces a sparse file matcher: {document}"
    );
    document["debug"] = serde_json::json!(true);
    let reload = client
        .post(server.admin_url("/load"))
        .json(&document)
        .send()
        .await
        .unwrap();
    let (status, body) = (reload.status(), reload.text().await.unwrap());
    assert_eq!(status, reqwest::StatusCode::OK, "round trip: {body}");
}
