// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;

#[tokio::test]
async fn conditional_config_writes_preserve_the_read_generation() {
    let mut server = TestServer::new_pingclairfile(&admin_test_pingclairfile("/__etag", "etag"));
    assert!(server.wait_until_ready().await);
    let client = no_proxy_client();
    let root = client
        .get(server.admin_url("/config/"))
        .send()
        .await
        .unwrap();
    let root_tag = root.headers()["etag"].to_str().unwrap().to_owned();
    let path = "/config/debug";
    let node = client.get(server.admin_url(path)).send().await.unwrap();
    let tag = node.headers()["etag"].to_str().unwrap().to_owned();
    assert_ne!(tag, root_tag);
    let accepted = client
        .patch(server.admin_url(path))
        .header("If-Match", &root_tag)
        .json(&true)
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), reqwest::StatusCode::OK);
    let current = client.get(server.admin_url(path)).send().await.unwrap();
    assert_ne!(current.headers()["etag"], tag);
    assert_eq!(
        current.json::<serde_json::Value>().await.unwrap(),
        serde_json::json!(true)
    );
    let rejected = client
        .patch(server.admin_url(path))
        .header("If-Match", &tag)
        .json(&false)
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), reqwest::StatusCode::PRECONDITION_FAILED);
    let accepted = client
        .patch(server.admin_url(path))
        .json(&false)
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), reqwest::StatusCode::OK);
    let current = client.get(server.admin_url(path)).send().await.unwrap();
    let tag = current.headers()["etag"].to_str().unwrap().to_owned();
    let first = client
        .patch(server.admin_url(path))
        .header("If-Match", &tag)
        .json(&true);
    let second = client
        .patch(server.admin_url(path))
        .header("If-Match", &tag)
        .json(&true);
    let (first, second) = tokio::join!(first.send(), second.send());
    let mut statuses = [
        first.unwrap().status().as_u16(),
        second.unwrap().status().as_u16(),
    ];
    statuses.sort_unstable();
    assert_eq!(statuses, [200, 412]);
}

#[tokio::test]
async fn stale_config_writes_are_refused_before_mutation() {
    let mut server = TestServer::new_pingclairfile(&admin_test_pingclairfile("/__stale", "stale"));
    assert!(server.wait_until_ready().await);
    let client = no_proxy_client();
    let path = "/config/debug";
    for method in [
        reqwest::Method::POST,
        reqwest::Method::PUT,
        reqwest::Method::PATCH,
        reqwest::Method::DELETE,
    ] {
        let rejected = client
            .request(method, server.admin_url(path))
            .header("If-Match", "\"definitely-stale\"")
            .json(&true)
            .send()
            .await
            .unwrap();
        assert_eq!(rejected.status(), reqwest::StatusCode::PRECONDITION_FAILED);
    }

    let current = client.get(server.admin_url(path)).send().await.unwrap();
    assert_eq!(
        current.json::<serde_json::Value>().await.unwrap(),
        serde_json::json!(false)
    );
}
