// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 A site's routes are one list in directive order, and the first route
//! that matches answers (issue #18).
//!
//! 📌 Every case here is one the router used to answer by the most specific
//! path instead. Each expected answer is the reference's; the #18 body
//! records v2.11.4 answering `hello` for the first one.

use super::TestServer;
use super::no_proxy_client;

/// 🔥 The #18 reproduction: `respond` ranks ahead of `file_server`, so the
/// catch-all `respond` answers even for a path the narrower `file_server`
/// route names. The router used to serve the file.
#[tokio::test]
async fn test_an_earlier_directive_answers_before_a_narrower_one() {
    let tree = tempfile::tempdir().expect("document root");
    std::fs::create_dir(tree.path().join("assets")).unwrap();
    std::fs::write(tree.path().join("assets/a.txt"), "the file").unwrap();
    let root = tree.path().to_string_lossy();
    let config = format!(
        r#"
        {{
            admin off
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            root * {root}
            file_server /assets/*
            respond "hello" 200
        }}
        "#
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let reply = no_proxy_client()
        .get(server.url(0, "/assets/a.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), 200);
    assert_eq!(reply.text().await.unwrap(), "hello");
}

/// ↪️ `redir` ranks ahead of `respond`, so a redirect glob answers a path
/// that an exact `respond` names more precisely.
#[tokio::test]
async fn test_directive_rank_beats_an_exact_path() {
    let config = r#"
        {
            admin off
        }

        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            respond /old/keep "kept" 200
            redir /old/* /new 308
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let reply = client.get(server.url(0, "/old/keep")).send().await.unwrap();
    assert_eq!(reply.status(), 308);
    assert_eq!(reply.headers().get("location").unwrap(), "/new");
}

/// 🧮 A matcher with two path patterns has no single path to sort by, so a
/// one-pattern sibling of the same directive goes ahead of it — even for a
/// path the two-pattern matcher names exactly.
#[tokio::test]
async fn test_a_single_path_sibling_goes_ahead_of_a_multi_path_matcher() {
    let config = r#"
        {
            admin off
        }

        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            @both path /a /b
            respond @both "both" 200
            respond /a* "a glob" 200
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = no_proxy_client();
    let a = client.get(server.url(0, "/a")).send().await.unwrap();
    assert_eq!(a.text().await.unwrap(), "a glob");
    let b = client.get(server.url(0, "/b")).send().await.unwrap();
    assert_eq!(b.text().await.unwrap(), "both");
}
