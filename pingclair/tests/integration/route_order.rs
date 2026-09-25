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

/// 🔀 File order decides nothing that directive order already decides.
/// Two servers write the same directives in opposite orders and must
/// answer every request identically. `redir /old/*` answers `/old/keep`
/// ahead of the exact `respond /old/keep`, because `redir` ranks earlier;
/// the router used to pick the exact path. `header` runs before `respond`
/// wherever it is written.
#[tokio::test]
async fn test_reversing_file_order_changes_no_answer() {
    let config = |body: &str| {
        format!(
            r#"
            {{
                admin off
            }}

            http://__PINGCLAIR_TEST_LISTEN__ {{
                @readiness path __PINGCLAIR_TEST_READINESS_PATH__
                respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
                {body}
            }}
            "#
        )
    };
    let respond_written_first = r#"
                respond "catch-all" 200
                respond /old/keep "kept" 200
                header X-Order on
                redir /old/* /new 308
    "#;
    let redir_written_first = r#"
                redir /old/* /new 308
                header X-Order on
                respond /old/keep "kept" 200
                respond "catch-all" 200
    "#;

    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let mut answers = Vec::new();
    for body in [respond_written_first, redir_written_first] {
        let mut server = TestServer::new_pingclairfile(&config(body));
        assert!(server.wait_until_ready().await, "server failed to start");
        let mut seen = Vec::new();
        for path in ["/old/keep", "/page"] {
            let reply = client.get(server.url(0, path)).send().await.unwrap();
            let header = |name: &str| {
                reply
                    .headers()
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string)
            };
            let status = reply.status().as_u16();
            let (location, order) = (header("location"), header("x-order"));
            seen.push((status, location, order, reply.text().await.unwrap()));
        }
        server.stop();
        answers.push(seen);
    }

    assert_eq!(answers[0], answers[1], "file order changed an answer");
    assert_eq!(answers[0][0].0, 308, "`redir` answers `/old/keep`");
    assert_eq!(answers[0][0].1.as_deref(), Some("/new"));
    assert_eq!(
        answers[0][1],
        (200, None, Some("on".to_string()), "catch-all".to_string())
    );
}

/// 🧩 Route paths with a `*` that is not at the end (issue #193): a
/// mid-path `*` matches within one segment, a leading `*` is a suffix at any
/// depth, and both answer beside plain prefixes where the order puts them —
/// longest trimmed pattern first, so `/files/*/raw/*` leads and `/a/*`
/// trails. Before the fix none of the three patterns ever matched.
#[tokio::test]
async fn test_wildcards_anywhere_in_a_route_path_match() {
    let config = r#"
        {
            admin off
        }

        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            @mid path /a/*x
            respond @mid "mid" 200
            @php path *.php
            respond @php "php" 200
            @segments path /files/*/raw/*
            respond @segments "segments" 200
            respond /a/* "a prefix" 200
            respond /files/* "files prefix" 200
            respond "catch-all" 200
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = no_proxy_client();
    let mut answers = Vec::new();
    for path in [
        "/a/bx",
        "/a/b/cx",
        "/index.php",
        "/a/deep/page.php",
        "/files/7/raw/readme",
        "/files/7/8/raw/readme",
        "/elsewhere",
    ] {
        let reply = client.get(server.url(0, path)).send().await.unwrap();
        answers.push((path, reply.text().await.unwrap()));
    }
    assert_eq!(
        answers,
        [
            ("/a/bx", "mid".to_string()),
            ("/a/b/cx", "a prefix".to_string()),
            ("/index.php", "php".to_string()),
            ("/a/deep/page.php", "php".to_string()),
            ("/files/7/raw/readme", "segments".to_string()),
            ("/files/7/8/raw/readme", "files prefix".to_string()),
            ("/elsewhere", "catch-all".to_string()),
        ]
    );
}
