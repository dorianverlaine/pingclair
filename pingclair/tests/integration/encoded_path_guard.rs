// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ A path guard sees a percent-escaped path the way the file server does.
//!
//! The ingress decodes only unreserved escapes (`%41` is `A`), so a request
//! for `/secret%21` reached the matchers spelled that way, while the file
//! server decoded it to the file `secret!`. `basic_auth /secret!` did not
//! match the escaped spelling and the file was served without credentials.

use super::*;

/// 🔑 `alice` / `secret1`, at the cheapest bcrypt cost so the test stays fast.
const ALICE_HASH: &str = "$2y$04$EBGg0.PJo2Qi2WYiMUqXsuB9orpRrMXiABirLM33AHHNb5GzEcipS";

/// 🚫 Spelling a reserved character as an escape must not take a request out
/// of a guard's scope.
#[tokio::test]
async fn test_a_path_guard_covers_an_escaped_reserved_character() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("secret!"), "TOP SECRET").unwrap();
    let config = format!(
        r#"
        {{
            admin off
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            root * {}
            basic_auth /secret! {{
                alice {ALICE_HASH}
            }}
            file_server
        }}
        "#,
        root.path().to_str().unwrap()
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let mut seen = Vec::new();
    for (path, password) in [
        ("/secret!", None),
        ("/secret%21", None),
        ("/secret%21", Some("secret1")),
    ] {
        let mut request = no_proxy_client().get(server.url(0, path));
        if let Some(password) = password {
            request = request.basic_auth("alice", Some(password));
        }
        let response = request.send().await.unwrap();
        seen.push((path, password.is_some(), response.status().as_u16()));
    }
    server.stop();

    assert_eq!(
        seen,
        [
            ("/secret!", false, 401),
            ("/secret%21", false, 401),
            ("/secret%21", true, 200),
        ]
    );
}
