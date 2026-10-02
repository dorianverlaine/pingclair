//! 🛡️ A path guard sees a percent-escaped path the way the file server does,
//! over HTTP/3 as over HTTP/1.
//!
//! Only unreserved escapes are decoded at ingress, so `/secret%21` reached
//! the matchers spelled that way while the file server served the file
//! `secret!`, and `basic_auth /secret!` let it through without credentials.

use super::*;

/// 🔑 `alice` / `secret1`, at the cheapest bcrypt cost so the test stays fast.
const ALICE_HASH: &str = "$2y$04$EBGg0.PJo2Qi2WYiMUqXsuB9orpRrMXiABirLM33AHHNb5GzEcipS";

/// 🚫 Spelling a reserved character as an escape must not take a request out
/// of a guard's scope.
#[tokio::test]
async fn h3_path_guard_covers_an_escaped_reserved_character() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("secret!"), "TOP SECRET").unwrap();
    let source = format!(
        r#":443 {{
            root * {}
            basic_auth /secret! {{
                alice {ALICE_HASH}
            }}
            file_server
        }}"#,
        root.path().to_str().unwrap()
    );
    let site = pingclair_config::compile(&source).unwrap().servers[0].clone();
    let server = spawn_h3_server_with(|address| ServerConfig {
        listen: vec![address.to_string()],
        ..site
    })
    .await;

    let mut seen = Vec::new();
    for path in ["/secret!", "/secret%21"] {
        seen.push((path, false, h3_get(server, path).await.unwrap().status));
    }
    let authorized = h3_get_with_headers(
        server,
        "/secret%21",
        &[("authorization", "Basic YWxpY2U6c2VjcmV0MQ==")],
    )
    .await
    .unwrap();
    seen.push(("/secret%21", true, authorized.status));

    assert_eq!(
        seen,
        [
            ("/secret!", false, 401),
            ("/secret%21", false, 401),
            ("/secret%21", true, 200),
        ]
    );
}
