//! 🛡️ A path-scoped guard sees the same path over HTTP/3 as over HTTP/1.
//!
//! Matchers compare the path without its query string; the router already
//! did that on HTTP/3, so `/secret?x=1` reached the `respond /secret` route.
//! The guard copied ahead of that route compared `/secret` with the whole
//! `/secret?x=1` instead, did not match, and let an unauthenticated client
//! read the protected body. HTTP/1 and HTTP/2 match the path alone.

use super::*;

/// 🔑 `alice` / `secret1`, at the cheapest bcrypt cost so the test stays fast.
const ALICE_HASH: &str = "$2y$04$EBGg0.PJo2Qi2WYiMUqXsuB9orpRrMXiABirLM33AHHNb5GzEcipS";

/// 🚫 Adding a query string must not take a request out of a guard's scope.
#[tokio::test]
async fn h3_scoped_basic_auth_ignores_the_query_string() {
    let source = format!(
        r#":443 {{
            basic_auth /secret {{
                alice {ALICE_HASH}
            }}
            respond /secret "TOP SECRET"
        }}"#
    );
    let site = pingclair_config::compile(&source).unwrap().servers[0].clone();
    let server = spawn_h3_server_with(|address| ServerConfig {
        listen: vec![address.to_string()],
        ..site
    })
    .await;

    let mut seen = Vec::new();
    for path in ["/secret", "/secret?x=1", "/secret?"] {
        let response = h3_get(server, path).await.unwrap();
        seen.push((
            path,
            response.status,
            String::from_utf8_lossy(&response.body).into_owned(),
        ));
    }
    let authorized = h3_get_with_headers(
        server,
        "/secret?x=1",
        &[("authorization", "Basic YWxpY2U6c2VjcmV0MQ==")],
    )
    .await
    .unwrap();
    seen.push((
        "/secret?x=1 (alice)",
        authorized.status,
        String::from_utf8_lossy(&authorized.body).into_owned(),
    ));

    let statuses: Vec<_> = seen
        .iter()
        .map(|(path, status, _)| (*path, *status))
        .collect();
    assert_eq!(
        statuses,
        vec![
            ("/secret", 401),
            ("/secret?x=1", 401),
            ("/secret?", 401),
            ("/secret?x=1 (alice)", 200),
        ],
        "full responses: {seen:?}"
    );
}
