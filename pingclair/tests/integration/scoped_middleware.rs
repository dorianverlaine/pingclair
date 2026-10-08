// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ Middleware written with a matcher runs ahead of whichever route
//! answers a request it matches.
//!
//! A site's routes are tried first to last and the first that matches answers
//! (issue #18). A `basic_auth /secret` line is not a route that answers, so on
//! its own it can only guard requests that fall through to the site's
//! fallback pipeline. When a sibling such as `respond /secret` answered first,
//! the guard never ran and an unauthenticated client got the protected body.
//! Every case below served the request unguarded before the fix.

use super::*;

/// 🔑 `alice` / `secret1`, at the cheapest bcrypt cost so the test stays fast.
const ALICE_HASH: &str = "$2y$04$EBGg0.PJo2Qi2WYiMUqXsuB9orpRrMXiABirLM33AHHNb5GzEcipS";

/// 🧾 Wraps a site body with the readiness route every test server needs.
fn site(body: &str) -> String {
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
}

/// 🔍 Status and body of one request, optionally with credentials.
async fn fetch(server: &TestServer, path: &str, credentials: Option<&str>) -> (u16, String) {
    let mut request = no_proxy_client().get(server.url(0, path));
    if let Some(password) = credentials {
        request = request.basic_auth("alice", Some(password));
    }
    let response = request.send().await.unwrap();
    (response.status().as_u16(), response.text().await.unwrap())
}

/// 🔥 The reproduction: `respond /secret` ranks ahead of the site's fallback,
/// so it answered before `basic_auth /secret` could ask for credentials. The
/// same holds for a terminal `handle` block.
#[tokio::test]
async fn basic_auth_guards_the_route_that_answers() {
    let config = site(&format!(
        r#"
            basic_auth /secret {{
                alice {ALICE_HASH}
            }}
            respond /secret "TOP SECRET"

            basic_auth /vault/* {{
                alice {ALICE_HASH}
            }}
            handle /vault/* {{
                respond "VAULT"
            }}

            respond /public "PUBLIC"
        "#
    ));
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    // 🔤 Route paths match without regard to case, so the guard must too.
    for (path, body) in [
        ("/secret", "TOP SECRET"),
        ("/SECRET", "TOP SECRET"),
        ("/vault/a", "VAULT"),
    ] {
        let (status, text) = fetch(&server, path, None).await;
        assert_eq!(status, 401, "{path} without credentials");
        assert_ne!(text, body, "{path} leaked its body");
        assert_eq!(fetch(&server, path, Some("wrong")).await.0, 401, "{path}");
        assert_eq!(
            fetch(&server, path, Some("secret1")).await,
            (200, body.to_string()),
            "{path} with credentials"
        );
    }
    // 🎯 A path the guard's matcher does not name stays open.
    assert_eq!(
        fetch(&server, "/public", None).await,
        (200, "PUBLIC".to_string())
    );
}

/// 🧩 Two scoped middleware lines that match the same request both run.
/// The narrower `header` line used to be a route of its own, sorted ahead of
/// the guard because its path is longer, so it answered `/admin/public`
/// through the fallback without the guard ever seeing the request.
#[tokio::test]
async fn overlapping_scoped_middleware_all_run() {
    let config = site(&format!(
        r#"
            basic_auth /admin/* {{
                alice {ALICE_HASH}
            }}
            header /admin/public X-Public yes
            respond "FALLBACK"
        "#
    ));
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    assert_eq!(fetch(&server, "/admin/public", None).await.0, 401);
    let response = no_proxy_client()
        .get(server.url(0, "/admin/public"))
        .basic_auth("alice", Some("secret1"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers().get("x-public").unwrap(), "yes");
    assert_eq!(response.text().await.unwrap(), "FALLBACK");
    assert_eq!(
        fetch(&server, "/elsewhere", None).await,
        (200, "FALLBACK".to_string())
    );
}

/// 🔐 A gateway that admits a request carrying `X-Token: letmein`, or one for
/// the harness's readiness path, and refuses everything else with 401. It
/// answers until the test ends.
async fn spawn_auth_gateway() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let request =
                    read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(2)).await;
                let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
                let admitted = request.contains("x-token: letmein\r\n")
                    || request.contains("x-forwarded-uri: /__pingclair_test_ready");
                let reply: &[u8] = if admitted {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else {
                    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndenied"
                };
                let _ = stream.write_all(reply).await;
            });
        }
    });
    address
}

/// 🔍 Status and body of one request, optionally with the gateway's token.
async fn fetch_with_token(server: &TestServer, path: &str, token: bool) -> (u16, String) {
    let mut request = no_proxy_client().get(server.url(0, path));
    if token {
        request = request.header("X-Token", "letmein");
    }
    let response = request.send().await.unwrap();
    (response.status().as_u16(), response.text().await.unwrap())
}

/// 🔐 `forward_auth` with a matcher guards a terminal sibling the same way.
#[tokio::test]
async fn scoped_forward_auth_guards_the_route_that_answers() {
    let gateway = spawn_auth_gateway().await;
    let config = site(&format!(
        r#"
            forward_auth /secret http://{gateway} {{
                uri /check
            }}
            respond /secret "TOP SECRET"
            respond /public "PUBLIC"
        "#
    ));
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    assert_eq!(
        fetch_with_token(&server, "/secret", false).await,
        (401, "denied".to_string())
    );
    assert_eq!(
        fetch_with_token(&server, "/secret", true).await,
        (200, "TOP SECRET".to_string())
    );
    assert_eq!(
        fetch_with_token(&server, "/public", false).await,
        (200, "PUBLIC".to_string())
    );
}

/// 🔐 An unscoped `forward_auth` runs before the site's own `respond`. It
/// used to rank as `reverse_proxy`, after `respond`, so the fallback answered
/// and the gateway was never asked.
#[tokio::test]
async fn site_forward_auth_runs_before_respond() {
    let gateway = spawn_auth_gateway().await;
    let config = site(&format!(
        r#"
            forward_auth http://{gateway} {{
                uri /check
            }}
            respond "TOP SECRET"
        "#
    ));
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    assert_eq!(
        fetch_with_token(&server, "/anything", false).await,
        (401, "denied".to_string())
    );
    assert_eq!(
        fetch_with_token(&server, "/anything", true).await,
        (200, "TOP SECRET".to_string())
    );
}

/// 🏷️ A scoped `header` reaches the terminal route that answers its path,
/// and only that path.
#[tokio::test]
async fn scoped_header_reaches_the_route_that_answers() {
    let config = site(
        r#"
            header /tagged X-Scoped yes
            respond /tagged "tagged"
            respond /plain "plain"
        "#,
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = no_proxy_client();
    for (path, expected) in [("/tagged", Some("yes")), ("/plain", None)] {
        let response = client.get(server.url(0, path)).send().await.unwrap();
        assert_eq!(response.status(), 200, "{path}");
        assert_eq!(
            response
                .headers()
                .get("x-scoped")
                .map(|value| value.to_str().unwrap()),
            expected,
            "{path}"
        );
    }
}
/// 🛡️ A site-wide guard respects the documented order: `redir` answers first.
///
/// `redir` ranks ahead of `basic_auth` in the order table the adapter
/// publishes, and the reference answers that redirect without asking for
/// credentials. The unmatched `basic_auth` was copied ahead of *every*
/// answering route, so adding it to the site turned the same 308 into a 401
/// (#310).
#[tokio::test]
async fn site_wide_basic_auth_does_not_preempt_redir() {
    let server = TestServer::new_pingclairfile(&site(&format!(
        r#"
            redir /go /target 308

            basic_auth bcrypt "R" {{
                alice {ALICE_HASH}
            }}

            respond "welcome"
        "#
    )));
    // 🚪 A site-wide `basic_auth` guards every path — including the harness's
    // readiness route, which is the behaviour under test. Wait for the
    // listeners themselves: the banner is written after every one is bound.
    let mut up = false;
    for _ in 0..75 {
        if server.announced_its_listeners() {
            up = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(up, "server failed to start");

    // 🚫 The assertion is about the redirect itself: a client that follows it
    // lands on a path the guard protects and would report the 401 instead.
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let redirect = client.get(server.url(0, "/go")).send().await.unwrap();
    assert_eq!(
        (
            redirect.status().as_u16(),
            redirect
                .headers()
                .get("location")
                .unwrap()
                .to_str()
                .unwrap()
        ),
        (308, "/target"),
        "`redir` answers before `basic_auth`, exactly as the order table says"
    );

    // 🩺 The control: the guard still runs where nothing answered first.
    let unauthenticated = client.get(server.url(0, "/other")).send().await.unwrap();
    assert_eq!(unauthenticated.status(), 401);
    let authenticated = client
        .get(server.url(0, "/other"))
        .basic_auth("alice", Some("secret1"))
        .send()
        .await
        .unwrap();
    assert_eq!(authenticated.status(), 200);
}
