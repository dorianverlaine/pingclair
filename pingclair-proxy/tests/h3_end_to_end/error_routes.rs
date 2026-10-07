//! 🚨 `handle_errors` routes answer with their own pages over HTTP/3.
//!
//! The `file_server` in an error route used to be looked up in the slot of
//! the route that raised the error. Over HTTP/3 that slot was empty, so the
//! answer was `503 File Server Unavailable` whatever the error route said.

use super::*;

/// 📂 A site whose error route serves `<status>.html` from its own root.
fn error_page_site(error_root: &std::path::Path, extra: &str) -> ServerConfig {
    let source = format!(
        r#":443 {{
            handle_errors {{
                root * {error_root}
                rewrite * /{{err.status_code}}.html
                file_server
            }}
            handle /boom {{
                error "exploded" 503
            }}
            {extra}
        }}"#,
        error_root = error_root.display(),
    );
    pingclair_config::compile(&source).unwrap().servers[0].clone()
}

/// 🚨 A raised status renders the error route's page with that status, and
/// the failed request's `Range` does not turn it into a `206`.
#[tokio::test]
async fn h3_handle_errors_file_server_serves_the_error_page() {
    let error_root = tempfile::tempdir().unwrap();
    std::fs::write(error_root.path().join("503.html"), "<h1>page for 503</h1>").unwrap();
    let site = error_page_site(error_root.path(), "");
    let server = spawn_h3_server_with(|address| ServerConfig {
        listen: vec![address.to_string()],
        ..site
    })
    .await;

    let mut seen = Vec::new();
    for method in ["GET", "POST"] {
        let response = h3_attempt(
            H3Attempt {
                method,
                extra_headers: &[("range", "bytes=0-1")],
                ..H3Attempt::to(server, "/boom")
            },
            None,
        )
        .await
        .unwrap();
        seen.push((
            method,
            response.status,
            String::from_utf8_lossy(&response.body).into_owned(),
        ));
    }
    assert_eq!(
        seen,
        vec![
            ("GET", 503, "<h1>page for 503</h1>".to_string()),
            ("POST", 503, "<h1>page for 503</h1>".to_string()),
        ]
    );
}

/// 🔤 A regex `rewrite` inside `handle_errors` resolves against the error
/// route's own compiled pattern table over HTTP/3 too (#245).
#[tokio::test]
async fn h3_handle_errors_regex_rewrite_uses_the_error_routes_table() {
    let error_root = tempfile::tempdir().unwrap();
    std::fs::write(error_root.path().join("page.html"), "<h1>rewritten</h1>").unwrap();
    let source = format!(
        r#":443 {{
            handle_errors {{
                root * {error_root}
                rewrite "^/boom/(.*)$" "/$1"
                file_server
            }}
            handle /boom/* {{
                error "exploded" 503
            }}
        }}"#,
        error_root = error_root.path().display(),
    );
    let site = pingclair_config::compile(&source).unwrap().servers[0].clone();
    let server = spawn_h3_server_with(|address| ServerConfig {
        listen: vec![address.to_string()],
        ..site
    })
    .await;

    let response = h3_attempt(H3Attempt::to(server, "/boom/page.html"), None)
        .await
        .unwrap();
    assert_eq!(
        (
            response.status,
            String::from_utf8_lossy(&response.body).into_owned()
        ),
        (503, "<h1>rewritten</h1>".to_string())
    );
}

/// 🔥 A template that fails to render is raised on HTTP/3 too, so
/// `handle_errors` answers it exactly as HTTP/1 and HTTP/2 do (#245).
#[tokio::test]
async fn h3_a_template_failure_reaches_the_error_route() {
    let site_root = tempfile::tempdir().unwrap();
    std::fs::write(site_root.path().join("broken.html"), "before {{ unclosed").unwrap();
    let source = format!(
        r#":443 {{
            root * {site_root}
            handle_errors {{
                respond "error page for {{err.status_code}}" 500
            }}
            templates
            file_server
        }}"#,
        site_root = site_root.path().display(),
    );
    let site = pingclair_config::compile(&source).unwrap().servers[0].clone();
    let server = spawn_h3_server_with(|address| ServerConfig {
        listen: vec![address.to_string()],
        ..site
    })
    .await;

    let response = h3_attempt(H3Attempt::to(server, "/broken.html"), None)
        .await
        .unwrap();
    assert_eq!(
        (
            response.status,
            String::from_utf8_lossy(&response.body).into_owned()
        ),
        (500, "error page for 500".to_string())
    );
}

/// 🚨 Errors the server produces itself reach `handle_errors` over HTTP/3 as
/// on HTTP/1 and HTTP/2: an unreachable upstream (502), a body over its limit
/// whether declared (413 before planning) or streamed (413 while draining),
/// and a missing file (404).
#[tokio::test]
async fn h3_handle_errors_answers_proxy_body_size_and_missing_file_errors() {
    let error_root = tempfile::tempdir().unwrap();
    let site_root = tempfile::tempdir().unwrap();
    for status in [404, 413, 502] {
        std::fs::write(
            error_root.path().join(format!("{status}.html")),
            format!("<h1>page for {status}</h1>"),
        )
        .unwrap();
    }
    let dead_address = {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        listener.local_addr().unwrap()
    };
    let site = error_page_site(
        error_root.path(),
        &format!(
            r#"root * {site_root}
            handle /proxy {{
                reverse_proxy http://{dead_address}
            }}
            handle /upload {{
                request_body {{
                    max_size 10
                }}
                respond "accepted"
            }}
            file_server"#,
            site_root = site_root.path().display(),
        ),
    );
    let server = spawn_h3_server_with(|address| ServerConfig {
        listen: vec![address.to_string()],
        ..site
    })
    .await;

    let body = [b'x'; 100];
    let declared = h3_attempt(
        H3Attempt {
            method: "POST",
            body: &body,
            extra_headers: &[("content-length", "100")],
            ..H3Attempt::to(server, "/upload")
        },
        None,
    )
    .await
    .unwrap();
    let mut seen = vec![("declared body", declared)];
    seen.push(("proxy", h3_get(server, "/proxy").await.unwrap()));
    seen.push((
        "streamed body",
        h3_post(server, "/upload", &body).await.unwrap(),
    ));
    seen.push((
        "small body",
        h3_post(server, "/upload", b"tiny").await.unwrap(),
    ));
    seen.push((
        "missing file",
        h3_get(server, "/missing.txt").await.unwrap(),
    ));
    let seen: Vec<_> = seen
        .into_iter()
        .map(|(what, response)| {
            (
                what,
                response.status,
                String::from_utf8_lossy(&response.body).into_owned(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        vec![
            ("declared body", 413, "<h1>page for 413</h1>".to_string()),
            ("proxy", 502, "<h1>page for 502</h1>".to_string()),
            ("streamed body", 413, "<h1>page for 413</h1>".to_string()),
            ("small body", 200, "accepted".to_string()),
            ("missing file", 404, "<h1>page for 404</h1>".to_string()),
        ]
    );
}
