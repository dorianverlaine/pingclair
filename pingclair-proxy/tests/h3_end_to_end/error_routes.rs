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
