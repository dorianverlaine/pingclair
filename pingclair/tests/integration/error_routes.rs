// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚨 `handle_errors` routes answer with their own pages.
//!
//! Caddy's documented shape for a static error page is
//! `handle_errors { root * /srv/errors  rewrite * /{err.status_code}.html  file_server }`.
//! The `file_server` in it used to be looked up in the slot of the route that
//! raised the error, so the page was never served: HTTP/1 and HTTP/2 sent the
//! bare error text instead.

use super::{TestServer, no_proxy_client};

/// 📂 A site whose own root holds no error pages, and whose error route has a
/// root that does. Serving from the wrong one shows up as a missing page.
struct ErrorPageSite {
    _site_root: tempfile::TempDir,
    _error_root: tempfile::TempDir,
    config: String,
}

fn error_page_site(extra: &str) -> ErrorPageSite {
    let site_root = tempfile::tempdir().expect("site root");
    let error_root = tempfile::tempdir().expect("error root");
    std::fs::write(site_root.path().join("present.txt"), "present").unwrap();
    for status in [404, 503] {
        std::fs::write(
            error_root.path().join(format!("{status}.html")),
            format!("<h1>page for {status}</h1>"),
        )
        .unwrap();
    }
    let config = format!(
        r#"
        {{
            admin off
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            root * {site_root}

            handle_errors {{
                root * {error_root}
                rewrite * /{{err.status_code}}.html
                file_server
            }}

            handle /boom {{
                error "exploded" 503
            }}

            {extra}

            file_server
        }}
        "#,
        site_root = site_root.path().display(),
        error_root = error_root.path().display(),
    );
    ErrorPageSite {
        _site_root: site_root,
        _error_root: error_root,
        config,
    }
}

/// 🚨 A raised status and a missing file both render the error route's page,
/// with the error's status, on HTTP/1.1 and HTTP/2.
///
/// The request's `Range` and validators belong to the resource that failed,
/// not to the page, so they must not turn the error into a `206` or `304`.
#[tokio::test]
async fn test_handle_errors_file_server_serves_the_error_page() {
    let site = error_page_site("");
    let mut server = TestServer::new_pingclairfile(&site.config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let h2 = reqwest::Client::builder()
        .no_proxy()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    for (protocol, client) in [("h1", no_proxy_client()), ("h2", h2)] {
        let mut seen = Vec::new();
        for (method, path) in [
            (reqwest::Method::GET, "/boom"),
            (reqwest::Method::POST, "/boom"),
            (reqwest::Method::GET, "/missing.txt"),
            (reqwest::Method::GET, "/present.txt"),
        ] {
            let response = client
                .request(method.clone(), server.url(0, path))
                .header("Range", "bytes=0-1")
                .header("If-None-Match", "*")
                .send()
                .await
                .unwrap();
            seen.push((
                method.to_string(),
                path,
                response.status().as_u16(),
                response.text().await.unwrap(),
            ));
        }
        let expected = |method: &str, path, status, body: &str| {
            (method.to_string(), path, status, body.to_string())
        };
        assert_eq!(
            seen,
            vec![
                expected("GET", "/boom", 503, "<h1>page for 503</h1>"),
                expected("POST", "/boom", 503, "<h1>page for 503</h1>"),
                expected("GET", "/missing.txt", 404, "<h1>page for 404</h1>"),
                // 🎯 The site's own files still answer as before.
                expected("GET", "/present.txt", 304, ""),
            ],
            "{protocol}"
        );
    }
}
