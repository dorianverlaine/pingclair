// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 `Accept` negotiation end to end through the file server.

use super::*;
use pingclair_core::config::Negotiation;

/// 🧪 One tree with an HTML page, its Markdown twin, a directory page whose
/// twin is only the sibling `.md`, and an asset.
fn fixture(negotiate: bool) -> (tempfile::TempDir, FileServer) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.html"), "<h1>home</h1>").unwrap();
    std::fs::write(dir.path().join("index.md"), "# home").unwrap();
    std::fs::create_dir(dir.path().join("guide")).unwrap();
    std::fs::write(dir.path().join("guide/index.html"), "<h1>guide</h1>").unwrap();
    std::fs::write(dir.path().join("guide.md"), "# guide").unwrap();
    std::fs::create_dir(dir.path().join("bare")).unwrap();
    std::fs::write(dir.path().join("bare/index.html"), "<h1>bare</h1>").unwrap();
    std::fs::write(dir.path().join("page.html"), "<h1>page</h1>").unwrap();
    std::fs::write(dir.path().join("page.md"), "# page").unwrap();
    std::fs::write(dir.path().join("asset.png"), b"png-bytes").unwrap();
    let server = FileServer::new(FileServerConfig {
        root: dir.path().to_path_buf(),
        negotiate: if negotiate {
            vec![Negotiation::Markdown]
        } else {
            Vec::new()
        },
        ..FileServerConfig::default()
    });
    (dir, server)
}

/// 🧪 One GET, optionally carrying `Accept`, answered by the server.
async fn get(server: &FileServer, path: &str, accept: Option<&str>) -> ServedResponse {
    let mut headers = http::HeaderMap::new();
    if let Some(accept) = accept {
        headers.insert(http::header::ACCEPT, accept.parse().unwrap());
    }
    let request = FileRequest::new(&http::Method::GET, &headers);
    server
        .serve_auto(path, path, request, None)
        .await
        .unwrap()
        .expect("a response for a path that exists")
}

fn buffered(response: ServedResponse) -> ServedFile {
    match response {
        ServedResponse::Buffered(file) => file,
        _ => panic!("expected a buffered file"),
    }
}

#[tokio::test]
async fn a_preferred_markdown_twin_is_served_with_its_own_validators() {
    let (_dir, server) = fixture(true);
    let markdown = buffered(get(&server, "/", Some("text/markdown")).await);
    assert_eq!(markdown.content, &b"# home"[..]);
    assert_eq!(markdown.content_type, "text/markdown; charset=utf-8");
    assert!(markdown.vary_accept);

    // 🌐 The same URL with a browser's quality tie is the HTML, and it still
    // says the answer varies by `Accept`.
    let html = buffered(
        get(
            &server,
            "/",
            Some("text/html,application/xhtml+xml,*/*;q=0.8"),
        )
        .await,
    );
    assert_eq!(html.content, &b"<h1>home</h1>"[..]);
    assert_eq!(html.content_type, "text/html; charset=utf-8");
    assert!(html.vary_accept);
    assert_ne!(
        markdown.etag, html.etag,
        "each representation carries the tag of the file it served"
    );
}

#[tokio::test]
async fn q_zero_refuses_markdown_and_a_missing_twin_prefers_acceptable_html() {
    let (_dir, server) = fixture(true);
    let refused = buffered(get(&server, "/", Some("text/markdown;q=0, */*;q=1")).await);
    assert_eq!(refused.content, &b"<h1>home</h1>"[..]);

    // 📌 `bare` has no twin: an acceptable HTML still answers, a refused one
    // does not.
    let acceptable = buffered(get(&server, "/bare/", Some("text/markdown, text/html;q=0.5")).await);
    assert_eq!(acceptable.content, &b"<h1>bare</h1>"[..]);
    assert!(acceptable.vary_accept);
    let refused_html = get(&server, "/bare/", Some("text/markdown")).await;
    assert!(matches!(refused_html, ServedResponse::NotAcceptable));
}

#[tokio::test]
async fn the_directory_sibling_and_the_html_url_both_find_their_twins() {
    let (_dir, server) = fixture(true);
    let sibling = buffered(get(&server, "/guide/", Some("text/markdown")).await);
    assert_eq!(sibling.content, &b"# guide"[..]);
    let html_url = buffered(get(&server, "/page.html", Some("text/markdown")).await);
    assert_eq!(html_url.content, &b"# page"[..]);
}

#[tokio::test]
async fn assets_and_explicit_markdown_urls_never_negotiate() {
    let (_dir, server) = fixture(true);
    let asset = buffered(get(&server, "/asset.png", Some("text/markdown")).await);
    assert_eq!(asset.content, &b"png-bytes"[..]);
    assert!(
        !asset.vary_accept,
        "an asset does not depend on Accept, so it must not fragment its cache"
    );
    let explicit = buffered(get(&server, "/index.md", Some("text/html")).await);
    assert_eq!(explicit.content, &b"# home"[..]);
    assert!(
        !explicit.vary_accept,
        "an explicit `.md` URL is plain file serving"
    );
}

#[tokio::test]
async fn a_range_reads_the_representation_it_negotiated() {
    let (_dir, server) = fixture(true);
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::ACCEPT, "text/markdown".parse().unwrap());
    headers.insert(http::header::RANGE, "bytes=0-1".parse().unwrap());
    let request = FileRequest::new(&http::Method::GET, &headers);
    let ranged = buffered(
        server
            .serve_auto("/", "/", request, None)
            .await
            .unwrap()
            .expect("a response"),
    );
    assert_eq!(ranged.status, 206);
    assert_eq!(ranged.content, &b"# "[..]);
    assert_eq!(ranged.content_range.as_deref(), Some("bytes 0-1/6"));
    assert!(ranged.vary_accept);
}

#[tokio::test]
async fn a_file_server_without_the_modifier_never_negotiates() {
    let (_dir, server) = fixture(false);
    let html = buffered(get(&server, "/", Some("text/markdown")).await);
    assert_eq!(html.content, &b"<h1>home</h1>"[..]);
    assert!(!html.vary_accept);
}
