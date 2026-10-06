// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔁 Canonical redirects: where the client is sent next.
//!
//! A `308` from the file server is the one response whose entire content is a
//! URL the client will follow, which makes it the place where a small formatting
//! mistake becomes a navigation to somewhere else.

use super::{TestServer, raw_http1, site};

/// 🧾 A directory to point the canonical redirect at.
fn directory_fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("sub")).unwrap();
    std::fs::write(root.path().join("sub/index.html"), b"<h1>sub</h1>").unwrap();
    root
}

/// 🔒 A canonical redirect never names another origin.
///
/// `Location: //dir/` is a network-path reference (RFC 3986 §4.2): a browser
/// resolves it against the scheme and navigates to host `dir`, not back to this
/// server. RFC 9110 §10.2.2 expects the target to be a URI reference the client
/// can resolve, and a canonicalization redirect that changes origin is one an
/// attacker can aim whenever a directory name is influenced by them — the class
/// upstream tracks as caddyserver/caddy#8023.
#[tokio::test]
async fn test_canonical_redirect_stays_on_this_origin() {
    let root = directory_fixture();
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "root * {}\n            file_server",
        root.path().display()
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, _) = raw_http1(
        &server,
        b"GET //sub HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    )
    .await;
    server.stop();

    let location = head
        .lines()
        .find(|line| line.starts_with("location:"))
        .unwrap_or_else(|| panic!("a redirect carries a location: {head}"));
    let target = location.trim_start_matches("location:").trim();
    assert!(
        !target.starts_with("//"),
        "a location of {target:?} sends the client to another host"
    );
}

/// 🧭 A canonical redirect keeps the request's query string.
///
/// No RFC clause requires this one — it is Caddy parity, and upstream fixed the
/// identical loss in caddyserver/caddy#6109 — but a canonicalization redirect
/// exists to normalize a URL's *shape*. A client that loses `?page=2` to a
/// missing trailing slash has been sent somewhere it did not ask for, and a
/// cache or tracker downstream sees a different resource.
#[tokio::test]
async fn test_canonical_redirect_keeps_the_query() {
    let root = directory_fixture();
    let mut server = TestServer::new_pingclairfile(&site(&format!(
        "root * {}\n            file_server",
        root.path().display()
    )));
    assert!(server.wait_until_ready().await, "server failed to start");

    let (head, _) = raw_http1(
        &server,
        b"GET /sub?x=1&y=2 HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    )
    .await;
    server.stop();

    let location = head
        .lines()
        .find(|line| line.starts_with("location:"))
        .unwrap_or_else(|| panic!("a redirect carries a location: {head}"));
    assert!(
        location.contains("?x=1&y=2"),
        "the query string must survive canonicalization: {location:?}"
    );
}
