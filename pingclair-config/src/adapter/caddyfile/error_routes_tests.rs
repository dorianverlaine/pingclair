// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚨 Document roots inside `handle_errors`.

use pingclair_core::config::HandlerConfig;

/// 📂 The document root each file server in the first error route serves from.
fn error_file_server_roots(source: &str) -> Vec<String> {
    let config = crate::compile(source).unwrap_or_else(|error| panic!("must compile: {error}"));
    config.servers[0].error_routes[0]
        .handlers
        .iter()
        .filter_map(|element| match &element.handler {
            HandlerConfig::FileServer { root, .. } => Some(root.clone()),
            _ => None,
        })
        .collect()
}

/// 📂 `root * /srv/errors` inside `handle_errors` is the spelling Caddy's own
/// documentation uses for a static error page, and it used to be refused at
/// load as a directive "not supported inside a route or handle block".
#[test]
fn root_inside_handle_errors_sets_the_error_routes_document_root() {
    let roots = error_file_server_roots(
        "example.com {\n\troot * /srv/site\n\thandle_errors {\n\t\trewrite * /{err.status_code}.html\n\t\tfile_server\n\t\troot * /srv/errors\n\t}\n\tfile_server\n}",
    );
    assert_eq!(roots, vec!["/srv/errors".to_string()]);
}

/// 📂 Without a root of its own, an error route serves from the site root.
///
/// 🤡 The site root used to reach only `templates` inside an error route, so
/// a bare `file_server` there served from the process's working directory.
#[test]
fn error_route_without_a_root_inherits_the_site_root() {
    let roots = error_file_server_roots(
        "example.com {\n\troot * /srv/site\n\thandle_errors {\n\t\tfile_server\n\t}\n}",
    );
    assert_eq!(roots, vec!["/srv/site".to_string()]);
}

/// 🚫 A matcher-scoped root inside `handle_errors` is refused the same way it
/// is at site level, rather than widened to the whole error route.
#[test]
fn matcher_scoped_root_inside_handle_errors_is_refused() {
    let error = crate::compile(
        "example.com {\n\t@html path *.html\n\thandle_errors {\n\t\troot @html /srv/errors\n\t\tfile_server\n\t}\n}",
    )
    .expect_err("a matcher-scoped root must be refused");
    assert!(
        error.to_string().contains("root <matcher>"),
        "unexpected refusal: {error}"
    );
}
