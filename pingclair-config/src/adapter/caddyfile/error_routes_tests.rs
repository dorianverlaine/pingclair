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

/// 🔢 Directives inside `handle_errors` run in Caddy's directive order, not in
/// file order: the block is an ordinary route body (#245).
#[test]
fn handle_errors_runs_its_directives_in_caddys_order() {
    let config = crate::compile(
        "example.com {\n\thandle_errors {\n\t\trespond \"gone\"\n\t\theader X-Test y\n\t}\n}",
    )
    .unwrap();
    let order: Vec<&str> = config.servers[0].error_routes[0]
        .handlers
        .iter()
        .map(|element| match &element.handler {
            HandlerConfig::Headers { .. } => "header",
            HandlerConfig::Respond { .. } => "respond",
            other => panic!("unexpected handler in the error route: {other:?}"),
        })
        .collect();
    assert_eq!(order, vec!["header", "respond"]);
}

/// 🏷️ A named matcher defined inside `handle_errors` belongs to that block and
/// resolves like any other route body's matcher (#245).
#[test]
fn handle_errors_accepts_named_matcher_definitions() {
    let config = crate::compile(
        "example.com {\n\thandle_errors {\n\t\t@gone path /gone\n\t\trespond @gone \"gone\"\n\t\trespond \"other\"\n\t}\n}",
    )
    .unwrap();
    let handlers = &config.servers[0].error_routes[0].handlers;
    let matchers: Vec<Option<pingclair_core::config::Matcher>> = handlers
        .iter()
        .map(|element| element.matcher.clone())
        .collect();
    assert_eq!(
        matchers,
        vec![
            Some(pingclair_core::config::Matcher::Path {
                patterns: vec!["/gone".to_string()],
            }),
            None,
        ]
    );
}

/// 🚫 A name defined inside the error route does not leak into the site block,
/// and a site-level name still reaches the error route.
#[test]
fn handle_errors_shares_the_site_matcher_scope_but_keeps_its_own() {
    let shared = crate::compile(
        "example.com {\n\t@site path /site\n\thandle_errors {\n\t\trespond @site \"site\"\n\t}\n}",
    )
    .unwrap();
    let matcher = shared.servers[0].error_routes[0].handlers[0]
        .matcher
        .clone();
    assert_eq!(
        matcher,
        Some(pingclair_core::config::Matcher::Path {
            patterns: vec!["/site".to_string()],
        })
    );

    let leak = crate::compile(
        "example.com {\n\thandle_errors {\n\t\t@local path /local\n\t\trespond @local \"local\"\n\t}\n\trespond @local \"site\"\n}",
    )
    .expect_err("a name defined inside handle_errors must not reach the site block");
    assert!(
        leak.to_string().contains("matcher `local` is not defined"),
        "unexpected refusal: {leak}"
    );
}
