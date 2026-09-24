// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ⚡ Microbenchmarks for route selection, the one lookup every request makes.
//!
//! The table below is shaped like a real site: exact paths, nested prefix
//! globs, a header-guarded route, and a catch-all. Each benchmark asks for one
//! kind of path, so a change to how the router picks a route shows up as the
//! kind of request it slowed down rather than as one blended number.

use divan::black_box;
use pingclair_core::config::{HandlerConfig, Matcher, MatcherCondition, RouteConfig};
use pingclair_core::server::Router;
use std::collections::BTreeMap;
use std::sync::LazyLock;

fn main() {
    // 🏗️ Build the table before timing starts, so the first sample of
    // whichever benchmark runs first does not pay for construction.
    LazyLock::force(&ROUTER);
    divan::main();
}

/// 🧱 One `respond` route; the handler never runs here, only selection does.
fn route(path: &str, matcher: Option<Matcher>) -> RouteConfig {
    RouteConfig {
        path: path.to_string(),
        handler: HandlerConfig::Respond {
            status: 200,
            body: Some(path.to_string()),
            headers: BTreeMap::new(),
        },
        methods: None,
        matcher,
    }
}

fn path_matcher(pattern: &str) -> Option<Matcher> {
    Some(Matcher::Path {
        patterns: vec![pattern.to_string()],
    })
}

/// 🏗️ Built once: construction is configuration-time work and is not what
/// these benchmarks measure.
static ROUTER: LazyLock<Router> = LazyLock::new(|| {
    Router::new(vec![
        route("/health", path_matcher("/health")),
        route("/api/v2/users/*", path_matcher("/api/v2/users/*")),
        route("/api/v2/*", path_matcher("/api/v2/*")),
        route("/api/*", path_matcher("/api/*")),
        route("/assets/*", path_matcher("/assets/*")),
        route("/favicon.ico", path_matcher("/favicon.ico")),
        route(
            "/*",
            Some(Matcher::Header {
                name: "X-Canary".to_string(),
                condition: MatcherCondition::Exists,
            }),
        ),
        route("/*", None),
    ])
});

fn select(path: &str) -> Option<usize> {
    let headers = http::HeaderMap::new();
    ROUTER
        .match_normalized_request(
            black_box(path),
            "GET",
            &headers,
            "example.com",
            "127.0.0.1",
            "HTTP/1.1",
            None,
        )
        .map(|route| route.index)
}

#[divan::bench]
fn exact_path() -> Option<usize> {
    select("/health")
}

#[divan::bench]
fn nested_glob() -> Option<usize> {
    select("/api/v2/users/42")
}

#[divan::bench]
fn shallow_glob() -> Option<usize> {
    select("/assets/app.js")
}

#[divan::bench]
fn catch_all() -> Option<usize> {
    select("/blog/2026/09/hello")
}
