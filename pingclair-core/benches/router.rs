// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ⚡ Microbenchmarks for route selection, the one lookup every request makes.
//!
//! The table below is shaped like a real site: exact paths, nested prefix
//! globs, a header-guarded route, and a catch-all. Each benchmark asks for one
//! kind of path, so a change to how the router picks a route shows up as the
//! kind of request it slowed down rather than as one blended number.

use divan::black_box;
use pingclair_core::config::{HandlerConfig, IpRanges, Matcher, MatcherCondition, RouteConfig};
use pingclair_core::server::{RequestAddresses, Router};
use std::collections::BTreeMap;
use std::sync::LazyLock;

fn main() {
    // 🏗️ Build the table before timing starts, so the first sample of
    // whichever benchmark runs first does not pay for construction.
    LazyLock::force(&ROUTER);
    LazyLock::force(&IP_GUARDED);
    LazyLock::force(&WILDCARD);
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
            RequestAddresses::direct(std::net::Ipv4Addr::LOCALHOST.into()),
            "HTTP/1.1",
            None,
        )
        .map(|route| route.index)
}

#[divan::bench]
fn exact_path() -> Option<usize> {
    select("/health")
}

/// 🔤 The same route asked for in another case (issue #198): the path is
/// folded into a stack buffer before the tree walk, where a lowercase path
/// is passed through untouched.
#[divan::bench]
fn exact_path_mixed_case() -> Option<usize> {
    select("/Health")
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

/// 🧩 A PHP-style site: a suffix route the radix tree cannot hold, beside a
/// prefix and a catch-all (issue #193). The suffix route is a candidate for
/// every path, so both the hit and the miss pay for its compiled check.
static WILDCARD: LazyLock<Router> = LazyLock::new(|| {
    Router::new(vec![
        route("/api/*", path_matcher("/api/*")),
        route("*.php", path_matcher("*.php")),
        route("/*", None),
    ])
});

fn select_wildcard(path: &str) -> Option<usize> {
    let headers = http::HeaderMap::new();
    WILDCARD
        .match_normalized_request(
            black_box(path),
            "GET",
            &headers,
            "example.com",
            RequestAddresses::direct(std::net::Ipv4Addr::LOCALHOST.into()),
            "HTTP/1.1",
            None,
        )
        .map(|route| route.index)
}

#[divan::bench]
fn suffix_wildcard_hit() -> Option<usize> {
    select_wildcard("/blog/2026/index.php")
}

#[divan::bench]
fn suffix_wildcard_miss() -> Option<usize> {
    select_wildcard("/blog/2026/09/hello")
}

/// 🌐 A `remote_ip` matcher over the given ranges.
fn ip_matcher(ranges: &[&str]) -> Matcher {
    Matcher::RemoteIp(IpRanges::parse(ranges.iter().copied()).expect("benchmark ranges parse"))
}

/// 🌐 The address-blocking shape: a `remote_ip` guard in front of the site,
/// listing several ranges the request is in none of, so every range is
/// checked before the catch-all answers. This is the cost every request pays
/// on a site that blocks addresses.
static IP_GUARDED: LazyLock<Router> = LazyLock::new(|| {
    Router::new(vec![
        route(
            "/*",
            Some(ip_matcher(&[
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "2001:db8::/32",
            ])),
        ),
        route("/*", None),
    ])
});

#[divan::bench]
fn ip_guard_miss() -> Option<usize> {
    let headers = http::HeaderMap::new();
    IP_GUARDED
        .match_normalized_request(
            black_box("/index.html"),
            "GET",
            &headers,
            "example.com",
            black_box(RequestAddresses::direct(
                std::net::Ipv4Addr::new(203, 0, 113, 9).into(),
            )),
            "HTTP/1.1",
            None,
        )
        .map(|route| route.index)
}
