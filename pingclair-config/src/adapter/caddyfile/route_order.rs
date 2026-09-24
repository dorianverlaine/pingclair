// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 A site's routes as one ordered list, the way the reference format reads them.
//!
//! Two models of "which route answers" disagree here. The router picks the
//! **most specific path**: `file_server /assets/*` beats a catch-all `respond`
//! for `/assets/a.txt` wherever the two were written. The format picks the
//! **first route in directive order** that matches and answers: `respond`
//! sorts ahead of `file_server` in the order table, so the catch-all wins and
//! the file is never served. Issue #18 records the decision to adopt the
//! second model.
//!
//! 📌 This module is stage 1 of three. It only *builds* the ordered list, at
//! configuration time, beside the router; nothing consults it yet, so no
//! request is answered differently. Stage 2 switches selection over to it.
//!
//! The ordering key, in priority order:
//!
//! 1. The directive's rank in the order table ([`DirectiveOrder`]), which the
//!    `order` global option can rearrange.
//! 2. Within one rank, the route whose single path pattern is longer once a
//!    trailing `*` is removed goes first: `/foobar*` before `/foo`, because
//!    it names more of the path. A route with one path pattern goes before
//!    any route without one.
//! 3. Between two routes with no single path pattern, one with a matcher
//!    (say, a header) goes before one without, so a catch-all never hides a
//!    narrower sibling of the same directive.
//! 4. Between two patterns that are equal once trimmed, the exact one goes
//!    first: `/foo` before `/foo*`.
//! 5. Then file order, which is what is left when nothing else decides.
//!
//! 📜 Where this comes from: steps 2–5 reproduce `sortRoutes` in the
//! reference's Caddyfile adapter (`caddyconfig/httpcaddyfile/httptype.go`),
//! as the issue #18 decision of 2026-09-24 requires. That function was not
//! re-read for this change; the rule is written from memory of it, including
//! two details worth checking against the source if this ever disagrees with
//! a measurement:
//!
//! - Only a matcher with exactly **one** path pattern has a length. Several
//!   patterns (`path /a /b`), a pattern under `not`, or no path condition at
//!   all count as having none (the reference's issue #5037 case).
//! - Two different trimmed patterns of equal length are ordered
//!   alphabetically there; here they stay in file order, per the decision.
//!   The two can only disagree for patterns with a `*` in the middle — two
//!   different prefixes of the same length never match the same request.

use super::order::DirectiveOrder;
use super::sites::{handler_directive_name, handler_has_terminal};
use crate::parser::ast::{Handler, Matcher, RouteArm};
use std::cmp::Reverse;
use std::collections::HashMap;

/// 🔢 Where one route sits in the ordered list.
///
/// 🎯 The field order *is* the comparison: the derived `Ord` compares fields
/// top to bottom, so reordering these fields changes routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct RouteOrderKey {
    rank: usize,
    /// 📏 Trimmed length of the route's single path pattern. `Reverse` puts
    /// longer first, and `None` (no single pattern) after every `Some`.
    path_length: Reverse<Option<usize>>,
    unmatched: bool,
    wildcard: bool,
    file_index: usize,
}

impl RouteOrderKey {
    /// 🧭 The key for a route that one directive produced, before any site
    /// middleware is composed into it — composition hides which directive it
    /// was. Named matchers resolve through `matchers`, the way the reference
    /// reads the path out of the matcher set a name stands for.
    pub(super) fn for_arm(
        order: &DirectiveOrder,
        matchers: &HashMap<String, Matcher>,
        arm: &RouteArm,
        file_index: usize,
    ) -> Self {
        let pattern = arm
            .matcher
            .as_ref()
            .and_then(|matcher| sort_path(matcher, matchers));
        Self {
            rank: order.rank(handler_directive_name(&arm.handler)),
            path_length: Reverse(pattern.map(|pattern| trim_wildcard(pattern).len())),
            unmatched: arm.matcher.is_none(),
            wildcard: pattern.is_some_and(|pattern| pattern.ends_with('*')),
            file_index,
        }
    }

    /// 🧺 The key for the site's matcher-less pipeline.
    ///
    /// That pipeline bundles every unmatched directive into one route, and it
    /// answers through its first terminal handler, so that handler's rank is
    /// where the whole pipeline sits. A pipeline with nothing that answers
    /// sorts last, after every route that does.
    pub(super) fn for_catch_all(order: &DirectiveOrder, sorted_defaults: &[Handler]) -> Self {
        let rank = sorted_defaults
            .iter()
            .find(|handler| handler_has_terminal(handler))
            .map_or(usize::MAX, |handler| {
                order.rank(handler_directive_name(handler))
            });
        Self {
            rank,
            path_length: Reverse(None),
            unmatched: true,
            wildcard: false,
            file_index: usize::MAX,
        }
    }
}

/// ✂️ A pattern without its trailing `*`: the part that names a path.
fn trim_wildcard(pattern: &str) -> &str {
    pattern.strip_suffix('*').unwrap_or(pattern)
}

/// 📏 The one path pattern a matcher sorts by, if it has exactly one.
///
/// A named matcher is one matcher set whose conditions are `and`ed, so its
/// path patterns are collected across the `and` tree. `or` and `not` are not
/// descended: the reference does not read either as a plain path condition.
fn sort_path<'a>(matcher: &'a Matcher, matchers: &'a HashMap<String, Matcher>) -> Option<&'a str> {
    let mut patterns = Vec::new();
    collect_paths(matcher, matchers, &mut patterns, 0);
    match patterns.as_slice() {
        [pattern] => Some(pattern),
        _ => None,
    }
}

fn collect_paths<'a>(
    matcher: &'a Matcher,
    matchers: &'a HashMap<String, Matcher>,
    patterns: &mut Vec<&'a str>,
    depth: usize,
) {
    // 🛡️ A named matcher can name itself. The compiler rejects that later,
    // but this runs first and must not recurse forever on the way there.
    if depth > 16 {
        return;
    }
    match matcher {
        Matcher::Path(path) => patterns.extend(path.patterns.iter().map(String::as_str)),
        Matcher::Named(name) => {
            if let Some(named) = matchers.get(name) {
                collect_paths(named, matchers, patterns, depth + 1);
            }
        }
        Matcher::And(left, right) => {
            collect_paths(left, matchers, patterns, depth + 1);
            collect_paths(right, matchers, patterns, depth + 1);
        }
        Matcher::Header(_)
        | Matcher::Method(_)
        | Matcher::Query(_)
        | Matcher::Host(_)
        | Matcher::RemoteIp(_)
        | Matcher::Protocol(_)
        | Matcher::Vars { .. }
        | Matcher::PathRegexp { .. }
        | Matcher::HeaderRegexp { .. }
        | Matcher::File { .. }
        | Matcher::Or(..)
        | Matcher::Not(_) => {}
    }
}

/// 📋 Route indices in the order they would be tried, first entry first.
///
/// 🏗️ Configuration time only; the cost is a sort over a handful of routes
/// once per load, never per request.
pub(super) fn directive_order(keys: &[RouteOrderKey]) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..keys.len()).collect();
    indices.sort_by_key(|&index| keys[index]);
    indices
}

// MARK: - Tests

/// 🧪 The ordered list against the router it will replace.
///
/// Where the two models already agree, the first route in the list that
/// matches must be the route the router picks today. Where they disagree — a
/// narrower directive that sorts after a catch-all — the list must pick what
/// the reference picks, which is the behaviour stage 2 switches to.
#[cfg(test)]
mod tests {
    use pingclair_core::server::Router;

    /// 🔎 The site's ordered list, next to the routes the full compile made
    /// from the same arms.
    fn site(source: &str) -> (Vec<usize>, Vec<pingclair_core::config::RouteConfig>) {
        let ast = crate::parser::compile(source).expect("parse");
        let server = &ast.servers[0].inner;
        let arms = server
            .routes
            .as_ref()
            .map_or(0, |routes| routes.inner.arms.len());
        let routes = crate::compile(source).expect("compile").servers[0]
            .routes
            .clone();
        // 📏 One pattern per arm keeps arm indices and route indices equal;
        // multi-pattern matchers are stage 2's mapping to solve.
        assert_eq!(routes.len(), arms, "every arm compiled to one route");
        (server.directive_order.clone(), routes)
    }

    fn router_pick(routes: &[pingclair_core::config::RouteConfig], path: &str) -> Option<usize> {
        let headers = http::HeaderMap::new();
        Router::new(routes.to_vec())
            .match_request(
                path,
                "GET",
                &headers,
                "example.com",
                "127.0.0.1",
                "HTTP/1.1",
                None,
            )
            .map(|route| route.index)
    }

    /// 🧭 First route in the ordered list whose own matcher accepts the path,
    /// using a one-route router so path matching is the real one.
    fn ordered_pick(
        order: &[usize],
        routes: &[pingclair_core::config::RouteConfig],
        path: &str,
    ) -> Option<usize> {
        order
            .iter()
            .copied()
            .find(|&index| router_pick(std::slice::from_ref(&routes[index]), path).is_some())
    }

    #[test]
    fn the_list_agrees_with_the_router_where_the_models_already_agree() {
        let sources = [
            // 🎯 Narrower directive sorted ahead of the catch-all.
            "example.com {\n    redir /old /new\n    respond \"hello\" 200\n}",
            // 🎯 Two siblings of one directive: specificity is the tie-break.
            "example.com {\n    respond /api/* \"api\"\n    respond /api/v2/* \"v2\"\n    respond \"top\"\n}",
            // 🎯 A matched terminal ahead of a catch-all of a later rank.
            "example.com {\n    root * /srv\n    respond /health \"ok\"\n    file_server\n}",
            // 🎯 `handle` blocks, the common real-world shape.
            "example.com {\n    handle /api/* {\n        respond \"api\"\n    }\n    handle {\n        respond \"spa\"\n    }\n}",
            // 🎯 Middleware on a path, answered by the catch-all.
            "example.com {\n    header /x X-Scoped yes\n    respond \"hello\"\n}",
        ];
        for source in sources {
            let (order, routes) = site(source);
            for path in [
                "/",
                "/old",
                "/api/x",
                "/api/v2/x",
                "/health",
                "/x",
                "/other",
            ] {
                assert_eq!(
                    ordered_pick(&order, &routes, path),
                    router_pick(&routes, path),
                    "{path} in:\n{source}"
                );
            }
        }
    }

    #[test]
    fn the_list_puts_an_earlier_directive_ahead_of_a_more_specific_one() {
        // 🔥 The reproduction from issue #18: `respond` ranks ahead of
        // `file_server`, so the reference answers `hello` for the asset. The
        // router still answers with the file; stage 2 closes that gap.
        let (order, routes) = site(
            "example.com {\n    root * /srv\n    file_server /assets/*\n    respond \"hello\" 200\n}",
        );
        let catch_all = routes
            .iter()
            .position(|route| route.path == "/*")
            .expect("catch-all route");
        let assets = routes
            .iter()
            .position(|route| route.path == "/assets/*")
            .expect("asset route");
        assert_eq!(order, vec![catch_all, assets]);
        assert_eq!(
            ordered_pick(&order, &routes, "/assets/a.txt"),
            Some(catch_all)
        );
        assert_eq!(router_pick(&routes, "/assets/a.txt"), Some(assets));
    }

    #[test]
    fn siblings_of_one_directive_sort_by_trimmed_path_length_first() {
        // 📏 The 2026-09-24 tie-break: `/foobar*` names more of the path
        // than `/foo`, so it goes first even though `/foo` is exact; `/foo`
        // beats `/foo*` because they are equal once trimmed; a header-only
        // matcher has no path length and goes after every path route.
        let (order, routes) = site(concat!(
            "example.com {\n",
            "    @canary header X-Canary 1\n",
            "    respond @canary \"canary\"\n",
            "    respond /foo* \"foo glob\"\n",
            "    respond /foo \"foo\"\n",
            "    respond /foobar* \"foobar\"\n",
            "}",
        ));
        let paths: Vec<&str> = order
            .iter()
            .map(|&index| routes[index].path.as_str())
            .collect();
        assert_eq!(paths, ["/foobar*", "/foo", "/foo*", "/*"]);
    }

    #[test]
    fn the_order_option_moves_a_route_in_the_list() {
        // 🔀 With `file_server` moved first, the reference serves the asset,
        // which is also what the router does: the models agree again.
        let (order, routes) = site(
            "{\n    order file_server first\n}\nexample.com {\n    root * /srv\n    file_server /assets/*\n    respond \"hello\" 200\n}",
        );
        for path in ["/assets/a.txt", "/other"] {
            assert_eq!(
                ordered_pick(&order, &routes, path),
                router_pick(&routes, path),
                "{path}"
            );
        }
    }
}
