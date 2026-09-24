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
//! 2. Within one rank, a route with a matcher before one without, so a
//!    catch-all never hides a narrower sibling of the same directive.
//! 3. Then matcher specificity — exact paths before globs, longer before
//!    shorter — the same comparison the router's route sort uses today.
//! 4. Then file order, which is what is left when nothing else decides.

use super::order::DirectiveOrder;
use super::sites::{handler_directive_name, handler_has_terminal, route_specificity};
use crate::parser::ast::{Handler, RouteArm};
use std::cmp::Reverse;

/// 🔢 Where one route sits in the ordered list.
///
/// 🎯 The field order *is* the comparison: the derived `Ord` compares fields
/// top to bottom, so reordering these fields changes routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct RouteOrderKey {
    rank: usize,
    unmatched: bool,
    glob: usize,
    length: Reverse<usize>,
    file_index: usize,
}

impl RouteOrderKey {
    /// 🧭 The key for a route that one directive produced, before any site
    /// middleware is composed into it — composition hides which directive it
    /// was.
    pub(super) fn for_arm(order: &DirectiveOrder, arm: &RouteArm, file_index: usize) -> Self {
        let (glob, length) = route_specificity(&arm.matcher);
        Self {
            rank: order.rank(handler_directive_name(&arm.handler)),
            unmatched: arm.matcher.is_none(),
            glob,
            length: Reverse(length),
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
            unmatched: true,
            glob: 0,
            length: Reverse(0),
            file_index: usize::MAX,
        }
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
