// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 A site's routes as one ordered list, the way the reference format reads them.
//!
//! Two models of "which route answers" used to disagree here. The router
//! picked the **most specific path**: `file_server /assets/*` beat a
//! catch-all `respond` for `/assets/a.txt` wherever the two were written.
//! The format picks the **first route in directive order** that matches and
//! answers: `respond` sorts ahead of `file_server` in the order table, so the
//! catch-all wins and the file is never served. Issue #18 adopted the second
//! model; the router has followed it since the stage-2 commit.
//!
//! 📌 The site adapter sorts its routes by [`RouteOrderKey`] once, at load,
//! and emits them in that order (issue #18, stage 2). The router tries them
//! in that order and the first that matches answers; its radix tree only
//! narrows which of them a path can reach.
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
//!   The two can only disagree for patterns with a `*` that is not at the
//!   end — two different prefixes of the same length never match the same
//!   request. Since route paths honour such a `*` (issue #193) the
//!   difference is observable: with `@a path /a/*x` and `@b path /*/bx`,
//!   `/a/bx` matches both, and the one written first answers here, where the
//!   reference always picks `/*/bx` (`*` sorts before `a`).

use super::order::DirectiveOrder;
use super::sites::{handler_directive_name, handler_has_terminal};
use crate::parser::ast::{Handler, HandlerElement, Matcher, RouteArm};
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
    ///
    /// 🧩 A route that does not answer by itself (a matched `header`, say) is
    /// composed with the site's default pipeline and answers through that
    /// pipeline's terminal handler, so it takes `pipeline_rank`, the rank of
    /// that handler. Ranking it as `header` would put it ahead of every
    /// `respond` and let it answer requests those routes should answer.
    pub(super) fn for_arm(
        order: &DirectiveOrder,
        matchers: &HashMap<String, Matcher>,
        arm: &RouteArm,
        file_index: usize,
        pipeline_rank: usize,
    ) -> Self {
        let rank = if handler_has_terminal(&arm.handler) {
            order.rank(handler_directive_name(&arm.handler))
        } else {
            pipeline_rank
        };
        Self::new(rank, matchers, arm.matcher.as_ref(), file_index)
    }

    /// 🧩 The key for one element inside a `handle` block, where every
    /// element runs as a step and none is composed with anything.
    pub(super) fn for_element(
        order: &DirectiveOrder,
        matchers: &HashMap<String, Matcher>,
        element: &HandlerElement,
        file_index: usize,
    ) -> Self {
        let rank = order.rank(handler_directive_name(&element.handler));
        Self::new(rank, matchers, element.matcher.as_ref(), file_index)
    }

    /// 🧺 The key for the site's matcher-less pipeline, which sorts after
    /// every matched route of the same rank.
    pub(super) fn for_catch_all(pipeline_rank: usize) -> Self {
        Self {
            rank: pipeline_rank,
            path_length: Reverse(None),
            unmatched: true,
            wildcard: false,
            file_index: usize::MAX,
        }
    }

    /// 🔢 The rank the default pipeline answers at.
    ///
    /// That pipeline bundles every unmatched directive, and it answers
    /// through its first terminal handler, so that handler's rank is where
    /// the whole pipeline sits. A pipeline with nothing that answers sorts
    /// last, after every route that does.
    ///
    /// 📄 `templates` is skipped: it counts as terminal here because it reads
    /// the file itself, but in the reference it only rewrites the response of
    /// the handler after it (`file_server`, usually), and that handler's rank
    /// is where the pair answers. Ranking the pair as `templates` would put a
    /// catch-all ahead of every `respond`.
    pub(super) fn pipeline_rank(order: &DirectiveOrder, sorted_defaults: &[Handler]) -> usize {
        sorted_defaults
            .iter()
            .filter(|handler| !matches!(handler, Handler::Templates))
            .find(|handler| handler_has_terminal(handler))
            .map_or(usize::MAX, |handler| {
                order.rank(handler_directive_name(handler))
            })
    }

    fn new(
        rank: usize,
        matchers: &HashMap<String, Matcher>,
        matcher: Option<&Matcher>,
        file_index: usize,
    ) -> Self {
        let pattern = matcher.and_then(|matcher| sort_path(matcher, matchers));
        Self {
            rank,
            path_length: Reverse(pattern.map(|pattern| trim_wildcard(pattern).len())),
            unmatched: matcher.is_none(),
            wildcard: pattern.is_some_and(|pattern| pattern.ends_with('*')),
            file_index,
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
        | Matcher::ClientIp(_)
        | Matcher::Protocol(_)
        | Matcher::Vars { .. }
        | Matcher::PathRegexp { .. }
        | Matcher::HeaderRegexp { .. }
        | Matcher::File { .. }
        | Matcher::Or(..)
        | Matcher::Not(_) => {}
    }
}

// MARK: - Tests

/// 🧪 The order a site's compiled routes come out in, and what the router
/// answers from that order.
#[cfg(test)]
mod tests {
    use pingclair_core::config::{HandlerConfig, RouteConfig};

    fn routes(source: &str) -> Vec<RouteConfig> {
        crate::compile(source).expect("compile").servers[0]
            .routes
            .clone()
    }

    fn paths(source: &str) -> Vec<String> {
        routes(source).into_iter().map(|route| route.path).collect()
    }

    /// 💬 The first `respond` body in a route's handler tree, which is how
    /// these fixtures label their routes; `proxy` when there is none.
    fn body(handler: &HandlerConfig) -> Option<&str> {
        match handler {
            HandlerConfig::Respond { body, .. } => body.as_deref(),
            HandlerConfig::Pipeline { handlers } => {
                handlers.iter().find_map(|element| body(&element.handler))
            }
            _ => None,
        }
    }

    /// 🧭 The label of the route the real router picks for `path`.
    fn answer(source: &str, path: &str) -> String {
        let headers = http::HeaderMap::new();
        let router = pingclair_core::server::Router::new(routes(source));
        let route = router
            .match_request(
                path,
                "GET",
                &headers,
                "example.com",
                pingclair_core::server::RequestAddresses::direct(
                    std::net::Ipv4Addr::LOCALHOST.into(),
                ),
                "HTTP/1.1",
                None,
            )
            .expect("some route answers");
        body(&route.config.handler).unwrap_or("proxy").to_string()
    }

    fn bodies(source: &str) -> Vec<String> {
        routes(source)
            .iter()
            .map(|route| body(&route.handler).unwrap_or("proxy").to_string())
            .collect()
    }

    #[test]
    fn an_earlier_directive_goes_before_a_more_specific_one() {
        // 🔥 The reproduction from issue #18: `respond` ranks ahead of
        // `file_server`, so the catch-all comes first.
        let source = "example.com {\n    root * /srv\n    file_server /assets/*\n    respond \"hello\" 200\n}";
        assert_eq!(paths(source), ["/*", "/assets/*"]);
        assert_eq!(answer(source, "/assets/a.txt"), "hello");
    }

    #[test]
    fn the_order_option_moves_a_route_in_the_list() {
        // 🔀 With `file_server` moved first, the asset route leads again.
        let source = "{\n    order file_server first\n}\nexample.com {\n    root * /srv\n    file_server /assets/*\n    respond \"hello\" 200\n}";
        assert_eq!(paths(source), ["/assets/*", "/*"]);
    }

    #[test]
    fn siblings_of_one_directive_sort_by_trimmed_path_length_first() {
        // 📏 The 2026-09-24 tie-break: `/foobar*` names more of the path
        // than `/foo`, so it goes first even though `/foo` is exact; `/foo`
        // beats `/foo*` because they are equal once trimmed; a header-only
        // matcher has no path length and goes after every path route.
        let source = concat!(
            "example.com {\n",
            "    @canary header X-Canary 1\n",
            "    respond @canary \"canary\"\n",
            "    respond /foo* \"foo glob\"\n",
            "    respond /foo \"foo\"\n",
            "    respond /foobar* \"foobar\"\n",
            "}",
        );
        assert_eq!(bodies(source), ["foobar", "foo", "foo glob", "canary"]);
    }

    #[test]
    fn a_matcher_with_several_paths_has_no_path_length() {
        // 🧮 `path /a /b` compiles to one route per pattern, but it sorts as
        // one route with no length, so the single-path glob goes first and
        // the two patterns stay together after it.
        let source = concat!(
            "example.com {\n",
            "    @both path /a /b\n",
            "    respond @both \"both\"\n",
            "    respond /a* \"a glob\"\n",
            "}",
        );
        assert_eq!(paths(source), ["/a*", "/a", "/b"]);
        assert_eq!(answer(source, "/a"), "a glob");
        assert_eq!(answer(source, "/b"), "both");
    }

    #[test]
    fn a_matched_middleware_route_sorts_at_its_pipelines_rank() {
        // 🧩 `header @rest` is composed with the proxy, so it answers where
        // `reverse_proxy` ranks — after `respond`, ahead of the plain
        // catch-all. Ranked as `header` it would lead the list and answer
        // the readiness path with the proxy.
        let source = concat!(
            "example.com {\n",
            "    @ready path /ready\n",
            "    respond @ready \"ready\"\n",
            "    @rest not path /api/*\n",
            "    header @rest Cache-Control no-cache\n",
            "    reverse_proxy 127.0.0.1:9\n",
            "}",
        );
        let routes = routes(source);
        assert_eq!(body(&routes[0].handler), Some("ready"));
        assert!(routes[1].matcher.is_some(), "the `header @rest` route");
        assert!(routes[2].matcher.is_none(), "the catch-all");
        assert_eq!(answer(source, "/ready"), "ready");
        assert_eq!(answer(source, "/page"), "proxy");
    }

    #[test]
    fn php_fastcgi_ranks_as_itself() {
        // 🐘 Its expansion is a pipeline, which would otherwise rank as
        // `route`, ahead of `respond`; as itself it ranks after.
        let source = concat!(
            "example.com {\n",
            "    root * /srv\n",
            "    php_fastcgi /app/* 127.0.0.1:9000\n",
            "    respond \"hello\"\n",
            "}",
        );
        assert_eq!(bodies(source), ["hello", "proxy"]);
    }

    #[test]
    fn templates_does_not_rank_the_default_pipeline() {
        // 📄 `templates` ranks ahead of `respond`, but it only rewrites what
        // `file_server` produces, so the pair answers at `file_server`'s
        // rank. Ranked as `templates`, the catch-all would lead and serve
        // `/x` from disk instead of letting `respond /x` answer.
        let source = concat!(
            "example.com {\n",
            "    root * /srv\n",
            "    templates\n",
            "    file_server\n",
            "    respond /x \"x\"\n",
            "}",
        );
        assert_eq!(bodies(source), ["x", "proxy"]);
        assert_eq!(answer(source, "/x"), "x");
    }

    #[test]
    fn equal_length_different_patterns_keep_file_order() {
        // 📜 A deliberate difference from the reference, which orders two
        // different patterns of equal trimmed length alphabetically and so
        // puts `/*/bx` first whichever is written first (`*` sorts before
        // `a`). Here file order decides; issue #18 records the decision.
        //
        // 🧩 `/a/bx` matches both patterns, since a mid-path `*` matches
        // (issue #193), so the difference shows in which one answers.
        let written = |first: &str, second: &str| {
            format!(
                "example.com {{\n    @a path /a/*x\n    @b path /*/bx\n    respond {first}\n    respond {second}\n}}"
            )
        };
        let a = "@a \"a\"";
        let b = "@b \"b\"";
        assert_eq!(bodies(&written(a, b)), ["a", "b"]);
        assert_eq!(bodies(&written(b, a)), ["b", "a"]);
        assert_eq!(answer(&written(a, b), "/a/bx"), "a");
        assert_eq!(answer(&written(b, a), "/a/bx"), "b");
    }
}
