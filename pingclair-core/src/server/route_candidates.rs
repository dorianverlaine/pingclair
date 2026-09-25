// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌲 Which routes a request can possibly match, decided before any request.
//!
//! A site's routes are an ordered list: the first route that matches answers
//! (issue #18). Trying every route in order on every request would be correct
//! and slow, so the radix tree stays as a pre-filter. Each tree node stores
//! the list of routes that can match a path landing on that node — its own
//! routes, every shorter prefix glob that covers it, every catch-all, and
//! every wildcard route that could match there — already in list order. A
//! request then walks one short slice and stops at the first route whose
//! matcher agrees.
//!
//! 🧩 A route path with a `*` anywhere but at its end (`*.php`, `/a/*x`,
//! issue #193) cannot be a radix node: the tree only knows exact paths and
//! trailing wildcards. Such a route is instead listed on every node it could
//! match, and among the catch-alls, and the router tests its compiled
//! pattern ([`wildcard`]) before trusting it. Because every list is still in
//! list order, it answers exactly where the directive order puts it.
//!
//! 🏗️ Everything here runs once per configuration load. It favours plain
//! nested loops over clever indexing: a site has tens of routes, not
//! thousands, and a reload can afford a few microseconds.

use super::path_pattern::{self, PathPattern};
use crate::config::RouteConfig;
use std::collections::BTreeMap;

/// 🧭 What a route's path pattern covers, in the router's own glob dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoutePath<'a> {
    /// `/`, `/*`, `*`, or empty: every request.
    Any,
    /// A pattern whose only `*` is its last character, stored without it:
    /// every path that starts with the prefix, plus the bare prefixes
    /// [`bare_prefixes`] adds.
    Prefix(&'a str),
    /// No `*` at all, matched literally.
    Exact(&'a str),
    /// Any other `*` placement: suffix, substring, or glob. The tree cannot
    /// hold it, so the router checks it per candidate.
    Wildcard(PathPattern<&'a str>),
}

impl<'a> RoutePath<'a> {
    fn of(path: &'a str) -> Self {
        match path {
            // 📌 A bare `/` has always meant "the whole site" here, not the
            // root document alone; changing that is not part of issue #18.
            "" | "/" | "/*" | "*" => Self::Any,
            _ => match PathPattern::of(path) {
                PathPattern::Any => Self::Any,
                PathPattern::Exact(exact) => Self::Exact(exact),
                PathPattern::Prefix(prefix) => Self::Prefix(prefix),
                pattern @ (PathPattern::Suffix(_)
                | PathPattern::Substring(_)
                | PathPattern::Glob(_)) => Self::Wildcard(pattern),
            },
        }
    }

    /// 🔎 Whether this route belongs in `node`'s candidate list.
    ///
    /// For a tree-shaped route (any, exact, prefix) this means it matches
    /// every path that lands on `node`. A route this says no to cannot match
    /// any path that lands there — the radix tree already sent those paths
    /// to a longer static node. That second half is what lets a node's list
    /// stay short.
    ///
    /// 🧩 A wildcard route only *might* match there, so the router checks
    /// its pattern again per request; this only keeps it off the nodes where
    /// it provably cannot match.
    fn covers(self, node: Node<'_>) -> bool {
        match (self, node) {
            (Self::Any, _) => true,
            (Self::Exact(route), Node::Exact(node)) => route == node,
            (Self::Exact(_), Node::Prefix(_)) => false,
            // 🪜 `/proxy/*` also answers the bare `/proxy`; see [`bare_prefixes`].
            (Self::Prefix(route), Node::Exact(node)) => {
                node.starts_with(route) || route.strip_suffix('/') == Some(node)
            }
            (Self::Prefix(route), Node::Prefix(node)) => node.starts_with(route),
            // 🎯 An exact node is reached by exactly one path, so the answer
            // is already known.
            (Self::Wildcard(pattern), Node::Exact(node)) => pattern.matches(node),
            // 🌲 The paths under a prefix node and the paths the pattern can
            // match overlap only if one literal prefix extends the other.
            (Self::Wildcard(pattern), Node::Prefix(node)) => {
                let literal = pattern.literal_prefix().as_bytes();
                path_pattern::starts_with(node.as_bytes(), literal)
                    || path_pattern::starts_with(literal, node.as_bytes())
            }
        }
    }
}

/// 🧩 The pattern the router must test per request before a route counts as
/// matching, or `None` when the radix tree alone already decided the path.
pub(super) fn wildcard(path: &str) -> Option<PathPattern<Box<str>>> {
    match RoutePath::of(path) {
        RoutePath::Wildcard(pattern) => Some(pattern.to_owned()),
        RoutePath::Any | RoutePath::Prefix(_) | RoutePath::Exact(_) => None,
    }
}

/// 🌳 The set of paths one radix node answers for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Node<'a> {
    Exact(&'a str),
    Prefix(&'a str),
}

/// 📋 The pre-filter, ready to load into a radix tree.
pub(super) struct Candidates {
    /// One entry per radix node: the matchit pattern and the indices of the
    /// routes that can match there, ascending, which is list order.
    pub(super) nodes: Vec<(String, Box<[usize]>)>,
    /// Routes that can match a path landing on no node — the catch-alls and
    /// the wildcard routes — ascending. This is the whole list for such a
    /// path.
    pub(super) any: Box<[usize]>,
}

/// 🏗️ Builds every node's candidate list from the routes, in list order.
///
/// 🔤 Every route path is lowercased first (ASCII only), so the tree's
/// nodes are lowercase and `/Admin` and `/admin` are one node. The router
/// looks a request up with its path folded the same way; see
/// `Router::candidates`. This is what makes an exact or prefix route path
/// ignore letter case, like a wildcard one already does (issue #198).
pub(super) fn build(routes: &[RouteConfig]) -> Candidates {
    let paths: Vec<String> = routes
        .iter()
        .map(|route| route.path.to_ascii_lowercase())
        .collect();
    let kinds: Vec<RoutePath<'_>> = paths.iter().map(|path| RoutePath::of(path)).collect();

    // 🧮 Keyed by matchit pattern, so a glob's bare prefix and an exact route
    // on the same path become one node instead of two inserts where the
    // second loses. `BTreeMap` keeps the insert order deterministic.
    let mut nodes: BTreeMap<String, Node<'_>> = BTreeMap::new();
    for (path, kind) in paths.iter().zip(&kinds) {
        match *kind {
            // 🧩 Neither gets a node of its own; `covers` places them.
            RoutePath::Any | RoutePath::Wildcard(_) => {}
            RoutePath::Exact(path) => {
                nodes.insert(path.to_string(), Node::Exact(path));
            }
            RoutePath::Prefix(prefix) => {
                nodes.insert(glob_to_matchit(path), Node::Prefix(prefix));
                for bare in bare_prefixes(path) {
                    // 🪢 Every bare prefix is a prefix of the route's own
                    // path, so the node can borrow it from there.
                    let node = Node::Exact(&path[..bare.len()]);
                    nodes.entry(bare).or_insert(node);
                }
            }
        }
    }

    let candidates = |node: Node<'_>| -> Box<[usize]> {
        kinds
            .iter()
            .enumerate()
            .filter(|(_, kind)| kind.covers(node))
            .map(|(index, _)| index)
            .collect()
    };
    Candidates {
        nodes: nodes
            .into_iter()
            .map(|(pattern, node)| (pattern, candidates(node)))
            .collect(),
        any: kinds
            .iter()
            .enumerate()
            .filter(|(_, kind)| matches!(kind, RoutePath::Any | RoutePath::Wildcard(_)))
            .map(|(index, _)| index)
            .collect(),
    }
}

/// 🪜 The bare (non-wildcard) prefixes a glob path should also match.
///
/// A glob like `/proxy/*` must also match the bare directory it was written
/// to catch — both `/proxy/` and `/proxy` — with nothing after the prefix.
/// matchit's `{*rest}` needs at least one character after the prefix and
/// treats `/proxy` and `/proxy/` as distinct, so without these extra static
/// nodes the bare forms fell through to the default route — once surfacing
/// as a 500 `ConnectNoRoute` when that route had no upstream.
/// `/foo*` yields `/foo`; a non-glob yields nothing.
fn bare_prefixes(path: &str) -> Vec<String> {
    if let Some(prefix) = path.strip_suffix("/*") {
        if prefix.is_empty() {
            Vec::new()
        } else {
            vec![prefix.to_string(), format!("{prefix}/")]
        }
    } else if let Some(prefix) = path.strip_suffix('*') {
        if prefix.is_empty() {
            Vec::new()
        } else {
            vec![prefix.to_string()]
        }
    } else {
        Vec::new()
    }
}

/// 🔤 A glob in matchit's syntax: the trailing `*` becomes a named catch-all.
fn glob_to_matchit(path: &str) -> String {
    if let Some(prefix) = path.strip_suffix("/*") {
        format!("{prefix}/{{*rest}}")
    } else if let Some(prefix) = path.strip_suffix('*') {
        format!("{prefix}{{*rest}}")
    } else {
        path.to_string()
    }
}

// MARK: - Tests

/// 🧪 Wildcard route paths through the real router: they answer where list
/// order puts them, and stay off the nodes they can never match.
#[cfg(test)]
mod tests {
    use crate::config::{HandlerConfig, RouteConfig};
    use crate::server::{RequestAddresses, Router};
    use std::collections::BTreeMap;

    fn router(paths: &[&str]) -> Router {
        Router::new(
            paths
                .iter()
                .map(|path| RouteConfig {
                    path: path.to_string(),
                    handler: HandlerConfig::Respond {
                        status: 200,
                        body: None,
                        headers: BTreeMap::new(),
                    },
                    methods: None,
                    matcher: None,
                })
                .collect(),
        )
    }

    fn answer(router: &Router, path: &str) -> Option<usize> {
        router
            .match_normalized_request(
                path,
                "GET",
                &http::HeaderMap::new(),
                "example.com",
                RequestAddresses::direct(std::net::Ipv4Addr::LOCALHOST.into()),
                "HTTP/1.1",
                None,
            )
            .map(|route| route.index)
    }

    #[test]
    fn wildcard_routes_answer_in_list_order() {
        // 🧩 A mid-path `*` stays inside one segment, a leading `*` is a
        // suffix at any depth, and each answers only where it sits in the
        // list: the exact `/a/bx` at index 5 never gets `/a/bx`.
        let router = router(&["/a/*x", "*.php", "/a/*", "/static/*", "/*", "/a/bx"]);
        let answers: Vec<Option<usize>> = [
            "/a/bx",
            "/a/b/cx",
            "/a/b.php",
            "/static/x.php",
            "/static/x.css",
            "/other",
        ]
        .into_iter()
        .map(|path| answer(&router, path))
        .collect();
        assert_eq!(
            answers,
            [Some(0), Some(2), Some(1), Some(1), Some(3), Some(4)]
        );
    }

    #[test]
    fn a_wildcard_route_stays_off_nodes_it_cannot_match() {
        // 🌲 `/b/*x` can never match under `/static/`, so it is not in that
        // node's list; `*.php` could, so it is.
        let router = router(&["/b/*x", "*.php", "/static/*"]);
        let candidates: Vec<usize> = router
            .match_path("/static/app.js")
            .into_iter()
            .map(|route| route.index)
            .collect();
        assert_eq!(candidates, [1, 2]);
    }
}
