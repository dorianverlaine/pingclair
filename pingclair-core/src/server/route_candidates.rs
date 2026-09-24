// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌲 Which routes a request can possibly match, decided before any request.
//!
//! A site's routes are an ordered list: the first route that matches answers
//! (issue #18). Trying every route in order on every request would be correct
//! and slow, so the radix tree stays as a pre-filter. Each tree node stores
//! the list of routes that can match a path landing on that node — its own
//! routes, every shorter prefix glob that covers it, and every catch-all —
//! already in list order. A request then walks one short slice and stops at
//! the first route whose matcher agrees.
//!
//! 🏗️ Everything here runs once per configuration load. It favours plain
//! nested loops over clever indexing: a site has tens of routes, not
//! thousands, and a reload can afford a few microseconds.

use crate::config::RouteConfig;
use std::collections::BTreeMap;

/// 🧭 What a route's path pattern covers, in the router's own glob dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoutePath<'a> {
    /// `/`, `/*`, `*`, or empty: every request.
    Any,
    /// A pattern ending in `*`, stored without it: every path that starts
    /// with the prefix, plus the bare prefixes [`bare_prefixes`] adds.
    Prefix(&'a str),
    /// Anything else, matched literally.
    Exact(&'a str),
}

impl<'a> RoutePath<'a> {
    fn of(path: &'a str) -> Self {
        match path {
            // 📌 A bare `/` has always meant "the whole site" here, not the
            // root document alone; changing that is not part of issue #18.
            "" | "/" | "/*" | "*" => Self::Any,
            _ => match path.strip_suffix('*') {
                Some(prefix) => Self::Prefix(prefix),
                None => Self::Exact(path),
            },
        }
    }

    /// 🔎 Whether this route matches every path that lands on `node`.
    ///
    /// A node is never reached by a path the route would reject when this
    /// says yes, and a route this says no to cannot match any path that
    /// lands there — the radix tree already sent those paths to a longer
    /// static node. That second half is what lets a node's list stay short.
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
        }
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
    /// Routes that match any path, ascending. This is the whole list for a
    /// path that lands on no node.
    pub(super) any: Box<[usize]>,
}

/// 🏗️ Builds every node's candidate list from the routes, in list order.
pub(super) fn build(routes: &[RouteConfig]) -> Candidates {
    let kinds: Vec<RoutePath<'_>> = routes
        .iter()
        .map(|route| RoutePath::of(&route.path))
        .collect();

    // 🧮 Keyed by matchit pattern, so a glob's bare prefix and an exact route
    // on the same path become one node instead of two inserts where the
    // second loses. `BTreeMap` keeps the insert order deterministic.
    let mut nodes: BTreeMap<String, Node<'_>> = BTreeMap::new();
    for (route, kind) in routes.iter().zip(&kinds) {
        match *kind {
            RoutePath::Any => {}
            RoutePath::Exact(path) => {
                nodes.insert(path.to_string(), Node::Exact(path));
            }
            RoutePath::Prefix(prefix) => {
                nodes.insert(glob_to_matchit(&route.path), Node::Prefix(prefix));
                for bare in bare_prefixes(&route.path) {
                    // 🪢 Every bare prefix is a prefix of the route's own
                    // path, so the node can borrow it from there.
                    let node = Node::Exact(&route.path[..bare.len()]);
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
            .filter(|(_, kind)| **kind == RoutePath::Any)
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
