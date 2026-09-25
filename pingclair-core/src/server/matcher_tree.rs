// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌳 The shape a matcher is evaluated in, decided once at load.
//!
//! A `path` matcher's patterns never change after the configuration loads,
//! so neither does which kind each one is (exact, prefix, suffix, substring
//! or glob; see `path_pattern`). This tree mirrors a [`Matcher`] and keeps
//! every `path` pattern already classified, so a request only compares
//! bytes. The same classification answers a route's own path, which keeps a
//! pattern meaning one thing wherever it is written (issue #199).
//!
//! 🌿 Every other matcher is kept whole as a leaf and evaluated as before;
//! only `and`, `or` and `not` become branches, so a `path` pattern under any
//! of them is still compiled.

use super::path_pattern::PathPattern;
use crate::config::Matcher;

/// 🌳 One node of a compiled matcher.
#[derive(Debug, Clone)]
pub(super) enum MatcherNode {
    /// 🧩 A `path` matcher: matches when any of its patterns does.
    Path(Box<[PathPattern<Box<str>>]>),
    And(Box<MatcherNode>, Box<MatcherNode>),
    Or(Box<MatcherNode>, Box<MatcherNode>),
    Not(Box<MatcherNode>),
    /// 🌿 Any other matcher, evaluated from its configuration. It is never
    /// `Path`, `And`, `Or` or `Not`: [`MatcherNode::compile`] turns those
    /// into the variants above.
    Leaf(Matcher),
}

impl MatcherNode {
    /// 🏗️ Builds the tree. Configuration-time work, so it favours clarity.
    pub(super) fn compile(matcher: &Matcher) -> Self {
        match matcher {
            Matcher::Path { patterns } => Self::Path(
                patterns
                    .iter()
                    .map(|pattern| PathPattern::of(pattern).to_owned())
                    .collect(),
            ),
            Matcher::And(left, right) => Self::And(
                Box::new(Self::compile(left)),
                Box::new(Self::compile(right)),
            ),
            Matcher::Or(left, right) => Self::Or(
                Box::new(Self::compile(left)),
                Box::new(Self::compile(right)),
            ),
            Matcher::Not(inner) => Self::Not(Box::new(Self::compile(inner))),
            leaf => Self::Leaf(leaf.clone()),
        }
    }
}
