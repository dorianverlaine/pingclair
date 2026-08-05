// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔢 The order directives run in, as data.
//!
//! Directives do **not** run in the order they were written. `header` runs
//! before `respond` whether or not the file says so, `basic_auth` runs before
//! `file_server`, and a site that lists them the other way round behaves
//! identically. That is the single most surprising thing about the format for
//! someone reading a configuration top to bottom, and it is deliberate: it
//! means moving a line cannot silently change what a site does.
//!
//! The order used to be eleven numbers hand-assigned to handler types here.
//! Numbers cannot say *why* one thing precedes another, they drift from the
//! format they are copying with nothing to notice, and — the part that made
//! this worth changing — they cannot be reordered by a configuration, which is
//! what the `order` option exists to do.
//!
//! So it is a list of names now, in order, and a rank is a position in that
//! list. `order` produces a different list; everything downstream is unchanged.

use super::AdapterError;

/// 📋 The order directives run in unless a configuration says otherwise.
///
/// Copied verbatim from the format's own definition, comments and all, because
/// the value of this list is being *the same list* — paraphrasing it would make
/// the next comparison a reading exercise instead of a diff.
pub(super) static DEFAULT_ORDER: &[&str] = &[
    "tracing",
    // Set variables that may be used by other directives.
    "map",
    "vars",
    "fs",
    "root",
    "log_append",
    "skip_log", // Deprecated, renamed to log_skip.
    "log_skip",
    "log_name",
    "header",
    "copy_response_headers", // Only inside reverse_proxy's handle_response.
    "request_body",
    "redir",
    // Incoming request manipulation.
    "method",
    "rewrite",
    "uri",
    "try_files",
    // Middleware handlers; some wrap responses.
    "basicauth", // Deprecated, renamed to basic_auth.
    "basic_auth",
    "forward_auth",
    "request_header",
    "encode",
    "push",
    "intercept",
    "templates",
    // Special routing and dispatching directives.
    "invoke",
    "handle",
    "handle_path",
    "route",
    // Handlers that typically respond to requests.
    "abort",
    "error",
    "copy_response", // Only inside reverse_proxy's handle_response.
    "respond",
    "metrics",
    "reverse_proxy",
    "php_fastcgi",
    "file_server",
    "acme_server",
];

/// 🧭 Where a directive goes, relative to the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Position {
    First,
    Last,
    Before,
    After,
}

impl Position {
    fn parse(word: &str) -> Option<Self> {
        match word {
            "first" => Some(Self::First),
            "last" => Some(Self::Last),
            "before" => Some(Self::Before),
            "after" => Some(Self::After),
            _ => None,
        }
    }
}

/// 🔢 A directive order, either the default or one a configuration changed.
///
/// Held as owned names rather than borrowed ones because `order` rewrites it,
/// and a configuration's own order has to outlive the parse that produced it.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct DirectiveOrder {
    names: Vec<String>,
}

impl Default for DirectiveOrder {
    fn default() -> Self {
        Self {
            names: DEFAULT_ORDER.iter().map(|name| name.to_string()).collect(),
        }
    }
}

impl DirectiveOrder {
    /// Where a directive sits. Unknown names sort last, keeping their relative
    /// order — a directive nobody ranked is a handler that answers, and those
    /// come last anyway.
    pub(super) fn rank(&self, directive: &str) -> usize {
        self.names
            .iter()
            .position(|name| name == directive)
            .unwrap_or(self.names.len())
    }

    /// 🔀 Applies one `order` option: `order <directive> first|last`, or
    /// `order <directive> before|after <other>`.
    ///
    /// The directive being moved is removed from wherever it was first, so
    /// `order encode first` means what it says rather than leaving a second
    /// `encode` behind further down.
    pub(super) fn apply(&mut self, args: &[String]) -> Result<(), AdapterError> {
        let [directive, position, rest @ ..] = args else {
            return Err(AdapterError::InvalidArgument(
                "order".into(),
                "expected `order <directive> first|last` or \
                 `order <directive> before|after <other>`"
                    .into(),
            ));
        };

        // 🚫 A misspelled directive here would silently order nothing, and the
        // operator would be left looking at a configuration that says it does.
        if super::registry::directive(directive).is_none() {
            return Err(AdapterError::InvalidArgument(
                "order".into(),
                format!("`{directive}` is not a directive"),
            ));
        }

        let Some(position) = Position::parse(position) else {
            return Err(AdapterError::InvalidArgument(
                "order".into(),
                format!("`{position}` is not a position; expected first, last, before or after"),
            ));
        };

        self.names.retain(|name| name != directive);

        match position {
            Position::First | Position::Last => {
                if !rest.is_empty() {
                    return Err(AdapterError::InvalidArgument(
                        "order".into(),
                        format!("`{position:?}` takes no further arguments").to_lowercase(),
                    ));
                }
                if position == Position::First {
                    self.names.insert(0, directive.clone());
                } else {
                    self.names.push(directive.clone());
                }
            }
            Position::Before | Position::After => {
                let [other] = rest else {
                    return Err(AdapterError::InvalidArgument(
                        "order".into(),
                        "before and after need exactly one other directive".into(),
                    ));
                };
                let Some(index) = self.names.iter().position(|name| name == other) else {
                    return Err(AdapterError::InvalidArgument(
                        "order".into(),
                        format!("`{other}` is not in the directive order"),
                    ));
                };
                let index = if position == Position::After {
                    index + 1
                } else {
                    index
                };
                self.names.insert(index, directive.clone());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 📌 The list is the format's, so its length and endpoints are worth
    /// pinning: a silent truncation would reorder everything after it.
    #[test]
    fn the_default_order_matches_the_format() {
        assert_eq!(DEFAULT_ORDER.len(), 38);
        assert_eq!(DEFAULT_ORDER.first(), Some(&"tracing"));
        assert_eq!(DEFAULT_ORDER.last(), Some(&"acme_server"));
        // 🎯 The three relationships this crate's own tests rely on.
        let order = DirectiveOrder::default();
        assert!(order.rank("header") < order.rank("respond"));
        assert!(order.rank("basic_auth") < order.rank("file_server"));
        assert!(order.rank("respond") < order.rank("reverse_proxy"));
    }

    #[test]
    fn a_directive_may_be_moved_to_either_end() {
        let mut order = DirectiveOrder::default();
        order
            .apply(&["file_server".into(), "first".into()])
            .expect("first");
        assert_eq!(order.rank("file_server"), 0);

        let mut order = DirectiveOrder::default();
        order
            .apply(&["header".into(), "last".into()])
            .expect("last");
        assert_eq!(order.rank("header"), DEFAULT_ORDER.len() - 1);
    }

    #[test]
    fn a_directive_may_be_moved_next_to_another() {
        let mut order = DirectiveOrder::default();
        order
            .apply(&["encode".into(), "before".into(), "header".into()])
            .expect("before");
        assert!(order.rank("encode") < order.rank("header"));

        let mut order = DirectiveOrder::default();
        order
            .apply(&["header".into(), "after".into(), "respond".into()])
            .expect("after");
        assert!(order.rank("header") > order.rank("respond"));
    }

    /// 🧭 Moving a directive removes it from where it was, so it appears once.
    #[test]
    fn moving_a_directive_does_not_leave_a_copy_behind() {
        let mut order = DirectiveOrder::default();
        order
            .apply(&["encode".into(), "first".into()])
            .expect("first");
        assert_eq!(order.names.iter().filter(|n| *n == "encode").count(), 1);
        assert_eq!(order.names.len(), DEFAULT_ORDER.len());
    }

    /// 🚫 Every way of getting it wrong is refused, because an `order` that
    /// silently did nothing would leave a configuration claiming a behaviour it
    /// does not have.
    #[test]
    fn a_malformed_order_is_refused() {
        for args in [
            vec!["encode".to_string()],
            vec!["nonsuch".to_string(), "first".to_string()],
            vec!["encode".to_string(), "sideways".to_string()],
            vec!["encode".to_string(), "before".to_string()],
            vec![
                "encode".to_string(),
                "before".to_string(),
                "nonsuch".to_string(),
            ],
            vec![
                "encode".to_string(),
                "first".to_string(),
                "header".to_string(),
            ],
        ] {
            let mut order = DirectiveOrder::default();
            assert!(
                order.apply(&args).is_err(),
                "`order {}` must be refused",
                args.join(" ")
            );
        }
    }
}
