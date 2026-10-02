// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📂 The `root` directive: one document root for the scope it is written in.
//!
//! A site block and a `handle_errors` block both accept it, and both mean the
//! same thing by it — the directory a bare `file_server` (or a `file` matcher)
//! below serves from. The two scopes share this parser so the spellings they
//! accept, and the refusals they give, cannot drift apart.

use super::AdapterError;
use crate::parser::ast::Matcher;
use crate::parser::caddy_ast::Directive;
use std::collections::HashMap;

/// 📂 Reads `root <path>` or `root * <path>` and returns the path.
///
/// The optional `*` matcher token is accepted and ignored, matching Caddy's
/// disambiguation syntax. A named matcher (`root @m <path>`) is refused rather
/// than ignored: upstream that form sets the root only for the requests the
/// matcher selects, while this build has one root per scope, so accepting it
/// would serve every request from that path — the widening a matcher exists
/// to prevent.
pub(super) fn parse_root_directive(
    directive: &Directive,
    matchers: &HashMap<String, Matcher>,
) -> Result<String, AdapterError> {
    let args = if directive.args.first().is_some_and(|a| a == "*") {
        &directive.args[1..]
    } else {
        &directive.args[..]
    };
    // 🏷️ `root @m /var/www` names a matcher, and this used to be counted as
    // an ordinary argument — so the refusal read "expects 1 arguments, got 2"
    // and pointed at the path. The natural reading of that message is "drop
    // one of the two", and the one an operator would drop is the name Caddy
    // would have resolved. Resolving it here is what makes the failure
    // describe the actual mistake.
    if let Some(name) = args.first().filter(|arg| arg.starts_with('@')) {
        if !matchers.contains_key(name) {
            return Err(AdapterError::InvalidArgument(
                "root".into(),
                format!(
                    "matcher `{}` is not defined in this scope; define it in \
                     the site block or in this route/handle block",
                    name.strip_prefix('@').unwrap_or(name)
                ),
            ));
        }
        // 🚧 A matcher-scoped root is a per-request value upstream — it
        // compiles to a route whose handler sets `vars.root` — while a root
        // here is one value for the whole scope. Serving the whole scope from
        // it would widen what is served, so the configuration is refused until
        // the per-request form exists.
        return Err(AdapterError::UnsupportedFeature(
            "root <matcher>".into(),
            "a matcher-scoped root applies to the requests it matches; this \
             build has one document root per site, so accepting it would \
             serve the whole site from that path"
                .into(),
        ));
    }
    let [path] = args else {
        return Err(AdapterError::ArgumentCount(
            "root".into(),
            1,
            if args.is_empty() {
                directive.args.len()
            } else {
                args.len()
            },
        ));
    };
    Ok(path.clone())
}
