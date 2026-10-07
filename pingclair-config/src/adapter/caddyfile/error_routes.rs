// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚨 `handle_errors [<codes…>] { … }`: a server-level error route.
//!
//! The block is a route body that runs when the handler chain raised an error
//! status. Codes are three-digit statuses or `Nxx` ranges, ORed together; no
//! codes means the route catches every error status. Directives run in file
//! order and `handle` blocks are mutually exclusive — exactly the shape the
//! upstream format parses.

use super::AdapterError;
use super::directives::collect_subroute_elements;
use super::order::DirectiveOrder;
use super::root::parse_root_directive;
use crate::parser::ast::{ErrorRouteConfig, Matcher};
use crate::parser::caddy_ast::{Block, Directive};
use std::collections::HashMap;

/// 🚨 Adapts one `handle_errors` block into an error route.
pub(super) fn adapt_handle_errors(
    directive: &Directive,
    matchers: &HashMap<String, Matcher>,
    order: &DirectiveOrder,
) -> Result<ErrorRouteConfig, AdapterError> {
    let mut codes = Vec::new();
    let mut hundreds = Vec::new();
    for arg in &directive.args {
        if arg.len() == 3
            && let Ok(code) = arg.parse::<u16>()
            && (100..=599).contains(&code)
        {
            codes.push(code);
        } else if arg.len() == 3
            && let Some(digit) = arg.strip_suffix("xx")
            && let Ok(hundred) = digit.parse::<u8>()
        {
            if !hundreds.contains(&hundred) {
                hundreds.push(hundred);
            }
        } else {
            return Err(AdapterError::InvalidArgument(
                "handle_errors".into(),
                format!("bad status value `{arg}`"),
            ));
        }
    }
    let block = directive.block.as_ref().ok_or_else(|| {
        AdapterError::InvalidArgument("handle_errors".into(), "a block is required".into())
    })?;
    let mut root = None;
    let mut body = Vec::with_capacity(block.directives.len());
    for inner in &block.directives {
        // 📂 `root * /srv/errors` sets the document root the error route's
        // file servers read from. Upstream it sets `{http.vars.root}`, which a
        // bare `file_server` defaults to; the value here is a literal path
        // known at load time, so it is folded into those file servers by the
        // compiler instead of being looked up on every error. Like upstream,
        // its position in the block does not matter: Caddy sorts `root` ahead
        // of `file_server` whatever order they were written in, and a second
        // `root *` overwrites the first, so the last one written wins.
        if inner.name == "root" {
            root = Some(parse_root_directive(inner, matchers)?);
            continue;
        }
        body.push(inner.clone());
    }
    // 🧭 Everything else is an ordinary route body: `@name` definitions are
    // local to this block and see the site's matchers, and directives run in
    // Caddy's order rather than file order, exactly as inside `handle` (#245).
    // 📌 `root` is folded in at load and is not part of that ordering.
    let handlers = collect_subroute_elements(&Block { directives: body }, matchers, order, true)?;
    if handlers.is_empty() {
        return Err(AdapterError::InvalidArgument(
            "handle_errors".into(),
            "at least one directive is required".into(),
        ));
    }
    Ok(ErrorRouteConfig {
        codes,
        hundreds,
        root,
        handlers,
    })
}
