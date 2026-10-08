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
use crate::caddyfile::parser::ast::{ErrorRouteConfig, Handler, HandlerElement, Matcher};
use crate::caddyfile::parser::caddy_ast::{Block, Directive};
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
    // 🚫 A `reverse_proxy` inside the block is refused by name rather than
    // loaded and ignored. This build runs the upstream exchange as a lifecycle
    // step outside the handler chain, and an error route has no route slot for
    // it to read, so the handler would compile and then answer nothing — the
    // silent no-op this repository refuses instead of accepting (#245).
    // Everything else in the block is an ordinary route body.
    if handlers
        .iter()
        .any(|element| contains_proxy(&element.handler))
    {
        return Err(AdapterError::UnsupportedFeature(
            "handle_errors reverse_proxy".into(),
            "an error route cannot proxy yet: the upstream exchange runs outside the handler \
             chain, so this handler would load and then do nothing. Proxy in the site route and \
             render its errors here with `respond` or `file_server`, or move the upstream that \
             should answer errors into the route itself"
                .into(),
        ));
    }
    Ok(ErrorRouteConfig {
        codes,
        hundreds,
        root,
        handlers,
    })
}

/// 🔎 Whether a handler tree contains a `reverse_proxy`.
///
/// Walks the containers a `handle_errors` body can produce, so a proxy behind
/// `handle`/`route`/`try_files` is found as well as one written at the top
/// level of the block.
fn contains_proxy(handler: &Handler) -> bool {
    match handler {
        Handler::Proxy(_) => true,
        Handler::Pipeline(elements)
        | Handler::Handle(elements)
        | Handler::HandleGroup(elements)
        | Handler::HandlePath {
            handlers: elements, ..
        }
        | Handler::TryFiles(elements) => elements
            .iter()
            .any(|element: &HandlerElement| contains_proxy(&element.handler)),
        _ => false,
    }
}
