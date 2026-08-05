// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Adapter for converting Generic Caddyfile AST to Typed AST
//!
//! 🏗️ ARCHITECTURE: Two-pass adapter:
//!   Pass 1: Collect snippet definitions `(name) { ... }` and expand `import name`
//!   Pass 2: Convert the expanded generic directives into the Typed AST
//!
//! # 🗺️ Why this is a directory and not one file
//!
//! It was one file, and by 2026-08-05 that file was 5,643 lines. The cost was
//! not the length itself but the absence of any seam: a change to how a site
//! address is parsed and a change to how a matcher token is read looked like
//! neighbours, so both were made in the same place and neither had a boundary
//! to be checked against.
//!
//! The split follows the layering the format itself has, which is why it is a
//! step of the refactor rather than a tidy-up:
//!
//! | Module | Owns |
//! | --- | --- |
//! | [`sites`] | A site block becomes a server: routes, ordering, defaults. |
//! | [`options`] | The global block. |
//! | [`addresses`] | What a site address means. |
//! | [`matchers`] | The matcher token rule, and matcher definitions. |
//! | [`directives`] | One parsing function per directive. |
//! | [`reverse_proxy`] | `reverse_proxy` alone, because its block is as large as most of the others combined. |
//! | [`logs`] | The `log` block and its destinations. |
//! | [`tls`] | The `tls` directive. |
//!
//! 📌 The seam that matters is the one *above* this module: everything here
//! maps a parsed configuration onto HTTP, and nothing here does any parsing.
//! Tokenizing, block structure, and `import` expansion live in
//! [`crate::parser`] and [`super::imports`], which know nothing about HTTP.

mod addresses;
mod args;
mod directives;
mod logs;
mod matchers;
mod options;
mod reverse_proxy;
mod sites;
mod tls;

#[cfg(test)]
mod tests;

use options::adapt_global;
use sites::adapt_server;

use crate::parser::ast::*;
use crate::parser::caddy_ast::{Block, Directive};
use crate::parser::lexer::Location;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("Unknown directive '{0}'")]
    UnknownDirective(String),

    /// 🚫 A Caddy-compatible feature that Pingclair deliberately does not
    /// implement yet. Failing loudly here beats compiling a config that
    /// silently ignores half of what the operator asked for.
    #[error("Caddy-compatible directive '{0}' is not supported by Pingclair yet: {1}")]
    UnsupportedFeature(String, String),

    #[error("Directive '{0}' expects {1} arguments, got {2}")]
    ArgumentCount(String, usize, usize),

    #[error("Invalid argument for '{0}': {1}")]
    InvalidArgument(String, String),

    #[error("Block not allowed for directive '{0}'")]
    BlockNotAllowed(String),

    #[error("Duplicate global block")]
    DuplicateGlobal,

    #[error("Undefined snippet '{0}'")]
    UndefinedSnippet(String),

    #[error("Recursive snippet import detected: '{0}'")]
    RecursiveSnippet(String),
}

// MARK: - Snippet Expansion (Pass 1)

type SnippetMap = HashMap<String, Vec<Directive>>;
type SnippetCollection = (SnippetMap, Vec<Directive>);

/// Collect snippet `(name) { ... }` definitions from top-level directives
/// and return (snippets_map, remaining_directives).
pub(crate) fn collect_snippets(
    directives: Vec<Directive>,
) -> Result<SnippetCollection, AdapterError> {
    let mut snippets = SnippetMap::new();
    let mut remaining = Vec::new();

    for d in directives {
        if d.name.starts_with('(') && d.name.ends_with(')') {
            // Snippet definition: (name) { ... }
            let snippet_name = d.name[1..d.name.len() - 1].to_string();
            let body = d.block.map(|b| b.directives).unwrap_or_default();
            snippets.insert(snippet_name, body);
        } else {
            remaining.push(d);
        }
    }

    Ok((snippets, remaining))
}

// MARK: - Main Adapter (Pass 2)

/// Convert generic directives to Typed AST
pub fn adapt(directives: Vec<Directive>) -> Result<Ast, AdapterError> {
    adapt_from(directives, None)
}

/// 📦 Adapts directives, resolving relative `import` paths against `base`.
///
/// `base` is the directory of the file these directives were read from. `None`
/// means they did not come from a file, and a relative import then has nothing
/// to be relative to — which is refused rather than quietly resolved against
/// whatever directory the process happens to be in.
pub fn adapt_from(
    directives: Vec<Directive>,
    base: Option<&std::path::Path>,
) -> Result<Ast, AdapterError> {
    // Pass 1: Snippet collection + import expansion
    let (snippets, remaining) = collect_snippets(directives)?;
    // 📦 Snippets, files, globs, arguments and cycle detection all live in
    // `super::imports` now; the old expansion only knew about snippets, so
    // `import ./part.conf` failed with "undefined snippet" — a message about the
    // wrong concept entirely.
    let mut context = super::imports::ImportContext::new(base);
    let expanded = super::imports::expand(remaining, &snippets, &mut context)?;
    let expanded = coalesce_bare_single_site(expanded)?;

    // Pass 2: Convert to typed AST
    let mut ast = Ast::default();

    for d in expanded {
        if d.name.is_empty() || d.name == "global" || d.name == "options" {
            if ast.global.is_some() {
                return Err(AdapterError::DuplicateGlobal);
            }
            ast.global = Some(Node::new(adapt_global(d)?, Location::synthetic()));
        } else if d.name == "macro" {
            // 🐛 TODO: Support macros in Caddyfile?
            // Caddy uses snippets (import), which we now handle above.
        } else {
            let server = adapt_server(d)?;
            ast.servers.push(Node::new(server, Location::synthetic()));
        }
    }

    Ok(ast)
}

/// 🏠 Caddy lets a single-site file omit its curly braces: the first line is
/// the site address and every following directive belongs to that site.
/// `localhost\n\nrespond "Hello"` must parse as `localhost { respond ... }`.
///
/// The shorthand is only legal when no other braced site exists — with two
/// sites the file must use explicit braces, otherwise the bare directives
/// have no unambiguous home.
fn coalesce_bare_single_site(directives: Vec<Directive>) -> Result<Vec<Directive>, AdapterError> {
    let mut globals = Vec::new();
    let mut bare = Vec::new();
    let mut braced_sites = Vec::new();

    for d in directives {
        if d.name.is_empty() || d.name == "global" || d.name == "options" {
            globals.push(d);
        } else if d.block.is_some() {
            braced_sites.push(d);
        } else {
            bare.push(d);
        }
    }

    if bare.is_empty() {
        globals.extend(braced_sites);
        return Ok(globals);
    }

    if !braced_sites.is_empty() {
        return Err(AdapterError::InvalidArgument(
            "site address".into(),
            "bare (unbraced) directives cannot be mixed with braced site blocks; \
             wrap every site in { } when there is more than one"
                .into(),
        ));
    }

    // 🏠 The first bare directive is the site address; everything after it is
    // the site's content. A lone bare directive is an empty site.
    let mut site = bare.remove(0);
    if !bare.is_empty() {
        site.block = Some(Block { directives: bare });
    }
    globals.push(site);
    Ok(globals)
}
