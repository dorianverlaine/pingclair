// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌉 The directive tree, built from flat segments.
//!
//! Two parsers used to exist here. The tree parser decided, at every `{`,
//! whether the brace opened a directive's block or a new site — a question it
//! had no way to answer, because answering it needs to know which words are
//! directives and a format layer does not. The segment parser removes the
//! question instead: a directive's tokens are flat, its braces are ordinary
//! members of the run, and depth is a counter.
//!
//! This module keeps the second one and throws the first away. The adapter
//! above still receives the same [`Directive`] tree it always did, assembled
//! here from segments rather than guessed at while reading.
//!
//! # 🧭 Why the tree survives at all
//!
//! An earlier plan called this shape a bridge and rejected it: keeping the old
//! shape keeps the old bugs, pay the cost and get nothing. That reasoning
//! expired. The bug it named — a directive's block read as a second site,
//! a quarter of the format's own corpus — was fixed where it actually lived,
//! in how the adapter classified a name, and the shape had nothing to do with
//! it. What remained was the *guessing*, and that is what this deletes.
//!
//! The tree is a convenience for twenty-five directive parsers that have not
//! moved to a token cursor yet, and it is now built from something that cannot
//! guess wrong. They move one at a time, or not at all where the cursor buys
//! them nothing.

use super::caddy_ast::{Block, Directive, TokenRun};
use super::dispenser::Dispenser;
use super::lexer::{Location, Spanned, Token};
use super::parser::ParseError;
use super::server_block::{ServerBlock, parse_server_blocks};
use std::sync::Arc;

/// 🧩 Parses a configuration into the directive tree the adapter consumes.
pub fn parse_into_tree(source: &str) -> Result<Vec<Directive>, ParseError> {
    let blocks = parse_server_blocks(source).map_err(|error| match error {
        // 🧭 A lexer error already renders itself, position included.
        super::server_block::BlockParseError::Lex(lex) => ParseError::Lex(lex),
        // 📍 Everything else knows exactly where it is, and saying so is the
        // whole point of carrying a position on every token. Flattening these
        // to a synthetic location would undo that, silently, and an error that
        // cannot name a line is one an operator cannot act on.
        other => {
            let location = other.location().unwrap_or_else(Location::synthetic);
            ParseError::Syntax {
                message: other.to_string(),
                location,
            }
        }
    })?;
    blocks.into_iter().map(block_to_directive).collect()
}

/// 🏠 A site block becomes the directive the adapter recognises as a site.
///
/// The first address is its name and the rest are arguments, which is the shape
/// the adapter already expects. A block with no addresses at all is the global
/// options block, and an empty name is how the adapter has always known that.
fn block_to_directive(block: ServerBlock) -> Result<Directive, ParseError> {
    let has_braces = block.has_braces;
    let key_run = run_of(&block.keys);
    let mut keys = block.keys.iter().map(|key| text_of(&key.value));
    let name = keys.next().unwrap_or_default();
    let args: Vec<String> = keys.collect();

    let directives: Vec<Directive> = block
        .segments
        .iter()
        .map(|segment| segment_to_directive(segment, 0))
        .collect::<Result<_, _>>()?;

    // 🧭 A line with no braces and nothing under it is not a site — it is one
    // directive that happens to sit at the top of a file, which is what every
    // imported fragment looks like. Handing it an empty block would tell the
    // directive's own parser that the operator wrote `{ }`, and a parser that
    // branches on that reads its arguments from the wrong place: `header X-A b`
    // became a header directive with no headers in it.
    //
    // A block is written, or it is inferred from having contents. Neither, and
    // the shorthand handling above the adapter takes it from here.
    let block = (has_braces || !directives.is_empty()).then_some(Block { directives });

    Ok(Directive {
        name,
        args,
        block,
        // 📎 The site's own tokens are its addresses; a directive parser that
        // wants them can have them, and nothing does yet.
        tokens: key_run,
    })
}

/// 🛡️ How deep a directive's blocks may nest before the configuration is
/// refused.
///
/// Building the tree recurses, so a file nested deeply enough exhausts the
/// stack — and a stack overflow is not a caught error here: the release profile
/// aborts, taking the process with it, and the admin API is a way to reach this
/// code with attacker-supplied text. This crate has already shipped one
/// remotely triggerable overflow of exactly this shape.
///
/// 📌 The limit is a *separate* guard from the import-cycle detection, which
/// catches a name that comes back round and cannot see nesting at all. Two
/// failures, two guards; removing either because the other exists is how the
/// first one came back.
const MAX_BLOCK_DEPTH: usize = 100;

/// 🎯 One directive: its name, its arguments, and its block if it has one.
///
/// The block is found by walking the run with a cursor rather than by looking
/// for braces, so nesting is the cursor's problem and not this function's.
fn segment_to_directive(segment: &[Spanned<Token>], depth: usize) -> Result<Directive, ParseError> {
    if depth > MAX_BLOCK_DEPTH {
        return Err(ParseError::RecursionLimitExceeded);
    }
    let mut cursor = Dispenser::new(segment);
    let name = cursor
        .advance()
        .map(|token| text_of(&token.value))
        .unwrap_or_default();
    let args = cursor.remaining_arg_texts();

    let mut inner = Vec::new();
    let nesting = cursor.nesting();
    while cursor.next_block(nesting).is_some() {
        let Some(sub) = cursor.next_segment() else {
            break;
        };
        inner.push(segment_to_directive(sub.tokens(), depth + 1)?);
    }

    // 🧭 No block and an empty one are different things. `file_server` alone
    // and `file_server { }` mean the same to the file server, but a directive
    // that checks `block.is_some()` is asking whether the operator wrote
    // braces, and it deserves the true answer.
    let block = has_block(segment).then_some(Block { directives: inner });

    Ok(Directive {
        name,
        args,
        block,
        tokens: run_of(segment),
    })
}

/// Whether the run contains a brace of its own.
fn has_block(segment: &[Spanned<Token>]) -> bool {
    segment
        .iter()
        .any(|token| matches!(token.value, Token::BlockOpen))
}

/// 📎 Wraps a run of tokens so a directive parser can walk it with a cursor.
///
/// One allocation per directive, at configuration load. The tokens were already
/// copied into segments by the parser below, so sharing one buffer across
/// directives would mean reworking that parser to hand out ranges — a change
/// worth making only if this ever shows up in a measurement, which reading a
/// configuration once at startup is unlikely to do.
fn run_of(tokens: &[Spanned<Token>]) -> TokenRun {
    let end = tokens.len();
    TokenRun::new(Arc::from(tokens.to_vec()), 0, end)
}

/// 🔤 A token's text in the form the adapter expects.
fn text_of(token: &Token) -> String {
    match token {
        Token::Word(s) | Token::QuotedString(s) => s.clone(),
        // 🧭 Placeholders and environment variables keep their delimiters: the
        // value downstream is the whole `{host}`, resolved per request by
        // something that never sees this token.
        Token::Placeholder(s) => format!("{{{s}}}"),
        Token::EnvVar(s) => format!("${{{s}}}"),
        Token::BlockOpen => "{".into(),
        Token::BlockClose => "}".into(),
        Token::Newline => "\n".into(),
        Token::Whitespace | Token::Comment => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(source: &str) -> Vec<Directive> {
        parse_into_tree(source).expect("must parse")
    }

    #[test]
    fn a_site_becomes_a_directive_with_its_contents_as_a_block() {
        let parsed = tree("example.com {\n\trespond \"ok\" 200\n}\n");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "example.com");
        let inner = &parsed[0].block.as_ref().expect("a block").directives;
        assert_eq!(inner[0].name, "respond");
        assert_eq!(inner[0].args, ["ok", "200"]);
    }

    /// 🎯 The shape the tree parser could not represent: a directive's own
    /// block inside the braceless shorthand. One site, one directive.
    #[test]
    fn a_directives_block_does_not_become_a_second_site() {
        let parsed = tree(":80\nfile_server {\n\thide a.txt\n}\n");
        assert_eq!(parsed.len(), 1, "one site: {parsed:#?}");
        assert_eq!(parsed[0].name, ":80");
        let inner = &parsed[0].block.as_ref().expect("a block").directives;
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0].name, "file_server");
        assert_eq!(
            inner[0].block.as_ref().expect("its own block").directives[0].name,
            "hide"
        );
    }

    #[test]
    fn several_addresses_become_name_and_arguments() {
        let parsed = tree("a.example, b.example {\n\trespond \"x\"\n}\n");
        assert_eq!(parsed[0].name, "a.example,");
        assert_eq!(parsed[0].args, ["b.example"]);
    }

    #[test]
    fn an_addressless_block_keeps_the_empty_name_the_adapter_expects() {
        let parsed = tree("{\n\tauto_https off\n}\n\nlocalhost {\n\trespond \"x\"\n}\n");
        assert_eq!(parsed[0].name, "");
        assert_eq!(parsed[1].name, "localhost");
    }

    #[test]
    fn a_snippet_keeps_its_parenthesised_name() {
        let parsed = tree("(common) {\n\theader X-A b\n}\n");
        assert_eq!(parsed[0].name, "(common)");
    }

    /// 🧭 A placeholder is one argument and keeps its braces, or it stops being
    /// a placeholder and becomes the literal word inside it.
    #[test]
    fn a_placeholder_survives_as_one_argument() {
        let parsed = tree("example.com {\n\theader X-Host {host}\n}\n");
        let inner = &parsed[0].block.as_ref().expect("a block").directives;
        assert_eq!(inner[0].args, ["X-Host", "{host}"]);
    }

    #[test]
    fn nested_blocks_nest() {
        let parsed = tree(
            "example.com {\n\treverse_proxy 10.0.0.1 {\n\t\thealth_check {\n\t\t\tpath /up\n\t\t}\n\t}\n}\n",
        );
        let proxy = &parsed[0].block.as_ref().unwrap().directives[0];
        assert_eq!(proxy.args, ["10.0.0.1"]);
        let health = &proxy.block.as_ref().unwrap().directives[0];
        assert_eq!(health.name, "health_check");
        assert_eq!(health.block.as_ref().unwrap().directives[0].args, ["/up"]);
    }

    /// 📌 Writing braces and writing nothing are different, and a directive
    /// that asks `block.is_some()` is asking which one the operator did.
    #[test]
    fn an_absent_block_is_not_an_empty_one() {
        let parsed = tree("example.com {\n\tfile_server\n\tlog {\n\t\toutput stdout\n\t}\n}\n");
        let inner = &parsed[0].block.as_ref().unwrap().directives;
        assert!(inner[0].block.is_none(), "`file_server` wrote no braces");
        assert!(inner[1].block.is_some(), "`log` did");
    }

    /// 📎 Every directive carries the tokens it came from, so a parser that has
    /// moved to the cursor finds them there.
    #[test]
    fn directives_carry_their_tokens() {
        let parsed = tree("example.com {\n\tencode zstd gzip\n}\n");
        let encode = &parsed[0].block.as_ref().unwrap().directives[0];
        let mut cursor = encode.tokens.args_cursor().expect("a token run");
        assert_eq!(cursor.remaining_arg_texts(), ["zstd", "gzip"]);
    }
}
