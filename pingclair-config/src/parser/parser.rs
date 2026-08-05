// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚪 The crate's parsing entry point, and the errors it reports.
//!
//! The recursive-descent parser this module was named for is gone. It had to
//! decide, at every `{`, whether the brace opened a directive's block or a new
//! site — a question it could not answer, because answering it means knowing
//! which words are directives and this layer deliberately does not. It guessed,
//! and the guess was wrong for a quarter of the format's own test corpus.
//!
//! [`parse`] now runs the flat-segment parser and assembles the directive tree
//! from segments, where the question does not arise: a directive's braces are
//! ordinary members of its token run and depth is a counter.

use crate::parser::caddy_ast::Directive;
#[allow(unused_imports)]
use crate::parser::lexer::LexResult;
use crate::parser::lexer::{LexError, Location};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Lexer error: {0}")]
    Lex(#[from] LexError),

    // 📍 `line:column`, not the raw offsets. The debug form printed
    // `Location { start: 42, end: 48 }`, which tells an operator nothing they
    // can act on — they cannot see byte offsets in an editor.
    #[error("Unexpected token {token} at line {location}, expected {expected}")]
    UnexpectedToken {
        token: String,
        location: Location,
        expected: String,
    },

    #[error("Unexpected end of file, expected {expected}")]
    UnexpectedEof { expected: String },

    // 📍 A structural error from the block parser, with the position it
    // recorded. Rendering the position is the reason tokens carry one.
    #[error("{message} at line {location}")]
    Syntax { message: String, location: Location },

    #[error("Nesting too deep")]
    RecursionLimitExceeded,
}

pub fn parse(source: &str) -> Result<Vec<Directive>, ParseError> {
    // 🌐 Caddy substitutes `{$VAR}` (with an optional `:default`) before
    // tokenizing, so a variable may expand to several tokens or to nothing.
    // Doing it here keeps the lexer dumb and the substitution lossless.
    let expanded = expand_env_vars(source);
    // 🌉 The directive tree is assembled from flat segments now. The recursive
    // parser this function used to call had to decide, at every `{`, whether
    // the brace opened a directive's block or a new site — and could not, for
    // want of knowing which words are directives.
    crate::parser::segment_tree::parse_into_tree(&expanded)
}

/// 🌐 Replaces every `{$NAME}` or `{$NAME:default}` with the environment
/// variable's value. An unset variable without a default expands to the empty
/// string, exactly like Caddy; the result is re-tokenized, so whitespace in
/// the value produces several tokens.
fn expand_env_vars(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let mut rest = source;
    while let Some(start) = rest.find("{$") {
        result.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            // 📝 A dangling `{$` is left untouched; the lexer will reject it.
            result.push_str(&rest[start..]);
            return result;
        };
        let spec = &after[..end];
        let (name, default) = spec
            .split_once(':')
            .map_or((spec, None), |(name, default)| (name, Some(default)));
        let value = std::env::var(name)
            .ok()
            .or_else(|| default.map(str::to_string))
            .unwrap_or_default();
        result.push_str(&value);
        rest = &after[end + 1..];
    }
    result.push_str(rest);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// 🧭 The braceless shorthand is one site, not a run of loose directives.
    ///
    /// This used to come back as two top-level directives, which the adapter
    /// then merged into a site. The result was the same; the intermediate shape
    /// was a guess the parser had no business making, and it is gone.
    fn test_parse_simple_directive() {
        let source = "debug\nroot /var/www";
        let directives = parse(source).unwrap();
        assert_eq!(directives.len(), 1, "one site: {directives:#?}");
        assert_eq!(directives[0].name, "debug");
        let inner = &directives[0]
            .block
            .as_ref()
            .expect("its contents")
            .directives;
        assert_eq!(inner[0].name, "root");
        assert_eq!(inner[0].args[0], "/var/www");
    }

    #[test]
    fn test_parsing_block() {
        let source = r#"
            example.com {
                reverse_proxy localhost:8080
            }
        "#;
        let directives = parse(source).unwrap();
        assert_eq!(directives.len(), 1);
        let server = &directives[0];
        assert_eq!(server.name, "example.com");

        let block = server.block.as_ref().unwrap();
        assert_eq!(block.directives.len(), 1);
        assert_eq!(block.directives[0].name, "reverse_proxy");
        assert_eq!(block.directives[0].args[0], "localhost:8080");
    }

    #[test]
    fn test_nested_block_with_newlines() {
        let source = r#"
            route {
                Header X-Foo "Bar"
            }
        "#;
        let directives = parse(source).unwrap();
        let d = &directives[0];
        assert_eq!(d.name, "route");
        assert_eq!(d.block.as_ref().unwrap().directives.len(), 1);
    }
}
