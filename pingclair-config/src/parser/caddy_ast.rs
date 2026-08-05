// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Generic AST for Caddyfile syntax
//!
//! This AST represents the structure of a Caddyfile:
//! - Directives (Name + Args + Block)
//! - Blocks (List of Directives)

use crate::parser::dispenser::Dispenser;
use crate::parser::lexer::{Spanned, Token};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct Directive {
    /// Directive name (e.g. "server", "reverse_proxy", "example.com")
    pub name: String,

    /// Arguments following the name
    pub args: Vec<String>,

    /// Optional block { ... }
    pub block: Option<Block>,

    /// 🎯 The tokens this directive was read from, for parsers that have moved
    /// onto the cursor.
    ///
    /// `args` above is the same information with the tokens thrown away, and
    /// both are kept on purpose: directive parsers move to the cursor one at a
    /// time, and a directive whose parser has not moved yet still reads `args`.
    /// Keeping them side by side is what makes that migration possible without
    /// a flag day.
    pub tokens: TokenRun,
}

/// 📎 A window onto the token stream a directive came from.
///
/// The tokens are shared with every other directive in the same file rather
/// than copied per directive: a configuration is parsed once and the whole
/// stream outlives all of it, so cloning a `Directive` — which this adapter
/// does constantly — costs a reference count and a pair of indices.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TokenRun {
    tokens: Option<Arc<[Spanned<Token>]>>,
    start: usize,
    end: usize,
    /// How many leading arguments have already been taken by an outer layer.
    ///
    /// A matcher token is stripped before the directive's own parser runs, and
    /// the run cannot simply shrink: the directive's *name* is the first token
    /// and has to stay. So the skip is recorded instead of cut, and
    /// [`TokenRun::args_cursor`] applies it.
    skipped_args: usize,
}

impl TokenRun {
    /// Records the half-open range `start..end` of a shared token stream.
    pub fn new(tokens: Arc<[Spanned<Token>]>, start: usize, end: usize) -> Self {
        Self {
            tokens: Some(tokens),
            start,
            end,
            skipped_args: 0,
        }
    }

    /// 🧪 The run for a directive this compiler invented rather than read.
    ///
    /// Empty is the honest answer, not a missing value: the adapter synthesises
    /// directives while expanding blocks, and those never existed in a file. A
    /// parser that finds an empty run reads `args` instead, which is exactly
    /// the fallback the migration relies on.
    pub fn synthetic() -> Self {
        Self::default()
    }

    /// The tokens themselves, empty for a synthesised directive.
    pub fn tokens(&self) -> &[Spanned<Token>] {
        match &self.tokens {
            Some(tokens) => &tokens[self.start..self.end],
            None => &[],
        }
    }

    /// Whether this directive came from a file at all.
    pub fn is_empty(&self) -> bool {
        self.tokens().is_empty()
    }

    /// A cursor over this directive, positioned before its name.
    ///
    /// Use this to read the directive whole — including tokens an outer layer
    /// has already taken. Parsers that want the directive's own data want
    /// [`args_cursor`](Self::args_cursor) instead.
    pub fn dispenser(&self) -> Dispenser<'_> {
        Dispenser::new(self.tokens())
    }

    /// A cursor sitting on the directive's name, with any stripped arguments
    /// already consumed — so the next [`next_arg`](Dispenser::next_arg) yields
    /// the first argument that still belongs to this directive.
    ///
    /// `None` for a synthesised directive, which is the signal to read `args`.
    pub fn args_cursor(&self) -> Option<Dispenser<'_>> {
        if self.is_empty() {
            return None;
        }
        let mut cursor = Dispenser::new(self.tokens());
        cursor.advance()?;
        for _ in 0..self.skipped_args {
            cursor.next_arg()?;
        }
        Some(cursor)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    pub directives: Vec<Directive>,
}

impl Directive {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            args: Vec::new(),
            block: None,
            tokens: TokenRun::synthetic(),
        }
    }

    /// 🔪 Removes and returns the first argument, from **both** representations.
    ///
    /// The site layer strips a matcher token this way before the directive's
    /// own parser runs. Doing it to `args` alone would leave the token run
    /// still holding the matcher, so a parser that had moved to the cursor
    /// would read the matcher as data — which is precisely the defect the
    /// single matcher rule was written to remove, reintroduced by the
    /// migration meant to make it safer.
    ///
    /// That is why this is one method and not two lines at each call site.
    pub fn drop_first_arg(&mut self) -> Option<String> {
        if self.args.is_empty() {
            return None;
        }
        self.tokens.skipped_args += 1;
        Some(self.args.remove(0))
    }

    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    pub fn with_block(mut self, block: Block) -> Self {
        self.block = Some(block);
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::parser::parse;

    /// 📎 A parsed directive can be read either way, and both say the same
    /// thing. That equivalence is the contract the migration rests on.
    #[test]
    fn a_parsed_directive_reads_the_same_from_tokens_and_from_args() {
        let directives = parse("example.com {\n\tencode zstd gzip\n}").expect("parses");
        let site = &directives[0];
        let encode = &site.block.as_ref().expect("a block").directives[0];

        assert_eq!(encode.args, ["zstd", "gzip"]);
        let mut cursor = encode.tokens.args_cursor().expect("a token run");
        assert_eq!(cursor.remaining_arg_texts(), ["zstd", "gzip"]);
    }

    /// 🔪 Stripping a matcher has to move both representations, or a converted
    /// parser reads the matcher as data while an unconverted one does not —
    /// two parsers disagreeing about the same line.
    #[test]
    fn dropping_an_argument_moves_the_token_run_too() {
        let directives = parse("example.com {\n\trespond /health \"ok\" 200\n}").expect("parses");
        let mut respond = site_directive(&directives);

        assert_eq!(respond.drop_first_arg().as_deref(), Some("/health"));
        assert_eq!(respond.args, ["ok", "200"]);
        let mut cursor = respond.tokens.args_cursor().expect("a token run");
        assert_eq!(
            cursor.remaining_arg_texts(),
            ["ok", "200"],
            "the cursor must not hand the matcher back"
        );
    }

    /// 🧪 A directive nobody wrote has no tokens, and that is the signal to
    /// read `args` — not a missing value to paper over.
    #[test]
    fn a_synthesised_directive_has_no_token_run() {
        let synthetic = super::Directive::new("respond").with_args(vec!["ok".into()]);
        assert!(synthetic.tokens.is_empty());
        assert!(synthetic.tokens.args_cursor().is_none());
    }

    fn site_directive(directives: &[super::Directive]) -> super::Directive {
        directives[0].block.as_ref().expect("a block").directives[0].clone()
    }
}
