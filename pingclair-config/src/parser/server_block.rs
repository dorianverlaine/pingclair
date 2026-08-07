// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧱 The configuration file as addresses and flat token runs.
//!
//! This is the shape the format itself is defined in, and it differs from the
//! tree this crate has parsed into until now in one decisive way: **a
//! directive's tokens are flat, nested braces included.**
//!
//! ```text
//! :80
//! file_server {
//!     hide first.txt
//! }
//! ```
//!
//! becomes one [`ServerBlock`] whose keys are `[:80]` and which holds a single
//! segment of eight tokens — `file_server`, `{`, `hide`, `first.txt`, `}` — with
//! the braces sitting in the run like any other token. Depth is a counter, not
//! structure.
//!
//! 🎯 **Why that matters more than it looks.** Parsing into a tree forces a
//! decision at every `{`: does this brace open a directive's block, or a new
//! site? Our tree parser guesses, and guesses wrong for exactly the shape above
//! — 58 of the 228 configurations in the format's own corpus fail on it and
//! nothing else. Counting depth removes the question instead of answering it
//! better.
//!
//! It is also what a token cursor needs to exist at all. A cursor walks a run of
//! tokens; `args: Vec<String>` has no tokens left to walk, and no memory of
//! which of them were quoted.
//!
//! 📌 This module is additive. Nothing consumes it yet — the existing tree
//! parser and the adapter above it are untouched, and callers move over one
//! directive at a time later. A conversion that flips everything at once has no
//! way to prove it changed nothing.

use super::lexer::{LexError, Location, Spanned, Token, tokenize};

/// One directive and everything that belongs to it, flat.
///
/// The first token is the directive name. Nested braces are ordinary members of
/// the run, so a consumer tracks depth with a counter rather than descending
/// into a child node.
pub type Segment = Vec<Spanned<Token>>;

/// A site block: the addresses it answers for, and the directives inside it.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerBlock {
    /// The address tokens before the opening brace, comma-separated in source.
    ///
    /// Empty for the global options block, which is the one block that names no
    /// site — that emptiness is how it is recognised rather than by position.
    pub keys: Vec<Spanned<Token>>,
    /// One entry per directive.
    pub segments: Vec<Segment>,
    /// Whether the source wrote braces around this block.
    ///
    /// Kept because the single-site shorthand has no braces and the difference
    /// survives into error messages: telling an operator to add braces is only
    /// useful if we know they did not write any.
    pub has_braces: bool,
    /// A snippet definition — `(name) { … }` — rather than a site.
    ///
    /// Snippets are declarations, not servers, so anything walking blocks to
    /// build listeners has to skip them. Recording it here means that decision
    /// is made once, by the parser, instead of by every consumer re-testing the
    /// shape of the key.
    pub is_snippet: bool,
}

impl ServerBlock {
    /// The address texts, for the common case of a consumer that wants strings.
    pub fn key_texts(&self) -> Vec<String> {
        self.keys.iter().map(|k| k.value.to_string()).collect()
    }

    /// 🌐 Whether this is the global options block: braces, and no address.
    pub fn is_global_options(&self) -> bool {
        self.keys.is_empty() && self.has_braces && !self.is_snippet
    }
}

/// Errors this parser can report, all of which name a position.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BlockParseError {
    #[error("Lexer error: {0}")]
    Lex(#[from] LexError),

    /// 🧭 Reserved: the format requires a block to open at the end of a line,
    /// and this parser used to enforce it. Enforcing it here would have made
    /// swapping the front end also change what compiles — including two of this
    /// repository's own README examples — so the rule moved to its own change
    /// rather than riding along inside a refactor.
    #[error("unexpected token after '{{' on line {location}; a block must open at end of line")]
    TokenAfterOpenBrace { location: Location },

    #[error(
        "unexpected '{{' on line {location}; it belongs at the end of the previous line, \
         not on its own"
    )]
    OpenBraceOnOwnLine { location: Location },

    #[error("unexpected '}}' on line {location} with no matching '{{'")]
    UnmatchedCloseBrace { location: Location },

    #[error(
        "unexpected '{{}}' on line {location}; write '{{' then a newline, or drop the empty block"
    )]
    EmptyBraces { location: Location },

    #[error("unterminated block opened on line {location}; expected '}}'")]
    UnterminatedBlock { location: Location },

    #[error("expected '{{' on line {location} after the site address")]
    ExpectedOpenBrace { location: Location },
}

impl BlockParseError {
    /// 📍 Where the error is, for a caller that renders positions.
    ///
    /// Every variant carries one except a lexer error, which reports its own.
    pub fn location(&self) -> Option<Location> {
        match self {
            Self::Lex(_) => None,
            Self::TokenAfterOpenBrace { location }
            | Self::OpenBraceOnOwnLine { location }
            | Self::UnmatchedCloseBrace { location }
            | Self::EmptyBraces { location }
            | Self::UnterminatedBlock { location }
            | Self::ExpectedOpenBrace { location } => Some(*location),
        }
    }
}

/// 🧱 Parses a configuration into site blocks of flat segments.
pub fn parse_server_blocks(source: &str) -> Result<Vec<ServerBlock>, BlockParseError> {
    let tokens = tokenize(source)?;
    Parser {
        tokens: &tokens,
        cursor: 0,
    }
    .parse()
}

struct Parser<'a> {
    tokens: &'a [Spanned<Token>],
    cursor: usize,
}

impl<'a> Parser<'a> {
    fn parse(mut self) -> Result<Vec<ServerBlock>, BlockParseError> {
        let mut blocks = Vec::new();

        loop {
            self.skip_newlines();
            if self.cursor >= self.tokens.len() {
                break;
            }
            blocks.push(self.parse_block()?);
        }
        Ok(blocks)
    }

    /// Parses one block: its keys, then either a braced body or bare directives.
    fn parse_block(&mut self) -> Result<ServerBlock, BlockParseError> {
        let mut keys = Vec::new();

        // 🔑 Everything up to `{` or a newline is an address. A leading `{` with
        // no keys at all is the global options block.
        while let Some(token) = self.peek() {
            match &token.value {
                Token::BlockOpen | Token::Newline => break,
                // 🚫 A closing brace cannot be part of an address. Collecting it
                // as one would push the complaint to whatever came next, and an
                // error that names the wrong brace is worse than one that names
                // no brace at all: `}}}` on a line has three candidates and only
                // the first unmatched one is the operator's mistake.
                Token::BlockClose => {
                    return Err(BlockParseError::UnmatchedCloseBrace {
                        location: token.span,
                    });
                }
                _ => {
                    keys.push(token.clone());
                    self.cursor += 1;
                }
            }
        }

        let is_snippet = keys.len() == 1 && {
            let text = keys[0].value.to_string();
            text.starts_with('(') && text.ends_with(')')
        };

        match self.peek().map(|t| t.value.clone()) {
            Some(Token::BlockOpen) => {
                let open = self.here();
                self.cursor += 1;
                if matches!(self.peek().map(|t| &t.value), Some(Token::BlockClose)) {
                    return Err(BlockParseError::EmptyBraces { location: open });
                }
                let segments = self.parse_segments(open)?;
                Ok(ServerBlock {
                    keys,
                    segments,
                    has_braces: true,
                    is_snippet,
                })
            }
            // 🧱 The shorthand: an address on its own line, directives after it,
            // no braces anywhere. Runs to end of file.
            _ => {
                // 🧭 A top-level `import` line is a directive, not a site
                // address, and upstream expands it while parsing addresses.
                // Letting the shorthand rule run to EOF would swallow the
                // following site blocks into the import's own block, where
                // they are dropped — a file of snippets imported first and
                // a site imported after compiled green and served nothing.
                if matches!(
                    keys.first().map(|token| &token.value),
                    Some(Token::Word(word)) if word == "import"
                ) {
                    return Ok(ServerBlock {
                        keys,
                        segments: Vec::new(),
                        has_braces: false,
                        is_snippet: false,
                    });
                }
                let segments = self.parse_bare_segments()?;
                Ok(ServerBlock {
                    keys,
                    segments,
                    has_braces: false,
                    is_snippet,
                })
            }
        }
    }

    /// Collects segments until the brace that closes this block.
    fn parse_segments(&mut self, open: Location) -> Result<Vec<Segment>, BlockParseError> {
        let mut segments = Vec::new();
        loop {
            self.skip_newlines();
            match self.peek().map(|t| t.value.clone()) {
                None => return Err(BlockParseError::UnterminatedBlock { location: open }),
                Some(Token::BlockClose) => {
                    self.cursor += 1;
                    return Ok(segments);
                }
                _ => segments.push(self.parse_segment()?),
            }
        }
    }

    /// Collects segments to end of file, for the braceless shorthand.
    fn parse_bare_segments(&mut self) -> Result<Vec<Segment>, BlockParseError> {
        let mut segments = Vec::new();
        loop {
            self.skip_newlines();
            match self.peek().map(|t| t.value.clone()) {
                None => return Ok(segments),
                // 🧭 A close brace here belongs to nobody: the shorthand opened
                // nothing.
                Some(Token::BlockClose) => {
                    return Err(BlockParseError::UnmatchedCloseBrace {
                        location: self.here(),
                    });
                }
                _ => segments.push(self.parse_segment()?),
            }
        }
    }

    /// 🎯 One directive, flat, nested braces included.
    ///
    /// This is the whole point of the module. The segment ends at the first
    /// newline seen while the depth counter is zero — so a directive's own block
    /// is swallowed into the run rather than mistaken for something else.
    fn parse_segment(&mut self) -> Result<Segment, BlockParseError> {
        let mut segment = Vec::new();
        let mut depth = 0usize;
        let mut open_at = None;

        while let Some(token) = self.peek() {
            match &token.value {
                Token::Newline if depth == 0 => {
                    self.cursor += 1;
                    break;
                }
                // ⏎ Inside a block, newlines separate the block's own directives.
                // They stay in the run: a cursor needs them to tell where one
                // sub-directive ends and the next begins.
                Token::Newline => {
                    segment.push(token.clone());
                    self.cursor += 1;
                }
                Token::BlockOpen => {
                    let open = token.span;
                    if depth == 0 {
                        open_at = Some(open);
                    }
                    depth += 1;
                    segment.push(token.clone());
                    self.cursor += 1;
                    // 🚫 `{}` written together is refused, while an empty block
                    // spread over two lines is fine. `{}` on one line is
                    // usually someone reaching for a *value* — `respond {}` —
                    // and getting a block, silently, with the directive left
                    // holding no arguments.
                    if matches!(self.peek().map(|t| &t.value), Some(Token::BlockClose)) {
                        return Err(BlockParseError::EmptyBraces { location: open });
                    }
                }
                Token::BlockClose => {
                    if depth == 0 {
                        // 🧭 Not ours: it closes the enclosing site block, so
                        // leave it for the caller and end the segment here.
                        break;
                    }
                    depth -= 1;
                    segment.push(token.clone());
                    self.cursor += 1;
                }
                _ => {
                    segment.push(token.clone());
                    self.cursor += 1;
                }
            }
        }

        if depth > 0 {
            return Err(BlockParseError::UnterminatedBlock {
                location: open_at.unwrap_or_else(|| self.here()),
            });
        }
        Ok(segment)
    }

    fn peek(&self) -> Option<&'a Spanned<Token>> {
        self.tokens.get(self.cursor)
    }

    fn skip_newlines(&mut self) {
        while matches!(self.peek().map(|t| &t.value), Some(Token::Newline)) {
            self.cursor += 1;
        }
    }

    /// The position to blame, falling back to the last token at end of input.
    fn here(&self) -> Location {
        self.tokens
            .get(self.cursor)
            .or_else(|| self.tokens.last())
            .map(|t| t.span)
            .unwrap_or_else(Location::synthetic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocks(source: &str) -> Vec<ServerBlock> {
        parse_server_blocks(source).expect("must parse")
    }

    fn texts(segment: &Segment) -> Vec<String> {
        segment
            .iter()
            .filter(|t| !matches!(t.value, Token::Newline))
            .map(|t| t.value.to_string())
            .collect()
    }

    /// 🎯 The shape the tree parser cannot represent: a directive's own block,
    /// inside the braceless shorthand. Flat segments make it unremarkable.
    #[test]
    fn a_directives_block_stays_inside_its_segment() {
        let parsed = blocks(":80\nfile_server {\n\thide first.txt\n}\n");
        assert_eq!(parsed.len(), 1, "one site, not two: {parsed:#?}");
        assert_eq!(parsed[0].key_texts(), vec![":80"]);
        assert!(!parsed[0].has_braces);
        assert_eq!(parsed[0].segments.len(), 1, "one directive");
        assert_eq!(
            texts(&parsed[0].segments[0]),
            vec!["file_server", "{", "hide", "first.txt", "}"]
        );
    }

    #[test]
    fn the_shorthand_takes_several_directives() {
        let parsed = blocks(":80\nroot * /srv\nfile_server\n");
        assert_eq!(parsed[0].segments.len(), 2);
        assert_eq!(texts(&parsed[0].segments[1]), vec!["file_server"]);
    }

    #[test]
    fn a_braced_site_keeps_its_keys() {
        let parsed = blocks("a.example, b.example {\n\trespond \"ok\"\n}\n");
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].has_braces);
        // 🧭 The comma is a token like any other; splitting addresses is the
        // address layer's job, not the parser's.
        // 🧭 The comma stays attached to the token the lexer produced
        // (`["a.example,", "b.example"]`). Splitting addresses is the address
        // layer's job, and doing it here would mean the parser deciding what
        // counts as one address — a question that also involves ports, schemes
        // and IPv6 brackets.
        assert_eq!(parsed[0].key_texts(), vec!["a.example,", "b.example"]);
    }

    /// 🌐 No address plus braces is the global options block, and that is how it
    /// is recognised — not by being first.
    #[test]
    fn an_addressless_block_is_the_global_options_block() {
        let parsed = blocks("{\n\tauto_https off\n}\n\nlocalhost\n");
        assert!(parsed[0].is_global_options());
        assert!(!parsed[1].is_global_options());
        assert_eq!(parsed[1].key_texts(), vec!["localhost"]);
    }

    #[test]
    fn a_parenthesised_name_is_a_snippet() {
        let parsed = blocks("(common) {\n\theader X-A b\n}\n\nlocalhost {\n\timport common\n}\n");
        assert!(parsed[0].is_snippet);
        assert!(!parsed[0].is_global_options());
        assert!(!parsed[1].is_snippet);
    }

    /// 🧭 A top-level `import` line must not swallow the blocks that follow
    /// it, the way the braceless shorthand swallows directives after a bare
    /// site address — upstream expands top-level imports while parsing
    /// addresses, so `import ./defs.conf` and the next site are two blocks.
    #[test]
    fn a_top_level_import_does_not_swallow_the_following_site() {
        let parsed = blocks("import ./defs.conf\n\nexample.com {\n\trespond \"ok\"\n}\n");
        assert_eq!(parsed.len(), 2, "import and site are separate blocks");
        assert_eq!(parsed[0].key_texts(), vec!["import", "./defs.conf"]);
        assert!(parsed[0].segments.is_empty());
        assert!(!parsed[0].has_braces);
        assert_eq!(parsed[1].key_texts(), vec!["example.com"]);
        assert!(parsed[1].has_braces);
    }

    #[test]
    fn nested_blocks_nest_in_one_segment() {
        let parsed =
            blocks("a.example {\n\tfile_server {\n\t\tbrowse {\n\t\t\tsort name\n\t\t}\n\t}\n}\n");
        assert_eq!(parsed[0].segments.len(), 1);
        let flat = texts(&parsed[0].segments[0]);
        assert_eq!(flat.iter().filter(|t| *t == "{").count(), 2);
        assert_eq!(flat.iter().filter(|t| *t == "}").count(), 2);
    }

    // MARK: - Refusals

    /// 🧭 A block opening with something after it on the same line is accepted
    /// here, and the format does not accept it.
    ///
    /// The divergence is deliberate and temporary. This parser replaced one
    /// that allowed the shape, and enforcing the rule in the same change would
    /// have meant a front-end swap that also changed what compiles — including
    /// two README examples in this repository. Tightening it is its own change,
    /// with its own documentation updates.
    #[test]
    fn a_token_after_the_opening_brace_is_accepted_for_now() {
        let parsed = blocks("a.example { respond \"x\"\n}\n");
        assert_eq!(parsed.len(), 1);
        assert_eq!(texts(&parsed[0].segments[0]), vec!["respond", "\"x\""]);
    }

    #[test]
    fn an_unmatched_close_brace_is_refused() {
        assert!(parse_server_blocks(":80\nrespond \"ok\"\n}\n").is_err());
    }

    #[test]
    fn an_unterminated_block_is_refused() {
        assert!(parse_server_blocks("a.example {\n\trespond \"ok\"\n").is_err());
    }

    /// 🧭 Bare-plus-braced is **not** a parse error at this layer, and finding
    /// that out was the point of writing the test.
    ///
    /// The braceless shorthand runs to end of file, so `other.example { … }`
    /// after a bare site parses as one more *directive* — named
    /// `other.example`, carrying a block. Nothing here can tell that apart from
    /// a legitimate directive without knowing which names are directives, which
    /// is knowledge this layer does not have and should not acquire.
    ///
    /// So the refusal belongs above: the layer that knows the directive names is
    /// the one that can say "this looks like a second site". The existing
    /// adapter already reports it, and that is the right place for it.
    #[test]
    fn bare_plus_braced_parses_here_and_is_refused_above() {
        let parsed =
            blocks("example.com\nrespond \"one\"\n\nother.example {\n\trespond \"two\"\n}\n");
        assert_eq!(parsed.len(), 1, "one bare site: {parsed:#?}");
        assert_eq!(
            parsed[0].segments.len(),
            2,
            "the second site became a directive"
        );
        assert_eq!(texts(&parsed[0].segments[1])[0], "other.example");
    }

    /// 📌 Errors name a line, because a position an operator cannot see is not
    /// a position.
    #[test]
    fn errors_carry_a_line_number() {
        let error = parse_server_blocks("a.example {\n\trespond \"ok\"\n")
            .expect_err("must fail")
            .to_string();
        assert!(error.contains("line 1:"), "expected a position: {error}");
    }
}
