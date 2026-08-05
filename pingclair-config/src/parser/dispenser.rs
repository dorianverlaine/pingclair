// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🎯 A cursor over one directive's tokens.
//!
//! Every directive parser in this crate currently reads `args: Vec<String>` —
//! a list of strings with the tokens already thrown away. Three things go
//! missing in that conversion, and each has cost this project a defect:
//!
//! - **Whether a value was quoted.** `"{"` written by an operator is an
//!   argument; a bare `{` opens a block. Once both are the string `{`, the
//!   difference is unrecoverable, and code downstream has to guess.
//! - **Where the value came from.** An error can say what is wrong but not
//!   where, because a `String` has no position.
//! - **Where the line ended.** A directive's arguments stop at the end of its
//!   line. A flat `Vec<String>` has no lines in it, so every parser that cares
//!   re-invents a rule for where the arguments stop.
//!
//! A cursor keeps all three: it walks the tokens themselves and knows which
//! line each one is on.
//!
//! # 🧭 Where this departs from the format's own implementation
//!
//! The reference cursor has **no newline tokens** — its lexer drops them, and
//! "is the next token on the same line?" is answered by comparing the line
//! number recorded on each token, with extra care for tokens spliced in from an
//! imported file, whose line numbers come from a different file entirely.
//!
//! Our token stream keeps newlines ([`Token::Newline`]), so this cursor asks
//! the stream instead of doing arithmetic on line numbers. That is not a
//! shortcut: a quoted string or a heredoc can span lines, so a token's line
//! number is the line it *started* on and the arithmetic has an edge case that
//! the explicit token simply does not have.
//!
//! The consequence is that newline tokens are invisible to callers. They decide
//! where arguments stop, and block iteration steps over them, but no method
//! ever hands one back.
//!
//! # 🎯 Borrowing, not copying
//!
//! [`Dispenser::next_segment`] returns another `Dispenser` over a **subslice**
//! of the same tokens. The reference implementation copies the tokens into a
//! new cursor, and translating that literally would put one allocation per
//! directive on the configuration path — turning "read the config" into "copy
//! the config, once per nesting level". Segments are contiguous in the token
//! stream, so a borrow says the same thing for free.

use super::lexer::{Location, Spanned, Token};
use super::server_block::Segment;

/// A cursor over a run of tokens belonging to one directive.
///
/// The cursor starts *before* the first token, so the first call to
/// [`advance`](Self::advance) yields the directive's name. That is deliberate: a
/// caller loops `while let Some(token) = d.advance()` over sub-directives, and
/// having the loop yield the name first means the same loop shape works at
/// every level.
#[derive(Debug, Clone)]
pub struct Dispenser<'a> {
    tokens: &'a [Spanned<Token>],
    /// `None` means "before the first token", which is a distinct state from
    /// "at token 0" and the reason this is not a plain `usize`.
    cursor: Option<usize>,
    nesting: usize,
}

impl<'a> Dispenser<'a> {
    /// Creates a cursor positioned before the first token.
    pub fn new(tokens: &'a [Spanned<Token>]) -> Self {
        Self {
            tokens,
            cursor: None,
            nesting: 0,
        }
    }

    // MARK: - Position

    /// The token under the cursor, or `None` before the first one.
    pub fn token(&self) -> Option<&'a Spanned<Token>> {
        self.cursor.and_then(|i| self.tokens.get(i))
    }

    /// The current token's text, with quotes already removed.
    pub fn val(&self) -> Option<std::borrow::Cow<'a, str>> {
        self.token().map(|t| token_text(&t.value))
    }

    /// The tokens this cursor walks, for a caller building something from them.
    pub fn tokens(&self) -> &'a [Spanned<Token>] {
        self.tokens
    }

    /// Where the current token is, for an error that names a place.
    ///
    /// Falls back to the run's first token before the cursor has moved, and to
    /// a synthetic location for an empty run — an error still has to say
    /// something, and "line 0" reads as "not from a file".
    pub fn location(&self) -> Location {
        self.token()
            .or_else(|| self.tokens.first())
            .map_or_else(Location::synthetic, |t| t.span)
    }

    /// The current block depth. Needed when nesting [`next_block`](Self::next_block) loops.
    pub fn nesting(&self) -> usize {
        self.nesting
    }

    /// 📖 Whether the current token was written in quotes.
    ///
    /// This is the whole reason the cursor exists. `respond "{"`  and a block
    /// opening are the same three characters once quoting is forgotten.
    pub fn is_quoted(&self) -> bool {
        matches!(self.token().map(|t| &t.value), Some(Token::QuotedString(_)))
    }

    // MARK: - Moving

    /// Advances to the next token, whatever it is, skipping newlines.
    ///
    /// Use this to step from one sub-directive to the next. To read a single
    /// directive's own arguments, use [`next_arg`](Self::next_arg), which stops
    /// at the end of the line.
    pub fn advance(&mut self) -> Option<&'a Spanned<Token>> {
        let mut i = self.cursor.map_or(0, |c| c + 1);
        while matches!(self.tokens.get(i).map(|t| &t.value), Some(Token::Newline)) {
            i += 1;
        }
        if i >= self.tokens.len() {
            return None;
        }
        self.cursor = Some(i);
        self.tokens.get(i)
    }

    /// Advances to the next argument: the next token on the same line, unless
    /// it opens a block.
    ///
    /// An unquoted `{` is not an argument — it belongs to the block that
    /// follows — so the cursor stops in front of it and leaves it for
    /// [`next_block`](Self::next_block). A **quoted** `"{"` is an ordinary
    /// argument and is returned like any other.
    pub fn next_arg(&mut self) -> Option<&'a Spanned<Token>> {
        let i = self.cursor.map_or(0, |c| c + 1);
        let token = self.tokens.get(i)?;
        if matches!(token.value, Token::Newline | Token::BlockOpen) {
            return None;
        }
        self.cursor = Some(i);
        Some(token)
    }

    /// Advances only if the next token starts a new line.
    ///
    /// The mirror of [`next_arg`](Self::next_arg): it moves when that one would
    /// not, which is how a caller walks line by line.
    pub fn next_line(&mut self) -> Option<&'a Spanned<Token>> {
        let start = self.cursor.map_or(0, |c| c + 1);
        if !matches!(
            self.tokens.get(start).map(|t| &t.value),
            Some(Token::Newline)
        ) {
            return None;
        }
        self.advance()
    }

    /// Every remaining argument on this line, as tokens.
    pub fn remaining_args(&mut self) -> Vec<&'a Spanned<Token>> {
        let mut args = Vec::new();
        while let Some(token) = self.next_arg() {
            args.push(token);
        }
        args
    }

    /// Every remaining argument on this line, as text with quotes removed.
    pub fn remaining_arg_texts(&mut self) -> Vec<String> {
        self.remaining_args()
            .into_iter()
            .map(|t| token_text(&t.value).into_owned())
            .collect()
    }

    /// How many arguments remain on this line, without consuming them.
    pub fn count_remaining_args(&self) -> usize {
        let mut i = self.cursor.map_or(0, |c| c + 1);
        let mut count = 0;
        while let Some(token) = self.tokens.get(i) {
            if matches!(token.value, Token::Newline | Token::BlockOpen) {
                break;
            }
            count += 1;
            i += 1;
        }
        count
    }

    // MARK: - Blocks

    /// Walks the tokens of a block, one call per token.
    ///
    /// The intended shape is a loop, with the depth captured before it starts:
    ///
    /// ```ignore
    /// let nesting = d.nesting();
    /// while d.next_block(nesting).is_some() {
    ///     // `d.val()` is a sub-directive name; `d.remaining_args()` its arguments.
    /// }
    /// ```
    ///
    /// The braces around the outermost block are consumed here and never
    /// handed back, so a caller sees the contents and nothing else. An empty
    /// block (`{}`) ends the loop immediately — which is a real answer, not an
    /// error: the operator wrote a block and put nothing in it.
    pub fn next_block(&mut self, initial_nesting: usize) -> Option<&'a Spanned<Token>> {
        if self.nesting > initial_nesting {
            let token = self.advance()?;
            match token.value {
                Token::BlockClose => {
                    self.nesting -= 1;
                    if self.nesting <= initial_nesting {
                        // 🧭 That brace closed the block being walked, so the
                        // walk is over and the brace is not part of it.
                        return None;
                    }
                }
                Token::BlockOpen => self.nesting += 1,
                _ => {}
            }
            return Some(token);
        }

        // 🧱 A block opens at the end of the line the directive is on.
        let i = self.cursor.map_or(0, |c| c + 1);
        if !matches!(self.tokens.get(i).map(|t| &t.value), Some(Token::BlockOpen)) {
            return None;
        }
        self.cursor = Some(i);
        let first = self.advance()?;
        if matches!(first.value, Token::BlockClose) {
            return None;
        }
        self.nesting += 1;
        Some(first)
    }

    /// A cursor over the whole directive **starting at the current token**: its
    /// name, its arguments, and its block if it has one.
    ///
    /// Starting *here* rather than at the next token is what makes it usable
    /// from inside a [`next_block`](Self::next_block) loop, where the cursor has
    /// already landed on the sub-directive's name. A cursor that has not moved
    /// yet steps onto the first token first, so a fresh one yields the first
    /// whole directive.
    ///
    /// The returned cursor borrows a subslice of this one's tokens, so nothing
    /// is copied however deeply directives nest. Its own cursor starts before
    /// the directive's name, exactly like a freshly built one.
    ///
    /// This cursor is left on the segment's last token, and its nesting level is
    /// untouched — so the enclosing loop simply carries on.
    pub fn next_segment(&mut self) -> Option<Dispenser<'a>> {
        if self.cursor.is_none() {
            self.advance()?;
        }
        let start = self.cursor?;
        let mut i = start;
        // 📏 Arguments run to the end of the line or to the block opening.
        while matches!(
            self.tokens.get(i).map(|t| &t.value),
            Some(t) if !matches!(t, Token::Newline | Token::BlockOpen | Token::BlockClose)
        ) {
            i += 1;
        }
        if i == start {
            return None;
        }
        // 🧱 A block belonging to this directive extends the segment to its
        // matching close brace; depth is a counter because the braces are flat
        // in the run.
        if matches!(self.tokens.get(i).map(|t| &t.value), Some(Token::BlockOpen)) {
            let mut depth = 0usize;
            while let Some(token) = self.tokens.get(i) {
                match token.value {
                    Token::BlockOpen => depth += 1,
                    Token::BlockClose => {
                        depth -= 1;
                        if depth == 0 {
                            i += 1;
                            break;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
        }
        self.cursor = Some(i - 1);
        Some(Dispenser::new(&self.tokens[start..i]))
    }

    /// Rewinds to before the first token so the run can be walked again.
    pub fn reset(&mut self) {
        self.cursor = None;
        self.nesting = 0;
    }
}

impl<'a> From<&'a Segment> for Dispenser<'a> {
    fn from(segment: &'a Segment) -> Self {
        Dispenser::new(segment.as_slice())
    }
}

/// 🔤 A token's text with its syntax removed.
///
/// Placeholders and environment variables keep their braces because the value
/// downstream is the whole `{host}`, not the name inside it; a quoted string
/// loses its quotes because those were syntax, not content.
fn token_text(token: &Token) -> std::borrow::Cow<'_, str> {
    match token {
        Token::Word(s) | Token::QuotedString(s) => std::borrow::Cow::Borrowed(s),
        // 🧭 A placeholder's value is the whole `{host}`, not the name inside
        // it: it is resolved per request, much later, by something that has
        // never seen this token. Handing back `host` would quietly turn a
        // placeholder into a literal string — and `header_up X-Host {host}`
        // would send the four characters `host` upstream forever.
        Token::Placeholder(s) => std::borrow::Cow::Owned(format!("{{{s}}}")),
        Token::EnvVar(s) => std::borrow::Cow::Owned(format!("${{{s}}}")),
        Token::BlockOpen => std::borrow::Cow::Borrowed("{"),
        Token::BlockClose => std::borrow::Cow::Borrowed("}"),
        Token::Newline => std::borrow::Cow::Borrowed("\n"),
        Token::Whitespace | Token::Comment => std::borrow::Cow::Borrowed(""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::server_block::parse_server_blocks;

    /// Builds a cursor over the first directive of a one-site configuration.
    fn segment_of(source: &str) -> Vec<Spanned<Token>> {
        let blocks = parse_server_blocks(source).expect("must parse");
        blocks[0].segments[0].clone()
    }

    fn args_of(source: &str) -> Vec<String> {
        let tokens = segment_of(source);
        let mut d = Dispenser::new(&tokens);
        d.advance().expect("directive name");
        d.remaining_arg_texts()
    }

    #[test]
    fn the_first_step_lands_on_the_directive_name() {
        let tokens = segment_of(":80\nrespond \"ok\" 200\n");
        let mut d = Dispenser::new(&tokens);
        assert_eq!(
            d.advance().map(|t| token_text(&t.value)).as_deref(),
            Some("respond")
        );
        assert_eq!(d.val().as_deref(), Some("respond"));
    }

    #[test]
    fn arguments_stop_at_the_end_of_the_line() {
        assert_eq!(args_of(":80\nrespond \"ok\" 200\n"), ["ok", "200"]);
    }

    /// 🧱 An unquoted brace belongs to the block, not to the argument list.
    #[test]
    fn arguments_stop_before_a_block_opening() {
        assert_eq!(
            args_of(":80\nfile_server {\n\thide a.txt\n}\n"),
            [] as [&str; 0]
        );
    }

    /// 📖 The distinction the string form cannot make. A quoted brace is a
    /// value an operator typed on purpose.
    #[test]
    fn a_quoted_brace_is_an_ordinary_argument() {
        let tokens = segment_of(":80\nrespond \"{\" 200\n");
        let mut d = Dispenser::new(&tokens);
        d.advance();
        let args = d.remaining_args();
        assert_eq!(args.len(), 2, "the quoted brace is an argument");
        assert_eq!(token_text(&args[0].value), "{");
        assert!(matches!(args[0].value, Token::QuotedString(_)));
    }

    #[test]
    fn counting_arguments_does_not_consume_them() {
        let tokens = segment_of(":80\nrespond \"ok\" 200\n");
        let mut d = Dispenser::new(&tokens);
        d.advance();
        assert_eq!(d.count_remaining_args(), 2);
        assert_eq!(d.count_remaining_args(), 2, "counting twice gives the same");
        assert_eq!(d.remaining_arg_texts(), ["ok", "200"]);
    }

    #[test]
    fn a_block_yields_its_contents_without_its_braces() {
        let tokens = segment_of(":80\nfile_server {\n\thide a.txt\n\tbrowse\n}\n");
        let mut d = Dispenser::new(&tokens);
        d.advance().expect("file_server");
        let mut seen = Vec::new();
        let nesting = d.nesting();
        while d.next_block(nesting).is_some() {
            seen.push(d.val().unwrap_or_default().to_string());
        }
        assert_eq!(seen, ["hide", "a.txt", "browse"]);
    }

    /// 🧭 A sub-directive's own arguments still stop at its line ending, which
    /// is how a block loop tells one sub-directive from the next.
    #[test]
    fn a_block_loop_reads_one_sub_directive_at_a_time() {
        let tokens = segment_of(":80\nfile_server {\n\thide a.txt b.txt\n\tbrowse\n}\n");
        let mut d = Dispenser::new(&tokens);
        d.advance();
        let mut seen: Vec<(String, Vec<String>)> = Vec::new();
        let nesting = d.nesting();
        while d.next_block(nesting).is_some() {
            let name = d.val().unwrap_or_default().to_string();
            seen.push((name, d.remaining_arg_texts()));
        }
        assert_eq!(
            seen,
            [
                ("hide".to_string(), vec!["a.txt".into(), "b.txt".into()]),
                ("browse".to_string(), vec![]),
            ]
        );
    }

    /// 📌 An empty block is a real answer, not an error: the operator opened a
    /// block and wrote nothing in it.
    #[test]
    fn an_empty_block_ends_the_walk_immediately() {
        let tokens = segment_of(":80\nfile_server {\n}\n");
        let mut d = Dispenser::new(&tokens);
        d.advance();
        let nesting = d.nesting();
        assert!(d.next_block(nesting).is_none());
    }

    #[test]
    fn nested_blocks_come_back_out_to_the_right_level() {
        let tokens =
            segment_of(":80\nfile_server {\n\tbrowse {\n\t\tsort name\n\t}\n\thide a\n}\n");
        let mut d = Dispenser::new(&tokens);
        d.advance();
        let mut seen = Vec::new();
        let nesting = d.nesting();
        while d.next_block(nesting).is_some() {
            seen.push(d.val().unwrap_or_default().to_string());
        }
        // 🧭 The inner braces stay visible — only the outermost pair is
        // consumed — so a caller that wants structure uses `next_segment`.
        assert!(seen.contains(&"sort".to_string()));
        assert!(seen.contains(&"hide".to_string()));
    }

    /// 🎯 The shape this whole module exists to enable: walk a block, and take
    /// a whole sub-directive — its own block included — one at a time.
    ///
    /// Nothing is copied to do it. Each sub-cursor borrows a window onto the
    /// same tokens, at any depth.
    #[test]
    fn a_block_walk_hands_out_whole_sub_directives() {
        let tokens =
            segment_of(":80\nfile_server {\n\tbrowse {\n\t\tsort name\n\t}\n\thide a b\n}\n");
        let mut d = Dispenser::new(&tokens);
        d.advance().expect("file_server");

        let mut seen: Vec<(String, Vec<String>)> = Vec::new();
        let nesting = d.nesting();
        while d.next_block(nesting).is_some() {
            let mut sub = d.next_segment().expect("a sub-directive");
            let name = sub
                .advance()
                .map(|t| token_text(&t.value))
                .unwrap_or_default();
            seen.push((name.to_string(), sub.remaining_arg_texts()));

            // 🧱 `browse` carries its own block inside its segment, so the same
            // walk works one level down.
            if name == "browse" {
                let inner_nesting = sub.nesting();
                let mut inner = Vec::new();
                while sub.next_block(inner_nesting).is_some() {
                    inner.push(sub.val().unwrap_or_default().to_string());
                }
                assert_eq!(inner, ["sort", "name"]);
            }
        }

        assert_eq!(
            seen,
            [
                ("browse".to_string(), vec![]),
                ("hide".to_string(), vec!["a".into(), "b".into()]),
            ]
        );
    }

    /// 🧭 A fresh cursor's first segment is the whole directive, so a caller
    /// that only wants "this directive, entire" does not have to step first.
    #[test]
    fn a_fresh_cursor_yields_the_whole_first_directive() {
        let tokens = segment_of(":80\nfile_server {\n\thide a.txt\n}\n");
        let mut d = Dispenser::new(&tokens);
        let mut seg = d.next_segment().expect("the whole directive");
        assert_eq!(
            seg.advance().map(|t| token_text(&t.value)).as_deref(),
            Some("file_server")
        );
        let nesting = seg.nesting();
        let mut inner = Vec::new();
        while seg.next_block(nesting).is_some() {
            inner.push(seg.val().unwrap_or_default().to_string());
        }
        assert_eq!(inner, ["hide", "a.txt"]);
    }

    #[test]
    fn a_reset_cursor_walks_the_run_again() {
        let tokens = segment_of(":80\nrespond \"ok\" 200\n");
        let mut d = Dispenser::new(&tokens);
        d.advance();
        assert_eq!(d.remaining_arg_texts(), ["ok", "200"]);
        d.reset();
        d.advance();
        assert_eq!(d.remaining_arg_texts(), ["ok", "200"]);
    }

    /// 📍 Positions survive, so an error can name a line and a column.
    #[test]
    fn tokens_keep_their_position() {
        let tokens = segment_of("example.com {\n\trespond \"ok\" 200\n}\n");
        let mut d = Dispenser::new(&tokens);
        d.advance();
        assert_eq!(d.location().line, 2, "the directive is on line 2");
        d.next_arg();
        assert_eq!(d.location().line, 2);
        assert!(d.location().column > 1, "and a column inside that line");
    }

    /// 🧭 An empty run answers every question without panicking, because a
    /// caller reaches for the cursor before knowing whether there is anything
    /// in it.
    #[test]
    fn an_empty_run_is_answerable() {
        let mut d = Dispenser::new(&[]);
        assert!(d.advance().is_none());
        assert!(d.next_arg().is_none());
        assert!(d.next_line().is_none());
        assert!(d.next_segment().is_none());
        assert_eq!(d.count_remaining_args(), 0);
        assert_eq!(d.val(), None);
        assert_eq!(d.location().line, 0, "line 0 reads as 'not from a file'");
    }
}
