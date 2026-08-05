// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔤 Lexer for the Pingclair configuration DSL.
//!
//! Tokenizes the Caddyfile-style DSL.
//!
//! Key features:
//! - Whitespace sensitive (Newlines invoke statement termination)
//! - Directives are just Words
//! - { } for blocks
//! - "..." for quoted strings
//! - # for comments (skipped)
//! - {placeholder} for Caddy-style runtime placeholders

use std::fmt;

/// Source location for error reporting.
///
/// 📍 `start` and `end` are **character** offsets, not byte offsets: the lexer
/// walks a `Vec<char>`, so anything slicing the original string by these needs
/// to convert first.
///
/// `line` and `column` are stored rather than derived. Deriving them would save
/// sixteen bytes per token on an input measured in kilobytes, and cost every
/// error path a reference to the source text it does not otherwise need — the
/// wrong side of that trade. Both are 1-based, because that is what an editor
/// shows and what a human types into one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Location {
    pub start: usize,
    pub end: usize,
    pub line: usize,
    pub column: usize,
}

impl Location {
    /// 🧪 A location for a node this compiler synthesised rather than read.
    ///
    /// Line zero is impossible in a real file, so it reads as "not from source"
    /// wherever it surfaces — which is the honest answer for a directive the
    /// adapter invented, and better than borrowing some unrelated token's
    /// position and pointing the operator at the wrong line.
    pub const fn synthetic() -> Self {
        Self {
            start: 0,
            end: 0,
            line: 0,
            column: 0,
        }
    }
}

impl fmt::Display for Location {
    /// 📍 `line:column`, the form every compiler and editor already agrees on.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.line, self.column)
    }
}

/// 🗺️ Turns character offsets into line and column numbers.
///
/// Built once per tokenize pass and consulted per token, because the lexer
/// advances `pos` from a dozen places and threading a running line counter
/// through all of them is how one of them ends up forgetting.
struct LineIndex {
    /// Character offset of each newline, ascending.
    newlines: Vec<usize>,
}

impl LineIndex {
    fn new(chars: &[char]) -> Self {
        Self {
            newlines: chars
                .iter()
                .enumerate()
                .filter(|(_, c)| **c == '\n')
                .map(|(i, _)| i)
                .collect(),
        }
    }

    fn at(&self, offset: usize) -> (usize, usize) {
        // 🔍 How many newlines start before this offset: that is the 0-based line.
        let line = self.newlines.partition_point(|&nl| nl < offset);
        let line_start = if line == 0 {
            0
        } else {
            self.newlines[line - 1] + 1
        };
        (line + 1, offset - line_start + 1)
    }

    /// Builds a location spanning `start..end`, positioned at `start`.
    fn span(&self, start: usize, end: usize) -> Location {
        let (line, column) = self.at(start);
        Location {
            start,
            end,
            line,
            column,
        }
    }
}

/// A token with its location in the source
#[derive(Debug, Clone, PartialEq)]
pub struct Spanned<T> {
    pub value: T,
    pub span: Location,
}

impl<T> Spanned<T> {
    pub fn new(value: T, span: Location) -> Self {
        Self { value, span }
    }
}

/// Token types for Caddyfile-compatible syntax
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// Whitespace (skipped during tokenization)
    Whitespace,
    /// Comment (skipped during tokenization)
    Comment,
    /// Block open: {
    BlockOpen,
    /// Block close: }
    BlockClose,
    /// Newline
    Newline,
    /// Quoted string: "..."
    QuotedString(String),
    /// Environment variable: {$VAR}
    EnvVar(String),
    /// Caddy placeholder: {http.request.header.X} or {host} etc.
    /// 🏗️ ARCHITECTURE: Caddy uses {placeholder} for runtime variable
    /// substitution. These are NOT block openers — they must be matched
    /// before the single '{' token.
    Placeholder(String),
    /// Generic word
    Word(String),
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Token::BlockOpen => write!(f, "{{"),
            Token::BlockClose => write!(f, "}}"),
            Token::Newline => write!(f, "\\n"),
            Token::QuotedString(s) => write!(f, "\"{s}\""),
            Token::EnvVar(s) => write!(f, "{{${s}}}"),
            Token::Placeholder(s) => write!(f, "{{{s}}}"),
            Token::Word(s) => write!(f, "{s}"),
            _ => write!(f, "{self:?}"),
        }
    }
}

/// Lexer error
#[derive(Debug, Clone, thiserror::Error)]
pub enum LexError {
    #[error("Unexpected character at position {position}")]
    UnexpectedChar { position: usize },

    #[error(
        "heredoc marker on line {line} must contain only letters, digits, dashes \
         and underscores; got '{marker}'"
    )]
    HeredocMarkerInvalid { line: usize, marker: String },

    #[error("missing heredoc marker on line {line}; write it as `<<END`")]
    HeredocMarkerMissing { line: usize },

    #[error("too many '<' for a heredoc on line {line}; use exactly two, as in `<<END`")]
    HeredocTooManyAngles { line: usize },

    #[error(
        "unterminated heredoc <<{marker} opened on line {line}; expected a line ending with {marker}"
    )]
    HeredocUnterminated { line: usize, marker: String },

    #[error(
        "mismatched leading whitespace in heredoc <<{marker} on line {line}: \
         every line must begin with the same indentation as the closing marker"
    )]
    HeredocIndentMismatch { line: usize, marker: String },
}

/// Lexer result type
pub type LexResult = Result<Vec<Spanned<Token>>, LexError>;

/// 📜 Turns a raw heredoc body into its final text.
///
/// The indentation of the **closing marker** decides how much to strip from
/// every line, which is what lets a heredoc sit at whatever depth its
/// surrounding block does without that depth leaking into the value. Lines
/// indented *further* keep the difference, so the shape of the content survives.
///
/// A line that does not start with exactly that padding is an error rather than
/// a best-effort strip: guessing there would silently change the operator's text.
///
/// `\r` is dropped throughout, so a file saved on Windows produces the same
/// value as one saved anywhere else.
fn finalize_heredoc(raw: &str, marker: &str, open_line: usize) -> Result<String, LexError> {
    let last_newline = raw.rfind('\n').unwrap_or(0);
    // 🧭 Whatever sits between that newline and the marker is the padding.
    let padding = &raw[last_newline + 1..raw.len() - marker.len()];

    let mut out = String::with_capacity(raw.len());
    // 🧭 The slice ends with the newline that precedes the closing marker, so
    // splitting on it yields one trailing empty element that is not a line.
    // Counting it would add a newline the operator never wrote.
    let body_lines = raw[..last_newline + 1].split('\n');
    let line_count = body_lines.clone().count();
    for (offset, line) in body_lines.take(line_count.saturating_sub(1)).enumerate() {
        // ⏎ A blank line has no indentation to match, and demanding some would
        // make an empty line inside a heredoc an error.
        if line.is_empty() || line == "\r" {
            out.push('\n');
            continue;
        }
        if !line.starts_with(padding) {
            return Err(LexError::HeredocIndentMismatch {
                line: open_line + offset + 1,
                marker: marker.to_string(),
            });
        }
        out.push_str(&line[padding.len()..].replace('\r', ""));
        out.push('\n');
    }
    // 📌 The loop adds a newline per line, including the last one, which the
    // closing marker's own line already accounted for.
    if out.ends_with('\n') {
        out.pop();
    }
    Ok(out)
}

/// Unescape a quoted string literal
fn unescape_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some('\\') => result.push('\\'),
                Some('"') => result.push('"'),
                Some(c) => {
                    result.push('\\');
                    result.push(c);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// ✂️ Tokenizes a Pingclair DSL source string.
///
/// 🏗️ ARCHITECTURE: Hand-written lexer instead of `logos` derive macro.
/// This avoids regex priority ordering issues with `{placeholder}` vs `{`
/// (block open) which `logos` cannot reliably disambiguate. The hand-written
/// approach gives us full control over the state machine, especially for
/// distinguishing inline `{placeholder}` tokens from structural `{` blocks.
pub fn tokenize(source: &str) -> LexResult {
    let mut tokens = Vec::new();
    let chars: Vec<char> = source.chars().collect();
    let lines = LineIndex::new(&chars);
    let mut pos = 0;

    while pos < chars.len() {
        let c = chars[pos];

        // ── Skip whitespace (spaces, tabs) ────────────────────────────
        if c == ' ' || c == '\t' || c == '\x0C' {
            pos += 1;
            continue;
        }

        // ── Newlines (significant — statement terminators) ────────────
        if c == '\n' {
            tokens.push(Spanned::new(Token::Newline, lines.span(pos, pos + 1)));
            pos += 1;
            continue;
        }
        if c == '\r' {
            // \r\n → single Newline token
            let end = if pos + 1 < chars.len() && chars[pos + 1] == '\n' {
                pos + 2
            } else {
                pos + 1
            };
            tokens.push(Spanned::new(Token::Newline, lines.span(pos, end)));
            pos = end;
            continue;
        }

        // ── Comments: # until end of line ─────────────────────────────
        if c == '#' {
            while pos < chars.len() && chars[pos] != '\n' {
                pos += 1;
            }
            continue;
        }

        // ── Heredoc: <<MARKER … MARKER ─────────────────────────────────
        //
        // 📜 Lets a directive take multi-line text without escaping every
        // newline, which is what makes an inline HTML response readable. The
        // marker must be on its own after `<<`; `<< foo` with a space is an
        // ordinary token, because that is a shell redirect the operator may
        // legitimately be writing.
        if c == '<' && pos + 1 < chars.len() && chars[pos + 1] == '<' {
            let start = pos;
            let open_line = lines.at(start).0;
            let mut cursor = pos + 2;

            // 🚫 Three or more is a typo worth naming: `<<<END` reads as a
            // heredoc to a human and would otherwise become a marker of `<END`.
            if cursor < chars.len() && chars[cursor] == '<' {
                return Err(LexError::HeredocTooManyAngles { line: open_line });
            }

            let marker_start = cursor;
            while cursor < chars.len() && !chars[cursor].is_whitespace() {
                cursor += 1;
            }
            let marker: String = chars[marker_start..cursor].iter().collect();

            if marker.is_empty() {
                return Err(LexError::HeredocMarkerMissing { line: open_line });
            }
            if !marker
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return Err(LexError::HeredocMarkerInvalid {
                    line: open_line,
                    marker,
                });
            }

            // 🧭 The body starts after the newline that ends the opening line.
            while cursor < chars.len() && chars[cursor] != '\n' {
                cursor += 1;
            }
            if cursor >= chars.len() {
                return Err(LexError::HeredocUnterminated {
                    line: open_line,
                    marker,
                });
            }
            cursor += 1; // consume that newline
            let body_start = cursor;

            // 🔍 The heredoc ends at the first whitespace-delimited **word**
            // that ends with the marker — not the first *line* that does.
            // `    EOF 200` is a real closing line: the marker terminates the
            // body and `200` goes on to be lexed as an ordinary argument, which
            // is how `respond <<EOF … EOF 200` gets its status code.
            //
            // 🧭 A consequence worth knowing: inside a heredoc a `#` starts
            // nothing, so a marker sitting in what looks like a comment still
            // closes the body. That is deliberate — the body is literal text —
            // and it usually surfaces as a whitespace-mismatch error, which is a
            // far better outcome than reading to end of file.
            let mut marker_end = None;
            let mut scan = cursor;
            while scan < chars.len() {
                if chars[scan].is_whitespace() {
                    scan += 1;
                    continue;
                }
                let word_start = scan;
                while scan < chars.len() && !chars[scan].is_whitespace() {
                    scan += 1;
                }
                let word: String = chars[word_start..scan].iter().collect();
                if word.trim_end_matches('\r').ends_with(&marker) {
                    // 📌 The marker itself stays inside the slice: the finaliser
                    // reads the padding in front of it to know what to strip.
                    marker_end = Some(word_start + word.trim_end_matches('\r').chars().count());
                    break;
                }
            }

            let Some(marker_end) = marker_end else {
                return Err(LexError::HeredocUnterminated {
                    line: open_line,
                    marker,
                });
            };

            let raw: String = chars[body_start..marker_end].iter().collect();
            let text = finalize_heredoc(&raw, &marker, open_line)?;
            // ▶️ Resume immediately after the marker, so anything following it on
            // that line is still lexed.
            pos = marker_end;
            // 🏷️ Emitted as a quoted string because that is exactly what it is:
            // a single value whose contents are taken literally. Everything
            // downstream then needs no knowledge of heredocs at all.
            tokens.push(Spanned::new(
                Token::QuotedString(text),
                lines.span(start, pos),
            ));
            continue;
        }

        // ── Quoted strings: "..." ─────────────────────────────────────
        if c == '"' {
            let start = pos;
            pos += 1; // skip opening quote
            let mut s = String::new();
            while pos < chars.len() && chars[pos] != '"' {
                if chars[pos] == '\\' && pos + 1 < chars.len() {
                    s.push(chars[pos]);
                    s.push(chars[pos + 1]);
                    pos += 2;
                } else {
                    s.push(chars[pos]);
                    pos += 1;
                }
            }
            if pos < chars.len() {
                pos += 1; // skip closing quote
            }
            tokens.push(Spanned::new(
                Token::QuotedString(unescape_string(&s)),
                lines.span(start, pos),
            ));
            continue;
        }

        // ── Braces ────────────────────────────────────────────────────
        // 🛑 SAFETY: We must check for {$VAR} and {placeholder} BEFORE
        // emitting a bare BlockOpen. The disambiguation rule:
        //   {$...}        → EnvVar
        //   {word.word...} → Placeholder (no spaces, no newlines inside)
        //   {             → BlockOpen (standalone or followed by newline/space)
        if c == '{' {
            let start = pos;

            // Try to match {$VAR}
            if pos + 2 < chars.len() && chars[pos + 1] == '$' {
                let var_start = pos + 2;
                let mut var_end = var_start;
                while var_end < chars.len() && chars[var_end] != '}' && chars[var_end] != '\n' {
                    var_end += 1;
                }
                if var_end < chars.len() && chars[var_end] == '}' {
                    let var_name: String = chars[var_start..var_end].iter().collect();
                    pos = var_end + 1;
                    tokens.push(Spanned::new(
                        Token::EnvVar(var_name),
                        lines.span(start, pos),
                    ));
                    continue;
                }
            }

            // Try to match {placeholder} — must contain at least one char,
            // no whitespace, no newlines inside. Typically: {host},
            // {http.request.header.CF-Connecting-IP}, etc.
            let inner_start = pos + 1;
            let mut inner_end = inner_start;
            let mut is_placeholder = false;
            while inner_end < chars.len() {
                let ic = chars[inner_end];
                if ic == '}' {
                    // Only treat as placeholder if we consumed at least 1 char
                    // and the content doesn't look like a block (contains a-z, dots, dashes, underscores)
                    if inner_end > inner_start {
                        is_placeholder = true;
                    }
                    break;
                }
                // If we hit whitespace or newline, it's a block, not a placeholder
                if ic == ' ' || ic == '\t' || ic == '\n' || ic == '\r' {
                    break;
                }
                inner_end += 1;
            }

            if is_placeholder && inner_end < chars.len() && chars[inner_end] == '}' {
                let inner: String = chars[inner_start..inner_end].iter().collect();
                pos = inner_end + 1;
                tokens.push(Spanned::new(
                    Token::Placeholder(inner),
                    lines.span(start, pos),
                ));
                continue;
            }

            // Plain block open
            tokens.push(Spanned::new(Token::BlockOpen, lines.span(start, pos + 1)));
            pos += 1;
            continue;
        }

        if c == '}' {
            tokens.push(Spanned::new(Token::BlockClose, lines.span(pos, pos + 1)));
            pos += 1;
            continue;
        }

        // ── Generic word ──────────────────────────────────────────────
        // Anything that is not whitespace, braces, quotes, or comment start.
        let start = pos;
        while pos < chars.len() {
            let wc = chars[pos];
            match wc {
                ' ' | '\t' | '\r' | '\n' | '\x0C' | '}' | '#' | '"' => break,
                '{' => {
                    // 🧭 A placeholder (`{host}`, `{http.request.uri}`) glued
                    // to a word belongs to that word, so `https://www.{host}`
                    // stays ONE token like it does in Caddy. A `{$VAR}` stays
                    // independent so the EnvVar branch handles it, and a bare
                    // `{` (block open) ends the word.
                    if pos + 1 < chars.len() && chars[pos + 1] == '$' {
                        break;
                    }
                    let mut j = pos + 1;
                    let mut found_close = false;
                    while j < chars.len() {
                        let pc = chars[j];
                        if pc == '}' {
                            found_close = true;
                            break;
                        }
                        if matches!(pc, ' ' | '\t' | '\r' | '\n' | '\x0C') {
                            break;
                        }
                        j += 1;
                    }
                    if found_close {
                        pos = j + 1;
                        continue;
                    }
                    break;
                }
                _ => pos += 1,
            }
        }
        if pos > start {
            let word: String = chars[start..pos].iter().collect();
            tokens.push(Spanned::new(Token::Word(word), lines.span(start, pos)));
        } else {
            return Err(LexError::UnexpectedChar { position: pos });
        }
    }

    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_directive() {
        let tokens = tokenize("bind 127.0.0.1").unwrap();
        assert_eq!(tokens[0].value, Token::Word("bind".to_string()));
        assert_eq!(tokens[1].value, Token::Word("127.0.0.1".to_string()));
    }

    #[test]
    fn test_block() {
        let tokens = tokenize("example.com {\n  root *\n}").unwrap();
        let t: Vec<Token> = tokens.into_iter().map(|s| s.value).collect();
        assert_eq!(t[0], Token::Word("example.com".to_string()));
        assert_eq!(t[1], Token::BlockOpen);
        assert_eq!(t[2], Token::Newline);
        assert_eq!(t[3], Token::Word("root".to_string()));
        assert_eq!(t[4], Token::Word("*".to_string()));
        assert_eq!(t[5], Token::Newline);
        assert_eq!(t[6], Token::BlockClose);
    }

    #[test]
    fn test_quotes_and_comments() {
        let source = r#"
            # This is a comment
            root "/var/www/html" # Inline comment
        "#;
        let tokens = tokenize(source).unwrap();
        let t: Vec<Token> = tokens
            .into_iter()
            .filter(|t| !matches!(t.value, Token::Newline))
            .map(|s| s.value)
            .collect();
        assert_eq!(t[0], Token::Word("root".to_string()));
        assert_eq!(t[1], Token::QuotedString("/var/www/html".to_string()));
    }

    #[test]
    fn test_env_var() {
        let tokens = tokenize("listen {$PORT}").unwrap();
        assert_eq!(tokens[0].value, Token::Word("listen".to_string()));
        assert_eq!(tokens[1].value, Token::EnvVar("PORT".to_string()));
    }

    #[test]
    fn test_caddy_placeholder() {
        let tokens =
            tokenize("header_up X-Real-IP {http.request.header.CF-Connecting-IP}").unwrap();
        assert_eq!(tokens[0].value, Token::Word("header_up".to_string()));
        assert_eq!(tokens[1].value, Token::Word("X-Real-IP".to_string()));
        assert_eq!(
            tokens[2].value,
            Token::Placeholder("http.request.header.CF-Connecting-IP".to_string())
        );
    }

    #[test]
    fn test_block_open_vs_placeholder() {
        // `{` followed by newline → BlockOpen
        let tokens = tokenize("server {\nfoo\n}").unwrap();
        assert_eq!(tokens[1].value, Token::BlockOpen);

        // `{host}` on a line → Placeholder
        let tokens2 = tokenize("header_up Host {host}").unwrap();
        assert_eq!(tokens2[2].value, Token::Placeholder("host".to_string()));
    }

    #[test]
    fn test_snippet_definition() {
        // (name) is just a Word token since parens are not braces
        let tokens = tokenize("(security_headers) {\n}").unwrap();
        assert_eq!(
            tokens[0].value,
            Token::Word("(security_headers)".to_string())
        );
        assert_eq!(tokens[1].value, Token::BlockOpen);
    }
}

#[cfg(test)]
mod line_index_tests {
    use super::*;

    fn loc(source: &str, needle: char) -> Location {
        let chars: Vec<char> = source.chars().collect();
        let index = LineIndex::new(&chars);
        let at = chars.iter().position(|c| *c == needle).expect("needle");
        index.span(at, at + 1)
    }

    #[test]
    fn the_first_character_is_line_one_column_one() {
        let l = loc("x", 'x');
        assert_eq!((l.line, l.column), (1, 1));
    }

    #[test]
    fn a_newline_advances_the_line_and_resets_the_column() {
        let l = loc("ab\ncd\nX", 'X');
        assert_eq!((l.line, l.column), (3, 1));
        let l = loc("ab\ncXd", 'X');
        assert_eq!((l.line, l.column), (2, 2));
    }

    /// 📍 Offsets are character-based throughout, so a line of CJK text must not
    /// shift the columns after it — the failure this would cause is an error
    /// message pointing at the wrong place in a configuration that has a comment
    /// in it.
    #[test]
    fn multibyte_characters_do_not_shift_the_position() {
        let l = loc("# 中文註解\nabX", 'X');
        assert_eq!((l.line, l.column), (2, 3));
    }

    /// 🧭 `\r\n` is one line break. Counting the `\r` separately would report
    /// every line after the first as one too many on files written on Windows.
    #[test]
    fn crlf_counts_as_one_line_break() {
        let l = loc("a\r\nX", 'X');
        assert_eq!(l.line, 2);
    }

    #[test]
    fn a_synthetic_location_is_line_zero() {
        // 🧪 Impossible in a real file, which is the point: it reads as
        // "this node was invented, not read".
        assert_eq!(Location::synthetic().line, 0);
    }
}
