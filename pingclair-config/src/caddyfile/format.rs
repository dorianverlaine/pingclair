// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🖋️ `pingclair fmt`: the Caddyfile's formatting rules, applied to the text.
//!
//! The plain idea: re-indent and re-space the file, and change nothing else.
//! Every token — words, quoted and backtick strings, heredocs, and comments —
//! is written back exactly as it was read; only the whitespace between tokens
//! is decided here. Indentation is one tab per block level, a `{` joins the
//! line that opens the block, a `}` sits on its own line, runs of blank lines
//! collapse to one, and a top-level block is followed by a blank line. These
//! are the rules the upstream formatter applies, so the two formatters agree
//! on a file instead of rewriting each other's output.
//!
//! 🤡 The formatter this replaces parsed the file into directives and printed
//! the tree back. Comments are not part of that tree, so `fmt --overwrite`
//! deleted every comment in the file it was asked to tidy.
//!
//! 🛡️ A formatter that changes meaning is worse than none, so the result is
//! checked before it is returned: the tokens must survive unchanged, a second
//! pass must change nothing, and the real parser must read the same directive
//! tree from the output as from the input. If any check fails, the input comes
//! back as it was, trimmed. Off the request path, so clarity wins over speed.

use super::parser::caddy_ast::Directive;

/// 📏 Deeper nesting is still indented, but no further than this.
const MAX_INDENT: usize = 10;

/// 🧩 What a token is, as far as layout is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Open,
    Close,
    Comment,
    Word,
}

/// 🔤 One token, carrying its source text verbatim.
#[derive(Clone, Debug)]
struct Token<'a> {
    raw: &'a str,
    kind: Kind,
    /// The 1-based line the token starts on.
    line: usize,
    /// How many line breaks the token itself spans (a heredoc, or a quoted
    /// string written across lines).
    span: usize,
}

impl Token<'_> {
    /// Whether `next` starts on a later line than this token ends on.
    fn breaks_before(&self, next: &Token<'_>) -> bool {
        self.line + self.span < next.line
    }

    /// Whether at least one blank line separates this token from `next`.
    fn blank_line_before(&self, next: &Token<'_>) -> bool {
        next.line >= self.line + self.span + 2
    }
}

/// 🖋️ Formats a Pingclairfile, keeping every token and comment as written.
pub fn format(source: &str) -> String {
    let fallback = || format!("{}\n", source.trim());
    let Some(tokens) = lex(source) else {
        return fallback();
    };
    let formatted = render(&tokens);
    let Some(again) = lex(&formatted) else {
        return fallback();
    };
    let unchanged_tokens = tokens.len() == again.len()
        && tokens
            .iter()
            .zip(&again)
            .all(|(before, after)| before.raw == after.raw);
    if !unchanged_tokens || render(&again) != formatted || !same_tree(source, &formatted) {
        return fallback();
    }
    formatted
}

// MARK: - Lexing

/// 🔤 Splits the source into tokens, keeping each one's text verbatim.
///
/// The rules mirror the configuration lexer's, so a heredoc or a quoted string
/// that spans lines is one token here too. `None` means the text could not be
/// split safely (an unterminated heredoc), and the caller leaves it alone.
fn lex(source: &str) -> Option<Vec<Token<'_>>> {
    let chars: Vec<(usize, char)> = source.char_indices().collect();
    let end_of = |index: usize| chars.get(index).map_or(source.len(), |(at, _)| *at);
    let mut tokens = Vec::new();
    let mut line = 1;
    let mut i = 0;
    while i < chars.len() {
        let (start, c) = chars[i];
        match c {
            '\n' => {
                line += 1;
                i += 1;
            }
            c if c.is_whitespace() => i += 1,
            '#' => {
                while i < chars.len() && chars[i].1 != '\n' {
                    i += 1;
                }
                let raw = source[start..end_of(i)].trim_end();
                tokens.push(Token {
                    raw,
                    kind: Kind::Comment,
                    line,
                    span: 0,
                });
            }
            '<' if chars.get(i + 1).is_some_and(|(_, next)| *next == '<') => {
                let end = heredoc_end(&chars, i)?;
                let raw = &source[start..end_of(end)];
                let span = raw.matches('\n').count();
                tokens.push(Token {
                    raw,
                    kind: Kind::Word,
                    line,
                    span,
                });
                line += span;
                i = end;
            }
            _ => {
                let end = word_end(&chars, i);
                let raw = &source[start..end_of(end)];
                let span = raw.matches('\n').count();
                push_word(&mut tokens, raw, line, span);
                line += span;
                i = end;
            }
        }
    }
    Some(tokens)
}

/// 🔚 Where a word ends: at whitespace outside quotes. A quoted or backtick
/// stretch inside the word is part of it, newlines included.
fn word_end(chars: &[(usize, char)], mut i: usize) -> usize {
    while i < chars.len() {
        match chars[i].1 {
            c if c.is_whitespace() => break,
            '"' => {
                i += 1;
                while i < chars.len() && chars[i].1 != '"' {
                    if chars[i].1 == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
            }
            '`' => {
                i += 1;
                while i < chars.len() && chars[i].1 != '`' {
                    i += 1;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    i.min(chars.len())
}

/// 📜 Where a heredoc ends: just past the closing marker, as the configuration
/// lexer finds it. `None` when the marker never comes back.
fn heredoc_end(chars: &[(usize, char)], start: usize) -> Option<usize> {
    let mut cursor = start + 2;
    let marker_start = cursor;
    while cursor < chars.len() && !chars[cursor].1.is_whitespace() {
        cursor += 1;
    }
    let marker: String = chars[marker_start..cursor].iter().map(|(_, c)| c).collect();
    if marker.is_empty() {
        return None;
    }
    while cursor < chars.len() && chars[cursor].1 != '\n' {
        cursor += 1;
    }
    let mut scan = cursor;
    while scan < chars.len() {
        if chars[scan].1.is_whitespace() {
            scan += 1;
            continue;
        }
        let word_start = scan;
        while scan < chars.len() && !chars[scan].1.is_whitespace() {
            scan += 1;
        }
        let word: String = chars[word_start..scan].iter().map(|(_, c)| c).collect();
        if word.ends_with(&marker) {
            return Some(scan);
        }
    }
    None
}

/// 🧱 Records a word, splitting off a brace glued to its end when the brace is
/// structural rather than part of a placeholder: `example.com{` opens a block,
/// while `{path}` is one word.
fn push_word<'a>(tokens: &mut Vec<Token<'a>>, raw: &'a str, line: usize, span: usize) {
    let opens = raw.matches('{').count();
    let closes = raw.matches('}').count();
    let kind = |text: &str| match text {
        "{" => Kind::Open,
        "}" => Kind::Close,
        _ => Kind::Word,
    };
    if raw.len() > 1 && span == 0 && raw.ends_with('{') && opens > closes {
        let (word, brace) = raw.split_at(raw.len() - 1);
        tokens.push(Token {
            raw: word,
            kind: kind(word),
            line,
            span,
        });
        tokens.push(Token {
            raw: brace,
            kind: Kind::Open,
            line,
            span: 0,
        });
    } else if raw.len() > 1 && span == 0 && raw.ends_with('}') && closes > opens {
        let (word, brace) = raw.split_at(raw.len() - 1);
        push_word(tokens, word, line, span);
        tokens.push(Token {
            raw: brace,
            kind: Kind::Close,
            line,
            span: 0,
        });
    } else {
        tokens.push(Token {
            raw,
            kind: kind(raw),
            line,
            span,
        });
    }
}

// MARK: - Rendering

/// 🖋️ Lays the tokens out: indentation, line breaks and spacing only.
fn render(tokens: &[Token<'_>]) -> String {
    let mut out = String::new();
    let mut nesting = 0usize;
    let mut at_line_start = true;
    let mut previous_closed_top_level = false;
    let mut line_starts_with_import = false;
    let mut folded_open: Option<usize> = None;

    for (i, token) in tokens.iter().enumerate() {
        if folded_open == Some(i) {
            continue;
        }
        let previous = i.checked_sub(1).map(|p| &tokens[p]);
        let starts_line = previous.is_none_or(|p| p.breaks_before(token));
        if !matches!(token.kind, Kind::Open | Kind::Close) && starts_line {
            line_starts_with_import =
                nesting == 0 && token.kind != Kind::Comment && token.raw == "import";
        }
        let closes = token.kind == Kind::Close && nesting > 0;
        let trailing_comment = token.kind == Kind::Comment && !starts_line;

        // ↕️ Line breaks before this token: 0 stays on the line, 1 starts a
        // new one, 2 leaves one blank line.
        let mut breaks = match previous {
            Some(p) if p.blank_line_before(token) => 2,
            Some(p) if p.breaks_before(token) => 1,
            _ => 0,
        };
        match token.kind {
            // 🧱 A `{` joins the line it opens. The exceptions keep meaning:
            // after a comment it would be commented out, and a standalone `{`
            // right after a top-level `import` line opens an unrelated
            // global-options block.
            Kind::Open => {
                let after_comment = previous.is_some_and(|p| p.kind == Kind::Comment);
                breaks = if after_comment {
                    1
                } else if line_starts_with_import && nesting == 0 && starts_line && i > 0 {
                    breaks.max(1)
                } else {
                    0
                };
            }
            Kind::Close if closes => {
                if !at_line_start {
                    breaks = breaks.max(1);
                }
                nesting -= 1;
            }
            _ if trailing_comment => breaks = 0,
            _ => {}
        }
        if let Some(p) = previous {
            let after_close = p.kind == Kind::Close;
            // 🧱 Nothing but another `}` or a trailing comment shares a line
            // with a closing brace.
            if after_close && breaks == 0 && !closes && !trailing_comment {
                breaks = 1;
            }
            // 🧱 A block's contents start on their own line.
            if p.kind == Kind::Open && breaks == 0 && !trailing_comment {
                breaks = 1;
            }
        }
        // 🧱 A top-level block is followed by a blank line.
        if previous_closed_top_level && breaks < 2 && !trailing_comment {
            breaks = 2;
        }
        previous_closed_top_level = false;

        // 🧷 `addr # note` followed by `{` on the next line renders as
        // `addr { # note`: the brace has to come before the comment.
        if trailing_comment
            && breaks == 0
            && previous.is_some_and(|p| p.kind != Kind::Open)
            && let Some(next) = tokens.get(i + 1)
            && next.kind == Kind::Open
        {
            out.push(' ');
            out.push_str(next.raw);
            nesting += 1;
            folded_open = Some(i + 1);
        }

        for _ in 0..breaks {
            out.push('\n');
            at_line_start = true;
        }
        if at_line_start {
            out.push_str(&"\t".repeat(nesting.min(MAX_INDENT)));
        } else {
            out.push(' ');
        }
        out.push_str(token.raw);
        at_line_start = false;

        match token.kind {
            Kind::Open => nesting += 1,
            Kind::Close if closes && nesting == 0 => previous_closed_top_level = true,
            _ => {}
        }
    }
    format!("{}\n", out.trim())
}

// MARK: - Meaning check

/// 🛡️ Whether the parser reads the same directive tree from both texts.
/// Locations are ignored: they are exactly what formatting moves.
fn same_tree(before: &str, after: &str) -> bool {
    fn same(a: &[Directive], b: &[Directive]) -> bool {
        a.len() == b.len()
            && a.iter().zip(b).all(|(a, b)| {
                a.name == b.name
                    && a.args == b.args
                    && match (&a.block, &b.block) {
                        (None, None) => true,
                        (Some(a), Some(b)) => same(&a.directives, &b.directives),
                        _ => false,
                    }
            })
    }
    match (super::parser::parse(before), super::parser::parse(after)) {
        (Ok(a), Ok(b)) => same(&a, &b),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::format;

    /// 💬 Comments survive: standalone, trailing, and inside blocks.
    #[test]
    fn comments_are_kept_where_they_were() {
        let source = "# head\n{\n# global\n    admin off   # no admin\n}\n\n\
                      :8080 {   # site\n  respond \"hi\"\n}\n";
        assert_eq!(
            format(source),
            "# head\n{\n\t# global\n\tadmin off # no admin\n}\n\n\
             :8080 { # site\n\trespond \"hi\"\n}\n"
        );
    }

    /// 🧱 Indentation, brace placement and blank lines are normalized.
    #[test]
    fn layout_is_normalized() {
        let source = ":8080   {\n      root * /srv\n\n\n\n  file_server {\n  browse\n  }   }\n:8081 {\nrespond \"x\"\n}";
        assert_eq!(
            format(source),
            ":8080 {\n\troot * /srv\n\n\tfile_server {\n\t\tbrowse\n\t}\n}\n\n\
             :8081 {\n\trespond \"x\"\n}\n"
        );
    }

    /// 🔁 Formatting its own output changes nothing.
    #[test]
    fn formatting_is_idempotent() {
        let source = "{\n\tadmin off\n}\n\n# site\n:8080 {\n\t@api path /api/*\n\
                      \treverse_proxy @api 127.0.0.1:9000 # backend\n\n\
                      \tfile_server\n}\n";
        assert_eq!(format(source), source);
        assert_eq!(format(&format(source)), format(source));
    }

    /// 🧭 A site brace on the next line is valid Caddyfile, and formatting
    /// joins it to the address the same way it does for every other block.
    #[test]
    fn a_site_brace_on_the_next_line_is_joined() {
        let source = "example.com\n{\n\trespond \"ok\"\n}\n";
        assert_eq!(format(source), "example.com {\n\trespond \"ok\"\n}\n");
    }

    /// 📜 Heredocs, placeholders and multi-line strings are written back
    /// verbatim; only their lines' leading tokens are re-indented.
    #[test]
    fn token_bodies_are_verbatim() {
        let source =
            ":8080 {\n    respond <<HTML\n  <p>{path}</p>\n  HTML 200\n    header X \"a  b\"\n}\n";
        let formatted = format(source);
        assert!(
            formatted.contains("<<HTML\n  <p>{path}</p>\n  HTML 200"),
            "{formatted}"
        );
        assert!(formatted.contains("\theader X \"a  b\""), "{formatted}");
    }

    /// 🛡️ Text the parser cannot read comes back unchanged, trimmed.
    #[test]
    fn unreadable_input_is_returned_as_written() {
        let source = "  :8080 {\n respond \"hi\"\n";
        assert_eq!(format(source), ":8080 {\n respond \"hi\"\n");
    }
}
