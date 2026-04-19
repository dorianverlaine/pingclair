//! Lexer for Pingclairfile (Caddyfile Syntax)
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

/// Source location for error reporting
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Location {
    pub start: usize,
    pub end: usize,
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
            Token::QuotedString(s) => write!(f, "\"{}\"", s),
            Token::EnvVar(s) => write!(f, "{{${}}}", s),
            Token::Placeholder(s) => write!(f, "{{{}}}", s),
            Token::Word(s) => write!(f, "{}", s),
            _ => write!(f, "{:?}", self),
        }
    }
}

/// Lexer error
#[derive(Debug, Clone, thiserror::Error)]
pub enum LexError {
    #[error("Unexpected character at position {position}")]
    UnexpectedChar { position: usize },
}

/// Lexer result type
pub type LexResult = Result<Vec<Spanned<Token>>, LexError>;

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

/// Tokenize a Pingclairfile / Caddyfile source string.
///
/// 🏗️ ARCHITECTURE: Hand-written lexer instead of `logos` derive macro.
/// This avoids regex priority ordering issues with `{placeholder}` vs `{`
/// (block open) which `logos` cannot reliably disambiguate. The hand-written
/// approach gives us full control over the state machine, especially for
/// distinguishing inline `{placeholder}` tokens from structural `{` blocks.
pub fn tokenize(source: &str) -> LexResult {
    let mut tokens = Vec::new();
    let chars: Vec<char> = source.chars().collect();
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
            tokens.push(Spanned::new(Token::Newline, Location { start: pos, end: pos + 1 }));
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
            tokens.push(Spanned::new(Token::Newline, Location { start: pos, end }));
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
                Location { start, end: pos },
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
                        Location { start, end: pos },
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
                    Location { start, end: pos },
                ));
                continue;
            }

            // Plain block open
            tokens.push(Spanned::new(Token::BlockOpen, Location { start, end: pos + 1 }));
            pos += 1;
            continue;
        }

        if c == '}' {
            tokens.push(Spanned::new(Token::BlockClose, Location { start: pos, end: pos + 1 }));
            pos += 1;
            continue;
        }

        // ── Generic word ──────────────────────────────────────────────
        // Anything that is not whitespace, braces, quotes, or comment start.
        let start = pos;
        while pos < chars.len() {
            let wc = chars[pos];
            if wc == ' ' || wc == '\t' || wc == '\r' || wc == '\n'
                || wc == '\x0C' || wc == '{' || wc == '}' || wc == '#' || wc == '"'
            {
                break;
            }
            pos += 1;
        }
        if pos > start {
            let word: String = chars[start..pos].iter().collect();
            tokens.push(Spanned::new(Token::Word(word), Location { start, end: pos }));
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
        let t: Vec<Token> = tokens.into_iter()
            .filter(|t| !matches!(t.value, Token::Newline))
            .map(|s| s.value).collect();
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
        let tokens = tokenize("header_up X-Real-IP {http.request.header.CF-Connecting-IP}").unwrap();
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
        assert_eq!(tokens[0].value, Token::Word("(security_headers)".to_string()));
        assert_eq!(tokens[1].value, Token::BlockOpen);
    }
}
