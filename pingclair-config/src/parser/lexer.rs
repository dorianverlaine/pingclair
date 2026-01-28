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

use logos::{Logos, Span};
use std::fmt;

/// Source location for error reporting
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Location {
    pub start: usize,
    pub end: usize,
}

impl From<Span> for Location {
    fn from(span: Span) -> Self {
        Self {
            start: span.start,
            end: span.end,
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
    pub fn new(value: T, span: impl Into<Location>) -> Self {
        Self {
            value,
            span: span.into(),
        }
    }
}

/// Token types for Caddyfile-compatible syntax
#[derive(Logos, Debug, Clone, PartialEq)]
pub enum Token {
    // Skip whitespace (spaces and tabs), but NOT newlines
    #[regex(r"[ \t\f]+", logos::skip)]
    Whitespace,

    // Comments handling: Start with #, go until newline. 
    // We treat comments as skipped, but ensuring they consume until newline is important.
    // Actually, distinct newlines are significant, so comments should probably stop BEFORE the newline
    // so the newline can be emitted as a separte token if needed?
    // Caddyfile: Newline after comment is a terminator.
    #[regex(r"#[^\n]*", logos::skip)]
    Comment,

    // ============================================================
    // Structural
    // ============================================================
    #[token("{")]
    BlockOpen,

    #[token("}")]
    BlockClose,

    #[regex(r"\r?\n")]
    Newline,

    // ============================================================
    // Values
    // ============================================================

    /// Quoted string literal: "..."
    #[regex(r#""([^"\\]|\\.)*""#, |lex| {
        let s = lex.slice();
        // Remove quotes and unescape
        unescape_string(&s[1..s.len()-1])
    })]
    QuotedString(String),

    /// Environment Variable shorthand: {$VAR}
    /// We capture this as a specific token to allow the parser/adapter to handle expansion specially if needed,
    /// or we can treat it as a Word. Caddy often mandates `{$VAR}` (with $) for replacment at parse time.
    #[regex(r"\{\$[a-zA-Z_][a-zA-Z0-9_]*\}", |lex| {
        let s = lex.slice();
        s[2..s.len()-1].to_string() // Extract VAR from {$VAR}
    })]
    EnvVar(String),

    /// Generic Word (unquoted string, numbers, paths, etc.)
    /// Matches anything that isn't whitespace, braces, quotes, or comment start.
    #[regex(r#"[^ \t\r\n\f{}#"]+"#, |lex| lex.slice().to_string())]
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
            Token::Word(s) => write!(f, "{}", s),
            _ => write!(f, "{:?}", self),
        }
    }
}

/// Unescape a string literal
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

/// Lexer result type
pub type LexResult = Result<Vec<Spanned<Token>>, LexError>;

/// Lexer error
#[derive(Debug, Clone, thiserror::Error)]
pub enum LexError {
    #[error("Unexpected character at position {position}")]
    UnexpectedChar { position: usize },
}

/// Tokenize a Pingclairfile source string
pub fn tokenize(source: &str) -> LexResult {
    let lexer = Token::lexer(source);
    let mut tokens = Vec::new();
    
    for (result, span) in lexer.spanned() {
        match result {
            Ok(Token::Whitespace) | Ok(Token::Comment) => {
                // Should have been skipped by logos attribute, but if we catch them here, just ignore
                continue;
            },
            Ok(token) => {
                tokens.push(Spanned::new(token, span));
            }
            Err(_) => {
                // Logos returns Error for things it can't match?
                // Our Word regex is pretty permissive "[^...]+".
                // So mismatch is unlikely unless invalid utf8 maybe.
                return Err(LexError::UnexpectedChar { position: span.start });
            }
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
        // example.com { \n root * \n }
        // 0: Word("example.com")
        // 1: BlockOpen
        // 2: Newline
        // 3: Word("root")
        // 4: Word("*")
        // 5: Newline
        // 6: BlockClose
        
        let valid_tokens: Vec<Token> = tokens.into_iter().map(|s| s.value).collect();
        assert_eq!(valid_tokens[0], Token::Word("example.com".to_string()));
        assert_eq!(valid_tokens[1], Token::BlockOpen);
        assert_eq!(valid_tokens[2], Token::Newline);
        assert_eq!(valid_tokens[3], Token::Word("root".to_string()));
        assert_eq!(valid_tokens[4], Token::Word("*".to_string()));
        assert_eq!(valid_tokens[5], Token::Newline);
        assert_eq!(valid_tokens[6], Token::BlockClose);
    }

    #[test]
    fn test_quotes_and_comments() {
        let source = r#"
            # This is a comment
            root "/var/www/html" # Inline comment
        "#;
        let tokens = tokenize(source).unwrap();
        // Newline (initial empty line might be skipped if I strictly look at content)
        // Tokens:
        // Newline (from line 1 empty?)
        // Newline (end of comment line)
        // Word("root")
        // QuotedString("/var/www/html")
        // Newline
        
        let t: Vec<Token> = tokens.into_iter().filter(|t| !matches!(t.value, Token::Newline)).map(|s| s.value).collect();
        assert_eq!(t[0], Token::Word("root".to_string()));
        assert_eq!(t[1], Token::QuotedString("/var/www/html".to_string()));
    }
    
    #[test]
    fn test_env_var() {
        let tokens = tokenize("listen {$PORT}").unwrap();
        assert_eq!(tokens[0].value, Token::Word("listen".to_string()));
        assert_eq!(tokens[1].value, Token::EnvVar("PORT".to_string()));
    }
}
