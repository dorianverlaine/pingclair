//! Lexer for Pingclairfile
//!
//! Tokenizes the Pingclairfile DSL using logos for high-performance lexing.

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

/// Token types for Pingclairfile
#[derive(Logos, Debug, Clone, PartialEq)]
#[logos(skip r"[ \t\r\n\f]+")]  // Skip whitespace
pub enum Token {
    // Comments are handled as part of whitespace skip
    // Line comments: //...
    // Block comments: /*...*/ (not supported for simplicity)
    
    // ============================================================
    // Keywords
    // ============================================================
    #[token("global")]
    Global,

    #[token("server")]
    Server,

    #[token("route")]
    Route,

    #[token("match")]
    Match,

    #[token("macro")]
    Macro,

    #[token("use")]
    Use,

    #[token("proxy")]
    Proxy,

    #[token("headers")]
    Headers,

    #[token("header_up")]
    HeaderUp,

    #[token("log")]
    Log,

    #[token("compress")]
    Compress,

    #[token("bind")]
    Bind,

    #[token("listen")]
    Listen,

    #[token("transport")]
    Transport,

    #[token("respond")]
    Respond,

    #[token("redirect")]
    Redirect,

    #[token("output")]
    Output,

    #[token("format")]
    Format,

    #[token("filter")]
    Filter,

    #[token("exclude")]
    Exclude,

    #[token("set")]
    Set,

    #[token("remove")]
    Remove,

    #[token("add")]
    Add,

    #[token("body")]
    Body,

    #[token("path")]
    Path,

    #[token("header")]
    Header,

    #[token("method")]
    Method,

    #[token("query")]
    Query,

    #[token("handle")]
    Handle,

    #[token("host")]
    Host,

    #[token("remote_ip")]
    RemoteIp,

    #[token("protocol")]
    Protocol,

    #[token("plugin")]
    Plugin,

    #[token("file_server")]
    FileServer,

    #[token("protocols")]
    Protocols,

    #[token("debug")]
    Debug,

    #[token("logging")]
    Logging,

    #[token("level")]
    Level,

    #[token("flush_interval")]
    FlushInterval,

    #[token("read_timeout")]
    ReadTimeout,

    #[token("write_timeout")]
    WriteTimeout,

    // ============================================================
    // Type Keywords / Constants
    // ============================================================
    #[token("H1")]
    H1,

    #[token("H2")]
    H2,

    #[token("H3")]
    H3,

    #[token("Http")]
    Http,

    #[token("Https")]
    Https,

    #[token("Gzip")]
    Gzip,

    #[token("Br")]
    Br,

    #[token("Zstd")]
    Zstd,

    #[token("Immediate")]
    Immediate,

    #[token("Json")]
    Json,

    #[token("Text")]
    Text,

    #[token("File")]
    File,

    #[token("Stdout")]
    Stdout,

    #[token("Stderr")]
    Stderr,

    #[token("Info")]
    Info,

    #[token("Warn")]
    Warn,

    #[token("Error")]
    Error,

    #[token("Trace")]
    Trace,

    #[token("true")]
    True,

    #[token("false")]
    False,

    #[token("exists")]
    Exists,

    #[token("not")]
    Not,

    #[token("contains")]
    Contains,

    #[token("starts_with")]
    StartsWith,

    #[token("ends_with")]
    EndsWith,

    #[token("regex")]
    Regex,

    // ============================================================
    // Operators
    // ============================================================
    #[token("=>")]
    Arrow,

    #[token("|>")]
    Pipe,

    #[token("::")]
    DoubleColon,

    #[token("|")]
    Or,

    #[token("!")]
    Bang,

    #[token("&&")]
    And,

    #[token("||")]
    OrOr,

    #[token("==")]
    Eq,

    #[token("!=")]
    Ne,

    #[token("=")]
    Assign,

    #[token("*")]
    Star,

    #[token("?")]
    Question,

    // ============================================================
    // Delimiters
    // ============================================================
    #[token("{")]
    BraceOpen,

    #[token("}")]
    BraceClose,

    #[token("[")]
    BracketOpen,

    #[token("]")]
    BracketClose,

    #[token("(")]
    ParenOpen,

    #[token(")")]
    ParenClose,

    #[token(";")]
    Semicolon,

    #[token(":")]
    Colon,

    #[token(",")]
    Comma,

    #[token(".")]
    Dot,

    #[token("_", priority = 5)]
    Underscore,

    // ============================================================
    // Literals
    // ============================================================
    
    /// String literal: "..."
    #[regex(r#""([^"\\]|\\.)*""#, |lex| {
        let s = lex.slice();
        // Remove quotes and unescape
        unescape_string(&s[1..s.len()-1])
    })]
    String(String),

    /// Integer literal
    #[regex(r"-?[0-9]+", |lex| lex.slice().parse::<i64>().ok())]
    Integer(i64),

    /// Duration literal: 10s, 5m, 1h, 2d, 100ms
    #[regex(r"[0-9]+(?:ms|s|m|h|d)", |lex| parse_duration(lex.slice()))]
    Duration(u64),  // Always stored as milliseconds

    /// Identifier: starts with letter or underscore
    #[regex(r"[a-zA-Z_][a-zA-Z0-9_]*", |lex| lex.slice().to_string())]
    Identifier(String),

    /// Variable: ${...}
    #[regex(r"\$\{[^}]+\}", |lex| {
        let s = lex.slice();
        s[2..s.len()-1].to_string()  // Remove ${ and }
    })]
    Variable(String),

    /// URL literal: http://... or https://...
    #[regex(r"https?://[a-zA-Z0-9.:/_\-@]+", |lex| lex.slice().to_string())]
    Url(String),

    /// Path pattern: /path/to/something or /api/* (with string quotes)
    PathPattern(String),

    /// IP address with optional port
    #[regex(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?", |lex| lex.slice().to_string())]
    IpAddr(String),
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Token::Global => write!(f, "global"),
            Token::Server => write!(f, "server"),
            Token::Route => write!(f, "route"),
            Token::Match => write!(f, "match"),
            Token::Macro => write!(f, "macro"),
            Token::Use => write!(f, "use"),
            Token::Proxy => write!(f, "proxy"),
            Token::Headers => write!(f, "headers"),
            Token::HeaderUp => write!(f, "header_up"),
            Token::Log => write!(f, "log"),
            Token::Compress => write!(f, "compress"),
            Token::Bind => write!(f, "bind"),
            Token::Listen => write!(f, "listen"),
            Token::Transport => write!(f, "transport"),
            Token::Respond => write!(f, "respond"),
            Token::Redirect => write!(f, "redirect"),
            Token::Arrow => write!(f, "=>"),
            Token::Pipe => write!(f, "|>"),
            Token::BraceOpen => write!(f, "{{"),
            Token::BraceClose => write!(f, "}}"),
            Token::String(s) => write!(f, "\"{}\"", s),
            Token::Integer(n) => write!(f, "{}", n),
            Token::Duration(ms) => write!(f, "{}ms", ms),
            Token::Identifier(s) => write!(f, "{}", s),
            Token::Variable(s) => write!(f, "${{{}}}", s),
            Token::Url(s) => write!(f, "{}", s),
            Token::PathPattern(s) => write!(f, "{}", s),
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

/// Parse a duration string into milliseconds
fn parse_duration(s: &str) -> u64 {
    if s.ends_with("ms") {
        s[..s.len()-2].parse().unwrap_or(0)
    } else if s.ends_with("s") {
        s[..s.len()-1].parse::<u64>().unwrap_or(0) * 1000
    } else if s.ends_with("m") {
        s[..s.len()-1].parse::<u64>().unwrap_or(0) * 60 * 1000
    } else if s.ends_with("h") {
        s[..s.len()-1].parse::<u64>().unwrap_or(0) * 60 * 60 * 1000
    } else if s.ends_with("d") {
        s[..s.len()-1].parse::<u64>().unwrap_or(0) * 24 * 60 * 60 * 1000
    } else {
        0
    }
}

/// Lexer result type
pub type LexResult = Result<Vec<Spanned<Token>>, LexError>;

/// Lexer error
#[derive(Debug, Clone, thiserror::Error)]
pub enum LexError {
    #[error("Unexpected character at position {position}")]
    UnexpectedChar { position: usize },
    
    #[error("Unterminated string at position {position}")]
    UnterminatedString { position: usize },
}

/// Tokenize a Pingclairfile source string
pub fn tokenize(source: &str) -> LexResult {
    let lexer = Token::lexer(source);
    let mut tokens = Vec::new();
    
    for (result, span) in lexer.spanned() {
        match result {
            Ok(token) => {
                tokens.push(Spanned::new(token, span));
            }
            Err(_) => {
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
    fn test_keywords() {
        let tokens = tokenize("global server route match macro use").unwrap();
        assert_eq!(tokens.len(), 6);
        assert_eq!(tokens[0].value, Token::Global);
        assert_eq!(tokens[1].value, Token::Server);
        assert_eq!(tokens[2].value, Token::Route);
        assert_eq!(tokens[3].value, Token::Match);
        assert_eq!(tokens[4].value, Token::Macro);
        assert_eq!(tokens[5].value, Token::Use);
    }

    #[test]
    fn test_operators() {
        let tokens = tokenize("=> |> :: | ! && ||").unwrap();
        assert_eq!(tokens[0].value, Token::Arrow);
        assert_eq!(tokens[1].value, Token::Pipe);
        assert_eq!(tokens[2].value, Token::DoubleColon);
        assert_eq!(tokens[3].value, Token::Or);
        assert_eq!(tokens[4].value, Token::Bang);
        assert_eq!(tokens[5].value, Token::And);
        assert_eq!(tokens[6].value, Token::OrOr);
    }

    #[test]
    fn test_string_literal() {
        let tokens = tokenize(r#""hello world""#).unwrap();
        assert_eq!(tokens[0].value, Token::String("hello world".to_string()));
    }

    #[test]
    fn test_string_escape() {
        let tokens = tokenize(r#""hello\nworld""#).unwrap();
        assert_eq!(tokens[0].value, Token::String("hello\nworld".to_string()));
    }

    #[test]
    fn test_duration() {
        let tokens = tokenize("10s 5m 1h 2d 100ms").unwrap();
        assert_eq!(tokens[0].value, Token::Duration(10000));      // 10s = 10000ms
        assert_eq!(tokens[1].value, Token::Duration(300000));     // 5m = 300000ms
        assert_eq!(tokens[2].value, Token::Duration(3600000));    // 1h
        assert_eq!(tokens[3].value, Token::Duration(172800000));  // 2d
        assert_eq!(tokens[4].value, Token::Duration(100));        // 100ms
    }

    #[test]
    fn test_variable() {
        let tokens = tokenize(r#"${req.header["CF-Connecting-IP"]}"#).unwrap();
        assert_eq!(tokens[0].value, Token::Variable(r#"req.header["CF-Connecting-IP"]"#.to_string()));
    }

    #[test]
    fn test_url() {
        let tokens = tokenize("http://127.0.0.1:3210 https://example.com").unwrap();
        assert_eq!(tokens[0].value, Token::Url("http://127.0.0.1:3210".to_string()));
        assert_eq!(tokens[1].value, Token::Url("https://example.com".to_string()));
    }

    #[test]
    fn test_path_in_string() {
        // Paths are now represented as strings in Pingclairfile
        let tokens = tokenize(r#""/api/*" "/assets/image.png""#).unwrap();
        assert_eq!(tokens[0].value, Token::String("/api/*".to_string()));
        assert_eq!(tokens[1].value, Token::String("/assets/image.png".to_string()));
    }

    #[test]
    fn test_ip_address() {
        let tokens = tokenize("127.0.0.1 192.168.1.1:8080").unwrap();
        assert_eq!(tokens[0].value, Token::IpAddr("127.0.0.1".to_string()));
        assert_eq!(tokens[1].value, Token::IpAddr("192.168.1.1:8080".to_string()));
    }

    #[test]
    fn test_type_keywords() {
        let tokens = tokenize("H1 H2 H3 Gzip Br Zstd Json Immediate").unwrap();
        assert_eq!(tokens[0].value, Token::H1);
        assert_eq!(tokens[1].value, Token::H2);
        assert_eq!(tokens[2].value, Token::H3);
        assert_eq!(tokens[3].value, Token::Gzip);
        assert_eq!(tokens[4].value, Token::Br);
        assert_eq!(tokens[5].value, Token::Zstd);
        assert_eq!(tokens[6].value, Token::Json);
        assert_eq!(tokens[7].value, Token::Immediate);
    }

    #[test]
    fn test_source_without_comments() {
        // Comments were removed from lexer for simplicity
        // Real parsing should preprocess to remove comments
        let tokens = tokenize(r#"
            global { }
        "#).unwrap();
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0].value, Token::Global);
        assert_eq!(tokens[1].value, Token::BraceOpen);
        assert_eq!(tokens[2].value, Token::BraceClose);
    }

    #[test]
    fn test_macro_syntax() {
        let tokens = tokenize("macro security_headers!() { }").unwrap();
        assert_eq!(tokens[0].value, Token::Macro);
        assert_eq!(tokens[1].value, Token::Identifier("security_headers".to_string()));
        assert_eq!(tokens[2].value, Token::Bang);
        assert_eq!(tokens[3].value, Token::ParenOpen);
        assert_eq!(tokens[4].value, Token::ParenClose);
    }

    #[test]
    fn test_match_syntax() {
        let tokens = tokenize(r#"match path("/api/*") => { }"#).unwrap();
        assert_eq!(tokens[0].value, Token::Match);
        assert_eq!(tokens[1].value, Token::Path);
        assert_eq!(tokens[2].value, Token::ParenOpen);
        assert_eq!(tokens[3].value, Token::String("/api/*".to_string()));
        assert_eq!(tokens[4].value, Token::ParenClose);
        assert_eq!(tokens[5].value, Token::Arrow);
    }

    #[test]
    fn test_full_server_block() {
        let source = r#"
            server "example.com" {
                listen: "http://127.0.0.1:8080";
                bind: "127.0.0.1";
                compress: [Gzip, Br];
            }
        "#;
        let tokens = tokenize(source).unwrap();
        assert!(tokens.len() > 10);
        assert_eq!(tokens[0].value, Token::Server);
        assert_eq!(tokens[1].value, Token::String("example.com".to_string()));
    }
}
