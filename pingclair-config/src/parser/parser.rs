//! Recursive Descent Parser for Caddyfile syntax
//!
//! Consumes tokens and produces a Generic Directive AST.

use crate::parser::caddy_ast::{Directive, Block};
use crate::parser::lexer::{LexError, Location, Spanned, Token, tokenize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Lexer error: {0}")]
    Lex(#[from] LexError),

    #[error("Unexpected token {token} at {location:?}, expected {expected}")]
    UnexpectedToken {
        token: String,
        location: Location,
        expected: String,
    },

    #[error("Unexpected end of file, expected {expected}")]
    UnexpectedEof {
        expected: String,
    },
    
    #[error("Nesting too deep")]
    RecursionLimitExceeded,
}

pub struct Parser<'a> {
    tokens: &'a [Spanned<Token>],
    position: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    pub fn new(tokens: &'a [Spanned<Token>]) -> Self {
        Self {
            tokens,
            position: 0,
            depth: 0,
        }
    }

    /// Peek current token
    fn peek(&self) -> Option<&Spanned<Token>> {
        self.tokens.get(self.position)
    }
    
    fn is_eof(&self) -> bool {
        self.position >= self.tokens.len()
    }

    /// Consume current token if matches expectation
    fn consume(&mut self) -> Option<&Spanned<Token>> {
        if self.position < self.tokens.len() {
            let t = &self.tokens[self.position];
            self.position += 1;
            Some(t)
        } else {
            None
        }
    }

    /// Parse the entire config
    pub fn parse_config(&mut self) -> Result<Vec<Directive>, ParseError> {
        let mut directives = Vec::new();
        
        while !self.is_eof() {
            // Skip top-level newlines
            if let Some(token) = self.peek() {
                if matches!(token.value, Token::Newline) {
                    self.consume();
                    continue;
                }
            } else {
                break; 
            }
            
            directives.push(self.parse_directive()?);
        }
        
        Ok(directives)
    }

    /// Parse a single directive: Name [Args...] [Block]
    fn parse_directive(&mut self) -> Result<Directive, ParseError> {
        // 1. Check for global block start {
        if let Some(token) = self.peek() {
            if matches!(token.value, Token::BlockOpen) {
                return Ok(Directive {
                    name: "".to_string(),
                    args: Vec::new(),
                    block: Some(self.parse_block()?),
                });
            }
        }

        // 2. Normal directive name
        let name_token = self.consume().ok_or(ParseError::UnexpectedEof { expected: "directive name".to_string() })?;
        
        let name = match &name_token.value {
            Token::Word(s) | Token::QuotedString(s) | Token::EnvVar(s) => s.clone(),
            other => return Err(ParseError::UnexpectedToken { 
                token: format!("{}", other), 
                location: name_token.span, 
                expected: "directive name or global block".into() 
            }),
        };

        let mut args = Vec::new();
        let mut block = None;

        // 2. Loop args
        loop {
            let token = match self.peek() {
                Some(t) => t,
                None => break, // EOF ends directive
            };

            match &token.value {
                Token::Newline => {
                    self.consume();
                    break; // End of directive
                },
                Token::BlockOpen => {
                    // Start of block
                    block = Some(self.parse_block()?);
                    // After block, optional newline?
                    // Caddyfile directives end after the block close } usually?
                    // Or explicit newline.
                    // Usually: directive { ... } \n directive2
                    // block consumes closing }. Peek next.
                    // If next is Newline, consume it.
                    if let Some(next) = self.peek() {
                        if matches!(next.value, Token::Newline) {
                            self.consume();
                        }
                    }
                    break;
                },
                Token::BlockClose => {
                    // Should be handled by parse_block calling us. 
                    // If we see it here, it means this directive ends (and enclosing block closes).
                    // We DO NOT consume it. Let parent handle.
                    break;
                },
                Token::Word(s) => {
                    args.push(s.clone());
                    self.consume();
                },
                Token::QuotedString(s) => {
                    args.push(s.clone());
                    self.consume();
                },
                Token::EnvVar(s) => {
                    // treat env var as arg, Adapter will expand or assume it's expanded
                    // Actually, let's keep ${VAR} syntax?
                    // Or expand now?
                    // Let's keep ${VAR} syntax for now.
                    args.push(format!("${{{}}}", s)); 
                    self.consume();
                },
                _ => {
                    // Unexpected (e.g. Comment should keep going? Wait comment is skipped by Lexer)
                    // If we encounter other tokens?
                    // Current lexer only has these variants.
                    // Whitespace/Comment skipped.
                    // So unlikely to hit _ unless I missed something.
                    return Err(ParseError::UnexpectedToken {
                        token: format!("{}", token.value),
                        location: token.span,
                        expected: "argument, newline, or block".into()
                    });
                }
            }
        }

        Ok(Directive {
            name,
            args,
            block,
        })
    }
    
    /// Parse a block: { directives... }
    fn parse_block(&mut self) -> Result<Block, ParseError> {
        if self.depth > 100 {
            return Err(ParseError::RecursionLimitExceeded);
        }
        self.depth += 1;

        // Consume {
        let open_token = self.consume().ok_or(ParseError::UnexpectedEof { expected: "{".to_string() })?;
        if !matches!(open_token.value, Token::BlockOpen) {
             return Err(ParseError::UnexpectedToken { 
                token: format!("{}", open_token.value), 
                location: open_token.span, 
                expected: "{".into() 
            });
        }
        
        // Skip potential newline after {
        if let Some(t) = self.peek() {
            if matches!(t.value, Token::Newline) {
                self.consume();
            }
        }

        let mut directives = Vec::new();

        loop {
            let token = match self.peek() {
                Some(t) => t,
                None => return Err(ParseError::UnexpectedEof { expected: "}".to_string() }), // Missing }
            };
            
            match token.value {
                Token::BlockClose => {
                    self.consume(); // Consume }
                    break;
                },
                Token::Newline => {
                    self.consume(); // Skip empty lines
                    continue;
                },
                _ => {
                    directives.push(self.parse_directive()?);
                }
            }
        }
        
        self.depth -= 1;
        Ok(Block { directives })
    }
}

pub fn parse(source: &str) -> Result<Vec<Directive>, ParseError> {
    let tokens = tokenize(source)?;
    let mut parser = Parser::new(&tokens);
    parser.parse_config()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_directive() {
        let source = "debug\nroot /var/www";
        let directives = parse(source).unwrap();
        assert_eq!(directives.len(), 2);
        assert_eq!(directives[0].name, "debug");
        assert_eq!(directives[1].name, "root");
        assert_eq!(directives[1].args[0], "/var/www");
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
