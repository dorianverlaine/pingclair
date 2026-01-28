//! Parser module for Pingclairfile
//!
//! This module provides the lexer, AST, and parser for the Pingclairfile DSL.

pub mod ast;
pub mod caddy_ast;
pub mod lexer;
pub mod parser;
pub mod variables;
pub mod semantic;

pub use ast::*;
pub use lexer::{tokenize, Token, LexError, Spanned, Location};
pub use parser::{parse, ParseError, Parser};
pub use variables::{VariableResolver, ResolvedVariable};
pub use semantic::{SemanticAnalyzer, SemanticError};

pub use crate::adapter::caddyfile::{adapt, AdapterError};

/// Parse and analyze a Pingclairfile (Caddyfile syntax)
pub fn compile(source: &str) -> Result<ast::Ast, CompileError> {
    // 1. Parse into generic directives (Caddyfile AST)
    let directives = parse(source)?;
    
    // 2. Adapt into intermediate Typed AST
    let typed_ast = adapt(directives)?;
    
    // 3. Semantic analysis (validation, etc.)
    // Note: SemanticAnalyzer might need updates for new AST structure if changed
    // For now we use the adapted AST which is already somewhat validated
    let mut analyzer = SemanticAnalyzer::new();
    let analyzed = analyzer.analyze(typed_ast)?;
    
    Ok(analyzed)
}

/// Compile error
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),
    
    #[error("Adapt error: {0}")]
    Adapt(#[from] AdapterError),
    
    #[error("Semantic error: {0}")]
    Semantic(#[from] SemanticError),
}
