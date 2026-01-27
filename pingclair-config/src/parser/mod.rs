//! Parser module for Pingclairfile
//!
//! This module provides the lexer, AST, and parser for the Pingclairfile DSL.

pub mod ast;
pub mod lexer;
pub mod parser;
pub mod variables;
pub mod semantic;

pub use ast::*;
pub use lexer::{tokenize, Token, LexError, Spanned, Location};
pub use parser::{parse, ParseError, Parser};
pub use variables::{VariableResolver, ResolvedVariable};
pub use semantic::{SemanticAnalyzer, SemanticError};

/// Parse and analyze a Pingclairfile
pub fn compile(source: &str) -> Result<ast::Ast, CompileError> {
    // Parse
    let ast = parse(source)?;
    
    // Semantic analysis (macro expansion, validation)
    let mut analyzer = SemanticAnalyzer::new();
    let analyzed = analyzer.analyze(ast)?;
    
    Ok(analyzed)
}

/// Compile error
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),
    
    #[error("Semantic error: {0}")]
    Semantic(#[from] SemanticError),
}
