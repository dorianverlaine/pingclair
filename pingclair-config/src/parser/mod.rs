// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧩 Parser module for the Pingclair configuration DSL.
//!
//! This module provides the lexer, AST, and parser.

pub mod ast;
pub mod caddy_ast;
pub mod lexer;
// 🧩 The nested name preserves the crate's existing public parser API.
#[allow(clippy::module_inception)]
pub mod parser;
pub mod semantic;
pub mod variables;

pub use ast::*;
pub use lexer::{LexError, Location, Spanned, Token, tokenize};
pub use parser::{ParseError, Parser, parse};
pub use semantic::{SemanticAnalyzer, SemanticError};
pub use variables::{ResolvedVariable, VariableResolver};

pub use crate::adapter::caddyfile::{AdapterError, adapt};

/// 🔎 Parses and analyzes Pingclair DSL source text.
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
