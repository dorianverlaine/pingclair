//! Pingclair Configuration Parser
//!
//! This crate provides parsing and compilation for the Pingclairfile DSL.
//!
//! # Example
//!
//! ```rust,ignore
//! use pingclair_config::compile;
//!
//! let source = r#"
//!     server "example.com" {
//!         listen: "http://127.0.0.1:8080";
//!         route {
//!             _ => {
//!                 proxy "http://localhost:3000"
//!             }
//!         }
//!     }
//! "#;
//!
//! let config = compile(source).unwrap();
//! ```

pub mod adapter;
pub mod parser;
pub mod compiler;

pub use parser::{
    parse, compile as parse_and_analyze, 
    Ast, ParseError, CompileError as AnalyzeError,
    Token, tokenize, LexError,
    VariableResolver, ResolvedVariable,
    SemanticAnalyzer, SemanticError,
};

pub use compiler::{compile_ast, CompileError};

use pingclair_core::config::PingclairConfig;
use std::path::Path;

/// Full compilation pipeline: source -> PingclairConfig
pub fn compile(source: &str) -> Result<PingclairConfig, FullCompileError> {
    // Parse and analyze
    let ast = parse_and_analyze(source)?;
    
    // Compile to config
    let config = compile_ast(&ast)?;
    
    Ok(config)
}

/// Load and compile a Pingclairfile from a path
pub fn compile_file(path: impl AsRef<Path>) -> Result<PingclairConfig, FullCompileError> {
    let path = path.as_ref();
    let source = std::fs::read_to_string(path)
        .map_err(|e| FullCompileError::Io(e.to_string()))?;
        
    if path.extension().map_or(false, |ext| ext == "json") {
        serde_json::from_str(&source)
            .map_err(|e| FullCompileError::Io(format!("JSON parse error: {}", e)))
    } else {
        compile(&source)
    }
}

/// Full compilation error
#[derive(Debug, thiserror::Error)]
pub enum FullCompileError {
    #[error("IO error: {0}")]
    Io(String),
    
    #[error("Parse/analyze error: {0}")]
    Analyze(#[from] AnalyzeError),
    
    #[error("Compile error: {0}")]
    Compile(#[from] CompileError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_compile() {
        let source = r#"
            example.com {
                listen :8080
                
                reverse_proxy localhost:3000
                
                respond 404 "Not Found"
            }
        "#;

        let config = compile(source).unwrap();
        assert_eq!(config.servers.len(), 1);
        assert_eq!(config.servers[0].name, Some("example.com".to_string()));
        // Note: reverse_proxy and respond are grouped into a single default route (Pipeline)
        assert_eq!(config.servers[0].routes.len(), 1);
    }

    #[test]
    fn test_compile_complex() {
        let source = r#"
            global {
                protocols H1 H2
                debug false
            }

            ai.408timeout.com {
                listen :20615
                bind 127.0.0.1
                compress Gzip
                
                reverse_proxy http://127.0.0.1:3210
            }
        "#;

        let config = compile(source).unwrap();
        assert_eq!(config.servers.len(), 1);
        assert_eq!(config.servers[0].routes.len(), 1);
    }
}
