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

/// Load and merge multiple configuration files
pub fn compile_multiple_files(paths: &[impl AsRef<Path>]) -> Result<PingclairConfig, FullCompileError> {
    let mut final_config = pingclair_core::config::PingclairConfig::default();
    
    for path in paths {
        let config = compile_file(path.as_ref())?;
        
        // Merge configurations
        final_config.debug = final_config.debug || config.debug;
        final_config.servers.extend(config.servers);
        
        // Merge admin config (use the last one if multiple exist)
        if let Some(admin) = config.admin {
            final_config.admin = Some(admin);
        }
        
        // Merge global config
        if let Some(email) = config.global.email {
            final_config.global.email = Some(email);
        }
        if config.global.auto_https != pingclair_core::config::AutoHttpsMode::On {
            final_config.global.auto_https = config.global.auto_https;
        }
        
        // Merge logging config (use the last one if multiple exist)
        if !config.logging.level.is_empty() {
            final_config.logging = config.logging;
        }
    }
    
    Ok(final_config)
}

/// Load and merge configuration from directory (all .pingclair files)
pub fn compile_directory(dir_path: impl AsRef<Path>) -> Result<PingclairConfig, FullCompileError> {
    use std::fs;
    use std::ffi::OsStr;
    
    let dir_path = dir_path.as_ref();
    let mut config_paths = Vec::new();
    
    for entry in fs::read_dir(dir_path)
        .map_err(|e| FullCompileError::Io(e.to_string()))?
    {
        let entry = entry.map_err(|e| FullCompileError::Io(e.to_string()))?;
        let path = entry.path();
        
        if path.extension() == Some(OsStr::new("pingclair")) || 
           path.extension() == Some(OsStr::new("json")) ||
           path.file_stem() == Some(OsStr::new("Pingclairfile"))
        {
            config_paths.push(path);
        }
    }
    
    // Sort paths to ensure consistent loading order
    config_paths.sort();
    
    compile_multiple_files(&config_paths)
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
    use pingclair_core::config::HandlerConfig;

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
    fn test_named_site_address_compiles_to_wildcard_listen() {
        // `bench.local:8080` must compile to a wildcard bind + hostname-based
        // vhost, not a literal `bench.local:8080` bind (which crashed startup
        // unless the name resolved to a local interface).
        let source = r#"
            bench.local:8080 {
                respond "OK"
            }
        "#;

        let config = compile(source).unwrap();
        assert_eq!(config.servers.len(), 1);
        assert_eq!(config.servers[0].name, Some("bench.local".to_string()));
        assert_eq!(config.servers[0].listen, vec!["0.0.0.0:8080".to_string()]);
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

    #[test]
    fn test_compile_tls_cert_key() {
        let source = r#"
            example.com {
                listen :443
                tls /etc/ssl/cert.pem /etc/ssl/key.pem
                respond "OK"
            }
        "#;

        let config = compile(source).unwrap();
        let tls = config.servers[0].tls.as_ref().expect("tls config");
        assert_eq!(tls.cert.as_deref(), Some("/etc/ssl/cert.pem"));
        assert_eq!(tls.key.as_deref(), Some("/etc/ssl/key.pem"));
        assert!(!tls.auto);
    }

    #[test]
    fn test_compile_tls_auto() {
        let source = r#"
            example.com {
                listen :443
                tls auto
                respond "OK"
            }
        "#;

        let config = compile(source).unwrap();
        let tls = config.servers[0].tls.as_ref().expect("tls config");
        assert!(tls.auto);
    }

    #[test]
    fn test_compile_tls_block_form() {
        let source = r#"
            example.com {
                listen :443
                tls {
                    cert /etc/ssl/cert.pem
                    key /etc/ssl/key.pem
                    acme_email admin@example.com
                    http3
                }
                respond "OK"
            }
        "#;

        let config = compile(source).unwrap();
        let tls = config.servers[0].tls.as_ref().expect("tls config");
        assert_eq!(tls.cert.as_deref(), Some("/etc/ssl/cert.pem"));
        assert_eq!(tls.key.as_deref(), Some("/etc/ssl/key.pem"));
        assert_eq!(tls.acme_email.as_deref(), Some("admin@example.com"));
        assert!(tls.http3);
    }

    #[test]
    fn test_compile_tls_merges_with_https_scheme_default() {
        // An https:// site address already yields a default TlsConfig; the
        // `tls` directive must merge into it, not be overwritten by it.
        let source = r#"
            https://example.com {
                tls /etc/ssl/cert.pem /etc/ssl/key.pem
                respond "OK"
            }
        "#;

        let config = compile(source).unwrap();
        let tls = config.servers[0].tls.as_ref().expect("tls config");
        assert_eq!(tls.cert.as_deref(), Some("/etc/ssl/cert.pem"));
        assert_eq!(tls.key.as_deref(), Some("/etc/ssl/key.pem"));
    }

    #[test]
    fn test_compile_tls_off_disables_https_scheme_default() {
        let source = r#"
            https://example.com {
                tls off
                respond "OK"
            }
        "#;

        let config = compile(source).unwrap();
        assert!(config.servers[0].tls.is_none(), "tls off must clear the https-scheme default");
    }

    #[test]
    fn test_compile_admin_listen() {
        let source = r#"{
            admin 127.0.0.1:2019
        }

        example.com {
            listen :80
            respond "OK"
        }"#;

        let config = compile(source).unwrap();
        let admin = config.admin.as_ref().expect("admin config");
        assert_eq!(admin.listen, "127.0.0.1:2019");
        assert!(admin.enabled);
        assert!(admin.api_key.is_none());
    }

    #[test]
    fn test_compile_admin_off() {
        let source = r#"{
            admin off
        }

        example.com {
            listen :80
            respond "OK"
        }"#;

        let config = compile(source).unwrap();
        let admin = config.admin.as_ref().expect("admin config");
        assert!(!admin.enabled);
    }

    #[test]
    fn test_compile_admin_with_api_key() {
        let source = r#"{
            admin 127.0.0.1:2019 s3cret-token
        }

        example.com {
            listen :80
            respond "OK"
        }"#;

        let config = compile(source).unwrap();
        let admin = config.admin.as_ref().expect("admin config");
        assert_eq!(admin.listen, "127.0.0.1:2019");
        assert!(admin.enabled);
        assert_eq!(admin.api_key.as_deref(), Some("s3cret-token"));
    }

    #[test]
    fn test_compile_basic_auth_inline() {
        let source = r#"
            example.com {
                listen :80
                basic_auth alice secret1 bob secret2
                respond "OK"
            }
        "#;

        let config = compile(source).unwrap();
        let route = &config.servers[0].routes[0];
        let HandlerConfig::Pipeline { handlers } = &route.handler else {
            panic!("expected pipeline, got {:?}", route.handler);
        };
        let auth = handlers.iter().find_map(|h| match h {
            HandlerConfig::BasicAuth { realm, credentials } => Some((realm, credentials)),
            _ => None,
        }).expect("basic_auth handler");
        assert_eq!(auth.0, "Restricted");
        assert_eq!(auth.1.len(), 2);
        assert_eq!(auth.1[0].username, "alice");
        assert_eq!(auth.1[0].password, "secret1");
        assert!(!auth.1[0].hashed);
        assert_eq!(auth.1[1].username, "bob");
    }

    #[test]
    fn test_compile_basic_auth_block_with_realm() {
        let source = r#"
            example.com {
                listen :80
                basic_auth {
                    realm "Admin Area"
                    admin hunter2
                }
                respond "OK"
            }
        "#;

        let config = compile(source).unwrap();
        let route = &config.servers[0].routes[0];
        let HandlerConfig::Pipeline { handlers } = &route.handler else {
            panic!("expected pipeline, got {:?}", route.handler);
        };
        let auth = handlers.iter().find_map(|h| match h {
            HandlerConfig::BasicAuth { realm, credentials } => Some((realm, credentials)),
            _ => None,
        }).expect("basic_auth handler");
        assert_eq!(auth.0, "Admin Area");
        assert_eq!(auth.1.len(), 1);
        assert_eq!(auth.1[0].username, "admin");
        assert_eq!(auth.1[0].password, "hunter2");
    }

    #[test]
    fn test_compile_basic_auth_rejects_odd_args() {
        let source = r#"
            example.com {
                listen :80
                basic_auth alice
                respond "OK"
            }
        "#;

        assert!(compile(source).is_err());
    }
}
