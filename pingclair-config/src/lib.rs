//! 🧩 Pingclair configuration parser.
//!
//! This crate parses and compiles the Pingclair configuration DSL.
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
pub mod compiler;
pub mod parser;

pub use parser::{
    Ast, CompileError as AnalyzeError, LexError, ParseError, ResolvedVariable, SemanticAnalyzer,
    SemanticError, Token, VariableResolver, compile as parse_and_analyze, parse, tokenize,
};

pub use compiler::{CompileError, compile_ast};

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

/// 📄 Loads and compiles a supported configuration file from a path.
pub fn compile_file(path: impl AsRef<Path>) -> Result<PingclairConfig, FullCompileError> {
    let path = path.as_ref();
    let source = std::fs::read_to_string(path).map_err(|e| FullCompileError::Io(e.to_string()))?;

    if path.extension().map_or(false, |ext| ext == "json") {
        serde_json::from_str(&source)
            .map_err(|e| FullCompileError::Io(format!("JSON parse error: {}", e)))
    } else {
        compile(&source)
    }
}

/// Load and merge multiple configuration files
pub fn compile_multiple_files(
    paths: &[impl AsRef<Path>],
) -> Result<PingclairConfig, FullCompileError> {
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
    use std::ffi::OsStr;
    use std::fs;

    let dir_path = dir_path.as_ref();
    let mut config_paths = Vec::new();

    for entry in fs::read_dir(dir_path).map_err(|e| FullCompileError::Io(e.to_string()))? {
        let entry = entry.map_err(|e| FullCompileError::Io(e.to_string()))?;
        let path = entry.path();

        if path.extension() == Some(OsStr::new("pingclair"))
            || path.extension() == Some(OsStr::new("json"))
            || path.file_stem() == Some(OsStr::new("Pingclairfile"))
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
        assert!(
            config.servers[0].tls.is_none(),
            "tls off must clear the https-scheme default"
        );
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
        let auth = handlers
            .iter()
            .find_map(|h| match h {
                HandlerConfig::BasicAuth { realm, credentials } => Some((realm, credentials)),
                _ => None,
            })
            .expect("basic_auth handler");
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
        let auth = handlers
            .iter()
            .find_map(|h| match h {
                HandlerConfig::BasicAuth { realm, credentials } => Some((realm, credentials)),
                _ => None,
            })
            .expect("basic_auth handler");
        assert_eq!(auth.0, "Admin Area");
        assert_eq!(auth.1.len(), 1);
        assert_eq!(auth.1[0].username, "admin");
        assert_eq!(auth.1[0].password, "hunter2");
    }

    #[test]
    fn test_compile_basic_auth_detects_bcrypt_hash() {
        let source = r#"
            example.com {
                listen :80
                basic_auth alice "$2y$04$BjuNmKvAV.mEi7.yFrazX.S6w6OO7H0BzQfyVVFZBq/qbVXCVNX4W"
                respond "OK"
            }
        "#;

        let config = compile(source).unwrap();
        let HandlerConfig::Pipeline { handlers } = &config.servers[0].routes[0].handler else {
            panic!("expected pipeline");
        };
        let credentials = handlers
            .iter()
            .find_map(|handler| match handler {
                HandlerConfig::BasicAuth { credentials, .. } => Some(credentials),
                _ => None,
            })
            .expect("basic_auth handler");
        assert!(credentials[0].hashed);
    }

    #[test]
    fn test_compile_basic_auth_rejects_invalid_bcrypt_hash() {
        let source = r#"
            example.com {
                listen :80
                basic_auth alice "$2b$04$not-a-valid-hash"
                respond "OK"
            }
        "#;

        assert!(compile(source).is_err());
    }

    #[test]
    fn test_compile_basic_auth_rejects_excessive_bcrypt_cost() {
        let source = r#"
            example.com {
                listen :80
                basic_auth alice "$2y$15$BjuNmKvAV.mEi7.yFrazX.S6w6OO7H0BzQfyVVFZBq/qbVXCVNX4W"
                respond "OK"
            }
        "#;

        assert!(compile(source).is_err());
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

    #[test]
    fn test_compile_error_page() {
        let source = r#"
            example.com {
                listen :80
                error_page 404 /var/www/404.html
                error_page 500 502 503 504 /var/www/50x.html
                respond "OK"
            }
        "#;

        let config = compile(source).unwrap();
        let pages = &config.servers[0].error_pages;
        assert_eq!(
            pages.get(&404).map(|s| s.as_str()),
            Some("/var/www/404.html")
        );
        assert_eq!(
            pages.get(&500).map(|s| s.as_str()),
            Some("/var/www/50x.html")
        );
        assert_eq!(
            pages.get(&502).map(|s| s.as_str()),
            Some("/var/www/50x.html")
        );
        assert_eq!(
            pages.get(&504).map(|s| s.as_str()),
            Some("/var/www/50x.html")
        );
        assert!(pages.get(&403).is_none());
    }

    #[test]
    fn test_compile_error_page_rejects_bad_input() {
        // Single argument (no page path)
        assert!(
            compile("example.com {\n listen :80\n error_page 404\n respond \"OK\"\n}").is_err()
        );
        // Non-error status code
        assert!(
            compile("example.com {\n listen :80\n error_page 200 /ok.html\n respond \"OK\"\n}")
                .is_err()
        );
        // Non-numeric code
        assert!(
            compile("example.com {\n listen :80\n error_page abc /x.html\n respond \"OK\"\n}")
                .is_err()
        );
    }

    #[test]
    fn test_compile_caddy_parity_directives() {
        let source = r#"
            example.com {
                listen :80
                handle /api/* {
                    cors https://app.example.com {
                        methods GET POST
                        headers Content-Type Authorization
                        expose_headers X-Request-Id
                        allow_credentials
                        max_age 600
                    }
                    access_control {
                        allow_ip 10.0.0.0/8 2001:db8::/32
                        deny_ip 10.1.2.3
                        allow_referer app.example.com *.trusted.example
                        deny_referer evil.example
                        allow_user_agent "^PingclairClient/"
                        deny_user_agent "(?i)bot"
                    }
                    rewrite "^/api/(.*)$" "/v1/$1"
                    reverse_proxy {
                        lb_policy least_conn
                        to 127.0.0.1:3000 { weight 3 }
                        to 127.0.0.1:3001 { backup }
                    }
                }
            }
        "#;

        let config = compile(source).unwrap();
        let HandlerConfig::Pipeline { handlers } = &config.servers[0].routes[0].handler else {
            panic!("expected handler pipeline");
        };
        assert!(handlers.iter().any(|handler| matches!(handler, HandlerConfig::Cors {
            allowed_origins,
            allowed_methods,
            allow_credentials: true,
            max_age: 600,
            ..
        } if allowed_origins == &["https://app.example.com"] && allowed_methods == &["GET", "POST"])));
        assert!(handlers.iter().any(
            |handler| matches!(handler, HandlerConfig::AccessControl(access)
            if access.allowed_ips.len() == 2 && access.denied_user_agents == ["(?i)bot"])
        ));
        assert!(
            handlers
                .iter()
                .any(|handler| matches!(handler, HandlerConfig::Rewrite {
            regex: Some(pattern), regex_replace: Some(replacement), ..
        } if pattern == "^/api/(.*)$" && replacement == "/v1/$1"))
        );
        let proxy = handlers
            .iter()
            .find_map(|handler| match handler {
                HandlerConfig::ReverseProxy(proxy) => Some(proxy),
                _ => None,
            })
            .expect("reverse proxy handler");
        assert_eq!(proxy.load_balance.strategy, "least_conn");
        assert_eq!(proxy.upstream_options.len(), 2);
        assert_eq!(proxy.upstream_options[0].weight, 3);
        assert!(proxy.upstream_options[1].backup);
    }

    #[test]
    fn test_compile_redirect_directive() {
        let config = compile(
            r#"
            example.com {
                redir /new-home
            }
        "#,
        )
        .unwrap();

        assert!(matches!(
            &config.servers[0].routes[0].handler,
            HandlerConfig::Redirect { to, code }
                if to == "/new-home" && *code == 302
        ));
    }

    #[test]
    fn test_compile_redirect_codes_and_named_matcher() {
        let config = compile(
            r#"
            example.com {
                @legacy path /old/*
                redir @legacy https://example.com/new permanent
                redirect /temporary 307
            }
        "#,
        )
        .unwrap();

        let routes = &config.servers[0].routes;
        assert!(matches!(
            &routes[0].handler,
            HandlerConfig::Redirect { to, code }
                if to == "https://example.com/new" && *code == 301
        ));
        assert!(routes[0].matcher.is_some());
        assert!(matches!(
            &routes[1].handler,
            HandlerConfig::Redirect { to, code }
                if to == "/temporary" && *code == 307
        ));
    }

    #[test]
    fn test_reject_invalid_redirect_directive() {
        assert!(compile("example.com { redir }").is_err());
        assert!(compile("example.com { redir /target 200 }").is_err());
        assert!(compile("example.com { redir /target forever }").is_err());
        assert!(compile("example.com { redir /target { respond 200 } }").is_err());
    }
}
