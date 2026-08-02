// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

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
    // 🧩 Parse and analyze the human-readable configuration.
    let ast = parse_and_analyze(source)?;

    // 🏗️ Compile the typed tree and enforce cross-field invariants.
    let config = compile_ast(&ast)?;
    compiler::validate_config(&config)?;

    Ok(config)
}

/// 📄 Loads and compiles a supported configuration file from a path.
pub fn compile_file(path: impl AsRef<Path>) -> Result<PingclairConfig, FullCompileError> {
    let path = path.as_ref();
    let source = std::fs::read_to_string(path).map_err(|e| FullCompileError::Io(e.to_string()))?;

    if path.extension().is_some_and(|ext| ext == "json") {
        let config = serde_json::from_str(&source)
            .map_err(|e| FullCompileError::Io(format!("JSON parse error: {e}")))?;
        compiler::validate_config(&config)?;
        Ok(config)
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
    use pingclair_core::config::{HandlerConfig, LogFormat, LogOutput, Matcher};

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
        assert_eq!(config.servers[0].listen, vec!["[::]:8080".to_string()]);
    }

    #[test]
    fn test_compile_complex() {
        let source = r#"
            global {
                protocols H1 H2
                debug
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
    fn resource_limits_and_upstream_timeout_phases_compile() {
        let source = r#"
            :8080 {
                limits {
                    header_timeout 2s
                    body_timeout 3s
                    idle_timeout 4s
                    request_timeout 5s
                    max_headers 40
                    max_header_bytes 8192
                    max_connections 64
                    upload_bytes_per_sec 1000
                    download_bytes_per_sec 2000
                    long_connections {
                        idle_timeout 10m
                        request_timeout off
                    }
                }
                reverse_proxy 127.0.0.1:9000 {
                    retry {
                        max_attempts 4
                        total_timeout 2s
                        backoff 50ms
                        status_codes 429 502 503 504
                        methods GET HEAD PUT
                    }
                    overload {
                        max_in_flight 32
                        max_pending 8
                        pending_timeout 75ms
                        upstream_max_connections 16
                    }
                    circuit_breaker {
                        consecutive_failures 3
                        error_rate_percent 50
                        minimum_requests 4
                        window_requests 10
                        open_for 2s
                        half_open_requests 2
                        failure_statuses 429 502 503 504
                    }
                    transport http {
                        connect_timeout 100ms
                        first_byte_timeout 200ms
                        between_reads_timeout 300ms
                        write_timeout 400ms
                    }
                }
            }
        "#;

        let config = compile(source).expect("resource limits compile");
        let server = &config.servers[0];
        assert_eq!(server.limits.header_timeout_ms, Some(2_000));
        assert_eq!(server.limits.body_timeout_ms, Some(3_000));
        assert_eq!(server.limits.max_header_count, Some(40));
        assert_eq!(server.limits.max_header_bytes, Some(8_192));
        assert_eq!(server.limits.max_connections, Some(64));
        assert_eq!(
            server.limits.long_connections.idle_timeout_ms,
            Some(600_000)
        );
        assert_eq!(server.limits.long_connections.request_timeout_ms, Some(0));
        let HandlerConfig::ReverseProxy(proxy) = &server.routes[0].handler else {
            panic!("expected reverse proxy");
        };
        assert_eq!(proxy.connect_timeout, Some(100));
        assert_eq!(proxy.first_byte_timeout, Some(200));
        assert_eq!(proxy.between_reads_timeout, Some(300));
        assert_eq!(proxy.write_timeout, Some(400));
        assert_eq!(proxy.retry.max_attempts, 4);
        assert_eq!(proxy.retry.total_timeout_ms, Some(2_000));
        assert_eq!(proxy.retry.backoff_ms, 50);
        assert_eq!(proxy.retry.status_codes, vec![429, 502, 503, 504]);
        assert_eq!(proxy.retry.methods, vec!["GET", "HEAD", "PUT"]);
        assert_eq!(proxy.overload.max_in_flight, Some(32));
        assert_eq!(proxy.overload.max_pending, 8);
        assert_eq!(proxy.overload.pending_timeout_ms, 75);
        assert_eq!(proxy.overload.upstream_max_connections, Some(16));
        assert_eq!(proxy.circuit_breaker.consecutive_failures, Some(3));
        assert_eq!(proxy.circuit_breaker.error_rate_percent, Some(50));
        assert_eq!(proxy.circuit_breaker.minimum_requests, 4);
        assert_eq!(proxy.circuit_breaker.window_requests, 10);
        assert_eq!(proxy.circuit_breaker.open_duration_ms, 2_000);
        assert_eq!(proxy.circuit_breaker.half_open_requests, 2);
        assert_eq!(
            proxy.circuit_breaker.failure_statuses,
            vec![429, 502, 503, 504]
        );
    }

    #[test]
    fn resource_limit_typos_and_invalid_durations_fail_closed() {
        for source in [
            ":8080 { limits { max_conections 4 } respond \"ok\" }",
            ":8080 { limits { header_timeout nope } respond \"ok\" }",
            ":8080 { limits { max_headers 0 } respond \"ok\" }",
            ":8080 { limits { request_timeout 18446744073709551615m } respond \"ok\" }",
            ":8080 { reverse_proxy 127.0.0.1:9000 { transport http { first_byte_timeout nope } } }",
            ":8080 { reverse_proxy 127.0.0.1:9000 { retry { max_attempts 17 } } }",
            ":8080 { reverse_proxy 127.0.0.1:9000 { retry { methods GET POST } } }",
            ":8080 { reverse_proxy 127.0.0.1:9000 { retry { methods GET GET } } }",
            ":8080 { reverse_proxy 127.0.0.1:9000 { retry { status_codes 200 } } }",
            ":8080 { reverse_proxy 127.0.0.1:9000 { retry { status_codes 503 503 } } }",
            ":8080 { reverse_proxy 127.0.0.1:9000 { retry { total_timeout 10ms backoff 10ms } } }",
            ":8080 { reverse_proxy 127.0.0.1:9000 { retry { statu_codes 503 } } }",
            ":8080 { reverse_proxy 127.0.0.1:9000 { overload { max_pending 2 } } }",
            ":8080 { reverse_proxy 127.0.0.1:9000 { overload { max_in_flight 1 max_pending 1 pending_timeout 0ms } } }",
            ":8080 { reverse_proxy 127.0.0.1:9000 { overload { max_in_flight 0 } } }",
            ":8080 { reverse_proxy 127.0.0.1:9000 { overload { pending_timeout 1s } } }",
            ":8080 { reverse_proxy 127.0.0.1:9000 { overload { max_in_filght 1 } } }",
            ":8080 { reverse_proxy 127.0.0.1:9000 { circuit_breaker { open_for 1s } } }",
            ":8080 { reverse_proxy 127.0.0.1:9000 { circuit_breaker { error_rate_percent 101 } } }",
            ":8080 { reverse_proxy 127.0.0.1:9000 { circuit_breaker { consecutive_failures 2 minimum_requests 5 window_requests 4 } } }",
            ":8080 { reverse_proxy 127.0.0.1:9000 { circuit_breaker { consecutive_failures 2 failure_statuses 200 } } }",
            ":8080 { reverse_proxy 127.0.0.1:9000 { circuit_breaker { consecutive_failures 2 failure_statuses 503 503 } } }",
            ":8080 { reverse_proxy 127.0.0.1:9000 { circuit_breaker { consecuitive_failures 2 } } }",
        ] {
            assert!(compile(source).is_err(), "{source} must fail");
        }
    }

    #[test]
    fn legacy_json_keeps_connect_only_retry_and_unsafe_json_fails_closed() {
        let legacy_source = serde_json::json!({
            "servers": [{
                "listen": ["127.0.0.1:8080"],
                "routes": [{
                    "path": "/*",
                    "handler": {
                        "type": "reverse_proxy",
                        "upstreams": ["127.0.0.1:9000"]
                    }
                }]
            }]
        });
        let legacy: PingclairConfig = serde_json::from_value(legacy_source.clone()).unwrap();
        compiler::validate_config(&legacy).unwrap();
        let HandlerConfig::ReverseProxy(proxy) = &legacy.servers[0].routes[0].handler else {
            panic!("expected reverse proxy");
        };
        assert_eq!(proxy.retry.max_attempts, 16);
        assert!(proxy.retry.status_codes.is_empty());
        assert_eq!(
            *proxy.overload,
            pingclair_core::config::OverloadConfig::default()
        );
        assert_eq!(
            *proxy.circuit_breaker,
            pingclair_core::config::CircuitBreakerConfig::default()
        );

        let mut unsafe_source = legacy_source.clone();
        unsafe_source["servers"][0]["routes"][0]["handler"]["retry"] = serde_json::json!({
            "max_attempts": 2,
            "status_codes": [503],
            "methods": ["POST"]
        });
        let unsafe_config: PingclairConfig = serde_json::from_value(unsafe_source).unwrap();
        assert!(compiler::validate_config(&unsafe_config).is_err());

        let mut unsafe_overload = legacy_source.clone();
        unsafe_overload["servers"][0]["routes"][0]["handler"]["overload"] =
            serde_json::json!({ "max_pending": 1 });
        let unsafe_config: PingclairConfig = serde_json::from_value(unsafe_overload).unwrap();
        assert!(compiler::validate_config(&unsafe_config).is_err());

        let mut unsafe_breaker = legacy_source;
        unsafe_breaker["servers"][0]["routes"][0]["handler"]["circuit_breaker"] =
            serde_json::json!({ "consecutive_failures": 0 });
        let unsafe_config: PingclairConfig = serde_json::from_value(unsafe_breaker).unwrap();
        assert!(compiler::validate_config(&unsafe_config).is_err());
    }

    #[test]
    fn upstream_tls_compiles_from_the_dsl_into_the_route_handler() {
        // Setup scenarios
        let source = r#"
            :8080 {
                reverse_proxy https://backend.internal:8443 {
                    transport http {
                        tls_server_name origin.internal
                        tls_trusted_ca_certs /etc/pingclair/internal-ca.pem
                        tls_client_auth /etc/pingclair/client.crt /etc/pingclair/client.key
                    }
                }
            }
        "#;

        // Verification
        let config = compile(source).expect("upstream tls compiles");
        let HandlerConfig::ReverseProxy(proxy) = &config.servers[0].routes[0].handler else {
            panic!("expected reverse proxy");
        };
        assert_eq!(
            proxy.upstream_tls.server_name.as_deref(),
            Some("origin.internal")
        );
        assert_eq!(
            proxy.upstream_tls.trusted_ca_certs,
            vec!["/etc/pingclair/internal-ca.pem"]
        );
        assert_eq!(
            proxy.upstream_tls.client_identity().expect("complete pair"),
            Some(("/etc/pingclair/client.crt", "/etc/pingclair/client.key"))
        );
        assert!(!proxy.upstream_tls.insecure_skip_verify);
    }

    #[test]
    fn a_route_without_a_tls_block_carries_the_verifying_default() {
        // Setup scenarios
        let config = compile(":8080 { reverse_proxy https://backend:8443 }").expect("compiles");

        // Verification
        let HandlerConfig::ReverseProxy(proxy) = &config.servers[0].routes[0].handler else {
            panic!("expected reverse proxy");
        };
        assert!(
            !proxy.upstream_tls.is_customized(),
            "an untouched route must not carry any TLS customisation"
        );
        assert!(
            !proxy.upstream_tls.insecure_skip_verify,
            "verification must never be off by default"
        );
    }

    #[test]
    fn contradictory_upstream_tls_fails_closed_in_the_dsl() {
        for source in [
            ":8080 { reverse_proxy https://b:8443 { transport http { tls_client_auth /a.crt } } }",
            ":8080 { reverse_proxy https://b:8443 { transport http { tls_client_auth /a.crt /a.key /extra } } }",
            ":8080 { reverse_proxy https://b:8443 { transport http { tls_trusted_ca_certs } } }",
            ":8080 { reverse_proxy https://b:8443 { transport http { tls_server_name } } }",
            ":8080 { reverse_proxy https://b:8443 { transport http { tls_server_name a b } } }",
            ":8080 { reverse_proxy https://b:8443 { transport http { tls_insecure_skip_verify yes } } }",
            ":8080 { reverse_proxy https://b:8443 { transport http { tls_trusted_ca_certs /ca.pem\n tls_insecure_skip_verify } } }",
            ":8080 { reverse_proxy https://b:8443 { transport http { tls_server_name x\n tls_insecure_skip_verify } } }",
            ":8080 { reverse_proxy https://b:8443 { transport http { tls_insecure_skip_verifyy } } }",
        ] {
            assert!(compile(source).is_err(), "{source} must fail");
        }
    }

    #[test]
    fn contradictory_upstream_tls_also_fails_closed_over_json() {
        // Setup scenarios
        //
        // The Admin API posts a configuration document straight into the core
        // types, so every rule the Pingclairfile adapter enforces has to be
        // enforced here too or it can simply be routed around.
        let base = serde_json::json!({
            "servers": [{
                "listen": ["127.0.0.1:8080"],
                "routes": [{
                    "path": "/*",
                    "handler": {
                        "type": "reverse_proxy",
                        "upstreams": ["https://127.0.0.1:9000"]
                    }
                }]
            }]
        });

        // Verification
        for upstream_tls in [
            serde_json::json!({ "client_cert": "/a.crt" }),
            serde_json::json!({ "client_key": "/a.key" }),
            serde_json::json!({
                "insecure_skip_verify": true,
                "trusted_ca_certs": ["/ca.pem"]
            }),
            serde_json::json!({
                "insecure_skip_verify": true,
                "server_name": "origin.internal"
            }),
            serde_json::json!({ "trusted_ca_certs": ["  "] }),
        ] {
            let mut document = base.clone();
            document["servers"][0]["routes"][0]["handler"]["upstream_tls"] = upstream_tls.clone();
            let parsed: PingclairConfig =
                serde_json::from_value(document).expect("document parses");
            assert!(
                compiler::validate_config(&parsed).is_err(),
                "{upstream_tls} must be rejected"
            );
        }
    }

    #[test]
    fn upstream_tls_survives_a_json_round_trip_and_legacy_documents_still_load() {
        // Setup scenarios
        let compiled = compile(
            r#"
            :8080 {
                reverse_proxy https://backend:8443 {
                    transport http {
                        tls
                        tls_server_name origin.internal
                        tls_trusted_ca_certs /ca.pem
                    }
                }
            }
        "#,
        )
        .expect("compiles");

        // Verification
        let encoded = serde_json::to_string(&compiled).expect("serialises");
        let decoded: PingclairConfig = serde_json::from_str(&encoded).expect("round-trips");
        let (HandlerConfig::ReverseProxy(before), HandlerConfig::ReverseProxy(after)) = (
            &compiled.servers[0].routes[0].handler,
            &decoded.servers[0].routes[0].handler,
        ) else {
            panic!("expected reverse proxy on both sides");
        };
        assert_eq!(before.upstream_tls, after.upstream_tls);
        assert!(after.upstream_tls.enable);

        // A 0.1.7 document has no `upstream_tls` key at all and must still load
        // into the verifying default rather than being rejected.
        let legacy: PingclairConfig = serde_json::from_value(serde_json::json!({
            "servers": [{
                "listen": ["127.0.0.1:8080"],
                "routes": [{
                    "path": "/*",
                    "handler": { "type": "reverse_proxy", "upstreams": ["127.0.0.1:9000"] }
                }]
            }]
        }))
        .expect("legacy document loads");
        compiler::validate_config(&legacy).expect("legacy document validates");
        let HandlerConfig::ReverseProxy(proxy) = &legacy.servers[0].routes[0].handler else {
            panic!("expected reverse proxy");
        };
        assert_eq!(
            *proxy.upstream_tls,
            pingclair_core::config::UpstreamTlsConfig::default()
        );
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

    /// 🗄️ `cache { ttl }` survives the whole DSL → core pipeline.
    #[test]
    fn test_compile_reverse_proxy_cache() {
        let source = r#"
            example.com {
                reverse_proxy app:8080 {
                    cache {
                        ttl 60s
                    }
                }
            }
        "#;

        let config = compile(source).unwrap();
        let handler = &config.servers[0].routes[0].handler;
        let pingclair_core::config::HandlerConfig::ReverseProxy(proxy) = handler else {
            panic!("expected a reverse proxy, got {handler:?}");
        };
        let cache = proxy.cache.as_ref().expect("cache policy");
        assert_eq!(cache.ttl_secs, 60);
    }

    /// 🚫 No `ttl` means no cache, rather than a lifetime chosen for you.
    #[test]
    fn test_compile_cache_requires_a_ttl() {
        let error = compile(
            r#"
            example.com {
                reverse_proxy app:8080 {
                    cache {
                    }
                }
            }
            "#,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("ttl"), "unhelpful error: {error}");
    }

    /// 🛡️ The JSON document reaches the same rule, not just the Pingclairfile.
    ///
    /// A rule that only the DSL adapter runs is a rule the Admin API walks
    /// straight past: it deserializes JSON into the core types directly. So the
    /// check lives in `validate_config`, and this proves the JSON path reaches
    /// it — testing the function alone would prove nothing about the route.
    #[test]
    fn test_cache_ttl_bounds_apply_to_json_documents() {
        for ttl in [0u64, 99_999_999] {
            let document = format!(
                r#"{{"servers":[{{"listen":["127.0.0.1:8080"],"routes":[{{"path":"/*",
                   "handler":{{"type":"reverse_proxy","upstreams":["http://127.0.0.1:9"],
                   "cache":{{"ttl_secs":{ttl}}}}}}}]}}]}}"#
            );
            let parsed: pingclair_core::config::PingclairConfig =
                serde_json::from_str(&document).expect("document parses");
            let error = compiler::validate_config(&parsed)
                .expect_err("ttl {ttl} must be rejected")
                .to_string();
            assert!(error.contains("cache ttl"), "unhelpful error: {error}");
        }
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
    fn test_compile_tls_internal() {
        let source = r#"
            https://example.com {
                tls internal
                respond "OK"
            }
        "#;

        let config = compile(source).unwrap();
        let tls = config.servers[0].tls.as_ref().expect("tls config");
        assert!(tls.internal);
        assert!(!tls.auto);
        assert!(tls.cert.is_none());
    }

    #[test]
    fn test_compile_tls_internal_requires_concrete_name() {
        let error = compile(
            r#"
                :8443 {
                    tls internal
                    respond "OK"
                }
            "#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("concrete server name"));
    }

    #[test]
    fn test_compile_tls_internal_rejects_conflicting_issuer() {
        let error = compile(
            r#"
                example.com {
                    tls {
                        internal
                        auto
                    }
                    respond "OK"
                }
            "#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("internal"));
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
    fn test_compile_trusted_proxies() {
        let source = r#"{
            trusted_proxies 127.0.0.1 10.0.0.0/8 2001:db8::/32
        }

        example.com {
            listen :80 proxy_protocol
            respond "OK"
        }"#;

        let config = compile(source).unwrap();
        assert_eq!(
            config.global.trusted_proxies,
            ["127.0.0.1", "10.0.0.0/8", "2001:db8::/32"]
        );
        assert_eq!(config.servers[0].proxy_protocol_listen, ["[::]:80"]);
    }

    #[test]
    fn proxy_protocol_is_declared_per_listener_not_globally() {
        // Setup scenarios
        //
        // nginx spells this `listen 443 proxy_protocol`. It has to be
        // per-listener: a deployment commonly has one port behind an L4
        // balancer and another reached directly, and a single switch would
        // make the direct one reject every connection.
        let config = compile(
            r#"{
                trusted_proxies 10.0.0.0/8
            }

            example.com {
                listen :80
                listen :8443 proxy_protocol
                respond "OK"
            }"#,
        )
        .expect("per-listener proxy_protocol compiles");

        // Verification
        let server = &config.servers[0];
        assert!(server.listen.contains(&"[::]:80".to_string()));
        assert!(server.listen.contains(&"[::]:8443".to_string()));
        assert_eq!(
            server.proxy_protocol_listen,
            ["[::]:8443"],
            "only the declared listener may require the header"
        );
    }

    #[test]
    fn proxy_protocol_survives_a_json_round_trip() {
        // Setup scenarios
        let compiled = compile(
            r#"{
                trusted_proxies 10.0.0.0/8
            }

            example.com {
                listen :8443 proxy_protocol
                respond "OK"
            }"#,
        )
        .expect("compiles");

        // Verification
        let encoded = serde_json::to_string(&compiled).expect("serialises");
        let decoded: PingclairConfig = serde_json::from_str(&encoded).expect("round-trips");
        assert_eq!(
            decoded.servers[0].proxy_protocol_listen,
            compiled.servers[0].proxy_protocol_listen
        );
        assert_eq!(decoded.servers[0].listen, compiled.servers[0].listen);
        compiler::validate_config(&decoded).expect("round-tripped document still validates");

        // A document written before this field existed loads as "no listener
        // requires the header" rather than failing.
        let legacy: PingclairConfig = serde_json::from_value(serde_json::json!({
            "servers": [{ "listen": ["[::]:8443"], "routes": [] }]
        }))
        .expect("legacy document loads");
        assert!(legacy.servers[0].proxy_protocol_listen.is_empty());
        compiler::validate_config(&legacy).expect("legacy document validates");
    }

    #[test]
    fn misdeclared_proxy_protocol_listeners_fail_closed() {
        for source in [
            // An unknown listener flag is a typo, not something to drop.
            r#"{ trusted_proxies 10.0.0.0/8 }
               a.example { listen :8443 proxy_protocolo
                           respond "OK" }"#,
            // Requiring the header with nothing trusted rejects every peer.
            r#"a.example { listen :8443 proxy_protocol
                           respond "OK" }"#,
            // One socket cannot both require and not require the header.
            r#"{ trusted_proxies 10.0.0.0/8 }
               a.example { listen :8443 proxy_protocol
                           respond "OK" }
               b.example { listen :8443
                           respond "OK" }"#,
        ] {
            assert!(compile(source).is_err(), "{source} must fail");
        }
    }

    #[test]
    fn an_undefined_matcher_name_is_refused_rather_than_matching_everything() {
        // Setup scenarios
        //
        // `compile_matcher` used to resolve an unknown name to `path /*`, so one
        // typo turned a restricted route into an open one — and the config
        // validated cleanly. Found 2026-07-30 while searching the parser on
        // purpose rather than bumping into it; evidence kept locally under
        // benchmarks/results/ (never committed to the repository).
        let source = r#"
            :8080 {
                @admin_only path /admin/*
                handle @admin_onlyy { respond "SECRET" 200 }
                respond "public"
            }"#;

        // Verification
        let error = compile(source).expect_err("an undefined matcher must be refused");
        let message = error.to_string();
        assert!(
            message.contains("admin_onlyy"),
            "the diagnostic must name the matcher that does not resolve: {message}"
        );
        assert!(
            !message.contains("@@"),
            "the stored name already carries its @: {message}"
        );

        // The same config with the name spelled correctly still compiles.
        compile(&source.replace("@admin_onlyy", "@admin_only")).expect("the fixed name compiles");
    }

    #[test]
    fn matcher_nesting_is_bounded_rather_than_exhausting_the_stack() {
        // Setup scenarios
        //
        // Blocks were capped at 100 in the parser; matchers are a separate
        // recursion and were not capped at all, so this aborted the process
        // under a release profile that aborts on panic.
        for depth in [40usize, 5_000, 50_000] {
            let source = format!(
                ":8080 {{\n  @deep {}path /x\n  handle @deep {{ respond \"ok\" }}\n}}",
                "not ".repeat(depth)
            );
            assert!(
                compile(&source).is_err(),
                "matcher nesting {depth} deep must be refused, not accepted"
            );
        }

        // A realistic amount of nesting still works.
        compile(":8080 {\n  @x not path /admin/*\n  handle @x { respond \"ok\" }\n}")
            .expect("one level of negation is ordinary and must still compile");
    }

    #[test]
    fn test_compile_trusted_proxies_rejects_invalid_rule() {
        let source = r#"{
            trusted_proxies definitely-not-a-network
        }

        example.com {
            respond "OK"
        }"#;

        assert!(compile(source).is_err());
    }

    #[test]
    fn test_proxy_protocol_requires_a_trusted_transport_network() {
        // A listener that demands the header with nothing trusted would reject
        // every peer, so the configuration is refused rather than started.
        let source = r#"example.com {
            listen :8443 proxy_protocol
            respond "OK"
        }"#;

        assert!(compile(source).is_err());
    }

    #[test]
    fn test_compile_dns_refresh() {
        let with_directive = |value: &str| {
            let source = format!(
                r#"{{
                    dns_refresh {value}
                }}

                example.com {{
                    listen :80
                    respond "OK"
                }}"#
            );
            compile(&source)
        };

        assert_eq!(
            with_directive("10s").unwrap().global.dns_refresh_secs,
            10,
            "an explicit interval wins"
        );
        assert_eq!(with_directive("2m").unwrap().global.dns_refresh_secs, 120);
        assert_eq!(
            with_directive("off").unwrap().global.dns_refresh_secs,
            0,
            "`off` pins upstreams to their startup addresses"
        );

        // A bare number reads as milliseconds elsewhere in the grammar, so
        // accepting it here would turn `dns_refresh 30` into 30ms of lookups.
        assert!(with_directive("30").is_err());
        assert!(with_directive("500ms").is_err());
        assert!(with_directive("soon").is_err());

        let default = compile("example.com {\n listen :80\n respond \"OK\"\n}").unwrap();
        assert_eq!(
            default.global.dns_refresh_secs, 30,
            "the default must survive a config that never mentions dns_refresh"
        );
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
    fn test_compile_gzip_types() {
        let source = r#"
            example.com {
                listen :80
                gzip_types text/* application/problem+json
                respond "OK"
            }
        "#;

        let config = compile(source).unwrap();
        assert_eq!(
            config.servers[0].gzip_types,
            vec!["text/*", "application/problem+json"]
        );
    }

    #[test]
    fn test_compile_gzip_types_rejects_invalid_patterns() {
        let missing_type = r#"
            example.com {
                gzip_types json
                respond "OK"
            }
        "#;
        let misplaced_wildcard = r#"
            example.com {
                gzip_types application/json*
                respond "OK"
            }
        "#;

        assert!(compile(missing_type).is_err());
        assert!(compile(misplaced_wildcard).is_err());
    }

    /// 🗜️ The `encode` directive's argument order is the server's preference
    /// order, so it has to survive compilation intact rather than being
    /// normalized into some fixed ranking.
    #[test]
    fn test_compile_encode_preserves_argument_order() {
        use pingclair_core::config::Encoding;

        let zstd_first = compile(
            r#"
            example.com {
                encode zstd gzip
                respond "OK"
            }
        "#,
        )
        .unwrap();
        assert_eq!(
            zstd_first.servers[0].encodings,
            vec![Encoding::Zstd, Encoding::Gzip]
        );

        let gzip_first = compile(
            r#"
            example.com {
                encode gzip zstd
                respond "OK"
            }
        "#,
        )
        .unwrap();
        assert_eq!(
            gzip_first.servers[0].encodings,
            vec![Encoding::Gzip, Encoding::Zstd]
        );
    }

    #[test]
    fn test_compile_encode_defaults_and_off() {
        use pingclair_core::config::Encoding;

        // No directive at all: gzip, matching every release through 0.1.7.
        let implicit = compile(
            r#"
            example.com {
                respond "OK"
            }
        "#,
        )
        .unwrap();
        assert_eq!(implicit.servers[0].encodings, vec![Encoding::Gzip]);

        // Bare `encode`: also gzip.
        let bare = compile(
            r#"
            example.com {
                encode
                respond "OK"
            }
        "#,
        )
        .unwrap();
        assert_eq!(bare.servers[0].encodings, vec![Encoding::Gzip]);

        // `encode off` is the only way to get an empty list — the runtime
        // reads that as "never compress on this server".
        let off = compile(
            r#"
            example.com {
                encode off
                respond "OK"
            }
        "#,
        )
        .unwrap();
        assert!(off.servers[0].encodings.is_empty());
    }

    /// Brotli parses (Caddyfiles in the wild write it) but has no streaming
    /// encoder on the proxy path. It must fail loudly at compile time instead
    /// of quietly serving gzip under a config that asked for `br`.
    #[test]
    fn test_compile_encode_rejects_unsupported_and_unknown_codings() {
        for source in [
            r#"example.com { encode br
                respond "OK" }"#,
            r#"example.com { encode zstd br
                respond "OK" }"#,
            r#"example.com { encode gzipp
                respond "OK" }"#,
            // `off` is exclusive: mixing it with a coding is contradictory.
            r#"example.com { encode off gzip
                respond "OK" }"#,
        ] {
            assert!(
                compile(source).is_err(),
                "should have been rejected: {source}"
            );
        }
    }

    #[test]
    fn test_compile_encode_deduplicates() {
        use pingclair_core::config::Encoding;

        let config = compile(
            r#"
            example.com {
                encode zstd gzip zstd
                respond "OK"
            }
        "#,
        )
        .unwrap();
        assert_eq!(
            config.servers[0].encodings,
            vec![Encoding::Zstd, Encoding::Gzip]
        );
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
    fn test_production_cache_matchers_compose_with_default_proxy() {
        let config = compile(
            r#"
            {
                admin off
            }

            https://portfolio.example.com:6688 {
                tls /run/secrets/origin.crt /run/secrets/origin.key

                log {
                    output stdout
                    format json
                }

                encode zstd gzip

                header {
                    Strict-Transport-Security "max-age=31536000; includeSubDomains"
                    X-Content-Type-Options "nosniff"
                    X-Frame-Options "DENY"
                    Referrer-Policy "strict-origin-when-cross-origin"
                    Content-Security-Policy "default-src 'self'; object-src 'none'"
                    -Server
                }

                @api path /api/*
                header @api Cache-Control "no-store"

                @hashed path /assets/*
                header @hashed Cache-Control "public, max-age=31536000, immutable"

                @rest {
                    not path /assets/*
                    not path /api/*
                }
                header @rest Cache-Control "no-cache"

                reverse_proxy app:8080
            }
        "#,
        )
        .unwrap();

        fn inspect_policy(handler: &HandlerConfig) -> (Option<String>, bool, bool, bool) {
            fn visit(
                handler: &HandlerConfig,
                cache_control: &mut Option<String>,
                has_security_header: &mut bool,
                removes_server: &mut bool,
                has_proxy: &mut bool,
            ) {
                match handler {
                    HandlerConfig::Pipeline { handlers }
                    | HandlerConfig::Handle { handlers }
                    | HandlerConfig::HandlePath { handlers, .. } => {
                        for handler in handlers {
                            visit(
                                handler,
                                cache_control,
                                has_security_header,
                                removes_server,
                                has_proxy,
                            );
                        }
                    }
                    HandlerConfig::Headers { set, remove, .. } => {
                        if let Some(value) = set.get("Cache-Control") {
                            *cache_control = Some(value.clone());
                        }
                        *has_security_header |=
                            set.get("X-Frame-Options").map(String::as_str) == Some("DENY");
                        *removes_server |= remove.iter().any(|name| name == "Server");
                    }
                    HandlerConfig::ReverseProxy(_) => *has_proxy = true,
                    _ => {}
                }
            }

            let mut cache_control = None;
            let mut has_security_header = false;
            let mut removes_server = false;
            let mut has_proxy = false;
            visit(
                handler,
                &mut cache_control,
                &mut has_security_header,
                &mut removes_server,
                &mut has_proxy,
            );
            (
                cache_control,
                has_security_header,
                removes_server,
                has_proxy,
            )
        }

        let server = &config.servers[0];
        assert_eq!(server.listen, ["[::]:6688"]);
        assert!(matches!(
            server.log.as_ref(),
            Some(log)
                if matches!(&log.output, LogOutput::Stdout)
                    && matches!(&log.format, LogFormat::Json)
        ));

        for (path, expected_cache) in [
            ("/api/*", "no-store"),
            ("/assets/*", "public, max-age=31536000, immutable"),
        ] {
            let route = server
                .routes
                .iter()
                .find(|route| route.path == path)
                .unwrap();
            assert_eq!(
                inspect_policy(&route.handler),
                (Some(expected_cache.to_string()), true, true, true)
            );
        }

        let rest = server
            .routes
            .iter()
            .find(|route| route.path == "/*" && route.matcher.is_some())
            .unwrap();
        assert!(matches!(
            rest.matcher.as_ref(),
            Some(Matcher::And(left, right))
                if matches!(left.as_ref(), Matcher::Not(_))
                    && matches!(right.as_ref(), Matcher::Not(_))
        ));
        assert_eq!(
            inspect_policy(&rest.handler),
            (Some("no-cache".to_string()), true, true, true)
        );
    }

    #[test]
    fn test_compile_upstream_protocol_schemes() {
        let config = compile(
            r#"
            example.com {
                reverse_proxy h2c://127.0.0.1:50051 h2://grpc.example.com:443 https://api.example.com
            }
        "#,
        )
        .unwrap();

        let HandlerConfig::ReverseProxy(proxy) = &config.servers[0].routes[0].handler else {
            panic!("expected reverse proxy handler");
        };
        assert_eq!(
            proxy.upstreams,
            [
                "h2c://127.0.0.1:50051",
                "h2://grpc.example.com:443",
                "https://api.example.com",
            ]
        );
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
