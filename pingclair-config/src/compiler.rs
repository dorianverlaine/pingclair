//! 🏗️ Compiler for the Pingclair configuration DSL.
//!
//! This module converts the AST into a runtime `PingclairConfig`.

use crate::parser::ast::*;
use pingclair_core::config::{
    AccessControlConfig as CoreAccessControlConfig, AdminConfig, HandlerConfig, LoadBalanceConfig,
    LogConfig, LogFormat as CoreLogFormat, LogOutput as CoreLogOutput, Matcher as CoreMatcher,
    MatcherCondition, PingclairConfig, ProxyUpstream, ReverseProxyConfig, RouteConfig, ServerConfig,
    TlsConfig, default_gzip_types,
};
use pingclair_core::server::{MAX_BCRYPT_COST, bcrypt_hash_cost};
use std::collections::HashMap;
use thiserror::Error;

/// Compiler errors
#[derive(Debug, Error)]
pub enum CompileError {
    #[error("Invalid server configuration: {message}")]
    InvalidServer { message: String },

    #[error("Invalid route configuration: {message}")]
    InvalidRoute { message: String },

    #[error("Unsupported feature: {feature}")]
    UnsupportedFeature { feature: String },
}

type CompileResult<T> = Result<T, CompileError>;

/// Compile AST to PingclairConfig
pub fn compile_ast(ast: &Ast) -> CompileResult<PingclairConfig> {
    let mut config = PingclairConfig::default();

    // Compile global config
    if let Some(global) = &ast.global {
        compile_global(&global.inner, &mut config)?;
    }

    // Compile servers
    for server_node in &ast.servers {
        let server_config = compile_server(&server_node.inner)?;
        config.servers.push(server_config);
    }

    Ok(config)
}

fn compile_global(global: &GlobalBlock, config: &mut PingclairConfig) -> CompileResult<()> {
    // Set debug mode
    if let Some(debug) = global.debug {
        config.debug = debug;
    }

    // Set global ACME email
    if let Some(email) = &global.email {
        config.global.email = Some(email.clone());
    }

    // Set global auto-HTTPS mode
    if let Some(mode) = global.auto_https {
        // Map AST AutoHttpsMode to Core AutoHttpsMode
        use pingclair_core::config::AutoHttpsMode as CoreMode;
        config.global.auto_https = match mode {
            AutoHttpsMode::On => CoreMode::On,
            AutoHttpsMode::Off => CoreMode::Off,
            AutoHttpsMode::DisableRedirects => CoreMode::DisableRedirects,
        };
    }

    // Set admin API configuration (`admin <listen> [api_key]` / `admin off`)
    if let Some(admin) = &global.admin {
        config.admin = Some(AdminConfig {
            listen: admin.listen.clone(),
            enabled: admin.enabled,
            api_key: admin.api_key.clone(),
        });
    }

    config.global.trusted_proxies = global.trusted_proxies.clone();

    Ok(())
}

fn compile_server(server: &ServerBlock) -> CompileResult<ServerConfig> {
    let mut config = ServerConfig {
        name: Some(server.name.clone()),
        listen: Vec::new(),
        routes: Vec::new(),
        tls: None,
        log: None,
        client_max_body_size: 1024 * 1024, // 1MB default
        security: Default::default(),
        gzip_types: if server.gzip_types.is_empty() {
            default_gzip_types()
        } else {
            server.gzip_types.clone()
        },
        error_pages: server.error_pages.iter().cloned().collect(),
    };

    // Listen addresses
    for listen in &server.listens {
        let addr = if let Some(port) = listen.port {
            format!("{}:{}", listen.host, port)
        } else {
            listen.host.clone()
        };
        config.listen.push(addr);

        // Set TLS based on scheme
        if listen.scheme == Scheme::Https {
            config.tls = Some(TlsConfig::default());
        }
    }

    // TLS directive (`tls cert key`, `tls auto`, `tls off`, or block form).
    // Merged with the https-scheme default above so neither clobbers the other.
    if let Some(tls) = &server.tls {
        if tls.off {
            config.tls = None;
        } else {
            let mut merged = config.tls.take().unwrap_or_default();
            merged.auto = merged.auto || tls.auto;
            if tls.cert.is_some() {
                merged.cert = tls.cert.clone();
            }
            if tls.key.is_some() {
                merged.key = tls.key.clone();
            }
            if tls.acme_email.is_some() {
                merged.acme_email = tls.acme_email.clone();
            }
            if let Some(http3) = tls.http3 {
                merged.http3 = http3;
            }
            config.tls = Some(merged);
        }
    }

    // Bind address (add as first listen if no explicit listens)
    if let Some(bind) = &server.bind
        && config.listen.is_empty()
    {
        config.listen.push(bind.clone());
    }

    // Log configuration
    if let Some(log) = &server.log {
        config.log = Some(compile_log(&log.inner)?);
    }

    // Routes
    if let Some(routes) = &server.routes {
        for arm in &routes.inner.arms {
            let route_config = compile_route_arm(&arm.inner, &server.matchers)?;
            config.routes.push(route_config);
        }
    }

    // Process generic directives for settings like tls, client_max_body_size
    for directive in &server.directives {
        if let Directive::Setting { key, value } = directive {
            match key.as_str() {
                "client_max_body_size" => {
                    if let Expr::Integer(size) = value {
                        config.client_max_body_size = *size as u64;
                    }
                }
                "tls" => {
                    let mut tls = TlsConfig::default();
                    match value {
                        Expr::Ident(id) if id == "auto" => {
                            tls.auto = true;
                        }
                        Expr::Map(map) => {
                            if let Some(Expr::Bool(b)) = map.get("auto") {
                                tls.auto = *b;
                            }
                            if let Some(Expr::String(s)) = map.get("cert") {
                                tls.cert = Some(s.clone());
                            }
                            if let Some(Expr::String(s)) = map.get("key") {
                                tls.key = Some(s.clone());
                            }
                            if let Some(Expr::String(s)) = map.get("acme_email") {
                                tls.acme_email = Some(s.clone());
                            }
                            if let Some(Expr::Bool(b)) = map.get("http3") {
                                tls.http3 = *b;
                            }
                        }
                        _ => {}
                    }
                    config.tls = Some(tls);
                }
                _ => {}
            }
        }
    }

    Ok(config)
}

fn compile_log(log: &LogBlock) -> CompileResult<LogConfig> {
    let output = match &log.output {
        LogOutput::File(path) => CoreLogOutput::File(path.clone()),
        LogOutput::Stdout => CoreLogOutput::Stdout,
        LogOutput::Stderr => CoreLogOutput::Stderr,
    };

    let format = match log.format.format_type {
        LogFormatType::Json => CoreLogFormat::Json,
        LogFormatType::Text => CoreLogFormat::Text,
    };

    Ok(LogConfig {
        output,
        format,
        level: None, // Use global level
    })
}

fn find_path_pattern(matcher: &Matcher, matchers: &HashMap<String, Matcher>) -> Option<String> {
    match matcher {
        Matcher::Path(pm) => pm.patterns.first().cloned(),
        Matcher::Named(name) => matchers
            .get(name)
            .and_then(|m| find_path_pattern(m, matchers)),
        Matcher::And(left, right) | Matcher::Or(left, right) => {
            find_path_pattern(left, matchers).or_else(|| find_path_pattern(right, matchers))
        }
        _ => None,
    }
}

fn compile_route_arm(
    arm: &RouteArm,
    matchers: &HashMap<String, Matcher>,
) -> CompileResult<RouteConfig> {
    // Compile matcher to path pattern
    let path = arm
        .matcher
        .as_ref()
        .and_then(|m| find_path_pattern(m, matchers))
        .unwrap_or_else(|| "/*".to_string());

    // Compile matcher conditions
    let matcher = arm.matcher.as_ref().map(|m| compile_matcher(m, matchers));

    // Compile handler
    let handler = compile_handler(&arm.handler)?;

    Ok(RouteConfig {
        path,
        handler,
        methods: None,
        matcher,
    })
}

fn compile_matcher(matcher: &Matcher, matchers: &HashMap<String, Matcher>) -> CoreMatcher {
    match matcher {
        Matcher::Named(name) => {
            if let Some(m) = matchers.get(name) {
                compile_matcher(m, matchers)
            } else {
                // Fallback or error? CoreMatcher doesn't have a "None" that's safe here
                // but we can use an empty And or similar if needed.
                // For now, assume it exists or return a dummy.
                CoreMatcher::Path {
                    patterns: vec!["/*".to_string()],
                }
            }
        }
        Matcher::Path(pm) => CoreMatcher::Path {
            patterns: pm.patterns.clone(),
        },
        Matcher::Header(hm) => {
            let condition = match &hm.condition {
                HeaderCondition::Exists => MatcherCondition::Exists,
                HeaderCondition::Equals(v) => MatcherCondition::Equals(v.clone()),
                HeaderCondition::Contains(v) => MatcherCondition::Contains(v.clone()),
                HeaderCondition::StartsWith(v) => MatcherCondition::StartsWith(v.clone()),
                HeaderCondition::EndsWith(v) => MatcherCondition::EndsWith(v.clone()),
                HeaderCondition::Regex(v) => MatcherCondition::Regex(v.clone()),
            };
            CoreMatcher::Header {
                name: hm.name.clone(),
                condition,
            }
        }
        Matcher::Method(methods) => CoreMatcher::Method {
            methods: methods
                .iter()
                .map(|m| format!("{:?}", m).to_uppercase())
                .collect(),
        },
        Matcher::Query(qm) => {
            let condition = match &qm.condition {
                HeaderCondition::Exists => MatcherCondition::Exists,
                HeaderCondition::Equals(v) => MatcherCondition::Equals(v.clone()),
                _ => MatcherCondition::Exists,
            };
            CoreMatcher::Query {
                name: qm.name.clone(),
                condition,
            }
        }
        Matcher::Host(hosts) => CoreMatcher::Host(hosts.clone()),
        Matcher::RemoteIp(ips) => CoreMatcher::RemoteIp(ips.clone()),
        Matcher::Protocol(protocols) => CoreMatcher::Protocol(protocols.clone()),
        Matcher::And(left, right) => CoreMatcher::And(
            Box::new(compile_matcher(left, matchers)),
            Box::new(compile_matcher(right, matchers)),
        ),
        Matcher::Or(left, right) => CoreMatcher::Or(
            Box::new(compile_matcher(left, matchers)),
            Box::new(compile_matcher(right, matchers)),
        ),
        Matcher::Not(inner) => CoreMatcher::Not(Box::new(compile_matcher(inner, matchers))),
    }
}

fn compile_handler(handler: &Handler) -> CompileResult<HandlerConfig> {
    match handler {
        Handler::Proxy(proxy) => {
            let mut config = ReverseProxyConfig {
                upstreams: proxy.upstreams.clone(),
                upstream_options: proxy
                    .upstream_options
                    .iter()
                    .map(|upstream| ProxyUpstream {
                        address: upstream.address.clone(),
                        weight: upstream.weight,
                        backup: upstream.backup,
                    })
                    .collect(),
                load_balance: LoadBalanceConfig::default(),
                health_check: None,
                headers_up: HashMap::new(),
                headers_down: HashMap::new(),
                flush_interval: None,
                read_timeout: None,
                write_timeout: None,
            };

            if let Some(policy) = &proxy.lb_policy {
                config.load_balance.strategy = policy.clone();
            }

            // Flush interval
            if let Some(fi) = &proxy.flush_interval {
                config.flush_interval = Some(match fi {
                    FlushInterval::Immediate => -1,
                    FlushInterval::Duration(ms) => *ms as i64,
                });
            }

            // Header up
            for (key, value) in &proxy.header_up {
                let value_str = match value {
                    Expr::String(s) => s.clone(),
                    Expr::Variable(v) => format!("${{{}}}", v.path),
                    _ => continue,
                };
                config.headers_up.insert(key.clone(), value_str);
            }

            // Transport
            if let Some(transport) = &proxy.transport {
                config.read_timeout = transport.read_timeout.map(|ms| ms as i64);
                config.write_timeout = transport.write_timeout.map(|ms| ms as i64);
            }

            Ok(HandlerConfig::ReverseProxy(config))
        }

        Handler::Respond(resp) => Ok(HandlerConfig::Respond {
            status: resp.status,
            body: resp.body.as_ref().and_then(|e| match e {
                Expr::String(s) => Some(s.clone()),
                _ => None,
            }),
            headers: resp.headers.clone(),
        }),

        Handler::Redirect(redir) => Ok(HandlerConfig::Redirect {
            to: redir.to.clone(),
            code: redir.code,
        }),

        Handler::Headers(headers) => Ok(HandlerConfig::Headers {
            set: headers.set.clone(),
            add: headers.add.clone(),
            remove: headers.remove.clone(),
        }),

        Handler::Pipeline(handlers) => {
            let compiled: Result<Vec<_>, _> = handlers.iter().map(compile_handler).collect();
            Ok(HandlerConfig::Pipeline {
                handlers: compiled?,
            })
        }

        Handler::FileServer(fs) => Ok(HandlerConfig::FileServer {
            root: fs.root.clone(),
            index: fs.index.clone(),
            browse: fs.browse,
            compress: fs.compress,
        }),

        Handler::Handle(sub_handlers) => {
            // Recursively compile each sub-handler in the Handle block
            let mut compiled = Vec::new();
            for h in sub_handlers {
                compiled.push(compile_handler(h)?);
            }
            Ok(HandlerConfig::Handle { handlers: compiled })
        }

        Handler::BasicAuth(config) => {
            let credentials = config
                .credentials
                .iter()
                .map(|(username, password)| compile_basic_auth_credential(username, password))
                .collect::<CompileResult<Vec<_>>>()?;
            Ok(HandlerConfig::BasicAuth {
                realm: config
                    .realm
                    .clone()
                    .unwrap_or_else(|| "Restricted".to_string()),
                credentials,
            })
        }

        Handler::Rewrite(rewrite) => {
            if let Some(pattern) = &rewrite.regex {
                regex::Regex::new(pattern).map_err(|error| CompileError::InvalidRoute {
                    message: format!("invalid rewrite regex `{pattern}`: {error}"),
                })?;
            }
            Ok(HandlerConfig::Rewrite {
                strip_prefix: None,
                strip_suffix: None,
                replace: rewrite.replace.clone(),
                regex: rewrite.regex.clone(),
                regex_replace: rewrite.regex_replace.clone(),
            })
        }

        Handler::Cors(cors) => Ok(HandlerConfig::Cors {
            allowed_origins: cors.allowed_origins.clone(),
            allowed_methods: if cors.allowed_methods.is_empty() {
                vec![
                    "GET".into(),
                    "POST".into(),
                    "PUT".into(),
                    "DELETE".into(),
                    "OPTIONS".into(),
                ]
            } else {
                cors.allowed_methods.clone()
            },
            allowed_headers: if cors.allowed_headers.is_empty() {
                vec![
                    "Content-Type".into(),
                    "Authorization".into(),
                    "X-Requested-With".into(),
                ]
            } else {
                cors.allowed_headers.clone()
            },
            exposed_headers: cors.exposed_headers.clone(),
            allow_credentials: cors.allow_credentials,
            max_age: cors.max_age.unwrap_or(86_400),
        }),

        Handler::AccessControl(access) => {
            Ok(HandlerConfig::AccessControl(CoreAccessControlConfig {
                allowed_ips: access.allowed_ips.clone(),
                denied_ips: access.denied_ips.clone(),
                allowed_referers: access.allowed_referers.clone(),
                denied_referers: access.denied_referers.clone(),
                allowed_user_agents: access.allowed_user_agents.clone(),
                denied_user_agents: access.denied_user_agents.clone(),
            }))
        }

        Handler::Plugin { name, args } => {
            let args_str = args
                .iter()
                .map(|e| match e {
                    Expr::String(s) => s.clone(),
                    _ => format!("{:?}", e),
                })
                .collect();
            Ok(HandlerConfig::Plugin {
                name: name.clone(),
                args: args_str,
            })
        }
    }
}

/// 🔐 Compiles and bounds a Basic Auth credential's bcrypt work factor.
fn compile_basic_auth_credential(
    username: &str,
    password: &str,
) -> CompileResult<pingclair_core::config::BasicAuthCredential> {
    let hashed = if password.starts_with("$2") {
        let Some(cost) = bcrypt_hash_cost(password) else {
            return Err(CompileError::InvalidRoute {
                message: format!("invalid bcrypt hash for basic_auth user `{username}`"),
            });
        };
        if cost > MAX_BCRYPT_COST {
            return Err(CompileError::InvalidRoute {
                message: format!(
                    "bcrypt cost {cost} for basic_auth user `{username}` exceeds the maximum {MAX_BCRYPT_COST}"
                ),
            });
        }
        true
    } else {
        false
    };

    Ok(pingclair_core::config::BasicAuthCredential {
        username: username.to_string(),
        password: password.to_string(),
        hashed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_simple_server() {
        let ast = crate::parser::compile(
            r#"
            example.com {
                listen :8080
            }
        "#,
        )
        .unwrap();

        let config = compile_ast(&ast).unwrap();
        assert_eq!(config.servers.len(), 1);
        assert_eq!(config.servers[0].name, Some("example.com".to_string()));
    }

    #[test]
    fn test_compile_proxy() {
        let ast = crate::parser::compile(
            r#"
            api.example.com {
                listen :8080
                reverse_proxy localhost:3000
            }
        "#,
        )
        .unwrap();

        let config = compile_ast(&ast).unwrap();
        assert_eq!(config.servers[0].routes.len(), 1);
    }

    #[test]
    fn test_compile_named_matcher() {
        let ast = crate::parser::compile(
            r#"
            example.com {
                @api {
                    path /api/*
                    method POST
                }
                reverse_proxy @api localhost:3000
            }
        "#,
        )
        .unwrap();

        let config = compile_ast(&ast).unwrap();
        assert_eq!(config.servers[0].routes.len(), 1);

        let route = &config.servers[0].routes[0];
        assert_eq!(route.path, "/api/*");

        if let Some(CoreMatcher::And(left, right)) = &route.matcher {
            // Verify it's combined as expected
            match (left.as_ref(), right.as_ref()) {
                (CoreMatcher::Path { .. }, CoreMatcher::Method { .. }) => {}
                (CoreMatcher::Method { .. }, CoreMatcher::Path { .. }) => {}
                _ => panic!("Expected Path and Method matchers, got {:?}", route.matcher),
            }
        } else {
            panic!("Expected And matcher, got {:?}", route.matcher);
        }
    }
}
