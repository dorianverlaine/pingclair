//! Compiler for Pingclairfile
//!
//! Converts the AST into runtime PingclairConfig.

use crate::parser::ast::*;
use pingclair_core::config::{
    PingclairConfig, ServerConfig, RouteConfig, HandlerConfig,
    TlsConfig, ReverseProxyConfig,
    LoadBalanceConfig, LogConfig, LogOutput as CoreLogOutput, LogFormat as CoreLogFormat,
    Matcher as CoreMatcher, MatcherCondition,
};
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
    
    // Compile protocols (stored in admin or as global setting)
    // For now, we'll handle this at runtime
    
    Ok(())
}

fn compile_server(server: &ServerBlock) -> CompileResult<ServerConfig> {
    let mut config = ServerConfig {
        name: Some(server.name.clone()),
        listen: Vec::new(),
        routes: Vec::new(),
        tls: None,
        log: None,
    };
    
    // Listen address
    if let Some(listen) = &server.listen {
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
    
    // Bind address (add as listen if no explicit listen)
    if let Some(bind) = &server.bind {
        if config.listen.is_empty() {
            config.listen.push(bind.clone());
        }
    }
    
    // Log configuration
    if let Some(log) = &server.log {
        config.log = Some(compile_log(&log.inner)?);
    }
    
    // Routes
    if let Some(routes) = &server.routes {
        for arm in &routes.inner.arms {
            let route_config = compile_route_arm(&arm.inner)?;
            config.routes.push(route_config);
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

fn compile_route_arm(arm: &RouteArm) -> CompileResult<RouteConfig> {
    // Compile matcher to path pattern
    let path = match &arm.matcher {
        Some(Matcher::Path(pm)) => {
            if pm.patterns.len() == 1 {
                pm.patterns[0].clone()
            } else {
                // Multiple patterns - use first for now
                pm.patterns.first().cloned().unwrap_or_else(|| "/*".to_string())
            }
        }
        Some(_) => {
            // Other matchers - need to be handled at runtime
            "/*".to_string()
        }
        None => {
            // Default route
            "/*".to_string()
        }
    };
    
    // Compile matcher conditions
    let matcher = arm.matcher.as_ref().map(compile_matcher);
    
    // Compile handler
    let handler = compile_handler(&arm.handler)?;
    
    Ok(RouteConfig {
        path,
        handler,
        methods: None,
        matcher,
    })
}

fn compile_matcher(matcher: &Matcher) -> CoreMatcher {
    // Use imports already declared at top of file
    
    match matcher {
        Matcher::Path(pm) => {
            CoreMatcher::Path {
                patterns: pm.patterns.clone(),
            }
        }
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
        Matcher::Method(methods) => {
            CoreMatcher::Method {
                methods: methods.iter().map(|m| format!("{:?}", m).to_uppercase()).collect(),
            }
        }
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
        Matcher::Host(hosts) => {
            CoreMatcher::Host(hosts.clone())
        }
        Matcher::RemoteIp(ips) => {
            CoreMatcher::RemoteIp(ips.clone())
        }
        Matcher::Protocol(protocols) => {
            CoreMatcher::Protocol(protocols.clone())
        }
        Matcher::And(left, right) => {
            CoreMatcher::And(
                Box::new(compile_matcher(left)),
                Box::new(compile_matcher(right)),
            )
        }
        Matcher::Or(left, right) => {
            CoreMatcher::Or(
                Box::new(compile_matcher(left)),
                Box::new(compile_matcher(right)),
            )
        }
        Matcher::Not(inner) => {
            CoreMatcher::Not(Box::new(compile_matcher(inner)))
        }
    }
}

fn compile_handler(handler: &Handler) -> CompileResult<HandlerConfig> {
    match handler {
        Handler::Proxy(proxy) => {
            let mut config = ReverseProxyConfig {
                upstreams: proxy.upstreams.clone(),
                load_balance: LoadBalanceConfig::default(),
                health_check: None,
                headers_up: HashMap::new(),
                headers_down: HashMap::new(),
                flush_interval: None,
                read_timeout: None,
                write_timeout: None,
            };
            
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
        
        Handler::Respond(resp) => {
            Ok(HandlerConfig::Respond {
                status: resp.status,
                body: resp.body.as_ref().and_then(|e| match e {
                    Expr::String(s) => Some(s.clone()),
                    _ => None,
                }),
                headers: resp.headers.clone(),
            })
        }
        
        Handler::Redirect(redir) => {
            Ok(HandlerConfig::Redirect {
                to: redir.to.clone(),
                code: redir.code,
            })
        }
        
        Handler::Headers(headers) => {
            Ok(HandlerConfig::Headers {
                set: headers.set.clone(),
                add: headers.add.clone(),
                remove: headers.remove.clone(),
            })
        }
        
        Handler::Pipeline(handlers) => {
            let compiled: Result<Vec<_>, _> = handlers.iter()
                .map(compile_handler)
                .collect();
            Ok(HandlerConfig::Pipeline(compiled?))
        }
        
        Handler::FileServer(fs) => {
            Ok(HandlerConfig::FileServer {
                root: fs.root.clone(),
                index: fs.index.clone(),
                browse: fs.browse,
                compress: fs.compress,
            })
        }
        
        Handler::Handle(directives) => {
            // Need a way to compile directives to handlers
            // For now, only support top-level handlers within handle block
            // Handle blocks often contain things like headers, rewrite, respond, proxy
            // We can treat it as a pipeline for now
            let mut handlers = Vec::new();
            for node in directives {
                match &node.inner {
                    Directive::Headers(h) => {
                        handlers.push(HandlerConfig::Headers {
                            set: h.set.clone(),
                            add: h.add.clone(),
                            remove: h.remove.clone(),
                        });
                    }
                    _ => {
                        // Skip or implement more later
                    }
                }
            }
            Ok(HandlerConfig::Handle(handlers))
        }

        Handler::Plugin { name, args } => {
            let args_str = args.iter().map(|e| match e {
                Expr::String(s) => s.clone(),
                _ => format!("{:?}", e),
            }).collect();
            Ok(HandlerConfig::Plugin { name: name.clone(), args: args_str })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;

    #[test]
    fn test_compile_simple_server() {
        let ast = parse(r#"
            server "example.com" {
                listen: "http://127.0.0.1:8080";
            }
        "#).unwrap();

        let config = compile_ast(&ast).unwrap();
        assert_eq!(config.servers.len(), 1);
        assert_eq!(config.servers[0].name, Some("example.com".to_string()));
    }

    #[test]
    fn test_compile_proxy() {
        let ast = parse(r#"
            server "api.example.com" {
                listen: "http://127.0.0.1:8080";
                route {
                    _ => {
                        proxy "http://localhost:3000" {
                            flush_interval: Immediate;
                        }
                    }
                }
            }
        "#).unwrap();

        let config = compile_ast(&ast).unwrap();
        assert_eq!(config.servers[0].routes.len(), 1);
    }
}
