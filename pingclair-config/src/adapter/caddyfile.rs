//! Adapter for converting Generic Caddyfile AST to Typed AST

use crate::parser::ast::*;
use crate::parser::caddy_ast::{Directive, Block};
use crate::parser::lexer::Location;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("Unknown directive '{0}'")]
    UnknownDirective(String),
    
    #[error("Directive '{0}' expects {1} arguments, got {2}")]
    ArgumentCount(String, usize, usize),
    
    #[error("Invalid argument for '{0}': {1}")]
    InvalidArgument(String, String),
    
    #[error("Block not allowed for directive '{0}'")]
    BlockNotAllowed(String),

    #[error("Duplicate global block")]
    DuplicateGlobal,
}

/// Convert generic directives to Typed AST
pub fn adapt(directives: Vec<Directive>) -> Result<Ast, AdapterError> {
    let mut ast = Ast::default();
    
    for d in directives {
        if d.name.is_empty() || d.name == "global" || d.name == "options" {
            if ast.global.is_some() {
                return Err(AdapterError::DuplicateGlobal);
            }
            ast.global = Some(Node::new(adapt_global(d)?, Location { start: 0, end: 0 }));
        } else {
            // Check if it's a macro definition: macro name { ... }
            if d.name == "macro" {
                 // TODO: Support macros in Caddyfile? 
                 // Caddy uses snippets (import), let's stick to that later.
            } else {
                let server = adapt_server(d)?;
                ast.servers.push(Node::new(server, Location { start: 0, end: 0 }));
            }
        }
    }
    
    Ok(ast)
}

fn adapt_global(d: Directive) -> Result<GlobalBlock, AdapterError> {
    let mut global = GlobalBlock::default();
    if let Some(block) = d.block {
        for sub in block.directives {
            match sub.name.as_str() {
                "debug" => {
                    global.debug = Some(sub.args.get(0).map(|s| s == "true").unwrap_or(true));
                }
                "email" => {
                    global.email = sub.args.get(0).cloned();
                }
                "auto_https" => {
                    if let Some(arg) = sub.args.get(0) {
                        match arg.as_str() {
                            "on" => global.auto_https = Some(AutoHttpsMode::On),
                            "off" => global.auto_https = Some(AutoHttpsMode::Off),
                            "disable_redirects" => global.auto_https = Some(AutoHttpsMode::DisableRedirects),
                            _ => return Err(AdapterError::InvalidArgument("auto_https".into(), arg.clone())),
                        }
                    }
                }
                "protocols" => {
                    for arg in sub.args {
                        match arg.as_str() {
                            "H1" => global.protocols.push(Protocol::H1),
                            "H2" => global.protocols.push(Protocol::H2),
                            "H3" => global.protocols.push(Protocol::H3),
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(global)
}

fn adapt_server(d: Directive) -> Result<ServerBlock, AdapterError> {
    let mut server = ServerBlock::new(d.name.clone());
    
    // Collect all addresses (name + args)
    let mut names = vec![d.name.clone()];
    for arg in &d.args {
        // If it starts with : or contains :, it's likely an address
        if arg.starts_with(':') || arg.contains(':') || arg.contains('.') || *arg == "localhost" {
            names.push(arg.clone());
        }
    }

    for name in names {
        if name.starts_with(':') || name.contains(':') {
            server.listens.push(ListenAddr {
                scheme: Scheme::Http, // Default to HTTP for now
                host: if name.starts_with(':') { "0.0.0.0".to_string() } else { name.split(':').collect::<Vec<_>>()[0].to_string() },
                port: name.split(':').last().and_then(|p| p.parse().ok()),
            });
        }
    }

    // If we have multiple listeners or one that is just a port, 
    // we should let the name be generic or None to match everything on those ports
    if server.listens.len() > 1 || server.name.starts_with(':') {
        // Use a wildcard name to be the default for the port
        server.name = "_".to_string(); 
    }
    
    if let Some(block) = d.block {
        let mut default_handlers = Vec::new();
        
        for sub_d in block.directives {
            match sub_d.name.as_str() {
                "bind" => {
                    if sub_d.args.is_empty() { return Err(AdapterError::ArgumentCount("bind".into(), 1, 0)); }
                    server.bind = Some(sub_d.args[0].clone());
                },
                "listen" => {
                    if sub_d.args.is_empty() { return Err(AdapterError::ArgumentCount("listen".into(), 1, 0)); }
                    let addr = &sub_d.args[0];
                    server.listens.push(ListenAddr {
                        scheme: if addr.starts_with("https") { Scheme::Https } else { Scheme::Http },
                        host: "0.0.0.0".to_string(), 
                        port: addr.split(':').last().and_then(|p| p.parse().ok()),
                    });
                },
                "compress" => {
                    for arg in sub_d.args {
                        match arg.as_str() {
                            "Gzip" | "gzip" => server.compress.push(CompressionAlgo::Gzip),
                            "Br" | "br" => server.compress.push(CompressionAlgo::Br),
                            "Zstd" | "zstd" => server.compress.push(CompressionAlgo::Zstd),
                            _ => {}
                        }
                    }
                },
                "route" | "handle" => {
                    let (matcher, inner_block) = parse_matcher_and_block(&sub_d)?;
                    if let Some(blk) = inner_block {
                        let mut handlers = Vec::new();
                        for inner_d in &blk.directives {
                            handlers.push(adapt_handler(inner_d.clone())?);
                        }
                        if matcher.is_none() {
                            default_handlers.push(Handler::Pipeline(handlers));
                        } else {
                            add_route(&mut server, matcher, Handler::Pipeline(handlers));
                        }
                    }
                },
                name if name.starts_with('@') => {
                    // Named matcher definition
                    let matcher = parse_matcher_definition(&sub_d)?;
                    server.matchers.insert(name.to_string(), matcher);
                }
        _ => {
                    // Try to extract matcher and adapt as handler
                    let (matcher, _) = parse_matcher_and_block(&sub_d)?;
                    let mut handler_d = sub_d.clone();
                    if matcher.is_some() {
                        if handler_d.args.is_empty() { return Err(AdapterError::ArgumentCount(sub_d.name, 1, 0)); }
                        handler_d.args.remove(0);
                    }
                    
                    let handler = adapt_handler(handler_d)?;
                    if matcher.is_some() {
                        add_route(&mut server, matcher, handler);
                    } else {
                        default_handlers.push(handler);
                    }
                }
            }
        }
        
        if !default_handlers.is_empty() {
            let final_handler = if default_handlers.len() == 1 {
                default_handlers.remove(0)
            } else {
                Handler::Pipeline(default_handlers)
            };
            add_route(&mut server, None, final_handler);
        }
    }
    
    Ok(server)
}

fn adapt_handler(d: Directive) -> Result<Handler, AdapterError> {
    match d.name.as_str() {
        "reverse_proxy" => {
            Ok(Handler::Proxy(Box::new(ProxyConfig::new(d.args))))
        },
        "respond" => {
             Ok(Handler::Respond(ResponseConfig {
                 status: 200,
                 body: d.args.get(0).map(|s| Expr::String(s.clone())),
                 headers: Default::default(),
             }))
        },
        "file_server" => {
            let mut root = ".".to_string();
            // Caddy pattern: file_server [<matcher>] [<root>]
            // Here <matcher> already handled by caller if it was @name.
            // If first arg is not @, it might be the root.
            if let Some(arg) = d.args.get(0) {
                root = arg.clone();
            }
            
            let mut config = FileServerConfig {
                root,
                index: vec!["index.html".into()],
                browse: false,
                compress: true,
            };
            
            if let Some(block) = d.block {
                for sub in block.directives {
                    match sub.name.as_str() {
                        "root" => if let Some(arg) = sub.args.get(0) { config.root = arg.clone(); },
                        "index" => config.index = sub.args.clone(),
                        "browse" => config.browse = sub.args.get(0).map(|s| s == "true").unwrap_or(true),
                        _ => {}
                    }
                }
            }
            Ok(Handler::FileServer(config))
        },
        "headers" => {
            let mut config = HeadersConfig::default();
            if let Some(block) = d.block {
                for sub in block.directives {
                    match sub.name.as_str() {
                        "set" | "header" => {
                            if sub.args.len() >= 2 {
                                config.set.insert(sub.args[0].clone(), sub.args[1].clone());
                            }
                        }
                        "add" => {
                            if sub.args.len() >= 2 {
                                config.add.insert(sub.args[0].clone(), sub.args[1].clone());
                            }
                        }
                        "remove" => {
                            for arg in sub.args { config.remove.push(arg); }
                        }
                        _ => {}
                    }
                }
            }
            Ok(Handler::Headers(config))
        },
        _ => Err(AdapterError::UnknownDirective(d.name)),
    }
}

fn parse_matcher_and_block(d: &Directive) -> Result<(Option<Matcher>, Option<&Block>), AdapterError> {
    let mut matcher = None;
    let block = d.block.as_ref();
    
    // Check first arg for @name
    if let Some(arg) = d.args.get(0) {
        if arg.starts_with('@') {
            matcher = Some(Matcher::Named(arg.clone()));
        }
    }
    
    Ok((matcher, block))
}

fn parse_matcher_definition(d: &Directive) -> Result<Matcher, AdapterError> {
    if let Some(block) = &d.block {
        let mut matchers = Vec::new();
        for sub in &block.directives {
            matchers.push(parse_single_matcher(sub)?);
        }
        
        if matchers.is_empty() {
             return Err(AdapterError::InvalidArgument(d.name.clone(), "Empty matcher block".into()));
        }
        
        let mut combined = matchers.remove(0);
        for m in matchers {
            combined = Matcher::And(Box::new(combined), Box::new(m));
        }
        Ok(combined)
    } else {
        // Inline matcher: @api path /v1/*
        // Convert the rest of d.args into a directive and parse it
        if d.args.is_empty() {
            return Err(AdapterError::ArgumentCount(d.name.clone(), 1, 0));
        }
        let sub_directive = Directive {
            name: d.args[0].clone(),
            args: d.args[1..].to_vec(),
            block: None,
        };
        parse_single_matcher(&sub_directive)
    }
}

fn parse_single_matcher(d: &Directive) -> Result<Matcher, AdapterError> {
    match d.name.as_str() {
        "path" => {
            Ok(Matcher::Path(PathMatcher { patterns: d.args.clone() }))
        }
        "method" => {
            let methods = d.args.iter().filter_map(|m| match m.to_uppercase().as_str() {
                "GET" => Some(HttpMethod::Get),
                "POST" => Some(HttpMethod::Post),
                "PUT" => Some(HttpMethod::Put),
                "DELETE" => Some(HttpMethod::Delete),
                _ => None,
            }).collect();
            Ok(Matcher::Method(methods))
        }
        "header" => {
            if d.args.len() < 2 { return Err(AdapterError::ArgumentCount("header".into(), 2, d.args.len())); }
            Ok(Matcher::Header(HeaderMatcher {
                name: d.args[0].clone(),
                condition: HeaderCondition::Equals(d.args[1].clone()),
            }))
        }
        _ => Err(AdapterError::UnknownDirective(format!("matcher: {}", d.name))),
    }
}

fn add_route(server: &mut ServerBlock, matcher: Option<Matcher>, handler: Handler) {
    if server.routes.is_none() {
        server.routes = Some(Node::new(RouteBlock { arms: Vec::new() }, Location{start:0, end:0}));
    }
    let routes = server.routes.as_mut().unwrap();
    routes.inner.arms.push(Node::new(RouteArm {
        matcher,
        handler,
    }, Location{start:0, end:0}));
}

#[cfg(test)]
mod global_tests {
    use super::*;
    use crate::parser::parse;

    #[test]
    fn test_global_block_parsing() {
        let source = r#"{
            email admin@example.com
            auto_https off
            debug true
        }"#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();
        
        let global = ast.global.unwrap().inner;
        assert_eq!(global.email, Some("admin@example.com".to_string()));
        assert_eq!(global.auto_https, Some(AutoHttpsMode::Off));
        assert_eq!(global.debug, Some(true));
    }

    #[test]
    fn test_multi_listener_adaptation() {
        let source = ":8080 :8081 { respond \"Hello\" }";
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();
        
        assert_eq!(ast.servers.len(), 1);
        let server = &ast.servers[0].inner;
        assert_eq!(server.listens.len(), 2);
        assert_eq!(server.listens[0].port, Some(8080));
        assert_eq!(server.listens[1].port, Some(8081));
    }
}
