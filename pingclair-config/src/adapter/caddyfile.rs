//! Adapter for converting Generic Caddyfile AST to Typed AST
//!
//! 🏗️ ARCHITECTURE: Two-pass adapter:
//!   Pass 1: Collect snippet definitions `(name) { ... }` and expand `import name`
//!   Pass 2: Convert the expanded generic directives into the Typed AST

use crate::parser::ast::*;
use crate::parser::caddy_ast::{Directive, Block};
use crate::parser::lexer::Location;
use thiserror::Error;
use std::collections::HashMap;

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

    #[error("Undefined snippet '{0}'")]
    UndefinedSnippet(String),

    #[error("Recursive snippet import detected: '{0}'")]
    RecursiveSnippet(String),
}

// MARK: - Snippet Expansion (Pass 1)

/// Collect snippet `(name) { ... }` definitions from top-level directives
/// and return (snippets_map, remaining_directives).
fn collect_snippets(
    directives: Vec<Directive>,
) -> Result<(HashMap<String, Vec<Directive>>, Vec<Directive>), AdapterError> {
    let mut snippets: HashMap<String, Vec<Directive>> = HashMap::new();
    let mut remaining = Vec::new();

    for d in directives {
        if d.name.starts_with('(') && d.name.ends_with(')') {
            // Snippet definition: (name) { ... }
            let snippet_name = d.name[1..d.name.len() - 1].to_string();
            let body = d.block
                .map(|b| b.directives)
                .unwrap_or_default();
            snippets.insert(snippet_name, body);
        } else {
            remaining.push(d);
        }
    }

    Ok((snippets, remaining))
}

/// Recursively expand `import snippet_name` directives.
///
/// 🛑 SAFETY: Tracks expansion depth to prevent infinite recursion
/// from circular snippet references (limit: 16).
fn expand_imports(
    directives: Vec<Directive>,
    snippets: &HashMap<String, Vec<Directive>>,
    depth: usize,
) -> Result<Vec<Directive>, AdapterError> {
    if depth > 16 {
        return Err(AdapterError::RecursiveSnippet("nesting too deep".into()));
    }

    let mut result = Vec::new();
    for d in directives {
        if d.name == "import" {
            if let Some(name) = d.args.first() {
                let body = snippets.get(name).ok_or_else(|| {
                    AdapterError::UndefinedSnippet(name.clone())
                })?;
                // Recursively expand in case the snippet itself imports others
                let expanded = expand_imports(body.clone(), snippets, depth + 1)?;
                result.extend(expanded);
            }
        } else {
            // Recursively expand imports inside blocks
            let expanded_block = if let Some(block) = d.block {
                let expanded_body = expand_imports(block.directives, snippets, depth + 1)?;
                Some(Block { directives: expanded_body })
            } else {
                None
            };
            result.push(Directive {
                name: d.name,
                args: d.args,
                block: expanded_block,
            });
        }
    }
    Ok(result)
}

// MARK: - Main Adapter (Pass 2)

/// Convert generic directives to Typed AST
pub fn adapt(directives: Vec<Directive>) -> Result<Ast, AdapterError> {
    // Pass 1: Snippet collection + import expansion
    let (snippets, remaining) = collect_snippets(directives)?;
    let expanded = expand_imports(remaining, &snippets, 0)?;

    // Pass 2: Convert to typed AST
    let mut ast = Ast::default();

    for d in expanded {
        if d.name.is_empty() || d.name == "global" || d.name == "options" {
            if ast.global.is_some() {
                return Err(AdapterError::DuplicateGlobal);
            }
            ast.global = Some(Node::new(adapt_global(d)?, Location { start: 0, end: 0 }));
        } else if d.name == "macro" {
            // 🐛 TODO: Support macros in Caddyfile?
            // Caddy uses snippets (import), which we now handle above.
        } else {
            let server = adapt_server(d)?;
            ast.servers.push(Node::new(server, Location { start: 0, end: 0 }));
        }
    }

    Ok(ast)
}

// MARK: - Global Block

fn adapt_global(d: Directive) -> Result<GlobalBlock, AdapterError> {
    let mut global = GlobalBlock::default();
    if let Some(block) = d.block {
        // ⚡ OPTIMIZATION: Flatten nested `servers { ... }` block into the
        // global config, matching Caddy's { servers { protocols h1 h2 } } syntax.
        let directives = expand_servers_block(block.directives);

        for sub in directives {
            match sub.name.as_str() {
                "debug" => {
                    global.debug = Some(sub.args.first().map(|s| s == "true").unwrap_or(true));
                }
                "email" => {
                    global.email = sub.args.first().cloned();
                }
                "auto_https" => {
                    if let Some(arg) = sub.args.first() {
                        match arg.as_str() {
                            "on" => global.auto_https = Some(AutoHttpsMode::On),
                            "off" => global.auto_https = Some(AutoHttpsMode::Off),
                            "disable_redirects" => global.auto_https = Some(AutoHttpsMode::DisableRedirects),
                            _ => return Err(AdapterError::InvalidArgument("auto_https".into(), arg.clone())),
                        }
                    }
                }
                "protocols" => {
                    for arg in &sub.args {
                        match arg.to_lowercase().as_str() {
                            "h1" => global.protocols.push(Protocol::H1),
                            "h2" => global.protocols.push(Protocol::H2),
                            "h3" => global.protocols.push(Protocol::H3),
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

/// Flatten Caddy's nested `servers { ... }` block.
///
/// Caddy allows:
/// ```text
/// {
///     servers {
///         protocols h1 h2
///     }
/// }
/// ```
/// We flatten `servers` children up to the parent level.
fn expand_servers_block(directives: Vec<Directive>) -> Vec<Directive> {
    let mut result = Vec::new();
    for d in directives {
        if d.name == "servers" {
            if let Some(block) = d.block {
                result.extend(block.directives);
            }
        } else {
            result.push(d);
        }
    }
    result
}

// MARK: - Server Block

fn adapt_server(d: Directive) -> Result<ServerBlock, AdapterError> {
    let mut server = ServerBlock::new(d.name.clone());

    // Parse server address(es) — support schemes like http://host:port
    let mut names = vec![d.name.clone()];
    for arg in &d.args {
        if arg.starts_with(':') || arg.contains(':') || arg.contains('.') || *arg == "localhost" {
            names.push(arg.clone());
        }
    }

    for name in &names {
        if let Some(parsed) = parse_server_address(name) {
            server.listens.push(parsed.listen);
            // Use the bare hostname (not the URL) as server name
            if !parsed.hostname.is_empty() && parsed.hostname != "0.0.0.0" {
                server.name = parsed.hostname;
            }
        }
    }

    // Fallback: if server name is still a full URL, strip it
    if server.name.contains("://") {
        if let Some(parsed) = parse_server_address(&server.name) {
            server.name = parsed.hostname;
        }
    }

    if server.listens.len() > 1 || server.name.starts_with(':') {
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
                "compress" | "encode" => {
                    // Caddy uses `encode gzip` / `encode zstd`
                    for arg in &sub_d.args {
                        match arg.to_lowercase().as_str() {
                            "gzip" => server.compress.push(CompressionAlgo::Gzip),
                            "br" | "brotli" => server.compress.push(CompressionAlgo::Br),
                            "zstd" => server.compress.push(CompressionAlgo::Zstd),
                            _ => {}
                        }
                    }
                    // If `encode` has no args, default to gzip
                    if sub_d.args.is_empty() {
                        server.compress.push(CompressionAlgo::Gzip);
                    }
                },
                "log" => {
                    if let Some(log_block) = sub_d.block {
                        let log = adapt_log_block(log_block)?;
                        server.log = Some(Node::new(log, Location { start: 0, end: 0 }));
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
                },
                "header" => {
                    // Caddy `header` directive at server level:
                    //   header @matcher Key "Value"
                    //   header { -Server ... }
                    let handler = adapt_header_directive(&sub_d)?;
                    let (matcher, _) = parse_matcher_and_block(&sub_d)?;
                    if matcher.is_some() {
                        add_route(&mut server, matcher, handler);
                    } else {
                        default_handlers.push(handler);
                    }
                },
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

// MARK: - URL Address Parsing

struct ParsedAddress {
    hostname: String,
    listen: ListenAddr,
}

/// Parse a Caddy server address like `http://ai.408timeout.com:20615`
/// or `:8080` or `example.com`.
fn parse_server_address(addr: &str) -> Option<ParsedAddress> {
    let (scheme, rest) = if let Some(stripped) = addr.strip_prefix("https://") {
        (Scheme::Https, stripped)
    } else if let Some(stripped) = addr.strip_prefix("http://") {
        (Scheme::Http, stripped)
    } else {
        (Scheme::Http, addr)
    };

    // rest is either: "host:port", ":port", "host", ""
    if rest.is_empty() {
        return None;
    }

    let (hostname, port) = if rest.starts_with(':') {
        // :port
        let p = rest[1..].parse::<u16>().ok();
        ("0.0.0.0".to_string(), p)
    } else if let Some(colon_pos) = rest.rfind(':') {
        // host:port
        let h = &rest[..colon_pos];
        let p = rest[colon_pos + 1..].parse::<u16>().ok();
        (h.to_string(), p)
    } else {
        // host only (default port based on scheme)
        let p = match scheme {
            Scheme::Https => Some(443),
            Scheme::Http => Some(80),
        };
        (rest.to_string(), p)
    };

    Some(ParsedAddress {
        hostname: hostname.clone(),
        listen: ListenAddr {
            scheme,
            host: hostname,
            port,
        },
    })
}

// MARK: - Log Block

fn adapt_log_block(block: Block) -> Result<LogBlock, AdapterError> {
    let mut output = LogOutput::Stdout;
    let mut format = LogFormat::default();

    for d in block.directives {
        match d.name.as_str() {
            "output" => {
                if let Some(kind) = d.args.first() {
                    match kind.as_str() {
                        "file" => {
                            if let Some(path) = d.args.get(1) {
                                output = LogOutput::File(path.clone());
                            }
                        }
                        "stdout" => output = LogOutput::Stdout,
                        "stderr" => output = LogOutput::Stderr,
                        _ => {}
                    }
                }
            }
            "format" => {
                if let Some(kind) = d.args.first() {
                    match kind.as_str() {
                        "json" => format.format_type = LogFormatType::Json,
                        "filter" => {
                            // `format filter { wrap json ... }` → extract "json"
                            format.format_type = LogFormatType::Json;
                            if let Some(filter_block) = d.block {
                                let mut filter = LogFilter::default();
                                for fb_d in filter_block.directives {
                                    if fb_d.name == "wrap" {
                                        if let Some(wrap_type) = fb_d.args.first() {
                                            match wrap_type.as_str() {
                                                "json" => format.format_type = LogFormatType::Json,
                                                _ => {}
                                            }
                                        }
                                    }
                                    if fb_d.name == "fields" {
                                        if let Some(fields_block) = fb_d.block {
                                            for field_d in fields_block.directives {
                                                // field_name "delete" → exclude field
                                                if field_d.args.first().map(|a| a.as_str()) == Some("delete") {
                                                    filter.exclude.push(field_d.name);
                                                }
                                            }
                                        }
                                    }
                                }
                                format.filter = Some(filter);
                            }
                        }
                        _ => format.format_type = LogFormatType::Text,
                    }
                }
            }
            _ => {}
        }
    }

    Ok(LogBlock { output, format })
}

// MARK: - Handler Adaptation

fn adapt_handler(d: Directive) -> Result<Handler, AdapterError> {
    match d.name.as_str() {
        "reverse_proxy" => {
            adapt_reverse_proxy(d)
        },
        "respond" => {
            adapt_respond(d)
        },
        "file_server" => {
            let mut root = ".".to_string();
            if let Some(arg) = d.args.first() {
                if !arg.starts_with('@') {
                    root = arg.clone();
                }
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
                        "root" => if let Some(arg) = sub.args.first() { config.root = arg.clone(); },
                        "index" => config.index = sub.args.clone(),
                        "browse" => config.browse = sub.args.first().map(|s| s == "true").unwrap_or(true),
                        _ => {}
                    }
                }
            }
            Ok(Handler::FileServer(config))
        },
        "header" => {
            adapt_header_directive(&d)
        },
        "handle" => {
            // `handle { ... }` inside another handle — nested exclusive routing
            let mut handlers = Vec::new();
            if let Some(block) = d.block {
                for inner_d in block.directives {
                    handlers.push(adapt_handler(inner_d)?);
                }
            }
            Ok(Handler::Handle(handlers))
        },
        _ => Err(AdapterError::UnknownDirective(d.name)),
    }
}

// MARK: - reverse_proxy Full Block Parsing

/// Adapt a `reverse_proxy` directive with full sub-block support.
///
/// Handles:
/// - `reverse_proxy host:port` (simple, args-only)
/// - `reverse_proxy host:port { header_up K V; flush_interval -1; transport http { ... } }`
fn adapt_reverse_proxy(d: Directive) -> Result<Handler, AdapterError> {
    // Collect upstreams from args (filter out matcher @names)
    let upstreams: Vec<String> = d.args.iter()
        .filter(|a| !a.starts_with('@'))
        .cloned()
        .collect();

    let mut proxy = ProxyConfig::new(upstreams);

    // Parse sub-block if present
    if let Some(block) = d.block {
        for sub in block.directives {
            match sub.name.as_str() {
                "header_up" => {
                    // header_up Key Value
                    // Value may be a {placeholder} → preserved as-is for runtime resolution
                    if sub.args.len() >= 2 {
                        let key = sub.args[0].clone();
                        let value = sub.args[1].clone();
                        proxy.header_up.insert(
                            key,
                            Expr::String(value),
                        );
                    }
                }
                "header_down" => {
                    // 🐛 TODO: header_down is not yet tracked in ProxyConfig AST.
                    // For now, silently ignore.
                }
                "flush_interval" => {
                    if let Some(val) = sub.args.first() {
                        if val == "-1" {
                            proxy.flush_interval = Some(FlushInterval::Immediate);
                        } else if let Ok(ms) = val.parse::<u64>() {
                            proxy.flush_interval = Some(FlushInterval::Duration(ms));
                        }
                    }
                }
                "transport" => {
                    // transport http { read_timeout 300s; write_timeout 300s }
                    if let Some(transport_block) = sub.block {
                        let mut transport = TransportConfig {
                            read_timeout: None,
                            write_timeout: None,
                        };
                        for t_sub in transport_block.directives {
                            match t_sub.name.as_str() {
                                "read_timeout" => {
                                    transport.read_timeout = t_sub.args.first()
                                        .and_then(|s| parse_duration_ms(s));
                                }
                                "write_timeout" => {
                                    transport.write_timeout = t_sub.args.first()
                                        .and_then(|s| parse_duration_ms(s));
                                }
                                _ => {}
                            }
                        }
                        proxy.transport = Some(transport);
                    }
                }
                "lb_policy" => {
                    // lb_policy round_robin / random / least_conn / ip_hash
                    // Not in AST ProxyConfig but will be consumed by core loader
                }
                _ => {}
            }
        }
    }

    Ok(Handler::Proxy(Box::new(proxy)))
}

/// Parse Caddy duration strings like "300s", "5m", "100ms" into milliseconds.
fn parse_duration_ms(s: &str) -> Option<u64> {
    if let Some(secs) = s.strip_suffix('s') {
        if let Some(ms) = secs.strip_suffix('m') {
            // "100ms" → strip 's' first gets "100m", then strip 'm' gets "100"
            return ms.parse::<u64>().ok();
        }
        return secs.parse::<u64>().ok().map(|v| v * 1000);
    }
    if let Some(mins) = s.strip_suffix('m') {
        return mins.parse::<u64>().ok().map(|v| v * 60_000);
    }
    // Plain number → milliseconds
    s.parse::<u64>().ok()
}

// MARK: - respond Full Parsing

/// Adapt `respond` directive: `respond ["body"] [status_code]`
///
/// Caddy allows multiple forms:
///   respond "body" 403
///   respond 404
///   respond "body"
fn adapt_respond(d: Directive) -> Result<Handler, AdapterError> {
    let mut status: u16 = 200;
    let mut body: Option<Expr> = None;

    match d.args.len() {
        0 => {
            // respond → 200 empty
        }
        1 => {
            let arg = &d.args[0];
            if let Ok(code) = arg.parse::<u16>() {
                status = code;
            } else {
                body = Some(Expr::String(arg.clone()));
            }
        }
        2 => {
            // respond "body" 403  OR  respond 403 "body"
            if let Ok(code) = d.args[1].parse::<u16>() {
                body = Some(Expr::String(d.args[0].clone()));
                status = code;
            } else if let Ok(code) = d.args[0].parse::<u16>() {
                status = code;
                body = Some(Expr::String(d.args[1].clone()));
            } else {
                body = Some(Expr::String(d.args[0].clone()));
            }
        }
        _ => {
            // First arg is body, last arg might be status
            body = Some(Expr::String(d.args[0].clone()));
            if let Some(last) = d.args.last() {
                if let Ok(code) = last.parse::<u16>() {
                    status = code;
                }
            }
        }
    }

    Ok(Handler::Respond(ResponseConfig {
        status,
        body,
        headers: Default::default(),
    }))
}

// MARK: - header Directive Adapter

/// Adapt Caddy `header` directive which can be:
/// - `header @matcher Key "Value"` (set a header conditionally)
/// - `header { -Server; Key "Value" }` (block form with set/remove)
/// - `header -Server` (inline remove, prefix `-`)
fn adapt_header_directive(d: &Directive) -> Result<Handler, AdapterError> {
    let mut config = HeadersConfig::default();

    if let Some(block) = &d.block {
        for sub in &block.directives {
            if sub.name.starts_with('-') {
                // `-Header` → remove
                config.remove.push(sub.name[1..].to_string());
            } else if sub.name.starts_with('+') {
                // `+Header Value` → add
                if let Some(val) = sub.args.first() {
                    config.add.insert(sub.name[1..].to_string(), val.clone());
                }
            } else {
                // `Header Value` → set
                if let Some(val) = sub.args.first() {
                    config.set.insert(sub.name.clone(), val.clone());
                }
            }
        }
    } else {
        // Inline form: `header @matcher Key "Value"` or `header -Server`
        // Skip @matcher argument
        let args: Vec<&String> = d.args.iter()
            .filter(|a| !a.starts_with('@'))
            .collect();

        if let Some(key) = args.first() {
            if key.starts_with('-') {
                config.remove.push(key[1..].to_string());
            } else if let Some(val) = args.get(1) {
                config.set.insert((*key).clone(), (*val).clone());
            }
        }
    }

    Ok(Handler::Headers(config))
}

// MARK: - Matchers

fn parse_matcher_and_block(d: &Directive) -> Result<(Option<Matcher>, Option<&Block>), AdapterError> {
    let mut matcher = None;
    let block = d.block.as_ref();

    // Check first arg for @name
    if let Some(arg) = d.args.first() {
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
            if d.args.is_empty() { return Err(AdapterError::ArgumentCount("header".into(), 1, d.args.len())); }

            let condition = if d.args.len() >= 2 {
                let val = &d.args[1];
                if val == "*" {
                    HeaderCondition::Exists
                } else if val.starts_with("*") && val.ends_with("*") {
                    HeaderCondition::Contains(val[1..val.len()-1].to_string())
                } else {
                    HeaderCondition::Equals(val.clone())
                }
            } else {
                // Single arg: header exists
                HeaderCondition::Exists
            };

            Ok(Matcher::Header(HeaderMatcher {
                name: d.args[0].clone(),
                condition,
            }))
        }
        _ => Err(AdapterError::UnknownDirective(format!("matcher: {}", d.name))),
    }
}

// MARK: - Helpers

fn add_route(server: &mut ServerBlock, matcher: Option<Matcher>, handler: Handler) {
    if server.routes.is_none() {
        server.routes = Some(Node::new(RouteBlock { arms: Vec::new() }, Location { start: 0, end: 0 }));
    }
    let routes = server.routes.as_mut().unwrap();
    routes.inner.arms.push(Node::new(RouteArm {
        matcher,
        handler,
    }, Location { start: 0, end: 0 }));
}

// MARK: - Tests

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

    #[test]
    fn test_snippet_expansion() {
        let source = r#"
            (security_headers) {
                header -Server
                header X-Content-Type-Options "nosniff"
            }

            example.com {
                listen :80
                import security_headers
                respond "Hello"
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        assert_eq!(ast.servers.len(), 1);
        let server = &ast.servers[0].inner;
        // After expansion, the server should have handler directives from the snippet
        assert!(server.routes.is_some());
    }

    #[test]
    fn test_respond_with_status_code() {
        let source = r#"
            example.com {
                listen :80
                respond "Access Denied" 403
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let server = &ast.servers[0].inner;
        let routes = server.routes.as_ref().unwrap();
        let handler = &routes.inner.arms[0].inner.handler;
        if let Handler::Respond(cfg) = handler {
            assert_eq!(cfg.status, 403);
        } else {
            panic!("Expected Respond handler");
        }
    }

    #[test]
    fn test_reverse_proxy_block_parsing() {
        let source = r#"
            api.example.com {
                listen :80
                reverse_proxy 127.0.0.1:3000 {
                    header_up X-Forwarded-Proto https
                    header_up X-Real-IP {http.request.header.CF-Connecting-IP}
                    flush_interval -1
                    transport http {
                        read_timeout 300s
                        write_timeout 300s
                    }
                }
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let server = &ast.servers[0].inner;
        let routes = server.routes.as_ref().unwrap();
        let handler = &routes.inner.arms[0].inner.handler;
        if let Handler::Proxy(proxy) = handler {
            assert_eq!(proxy.upstreams, vec!["127.0.0.1:3000"]);
            assert!(proxy.header_up.contains_key("X-Forwarded-Proto"));
            assert!(proxy.header_up.contains_key("X-Real-IP"));
            assert!(matches!(proxy.flush_interval, Some(FlushInterval::Immediate)));
            assert!(proxy.transport.is_some());
            let t = proxy.transport.as_ref().unwrap();
            assert_eq!(t.read_timeout, Some(300_000));
            assert_eq!(t.write_timeout, Some(300_000));
        } else {
            panic!("Expected Proxy handler");
        }
    }

    #[test]
    fn test_http_url_address_parsing() {
        let source = r#"
            http://ai.408timeout.com:20615 {
                bind 127.0.0.1
                respond "OK"
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let server = &ast.servers[0].inner;
        assert_eq!(server.name, "ai.408timeout.com");
        assert_eq!(server.bind, Some("127.0.0.1".to_string()));
    }

    #[test]
    fn test_servers_nested_global() {
        let source = r#"{
            servers {
                protocols h1 h2
            }
        }"#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();
        let global = ast.global.unwrap().inner;
        assert_eq!(global.protocols.len(), 2);
        assert!(global.protocols.contains(&Protocol::H1));
        assert!(global.protocols.contains(&Protocol::H2));
    }

    #[test]
    fn test_nested_import() {
        let source = r#"
            (inner) {
                header X-Inner "true"
            }
            (outer) {
                import inner
                header X-Outer "true"
            }
            example.com {
                listen :80
                import outer
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();
        assert_eq!(ast.servers.len(), 1);
    }

    #[test]
    fn test_header_deletion_syntax() {
        let source = r#"
            example.com {
                listen :80
                header {
                    -Server
                    X-Content-Type-Options "nosniff"
                }
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();
        let server = &ast.servers[0].inner;
        let routes = server.routes.as_ref().unwrap();
        let handler = &routes.inner.arms[0].inner.handler;
        if let Handler::Headers(cfg) = handler {
            assert!(cfg.remove.contains(&"Server".to_string()));
            assert!(cfg.set.contains_key("X-Content-Type-Options"));
        } else {
            panic!("Expected Headers handler, got {:?}", handler);
        }
    }

    #[test]
    fn test_header_wildcard_matcher() {
        // Caddy: `header Cf-Access-Jwt-Assertion *` means header exists
        let source = r#"
            example.com {
                listen :80
                @cf_access {
                    header Cf-Access-Jwt-Assertion *
                }
                handle @cf_access {
                    respond "OK"
                }
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();
        let server = &ast.servers[0].inner;
        assert!(server.matchers.contains_key("@cf_access"));
    }
}
