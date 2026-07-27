// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Adapter for converting Generic Caddyfile AST to Typed AST
//!
//! 🏗️ ARCHITECTURE: Two-pass adapter:
//!   Pass 1: Collect snippet definitions `(name) { ... }` and expand `import name`
//!   Pass 2: Convert the expanded generic directives into the Typed AST

use crate::parser::ast::*;
use crate::parser::caddy_ast::{Block, Directive};
use crate::parser::lexer::Location;
use std::collections::HashMap;
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

    #[error("Undefined snippet '{0}'")]
    UndefinedSnippet(String),

    #[error("Recursive snippet import detected: '{0}'")]
    RecursiveSnippet(String),
}

// MARK: - Snippet Expansion (Pass 1)

type SnippetMap = HashMap<String, Vec<Directive>>;
type SnippetCollection = (SnippetMap, Vec<Directive>);

/// Collect snippet `(name) { ... }` definitions from top-level directives
/// and return (snippets_map, remaining_directives).
fn collect_snippets(directives: Vec<Directive>) -> Result<SnippetCollection, AdapterError> {
    let mut snippets = SnippetMap::new();
    let mut remaining = Vec::new();

    for d in directives {
        if d.name.starts_with('(') && d.name.ends_with(')') {
            // Snippet definition: (name) { ... }
            let snippet_name = d.name[1..d.name.len() - 1].to_string();
            let body = d.block.map(|b| b.directives).unwrap_or_default();
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
                let body = snippets
                    .get(name)
                    .ok_or_else(|| AdapterError::UndefinedSnippet(name.clone()))?;
                // Recursively expand in case the snippet itself imports others
                let expanded = expand_imports(body.clone(), snippets, depth + 1)?;
                result.extend(expanded);
            }
        } else {
            // Recursively expand imports inside blocks
            let expanded_block = if let Some(block) = d.block {
                let expanded_body = expand_imports(block.directives, snippets, depth + 1)?;
                Some(Block {
                    directives: expanded_body,
                })
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
            ast.servers
                .push(Node::new(server, Location { start: 0, end: 0 }));
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
                            "disable_redirects" => {
                                global.auto_https = Some(AutoHttpsMode::DisableRedirects)
                            }
                            _ => {
                                return Err(AdapterError::InvalidArgument(
                                    "auto_https".into(),
                                    arg.clone(),
                                ));
                            }
                        }
                    }
                }
                "admin" => {
                    match sub.args.first() {
                        // `admin off` explicitly disables the admin API
                        Some(arg) if arg == "off" => {
                            global.admin = Some(AdminDirective {
                                listen: String::new(),
                                enabled: false,
                                api_key: None,
                            });
                        }
                        // `admin <listen> [api_key]` — the optional second
                        // argument is the Bearer token for the admin API.
                        Some(arg) => {
                            global.admin = Some(AdminDirective {
                                listen: arg.clone(),
                                enabled: true,
                                api_key: sub.args.get(1).cloned(),
                            });
                        }
                        None => return Err(AdapterError::ArgumentCount("admin".into(), 1, 0)),
                    }
                }
                "trusted_proxies" => {
                    if sub.args.is_empty() {
                        return Err(AdapterError::ArgumentCount("trusted_proxies".into(), 1, 0));
                    }
                    for rule in sub.args {
                        let valid = rule.parse::<ipnet::IpNet>().is_ok()
                            || rule.parse::<std::net::IpAddr>().is_ok();
                        if !valid {
                            return Err(AdapterError::InvalidArgument(
                                "trusted_proxies".into(),
                                format!("invalid IP or CIDR `{rule}`"),
                            ));
                        }
                        global.trusted_proxies.push(rule);
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

/// 🧾 Validates exact, subtype-wildcard, and structured-suffix MIME patterns.
fn is_valid_mime_pattern(pattern: &str) -> bool {
    let Some((media_type, subtype)) = pattern.split_once('/') else {
        return false;
    };
    if media_type.is_empty() || subtype.is_empty() || subtype.contains('/') {
        return false;
    }
    if media_type == "*" {
        return subtype == "*";
    }
    if media_type.contains('*') {
        return false;
    }
    match subtype.find('*') {
        None => true,
        Some(0) => subtype[1..].find('*').is_none(),
        Some(_) => false,
    }
}

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
    if server.name.contains("://")
        && let Some(parsed) = parse_server_address(&server.name)
    {
        server.name = parsed.hostname;
    }

    if server.listens.len() > 1 || server.name.starts_with(':') {
        server.name = "_".to_string();
    }

    if let Some(block) = d.block {
        let mut default_handlers = Vec::new();

        for sub_d in block.directives {
            match sub_d.name.as_str() {
                "bind" => {
                    if sub_d.args.is_empty() {
                        return Err(AdapterError::ArgumentCount("bind".into(), 1, 0));
                    }
                    server.bind = Some(sub_d.args[0].clone());
                }
                "listen" => {
                    if sub_d.args.is_empty() {
                        return Err(AdapterError::ArgumentCount("listen".into(), 1, 0));
                    }
                    let addr = &sub_d.args[0];
                    server.listens.push(ListenAddr {
                        scheme: if addr.starts_with("https") {
                            Scheme::Https
                        } else {
                            Scheme::Http
                        },
                        host: "0.0.0.0".to_string(),
                        port: addr.split(':').next_back().and_then(|p| p.parse().ok()),
                    });
                }
                "compress" | "encode" => {
                    // Caddy spells this `encode zstd gzip`, and argument order
                    // is meaningful: it is the server's preference order when
                    // several codings are acceptable to the client.
                    //
                    // Unknown arguments are rejected rather than skipped. The
                    // old loop ignored them, so `encode gzipp` silently gave a
                    // server that still compressed (via the unconditional
                    // gzip path) and looked like it had honored the typo.
                    let mut algos = Vec::with_capacity(sub_d.args.len());
                    for arg in &sub_d.args {
                        let algo = match arg.to_lowercase().as_str() {
                            // `off`/`none` is the only way to opt a server out
                            // of response compression, so it may not be mixed
                            // with codings.
                            "off" | "none" => {
                                if sub_d.args.len() > 1 {
                                    return Err(AdapterError::InvalidArgument(
                                        sub_d.name.clone(),
                                        "`off` cannot be combined with other codings".into(),
                                    ));
                                }
                                server.compress = Some(Vec::new());
                                continue;
                            }
                            "gzip" => CompressionAlgo::Gzip,
                            "br" | "brotli" => CompressionAlgo::Br,
                            "zstd" => CompressionAlgo::Zstd,
                            other => {
                                return Err(AdapterError::InvalidArgument(
                                    sub_d.name.clone(),
                                    format!(
                                        "unknown coding `{other}` (expected gzip, zstd, br or off)"
                                    ),
                                ));
                            }
                        };
                        // Duplicates would just be dead entries in the
                        // preference list; keep the first mention's rank.
                        if !algos.contains(&algo) {
                            algos.push(algo);
                        }
                    }
                    // Bare `encode` with no arguments means gzip, as before.
                    if sub_d.args.is_empty() {
                        algos.push(CompressionAlgo::Gzip);
                    }
                    if !algos.is_empty() {
                        server.compress = Some(algos);
                    }
                }
                "gzip_types" => {
                    if sub_d.args.is_empty() {
                        return Err(AdapterError::InvalidArgument(
                            "gzip_types".into(),
                            "at least one MIME pattern is required".into(),
                        ));
                    }
                    if let Some(pattern) = sub_d
                        .args
                        .iter()
                        .find(|pattern| !is_valid_mime_pattern(pattern))
                    {
                        return Err(AdapterError::InvalidArgument(
                            "gzip_types".into(),
                            format!("invalid MIME pattern `{pattern}`"),
                        ));
                    }
                    server.gzip_types = sub_d.args;
                }
                "log" => {
                    if let Some(log_block) = sub_d.block {
                        let log = adapt_log_block(log_block)?;
                        server.log = Some(Node::new(log, Location { start: 0, end: 0 }));
                    }
                }
                "tls" => {
                    server.tls = Some(adapt_tls_directive(&sub_d)?);
                }
                "error_page" => {
                    // nginx-style: error_page 404 /404.html
                    //              error_page 500 502 503 504 /50x.html
                    if sub_d.args.len() < 2 {
                        return Err(AdapterError::ArgumentCount(
                            "error_page".into(),
                            2,
                            sub_d.args.len(),
                        ));
                    }
                    let page = sub_d.args.last().unwrap().clone();
                    for code_str in &sub_d.args[..sub_d.args.len() - 1] {
                        let code = code_str.parse::<u16>().map_err(|_| {
                            AdapterError::InvalidArgument("error_page".into(), code_str.clone())
                        })?;
                        if !(400..=599).contains(&code) {
                            return Err(AdapterError::InvalidArgument(
                                "error_page".into(),
                                format!("status {code} is not an error code"),
                            ));
                        }
                        server.error_pages.push((code, page.clone()));
                    }
                }
                "route" | "handle" => {
                    let (matcher, inner_block) = parse_route_matcher_and_block(&sub_d)?;
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
                }
                name if name.starts_with('@') => {
                    // Named matcher definition
                    let matcher = parse_matcher_definition(&sub_d)?;
                    server.matchers.insert(name.to_string(), matcher);
                }
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
                }
                _ => {
                    // Try to extract matcher and adapt as handler
                    let (matcher, _) = parse_matcher_and_block(&sub_d)?;
                    let mut handler_d = sub_d.clone();
                    if matcher.is_some() {
                        if handler_d.args.is_empty() {
                            return Err(AdapterError::ArgumentCount(sub_d.name, 1, 0));
                        }
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
                default_handlers[0].clone()
            } else {
                Handler::Pipeline(default_handlers.clone())
            };

            if let Some(routes) = server.routes.as_mut() {
                for arm in &mut routes.inner.arms {
                    if !handler_has_terminal(&arm.inner.handler) {
                        arm.inner.handler = compose_with_default_handlers(
                            arm.inner.handler.clone(),
                            &default_handlers,
                        );
                    }
                }
            }

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

    let (hostname, port) = if let Some(port) = rest.strip_prefix(':') {
        // :port
        let p = port.parse::<u16>().ok();
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

    // Caddy/nginx semantics: only an IP literal in the site address is a
    // bind address. A *hostname* selects the virtual host via the Host
    // header while the listener binds all interfaces. Previously the
    // hostname was passed literally to Pingora as the bind host, so
    // `bench.local:8080 { ... }` crashed at startup with a BindError unless
    // the name happened to resolve to a local interface (localhost worked,
    // real domains didn't) — see benchmarks/README.md.
    let bind_host = if is_ip_literal(&hostname) {
        hostname.clone()
    } else {
        "0.0.0.0".to_string()
    };

    Some(ParsedAddress {
        hostname,
        listen: ListenAddr {
            scheme,
            host: bind_host,
            port,
        },
    })
}

/// Whether `host` is an IP literal (bare or bracketed IPv6 included) rather
/// than a hostname.
fn is_ip_literal(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
        || host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .is_some_and(|h| h.parse::<std::net::IpAddr>().is_ok())
}

// MARK: - 🔐 TLS Directive

/// 🔐 Adapts the supported downstream TLS directive forms.
fn adapt_tls_directive(d: &Directive) -> Result<TlsDirective, AdapterError> {
    let mut tls = TlsDirective::default();

    if let Some(block) = &d.block {
        for sub in &block.directives {
            match sub.name.as_str() {
                "cert" => tls.cert = sub.args.first().cloned(),
                "key" => tls.key = sub.args.first().cloned(),
                "acme_email" | "email" => tls.acme_email = sub.args.first().cloned(),
                "auto" => tls.auto = true,
                "internal" => {
                    if !sub.args.is_empty() {
                        return Err(AdapterError::InvalidArgument(
                            "tls internal".into(),
                            "expected no arguments".into(),
                        ));
                    }
                    tls.internal = true;
                }
                "http3" => {
                    tls.http3 = Some(
                        sub.args
                            .first()
                            .map(|s| s != "off" && s != "false")
                            .unwrap_or(true),
                    );
                }
                _ => return Err(AdapterError::UnknownDirective(format!("tls: {}", sub.name))),
            }
        }
    } else {
        match d.args.as_slice() {
            [arg] if arg == "off" => tls.off = true,
            [arg] if arg == "auto" => tls.auto = true,
            [arg] if arg == "internal" => tls.internal = true,
            [cert, key] => {
                tls.cert = Some(cert.clone());
                tls.key = Some(key.clone());
            }
            _ => {
                return Err(AdapterError::InvalidArgument(
                    "tls".into(),
                    "expected 'off', 'auto', 'internal', '<cert> <key>', or a block".into(),
                ));
            }
        }
    }

    // 🔗 A certificate without its matching private key is unusable.
    if tls.cert.is_some() != tls.key.is_some() {
        return Err(AdapterError::InvalidArgument(
            "tls".into(),
            "cert and key must be specified together".into(),
        ));
    }

    // 🛡️ A local issuer must never fall through to manual or public issuance.
    if tls.internal && (tls.auto || tls.cert.is_some() || tls.acme_email.is_some()) {
        return Err(AdapterError::InvalidArgument(
            "tls".into(),
            "internal cannot be combined with auto, cert/key, or an ACME email".into(),
        ));
    }

    Ok(tls)
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
                        "text" => format.format_type = LogFormatType::Text,
                        "filter" => {
                            // `format filter { wrap <json|text> ... }`.
                            // JSON is the default here because a filter block
                            // exists to drop fields, which only structured
                            // output makes meaningful — but an explicit
                            // `wrap text` must still win. This previously
                            // pinned Json before reading `wrap` at all, so
                            // `wrap text` was impossible to express.
                            format.format_type = LogFormatType::Json;
                            if let Some(filter_block) = d.block {
                                let mut filter = LogFilter::default();
                                for fb_d in filter_block.directives {
                                    if fb_d.name == "wrap" {
                                        match fb_d.args.first().map(|s| s.as_str()) {
                                            Some("json") => {
                                                format.format_type = LogFormatType::Json
                                            }
                                            Some("text") | Some("console") => {
                                                format.format_type = LogFormatType::Text
                                            }
                                            _ => {}
                                        }
                                    }
                                    if fb_d.name == "fields"
                                        && let Some(fields_block) = fb_d.block
                                    {
                                        for field_d in fields_block.directives {
                                            // field_name "delete" → exclude field
                                            if field_d.args.first().map(|a| a.as_str())
                                                == Some("delete")
                                            {
                                                filter.exclude.push(field_d.name);
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
        "reverse_proxy" => adapt_reverse_proxy(d),
        "respond" => adapt_respond(d),
        "redir" | "redirect" => adapt_redirect(d),
        "file_server" => {
            let mut root = ".".to_string();
            if let Some(arg) = d.args.first()
                && !arg.starts_with('@')
            {
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
                        "root" => {
                            if let Some(arg) = sub.args.first() {
                                config.root = arg.clone();
                            }
                        }
                        "index" => config.index = sub.args.clone(),
                        "browse" => {
                            config.browse = sub.args.first().map(|s| s == "true").unwrap_or(true)
                        }
                        _ => {}
                    }
                }
            }
            Ok(Handler::FileServer(config))
        }
        "header" => adapt_header_directive(&d),
        "handle" => {
            // `handle { ... }` inside another handle — nested exclusive routing
            let mut handlers = Vec::new();
            if let Some(block) = d.block {
                for inner_d in block.directives {
                    handlers.push(adapt_handler(inner_d)?);
                }
            }
            Ok(Handler::Handle(handlers))
        }
        "basic_auth" | "basicauth" => adapt_basic_auth(d),
        "rewrite" => adapt_rewrite(d),
        "cors" => adapt_cors(d),
        "access_control" => adapt_access_control(d),
        _ => Err(AdapterError::UnknownDirective(d.name)),
    }
}

fn adapt_redirect(d: Directive) -> Result<Handler, AdapterError> {
    if d.block.is_some() {
        return Err(AdapterError::BlockNotAllowed(d.name));
    }

    let (to, code) = match d.args.as_slice() {
        [to] => (to.clone(), 302),
        [to, code] => {
            let code = match code.as_str() {
                "temporary" => 302,
                "permanent" => 301,
                value => value.parse::<u16>().map_err(|_| {
                    AdapterError::InvalidArgument(d.name.clone(), value.to_string())
                })?,
            };
            (to.clone(), code)
        }
        _ => {
            return Err(AdapterError::InvalidArgument(
                d.name,
                "expected <location> [3xx|temporary|permanent]".into(),
            ));
        }
    };

    if !(300..=399).contains(&code) {
        return Err(AdapterError::InvalidArgument(
            d.name,
            format!("status {code} is not a redirect code"),
        ));
    }

    Ok(Handler::Redirect(RedirectConfig { to, code }))
}

/// Adapt `rewrite <replacement>` or `rewrite <regex> <replacement>`.
///
/// The two-argument form is deliberately explicit: it keeps a plain
/// replacement from accidentally treating punctuation as a regex and maps
/// capture groups directly to Rust-regex's `$1` replacement syntax.
fn adapt_rewrite(d: Directive) -> Result<Handler, AdapterError> {
    if d.block.is_some() {
        return Err(AdapterError::BlockNotAllowed("rewrite".into()));
    }
    match d.args.as_slice() {
        [replace] => Ok(Handler::Rewrite(RewriteConfig {
            replace: Some(replace.clone()),
            regex: None,
            regex_replace: None,
        })),
        [regex, replacement] => Ok(Handler::Rewrite(RewriteConfig {
            replace: None,
            regex: Some(regex.clone()),
            regex_replace: Some(replacement.clone()),
        })),
        _ => Err(AdapterError::InvalidArgument(
            "rewrite".into(),
            "expected <replacement> or <regex> <replacement>".into(),
        )),
    }
}

/// Adapt the CORS directive. Inline arguments are allowed origins; block
/// subdirectives are `origins`, `methods`, `headers`, `expose_headers`,
/// `allow_credentials`, and `max_age`.
fn adapt_cors(d: Directive) -> Result<Handler, AdapterError> {
    let mut config = CorsConfig {
        allowed_origins: d.args,
        ..Default::default()
    };
    if let Some(block) = d.block {
        for sub in block.directives {
            match sub.name.as_str() {
                "origins" => config.allowed_origins = sub.args,
                "methods" => config.allowed_methods = sub.args,
                "headers" => config.allowed_headers = sub.args,
                "expose_headers" => config.exposed_headers = sub.args,
                "allow_credentials" => {
                    config.allow_credentials = sub
                        .args
                        .first()
                        .map(|value| value == "true" || value == "on")
                        .unwrap_or(true);
                }
                "max_age" => {
                    let value = sub
                        .args
                        .first()
                        .ok_or_else(|| AdapterError::ArgumentCount("cors max_age".into(), 1, 0))?;
                    config.max_age = Some(value.parse().map_err(|_| {
                        AdapterError::InvalidArgument("cors max_age".into(), value.clone())
                    })?);
                }
                _ => {
                    return Err(AdapterError::UnknownDirective(format!(
                        "cors: {}",
                        sub.name
                    )));
                }
            }
        }
    }
    Ok(Handler::Cors(config))
}

/// Adapt route access control. Each subdirective accepts one or more values:
/// `allow_ip`, `deny_ip`, `allow_referer`, `deny_referer`, `allow_user_agent`,
/// and `deny_user_agent`.
fn adapt_access_control(d: Directive) -> Result<Handler, AdapterError> {
    if !d.args.is_empty() || d.block.is_none() {
        return Err(AdapterError::InvalidArgument(
            "access_control".into(),
            "expected a block of allow_/deny_ rules".into(),
        ));
    }
    let mut config = AccessControlConfig::default();
    for sub in d.block.unwrap().directives {
        if sub.args.is_empty() {
            return Err(AdapterError::ArgumentCount(sub.name, 1, 0));
        }
        match sub.name.as_str() {
            "allow_ip" => config.allowed_ips.extend(sub.args),
            "deny_ip" => config.denied_ips.extend(sub.args),
            "allow_referer" => config.allowed_referers.extend(sub.args),
            "deny_referer" => config.denied_referers.extend(sub.args),
            "allow_user_agent" => config.allowed_user_agents.extend(sub.args),
            "deny_user_agent" => config.denied_user_agents.extend(sub.args),
            _ => {
                return Err(AdapterError::UnknownDirective(format!(
                    "access_control: {}",
                    sub.name
                )));
            }
        }
    }
    Ok(Handler::AccessControl(config))
}

// MARK: - basic_auth Directive Adapter

/// 🔐 Adapts the `basic_auth` directive.
///
/// Supported forms are:
///   basic_auth <user> <password> [<user2> <password2>...]
///   basic_auth {
///       realm "Restricted Area"
///       <user> <password>
///   }
///
/// Password values beginning with a bcrypt marker are validated by the
/// compiler and emitted as hashed credentials.
fn adapt_basic_auth(d: Directive) -> Result<Handler, AdapterError> {
    let mut config = BasicAuthConfig {
        realm: None,
        credentials: Vec::new(),
    };

    let mut pairs_from = |args: &[String]| -> Result<(), AdapterError> {
        if !args.len().is_multiple_of(2) {
            return Err(AdapterError::InvalidArgument(
                "basic_auth".into(),
                "credentials must be <user> <password> pairs".into(),
            ));
        }
        for pair in args.chunks(2) {
            config.credentials.push((pair[0].clone(), pair[1].clone()));
        }
        Ok(())
    };

    if let Some(block) = &d.block {
        if !d.args.is_empty() {
            return Err(AdapterError::InvalidArgument(
                "basic_auth".into(),
                "cannot mix inline credentials with a block".into(),
            ));
        }
        for sub in &block.directives {
            if sub.name == "realm" {
                config.realm = sub.args.first().cloned();
            } else {
                pairs_from(
                    &std::iter::once(sub.name.clone())
                        .chain(sub.args.iter().cloned())
                        .collect::<Vec<_>>(),
                )?;
            }
        }
    } else {
        pairs_from(&d.args)?;
    }

    if config.credentials.is_empty() {
        return Err(AdapterError::InvalidArgument(
            "basic_auth".into(),
            "at least one credential pair is required".into(),
        ));
    }

    Ok(Handler::BasicAuth(config))
}

// MARK: - reverse_proxy Full Block Parsing

/// Adapt a `reverse_proxy` directive with full sub-block support.
///
/// Handles:
/// - `reverse_proxy host:port` (simple, args-only)
/// - `reverse_proxy { to host:port { weight 3 }; to host:port { backup } }`
/// - `reverse_proxy host:port { header_up K V; flush_interval -1; transport http { ... } }`
fn adapt_reverse_proxy(d: Directive) -> Result<Handler, AdapterError> {
    // Collect upstreams from args (filter out matcher @names)
    let upstreams: Vec<String> = d
        .args
        .iter()
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
                        proxy.header_up.insert(key, Expr::String(value));
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
                                    transport.read_timeout =
                                        t_sub.args.first().and_then(|s| parse_duration_ms(s));
                                }
                                "write_timeout" => {
                                    transport.write_timeout =
                                        t_sub.args.first().and_then(|s| parse_duration_ms(s));
                                }
                                _ => {}
                            }
                        }
                        proxy.transport = Some(transport);
                    }
                }
                "lb_policy" => {
                    let policy = sub
                        .args
                        .first()
                        .ok_or_else(|| AdapterError::ArgumentCount("lb_policy".into(), 1, 0))?;
                    match policy.as_str() {
                        "round_robin" | "random" | "least_conn" | "ip_hash" | "first" => {
                            proxy.lb_policy = Some(policy.clone());
                        }
                        _ => {
                            return Err(AdapterError::InvalidArgument(
                                "lb_policy".into(),
                                policy.clone(),
                            ));
                        }
                    }
                }
                "to" => {
                    let address = sub
                        .args
                        .first()
                        .ok_or_else(|| {
                            AdapterError::ArgumentCount("reverse_proxy to".into(), 1, 0)
                        })?
                        .clone();
                    if sub.args.len() != 1 {
                        return Err(AdapterError::InvalidArgument(
                            "reverse_proxy to".into(),
                            "expected exactly one upstream address".into(),
                        ));
                    }
                    let mut upstream = ProxyUpstreamConfig {
                        address: address.clone(),
                        weight: 1,
                        backup: false,
                    };
                    if let Some(to_block) = sub.block {
                        for option in to_block.directives {
                            match option.name.as_str() {
                                "weight" => {
                                    let raw = option.args.first().ok_or_else(|| {
                                        AdapterError::ArgumentCount(
                                            "reverse_proxy to weight".into(),
                                            1,
                                            0,
                                        )
                                    })?;
                                    upstream.weight = raw.parse().map_err(|_| {
                                        AdapterError::InvalidArgument(
                                            "reverse_proxy to weight".into(),
                                            raw.clone(),
                                        )
                                    })?;
                                    if upstream.weight == 0 {
                                        return Err(AdapterError::InvalidArgument(
                                            "reverse_proxy to weight".into(),
                                            "weight must be greater than zero".into(),
                                        ));
                                    }
                                }
                                "backup" => {
                                    upstream.backup = option
                                        .args
                                        .first()
                                        .map(|value| value != "false" && value != "off")
                                        .unwrap_or(true);
                                }
                                _ => {
                                    return Err(AdapterError::UnknownDirective(format!(
                                        "reverse_proxy to: {}",
                                        option.name
                                    )));
                                }
                            }
                        }
                    }
                    proxy.upstreams.push(address);
                    proxy.upstream_options.push(upstream);
                }
                _ => {}
            }
        }
    }

    if proxy.upstreams.is_empty() {
        return Err(AdapterError::ArgumentCount("reverse_proxy".into(), 1, 0));
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
            if let Some(last) = d.args.last()
                && let Ok(code) = last.parse::<u16>()
            {
                status = code;
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
        let args: Vec<&String> = d.args.iter().filter(|a| !a.starts_with('@')).collect();

        if let Some(key) = args.first() {
            if let Some(stripped) = key.strip_prefix('-') {
                config.remove.push(stripped.to_string());
            } else if let Some(val) = args.get(1) {
                config.set.insert((*key).clone(), (*val).clone());
            }
        }
    }

    Ok(Handler::Headers(config))
}

// MARK: - Matchers

fn parse_matcher_and_block(
    d: &Directive,
) -> Result<(Option<Matcher>, Option<&Block>), AdapterError> {
    let mut matcher = None;
    let block = d.block.as_ref();

    // Check first arg for @name
    if let Some(arg) = d.args.first()
        && arg.starts_with('@')
    {
        matcher = Some(Matcher::Named(arg.clone()));
    }

    Ok((matcher, block))
}

/// Parse the matcher for a `route`/`handle` directive.
///
/// Unlike the generic [`parse_matcher_and_block`], the first argument of a
/// `route`/`handle` block is *positionally* a matcher and accepts both
/// spellings Caddy allows:
///   - `@name`      → a named matcher defined elsewhere in the block
///   - `/some/path` → an inline path matcher (`handle /api/*`)
///
/// Historically only `@name` was recognised here, so `handle /api/*` (and
/// the equivalent `route "/api/*"`) silently dropped its path and collapsed
/// into the server's catch-all handler — every request matched it
/// regardless of URL. This dedicated helper keeps that leading-`/`
/// detection out of the generic branch, where a leading `/` is a real
/// argument (e.g. `file_server /var/www/html`), not a matcher.
fn parse_route_matcher_and_block(
    d: &Directive,
) -> Result<(Option<Matcher>, Option<&Block>), AdapterError> {
    let block = d.block.as_ref();
    let matcher = match d.args.first() {
        Some(arg) if arg.starts_with('@') => Some(Matcher::Named(arg.clone())),
        Some(arg) if arg.starts_with('/') => Some(Matcher::Path(PathMatcher {
            patterns: vec![arg.clone()],
        })),
        _ => None,
    };
    Ok((matcher, block))
}

fn parse_matcher_definition(d: &Directive) -> Result<Matcher, AdapterError> {
    if let Some(block) = &d.block {
        let mut matchers = Vec::new();
        for sub in &block.directives {
            matchers.push(parse_single_matcher(sub)?);
        }

        if matchers.is_empty() {
            return Err(AdapterError::InvalidArgument(
                d.name.clone(),
                "Empty matcher block".into(),
            ));
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
        "path" => Ok(Matcher::Path(PathMatcher {
            patterns: d.args.clone(),
        })),
        "not" => {
            let inner = if let Some(block) = &d.block {
                let mut matchers = block
                    .directives
                    .iter()
                    .map(parse_single_matcher)
                    .collect::<Result<Vec<_>, _>>()?;
                if matchers.is_empty() {
                    return Err(AdapterError::InvalidArgument(
                        "not".into(),
                        "empty matcher block".into(),
                    ));
                }
                let mut combined = matchers.remove(0);
                for matcher in matchers {
                    combined = Matcher::And(Box::new(combined), Box::new(matcher));
                }
                combined
            } else {
                let Some(name) = d.args.first() else {
                    return Err(AdapterError::ArgumentCount("not".into(), 1, 0));
                };
                let nested = Directive {
                    name: name.clone(),
                    args: d.args[1..].to_vec(),
                    block: None,
                };
                parse_single_matcher(&nested)?
            };
            Ok(Matcher::Not(Box::new(inner)))
        }
        "method" => {
            let methods = d
                .args
                .iter()
                .filter_map(|m| match m.to_uppercase().as_str() {
                    "GET" => Some(HttpMethod::Get),
                    "POST" => Some(HttpMethod::Post),
                    "PUT" => Some(HttpMethod::Put),
                    "DELETE" => Some(HttpMethod::Delete),
                    _ => None,
                })
                .collect();
            Ok(Matcher::Method(methods))
        }
        "header" => {
            if d.args.is_empty() {
                return Err(AdapterError::ArgumentCount(
                    "header".into(),
                    1,
                    d.args.len(),
                ));
            }

            let condition = if d.args.len() >= 2 {
                let val = &d.args[1];
                if val == "*" {
                    HeaderCondition::Exists
                } else if val.starts_with("*") && val.ends_with("*") {
                    HeaderCondition::Contains(val[1..val.len() - 1].to_string())
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
        _ => Err(AdapterError::UnknownDirective(format!(
            "matcher: {}",
            d.name
        ))),
    }
}

// MARK: - Helpers

/// 🧭 Reports whether a handler tree already owns the terminal response path.
fn handler_has_terminal(handler: &Handler) -> bool {
    match handler {
        Handler::Proxy(_) | Handler::Respond(_) | Handler::Redirect(_) | Handler::FileServer(_) => {
            true
        }
        Handler::Pipeline(handlers) | Handler::Handle(handlers) => {
            handlers.iter().any(handler_has_terminal)
        }
        Handler::Headers(_)
        | Handler::BasicAuth(_)
        | Handler::Rewrite(_)
        | Handler::Cors(_)
        | Handler::AccessControl(_)
        | Handler::Plugin { .. } => false,
    }
}

/// 🧩 Inserts matched middleware before the default terminal handler.
fn compose_with_default_handlers(matched: Handler, defaults: &[Handler]) -> Handler {
    let terminal_index = defaults
        .iter()
        .position(handler_has_terminal)
        .unwrap_or(defaults.len());
    let mut handlers = Vec::with_capacity(defaults.len() + 1);
    handlers.extend_from_slice(&defaults[..terminal_index]);
    handlers.push(matched);
    handlers.extend_from_slice(&defaults[terminal_index..]);
    Handler::Pipeline(handlers)
}

fn add_route(server: &mut ServerBlock, matcher: Option<Matcher>, handler: Handler) {
    if server.routes.is_none() {
        server.routes = Some(Node::new(
            RouteBlock { arms: Vec::new() },
            Location { start: 0, end: 0 },
        ));
    }
    let routes = server.routes.as_mut().unwrap();
    routes.inner.arms.push(Node::new(
        RouteArm { matcher, handler },
        Location { start: 0, end: 0 },
    ));
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
            assert!(matches!(
                proxy.flush_interval,
                Some(FlushInterval::Immediate)
            ));
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
    fn test_hostname_address_binds_wildcard_not_hostname() {
        // A named site address must not be bound literally: the listener
        // goes on all interfaces and the hostname is used for Host-header
        // routing (Caddy/nginx semantics). Binding the hostname itself
        // crashed startup for any name that doesn't resolve locally.
        let source = r#"
            bench.local:8080 {
                respond "OK"
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let server = &ast.servers[0].inner;
        assert_eq!(server.name, "bench.local");
        assert_eq!(server.listens.len(), 1);
        assert_eq!(server.listens[0].host, "0.0.0.0");
        assert_eq!(server.listens[0].port, Some(8080));
    }

    #[test]
    fn test_ip_literal_address_binds_to_that_ip() {
        // An IP literal *is* a bind address — only hostnames get the
        // bind-wildcard treatment.
        for (source, expected) in [
            ("127.0.0.1:8080 { respond \"OK\" }", "127.0.0.1"),
            ("192.168.1.10 { respond \"OK\" }", "192.168.1.10"),
        ] {
            let directives = parse(source).unwrap();
            let ast = adapt(directives).unwrap();
            let server = &ast.servers[0].inner;
            assert_eq!(
                server.listens[0].host, expected,
                "IP literal must stay the bind host"
            );
        }
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
            panic!("Expected Headers handler, got {handler:?}");
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

    // ---- Regression: `handle`/`route` with an inline path matcher ----
    //
    // `handle /api/*` and `route "/api/*"` must keep their path. The old
    // adapter only recognised `@name` matchers, so an inline path was
    // dropped and the block collapsed into the server's catch-all — every
    // request matched it regardless of URL. These use the full public
    // `compile()` pipeline so they assert the final RouteConfig.path, which
    // is what the runtime router actually keys on.

    fn compiled_routes(source: &str) -> Vec<pingclair_core::config::RouteConfig> {
        crate::compile(source).unwrap().servers.remove(0).routes
    }

    #[test]
    fn handle_with_inline_path_keeps_its_path() {
        let routes = compiled_routes(
            r#"
            :8080 {
                handle /proxy/* {
                    reverse_proxy 127.0.0.1:9000
                }
                file_server /var/www/html
            }
        "#,
        );

        // The proxy route must be keyed on /proxy/*, NOT collapsed to /*.
        let proxy = routes
            .iter()
            .find(|r| {
                matches!(
                    &r.handler,
                    pingclair_core::config::HandlerConfig::ReverseProxy(_)
                        | pingclair_core::config::HandlerConfig::Pipeline { .. }
                )
            })
            .expect("proxy route should exist");
        assert_eq!(proxy.path, "/proxy/*", "handle /proxy/* lost its path");

        // The bare file_server is the catch-all.
        let fs = routes
            .iter()
            .find(|r| {
                matches!(
                    &r.handler,
                    pingclair_core::config::HandlerConfig::FileServer { .. }
                )
            })
            .expect("file_server route should exist");
        assert_eq!(fs.path, "/*");
    }

    #[test]
    fn route_with_quoted_path_keeps_its_path() {
        let routes = compiled_routes(
            r#"
            example.com {
                route "/api/*" {
                    respond "api" 200
                }
                route "/health" {
                    respond "ok" 200
                }
            }
        "#,
        );
        let paths: Vec<_> = routes.iter().map(|r| r.path.as_str()).collect();
        assert!(
            paths.contains(&"/api/*"),
            "route \"/api/*\" lost its path; got {paths:?}"
        );
        assert!(
            paths.contains(&"/health"),
            "route \"/health\" lost its path; got {paths:?}"
        );
    }

    #[test]
    fn bare_file_server_root_is_not_mistaken_for_a_matcher() {
        // `file_server /var/www/html` at server level: the leading-'/' arg
        // is the ROOT, not a path matcher. It must stay the catch-all and
        // keep its root — the scoped fix must not leak into this branch.
        let routes = compiled_routes(
            r#"
            :8080 {
                file_server /var/www/html
            }
        "#,
        );
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].path, "/*");
        match &routes[0].handler {
            pingclair_core::config::HandlerConfig::FileServer { root, .. } => {
                assert_eq!(
                    root, "/var/www/html",
                    "file_server root was swallowed as a matcher"
                );
            }
            other => panic!("expected FileServer, got {other:?}"),
        }
    }

    // ---- tls server directive ----

    #[test]
    fn test_tls_cert_key() {
        let source = r#"
            example.com {
                listen :443
                tls /etc/ssl/cert.pem /etc/ssl/key.pem
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let tls = ast.servers[0].inner.tls.as_ref().expect("tls directive");
        assert_eq!(tls.cert.as_deref(), Some("/etc/ssl/cert.pem"));
        assert_eq!(tls.key.as_deref(), Some("/etc/ssl/key.pem"));
        assert!(!tls.auto);
        assert!(!tls.off);
    }

    #[test]
    fn test_tls_auto() {
        let source = r#"
            example.com {
                listen :443
                tls auto
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let tls = ast.servers[0].inner.tls.as_ref().expect("tls directive");
        assert!(tls.auto);
        assert!(tls.cert.is_none());
    }

    #[test]
    fn test_tls_internal() {
        let source = r#"
            example.com {
                listen :443
                tls internal
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let tls = ast.servers[0].inner.tls.as_ref().expect("tls directive");
        assert!(tls.internal);
        assert!(!tls.auto);
        assert!(tls.cert.is_none());
    }

    #[test]
    fn test_tls_internal_block_can_disable_http3() {
        let source = r#"
            example.com {
                listen :443
                tls {
                    internal
                    http3 off
                }
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let tls = ast.servers[0].inner.tls.as_ref().expect("tls directive");
        assert!(tls.internal);
        assert_eq!(tls.http3, Some(false));
    }

    #[test]
    fn test_tls_internal_rejects_public_or_manual_issuers() {
        for source in [
            "example.com { tls { internal auto } }",
            "example.com { tls { internal acme_email admin@example.com } }",
            "example.com { tls { internal cert cert.pem key key.pem } }",
        ] {
            let directives = parse(source).unwrap();
            assert!(matches!(
                adapt(directives),
                Err(AdapterError::InvalidArgument(..))
            ));
        }
    }

    #[test]
    fn test_tls_off() {
        let source = r#"
            example.com {
                listen :443
                tls off
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let tls = ast.servers[0].inner.tls.as_ref().expect("tls directive");
        assert!(tls.off);
    }

    #[test]
    fn test_tls_block_form() {
        let source = r#"
            example.com {
                listen :443
                tls {
                    cert /etc/ssl/cert.pem
                    key /etc/ssl/key.pem
                    acme_email admin@example.com
                    http3
                }
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let tls = ast.servers[0].inner.tls.as_ref().expect("tls directive");
        assert_eq!(tls.cert.as_deref(), Some("/etc/ssl/cert.pem"));
        assert_eq!(tls.key.as_deref(), Some("/etc/ssl/key.pem"));
        assert_eq!(tls.acme_email.as_deref(), Some("admin@example.com"));
        assert_eq!(tls.http3, Some(true));
    }

    #[test]
    fn test_tls_cert_without_key_is_an_error() {
        let source = r#"
            example.com {
                listen :443
                tls /etc/ssl/cert.pem
            }
        "#;
        let directives = parse(source).unwrap();
        let result = adapt(directives);
        assert!(matches!(result, Err(AdapterError::InvalidArgument(..))));
    }

    // ---- Global admin directive ----

    #[test]
    fn test_admin_listen() {
        let source = r#"{
            admin 127.0.0.1:2019
        }"#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let admin = ast.global.unwrap().inner.admin.expect("admin directive");
        assert_eq!(admin.listen, "127.0.0.1:2019");
        assert!(admin.enabled);
    }

    #[test]
    fn test_admin_off() {
        let source = r#"{
            admin off
        }"#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let admin = ast.global.unwrap().inner.admin.expect("admin directive");
        assert!(!admin.enabled);
    }
}

#[cfg(test)]
mod log_format_tests {
    use crate::compile;
    use pingclair_core::config::{LogFormat as CoreLogFormat, LogOutput as CoreLogOutput};

    fn log_of(source: &str) -> pingclair_core::config::LogConfig {
        compile(source)
            .unwrap()
            .servers
            .remove(0)
            .log
            .expect("log config")
    }

    #[test]
    fn plain_format_directives_compile() {
        assert!(matches!(
            log_of(":80 {\n log { format json }\n respond \"ok\" 200\n}").format,
            CoreLogFormat::Json
        ));
        assert!(matches!(
            log_of(":80 {\n log { format text }\n respond \"ok\" 200\n}").format,
            CoreLogFormat::Text
        ));
    }

    /// Regression: `format filter { wrap text }` used to be impossible to
    /// express — the adapter pinned Json before it ever read `wrap`, so a
    /// config asking for text silently got JSON.
    #[test]
    fn filter_block_honors_explicit_wrap() {
        let text = log_of(
            ":80 {\n log { format filter { wrap text\n fields { user_agent delete } } }\n respond \"ok\" 200\n}",
        );
        assert!(
            matches!(text.format, CoreLogFormat::Text),
            "wrap text must win over the filter block's JSON default"
        );

        let json = log_of(
            ":80 {\n log { format filter { wrap json\n fields { user_agent delete } } }\n respond \"ok\" 200\n}",
        );
        assert!(matches!(json.format, CoreLogFormat::Json));
    }

    /// A filter block with no explicit `wrap` still defaults to JSON, since
    /// dropping named fields only means something for structured output.
    #[test]
    fn filter_block_without_wrap_defaults_to_json() {
        let cfg = log_of(
            ":80 {\n log { format filter { fields { referer delete } } }\n respond \"ok\" 200\n}",
        );
        assert!(matches!(cfg.format, CoreLogFormat::Json));
    }

    /// Regression: field exclusions were parsed into the AST and then dropped
    /// by the compiler, so `fields { x delete }` was accepted and ignored.
    #[test]
    fn field_exclusions_survive_compilation() {
        let cfg = log_of(
            ":80 {\n log { format filter { wrap json\n fields { user_agent delete\n referer delete } } }\n respond \"ok\" 200\n}",
        );
        assert!(
            cfg.exclude_fields.contains(&"user_agent".to_string()),
            "{:?}",
            cfg.exclude_fields
        );
        assert!(
            cfg.exclude_fields.contains(&"referer".to_string()),
            "{:?}",
            cfg.exclude_fields
        );
    }

    #[test]
    fn output_targets_compile() {
        assert!(matches!(
            log_of(":80 {\n log { output stdout }\n respond \"ok\" 200\n}").output,
            CoreLogOutput::Stdout
        ));
        assert!(matches!(
            log_of(":80 {\n log { output stderr }\n respond \"ok\" 200\n}").output,
            CoreLogOutput::Stderr
        ));
        match log_of(":80 {\n log { output file /var/log/x.log }\n respond \"ok\" 200\n}").output {
            CoreLogOutput::File(p) => assert_eq!(p, "/var/log/x.log"),
            other => panic!("expected file output, got {other:?}"),
        }
    }
}
