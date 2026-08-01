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

    /// 🚫 A Caddy-compatible feature that Pingclair deliberately does not
    /// implement yet. Failing loudly here beats compiling a config that
    /// silently ignores half of what the operator asked for.
    #[error("Caddy-compatible directive '{0}' is not supported by Pingclair yet: {1}")]
    UnsupportedFeature(String, String),

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
    let expanded = coalesce_bare_single_site(expanded)?;

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

/// 🏠 Caddy lets a single-site file omit its curly braces: the first line is
/// the site address and every following directive belongs to that site.
/// `localhost\n\nrespond "Hello"` must parse as `localhost { respond ... }`.
///
/// The shorthand is only legal when no other braced site exists — with two
/// sites the file must use explicit braces, otherwise the bare directives
/// have no unambiguous home.
fn coalesce_bare_single_site(directives: Vec<Directive>) -> Result<Vec<Directive>, AdapterError> {
    let mut globals = Vec::new();
    let mut bare = Vec::new();
    let mut braced_sites = Vec::new();

    for d in directives {
        if d.name.is_empty() || d.name == "global" || d.name == "options" {
            globals.push(d);
        } else if d.block.is_some() {
            braced_sites.push(d);
        } else {
            bare.push(d);
        }
    }

    if bare.is_empty() {
        globals.extend(braced_sites);
        return Ok(globals);
    }

    if !braced_sites.is_empty() {
        return Err(AdapterError::InvalidArgument(
            "site address".into(),
            "bare (unbraced) directives cannot be mixed with braced site blocks; \
             wrap every site in { } when there is more than one"
                .into(),
        ));
    }

    // 🏠 The first bare directive is the site address; everything after it is
    // the site's content. A lone bare directive is an empty site.
    let mut site = bare.remove(0);
    if !bare.is_empty() {
        site.block = Some(Block { directives: bare });
    }
    globals.push(site);
    Ok(globals)
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
                    // 🚩 `debug fales` used to parse as "debug off": a typo
                    // silently disabled the very diagnostics being asked for.
                    // Caddy's `debug` is a bare flag, so any argument is a
                    // mistake worth rejecting.
                    if !sub.args.is_empty() {
                        return Err(AdapterError::ArgumentCount(
                            "debug".into(),
                            0,
                            sub.args.len(),
                        ));
                    }
                    global.debug = Some(true);
                }
                "email" => {
                    global.email = sub.args.first().cloned();
                }
                "http_port" => {
                    let value = expect_one_argument(&sub)?;
                    global.http_port = Some(value.parse::<u16>().map_err(|_| {
                        AdapterError::InvalidArgument("http_port".into(), value.to_string())
                    })?);
                }
                "https_port" => {
                    let value = expect_one_argument(&sub)?;
                    global.https_port = Some(value.parse::<u16>().map_err(|_| {
                        AdapterError::InvalidArgument("https_port".into(), value.to_string())
                    })?);
                }
                "metrics" => {
                    // 📊 `metrics` is a bare toggle; the block form
                    // (`per_host`, `otlp`) is deferred.
                    if sub.block.is_some() {
                        // TODO(v0.3): implement metrics { per_host; otlp }.
                        return Err(AdapterError::UnsupportedFeature(
                            "metrics block".into(),
                            "metrics per_host/otlp options are not implemented yet".into(),
                        ));
                    }
                    if !sub.args.is_empty() {
                        return Err(AdapterError::ArgumentCount(
                            "metrics".into(),
                            0,
                            sub.args.len(),
                        ));
                    }
                    global.metrics = Some(true);
                }
                "auto_https" => {
                    let arg = sub
                        .args
                        .first()
                        .ok_or_else(|| AdapterError::ArgumentCount("auto_https".into(), 1, 0))?;
                    match arg.as_str() {
                        "on" => global.auto_https = Some(AutoHttpsMode::On),
                        "off" => global.auto_https = Some(AutoHttpsMode::Off),
                        "disable_redirects" => {
                            global.auto_https = Some(AutoHttpsMode::DisableRedirects)
                        }
                        // 🚫 Caddy's `disable_certs` and `ignore_loaded_certs`
                        // modes are real syntax; name them explicitly instead
                        // of reporting a bare invalid argument.
                        "disable_certs" | "ignore_loaded_certs" => {
                            // TODO(v0.3): implement certificate-only and
                            // ignore-loaded-certificates automation modes.
                            return Err(AdapterError::UnsupportedFeature(
                                format!("auto_https {arg}"),
                                "only on, off and disable_redirects are implemented".into(),
                            ));
                        }
                        _ => {
                            return Err(AdapterError::InvalidArgument(
                                "auto_https".into(),
                                arg.clone(),
                            ));
                        }
                    }
                }
                "admin" => {
                    // 🚫 Caddy's `admin <addr> { origins ...; enforce_origin }`
                    // block form used to compile with the block silently
                    // dropped, leaving the endpoint without the origin checks
                    // the operator asked for.
                    if sub.block.is_some() {
                        // TODO(v0.3): implement admin origins/enforce_origin.
                        return Err(AdapterError::UnsupportedFeature(
                            "admin block".into(),
                            "admin origins/enforce_origin are not implemented yet".into(),
                        ));
                    }
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
                "dns_refresh" => {
                    let Some(value) = sub.args.first() else {
                        return Err(AdapterError::ArgumentCount("dns_refresh".into(), 1, 0));
                    };
                    global.dns_refresh_secs = Some(parse_dns_refresh(value)?);
                }
                "protocols" => {
                    for arg in &sub.args {
                        match arg.to_lowercase().as_str() {
                            "h1" => global.protocols.push(Protocol::H1),
                            "h2" => global.protocols.push(Protocol::H2),
                            "h3" => global.protocols.push(Protocol::H3),
                            other => {
                                return Err(AdapterError::InvalidArgument(
                                    "protocols".into(),
                                    other.to_string(),
                                ));
                            }
                        }
                    }
                }
                // 🚩 An unrecognised global directive is a typo, and a silently
                // ignored typo is a silently missing setting. `trusted_proxis`
                // would have meant "no trusted proxies at all" while reading
                // like the opposite — the same shape as `encode gzipp` and
                // `listen :443 proxy_protocol`, both of which were fixed for
                // exactly this reason.
                //
                // 🚫 Options that are real Caddy syntax but not implemented
                // here get a distinct message so a migrating Caddyfile is not
                // mistaken for a typo.
                other => {
                    if is_known_caddy_global_option(other) {
                        // TODO(v0.3): implement the remaining Caddy global
                        // options (default_bind, grace_period, storage, ...).
                        return Err(AdapterError::UnsupportedFeature(
                            format!("global: {other}"),
                            "this Caddy global option is not implemented yet".into(),
                        ));
                    }
                    return Err(AdapterError::UnknownDirective(format!("global: {other}")));
                }
            }
        }
    }
    Ok(global)
}

/// 🧾 Whether a global-block name is documented Caddy syntax rather than a
/// likely typo. The list mirrors `vendor/caddy-docs/markdown/caddyfile/options.md`.
fn is_known_caddy_global_option(name: &str) -> bool {
    matches!(
        name,
        "default_bind"
            | "order"
            | "storage"
            | "storage_clean_interval"
            | "persist_config"
            | "log"
            | "grace_period"
            | "shutdown_delay"
            | "default_sni"
            | "fallback_sni"
            | "local_certs"
            | "skip_install_trust"
            | "acme_ca"
            | "acme_ca_root"
            | "acme_eab"
            | "acme_dns"
            | "dns"
            | "ech"
            | "on_demand_tls"
            | "key_type"
            | "cert_issuer"
            | "renew_interval"
            | "cert_lifetime"
            | "ocsp_interval"
            | "ocsp_stapling"
            | "renewal_window_ratio"
            | "preferred_chains"
            | "filesystem"
            | "pki"
            | "events"
            | "frankenphp"
    )
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
    // 🏷️ Caddy separates multiple site addresses with commas; the lexer keeps
    // the comma attached to the token, so strip it before parsing.
    let strip_comma = |addr: &str| addr.trim_end_matches(',').to_string();
    let mut server = ServerBlock::new(strip_comma(&d.name));
    let mut names = vec![strip_comma(&d.name)];
    for arg in &d.args {
        if arg.starts_with(':') || arg.contains(':') || arg.contains('.') || *arg == "localhost" {
            names.push(strip_comma(arg));
        }
    }

    for name in &names {
        // 🌐 A catch-all scheme address (`http://`, `https://`) has no host;
        // it still names a listener (80 or 443) even though no Host header
        // will ever match it.
        if matches!(name.as_str(), "http://" | "https://") {
            let is_https = name == "https://";
            server.listens.push(ListenAddr {
                scheme: if is_https {
                    Scheme::Https
                } else {
                    Scheme::Http
                },
                host: "0.0.0.0".to_string(),
                port: Some(if is_https { 443 } else { 80 }),
                proxy_protocol: false,
            });
            continue;
        }
        if let Some(parsed) = parse_server_address(name) {
            // 📍 A bare hostname site address selects the virtual host; the
            // listener is derived later from whether TLS is configured.
            // Only explicit ports, schemes and IP literals create listeners
            // here — that is what lets `example.com { tls auto }` reach the
            // runtime's automatic-443 branch instead of being pinned to :80.
            if parsed.explicit {
                server.listens.push(parsed.listen);
            }
            // 🏠 Collect every hostname the site serves. The first one is the
            // primary name; the rest are additional virtual hosts sharing the
            // same configuration (Caddy's `example.com, www.example.com`).
            if !parsed.hostname.is_empty()
                && parsed.hostname != "0.0.0.0"
                && !server.names.contains(&parsed.hostname)
            {
                server.names.push(parsed.hostname);
            }
        } else if looks_like_unsupported_address(name) {
            // TODO(v0.3): support network prefixes, port ranges and Unix
            // sockets in site addresses.
            return Err(AdapterError::UnsupportedFeature(
                "site address".into(),
                format!(
                    "`{name}` uses a network prefix, a port range or a Unix socket, \
                     none of which Pingclair supports yet"
                ),
            ));
        }
    }

    // Fallback: if server name is still a full URL, strip it
    if server.name.contains("://")
        && let Some(parsed) = parse_server_address(&server.name)
    {
        server.name = parsed.hostname;
    }

    // 🏠 The primary name is the first hostname collected (or the raw address
    // when the site has none). It stays the hostname no matter how many
    // listeners the site carries; collapsing it to `_` turned every
    // multi-listener site into a catch-all that matched any Host header. Only
    // addresses without a hostname (bare `:port` and catch-all schemes) are
    // truly anonymous.
    if let Some(first) = server.names.first() {
        server.name = first.clone();
    }
    if server.name.starts_with(':')
        || server.name == "http://"
        || server.name == "https://"
        || server.name.contains("://")
    {
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
                    // 🚩 Trailing flags are rejected rather than dropped. This
                    // loop previously read `args[0]` only, so `listen :443
                    // proxy_protocol` produced a listener that quietly did not
                    // require the header it named.
                    let mut proxy_protocol = false;
                    for flag in &sub_d.args[1..] {
                        match flag.as_str() {
                            "proxy_protocol" => proxy_protocol = true,
                            other => {
                                return Err(AdapterError::InvalidArgument(
                                    "listen".into(),
                                    format!("unknown listener flag `{other}`"),
                                ));
                            }
                        }
                    }
                    server.listens.push(ListenAddr {
                        scheme: if addr.starts_with("https") {
                            Scheme::Https
                        } else {
                            Scheme::Http
                        },
                        host: "0.0.0.0".to_string(),
                        port: addr.split(':').next_back().and_then(|p| p.parse().ok()),
                        proxy_protocol,
                    });
                }
                "root" => {
                    // 📂 `root /var/www` or `root * /var/www`: the optional
                    // `*` matcher token is accepted and ignored, matching
                    // Caddy's disambiguation syntax.
                    let args = if sub_d.args.first().is_some_and(|a| a == "*") {
                        &sub_d.args[1..]
                    } else {
                        &sub_d.args[..]
                    };
                    let path = args.first().ok_or_else(|| {
                        AdapterError::ArgumentCount("root".into(), 1, sub_d.args.len())
                    })?;
                    if args.len() != 1 {
                        return Err(AdapterError::ArgumentCount("root".into(), 1, args.len()));
                    }
                    server.root = Some(path.clone());
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
                "limits" => {
                    server.limits = adapt_resource_limits(&sub_d)?;
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
                    // 🔁 Caddy's `redir /old.html /new.html` and
                    // `rewrite /old /new` carry an inline path matcher whose
                    // first argument does not end in `*`. Detect that shape so
                    // official examples compile.
                    let inline_path_matcher = if handler_d.name == "redir"
                        || handler_d.name == "redirect"
                        || handler_d.name == "rewrite"
                    {
                        if handler_d.name == "rewrite" {
                            handler_d.args.len() >= 2 && handler_d.args[0].starts_with('/')
                        } else {
                            handler_d.args.len() >= 2
                                && handler_d.args[0].starts_with('/')
                                && (handler_d.args[1].starts_with('/')
                                    || handler_d.args[1].contains("://"))
                                && !handler_d.args[1].parse::<u16>().is_ok()
                        }
                    } else {
                        false
                    };
                    if inline_path_matcher {
                        let path = handler_d.args.remove(0);
                        let route_matcher = Matcher::Path(PathMatcher {
                            patterns: vec![path.clone()],
                        });
                        let handler = adapt_handler(handler_d)?;
                        add_route(&mut server, Some(route_matcher), handler);
                        continue;
                    }
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

        // 🧭 Caddy sorts handler directives into a fixed chain so the file
        // order does not change behavior: `header` always runs before
        // `respond`, `basic_auth` before `file_server`, and so on. Sorting
        // the default pipeline here reproduces that guarantee.
        default_handlers.sort_by_key(caddy_handler_rank);

        let final_handler = if default_handlers.len() == 1 {
            default_handlers[0].clone()
        } else {
            Handler::Pipeline(default_handlers.clone())
        };

        if let Some(routes) = server.routes.as_mut() {
            // 🧭 Matched routes sort the same way, with middleware first: a
            // non-terminal route must run before a terminal route that would
            // otherwise shadow it, and equally ranked routes order by matcher
            // specificity (exact before glob, longer before shorter) like
            // Caddy's sorting algorithm.
            routes.inner.arms.sort_by(|left, right| {
                let left_terminal = handler_has_terminal(&left.inner.handler);
                let right_terminal = handler_has_terminal(&right.inner.handler);
                left_terminal.cmp(&right_terminal).then_with(|| {
                    let left_specificity = route_specificity(&left.inner.matcher);
                    let right_specificity = route_specificity(&right.inner.matcher);
                    // 🧭 Exact patterns (no `*`) first; within the same
                    // kind the longer pattern wins.
                    left_specificity
                        .0
                        .cmp(&right_specificity.0)
                        .then_with(|| right_specificity.1.cmp(&left_specificity.1))
                })
            });
            for arm in &mut routes.inner.arms {
                if !handler_has_terminal(&arm.inner.handler) {
                    arm.inner.handler =
                        compose_with_default_handlers(arm.inner.handler.clone(), &default_handlers);
                }
            }
        }

        if !default_handlers.is_empty() {
            add_route(&mut server, None, final_handler);
        }
    }

    // 🏠 Caddy serves localhost and IP-literal sites over HTTPS with its local
    // CA by default. Mirror that: a site with no explicit TLS and no `http://`
    // scheme gets the internal authority, so `localhost { ... }` is HTTPS
    // without the operator having to ask.
    if server.tls.is_none()
        && !d.name.starts_with("http://")
        && is_local_https_default(&server.name)
    {
        server.tls = Some(TlsDirective {
            off: false,
            auto: false,
            internal: true,
            cert: None,
            key: None,
            acme_email: None,
            http3: None,
        });
    }

    Ok(server)
}

/// 🏠 Whether a site name is a localhost-style host or an IP literal, which
/// Caddy serves over HTTPS with a locally-trusted certificate by default.
fn is_local_https_default(name: &str) -> bool {
    name == "localhost"
        || name.ends_with(".localhost")
        || name.ends_with(".local")
        || name.ends_with(".internal")
        || name.parse::<std::net::IpAddr>().is_ok()
}

/// 🧭 Maps a handler to its position in Caddy's default directive order.
/// Handlers that only modify the request/response run early; handlers that
/// write a terminal response run late.
fn caddy_handler_rank(handler: &Handler) -> usize {
    match handler {
        Handler::Headers(_) => 0,
        Handler::Redirect(_) => 1,
        Handler::Rewrite(_) => 2,
        Handler::BasicAuth(_) => 3,
        Handler::RateLimit(_) | Handler::Cors(_) | Handler::AccessControl(_) => 4,
        Handler::Pipeline(_) | Handler::Handle(_) => 5,
        // 🧭 Caddy's directive order runs `respond` before `reverse_proxy`
        // before `file_server`, and the first terminal handler wins. The
        // runtime pipeline lets a later handler override the body, so the
        // pipeline order must be the reverse of Caddy's priority: file_server
        // first, proxy next, respond last.
        Handler::FileServer(_) => 6,
        Handler::Proxy(_) => 7,
        Handler::Respond(_) => 8,
        Handler::Plugin { .. } => 9,
    }
}

/// 🧭 Matcher specificity for same-name route ordering: longer path patterns
/// win, and an exact pattern beats a glob of the same length.
fn route_specificity(matcher: &Option<Matcher>) -> (usize, usize) {
    let Some(matcher) = matcher else {
        return (0, 0);
    };
    match matcher {
        Matcher::Path(path) => {
            let pattern = path.patterns.first().map_or("", |p| p.as_str());
            // 🧭 Exact patterns outrank globs of any length; between two
            // patterns of the same kind the longer one wins.
            (pattern.contains('*') as usize, pattern.len())
        }
        _ => (0, 0),
    }
}

/// 🚫 Whether an address string uses Caddy syntax that Pingclair cannot
/// honor yet: a network prefix (`tcp/`, `unix/`), a Unix socket path
/// (`unix//...`), or a port range (`:8080-8085`).
fn looks_like_unsupported_address(addr: &str) -> bool {
    let bare = addr
        .strip_prefix("https://")
        .or_else(|| addr.strip_prefix("http://"))
        .unwrap_or(addr);
    // 🔧 IPv6 zone identifiers (`fe80::1%eth0`) are valid Caddy syntax but
    // need socket-address parsing this codebase does not do yet. Reject them
    // instead of treating the zone as part of a hostname.
    if bare.contains('[') && bare.contains('%') {
        return true;
    }
    let has_network_prefix = bare.split('/').next().is_some_and(|head| {
        matches!(
            head,
            "tcp"
                | "tcp4"
                | "tcp6"
                | "udp"
                | "udp4"
                | "udp6"
                | "ip"
                | "ip4"
                | "ip6"
                | "unix"
                | "unixgram"
                | "unixpacket"
        )
    });
    let has_port_range = bare
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.contains('-'));
    has_network_prefix || has_port_range
}

// MARK: - URL Address Parsing

struct ParsedAddress {
    hostname: String,
    listen: ListenAddr,
    /// 📍 Whether the address itself named a port or a scheme. A bare
    /// hostname (`example.com`) is a virtual-host selector, not a listener:
    /// the runtime derives 443/80 from TLS later, exactly like Caddy.
    explicit: bool,
}

/// Parse a Caddy server address like `http://ai.408timeout.com:20615`
/// or `:8080` or `example.com`.
fn parse_server_address(addr: &str) -> Option<ParsedAddress> {
    // 🚫 Caddy network addresses may carry a network prefix (`tcp/`,
    // `unix/`, ...) or a port range (`:8080-8085`). Neither has a runtime
    // equivalent here, and treating them as hostnames silently produces a
    // listener that serves the wrong thing.
    if addr.split('/').next().is_some_and(|head| {
        matches!(
            head,
            "tcp"
                | "tcp4"
                | "tcp6"
                | "udp"
                | "udp4"
                | "udp6"
                | "ip"
                | "ip4"
                | "ip6"
                | "unix"
                | "unixgram"
                | "unixpacket"
        )
    }) {
        return None;
    }

    let (scheme, rest) = if let Some(stripped) = addr.strip_prefix("https://") {
        (Scheme::Https, stripped)
    } else if let Some(stripped) = addr.strip_prefix("http://") {
        (Scheme::Http, stripped)
    } else {
        (Scheme::Http, addr)
    };
    let explicit_scheme = addr.contains("://");

    // rest is either: "host:port", ":port", "host", ""
    if rest.is_empty() {
        return None;
    }

    let (hostname, port, explicit_port) = if let Some(port) = rest.strip_prefix(':') {
        // :port
        let p = port.parse::<u16>().ok()?;
        ("0.0.0.0".to_string(), Some(p), true)
    } else if let Some(colon_pos) = rest.rfind(':') {
        // host:port
        let h = &rest[..colon_pos];
        let p = rest[colon_pos + 1..].parse::<u16>().ok()?;
        (h.to_string(), Some(p), true)
    } else {
        // host only (default port based on scheme)
        let p = match scheme {
            Scheme::Https => Some(443),
            Scheme::Http => Some(80),
        };
        (rest.to_string(), p, false)
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
        hostname: hostname.clone(),
        listen: ListenAddr {
            scheme,
            host: bind_host,
            port,
            // 📍 A site address carries no listener flags; `listen` does.
            proxy_protocol: false,
        },
        // ⚙️ A bare hostname with neither scheme nor port is implicit; the
        // runtime decides the listener from TLS. Everything else (an IP
        // literal, `host:port`, `:port`, `http://`/`https://`) names a
        // listener explicitly.
        // 📍 Explicit means the address itself named a listener: an explicit
        // scheme (`http://`, `https://`), an explicit port (`:8080`,
        // `host:8080`) or an IP literal (which binds by definition). A bare
        // hostname carries only a default port for scheme inference and must
        // not create a listener on its own.
        explicit: explicit_scheme || explicit_port || is_ip_literal(&hostname),
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
    let mut level = None;

    for d in block.directives {
        match d.name.as_str() {
            "output" => {
                let kind = d
                    .args
                    .first()
                    .ok_or_else(|| AdapterError::ArgumentCount("log output".into(), 1, 0))?;
                match kind.as_str() {
                    "file" => {
                        let path = d.args.get(1).ok_or_else(|| {
                            AdapterError::ArgumentCount("log output file".into(), 2, 1)
                        })?;
                        output = LogOutput::File(path.clone());
                    }
                    "stdout" => output = LogOutput::Stdout,
                    "stderr" => output = LogOutput::Stderr,
                    // 🚩 A typo in the log destination used to fall through to
                    // the default sink, so `output stdoutd` wrote to stderr and
                    // nobody could tell why the line went missing.
                    other => {
                        return Err(AdapterError::InvalidArgument(
                            "log output".into(),
                            format!("unknown output `{other}` (expected file, stdout or stderr)"),
                        ));
                    }
                }
            }
            "format" => {
                let kind = d
                    .args
                    .first()
                    .ok_or_else(|| AdapterError::ArgumentCount("log format".into(), 1, 0))?;
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
                                        Some("json") => format.format_type = LogFormatType::Json,
                                        Some("text") | Some("console") => {
                                            format.format_type = LogFormatType::Text
                                        }
                                        // 🚩 `wrap` with an unknown encoder or
                                        // no encoder is a config error, not a
                                        // reason to silently pick JSON.
                                        _ => {
                                            return Err(AdapterError::InvalidArgument(
                                                "log format filter wrap".into(),
                                                format!(
                                                    "expected json, text or console, got {:?}",
                                                    fb_d.args.first()
                                                ),
                                            ));
                                        }
                                    }
                                } else if fb_d.name == "fields"
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
                                } else {
                                    return Err(AdapterError::UnknownDirective(format!(
                                        "log format filter: {}",
                                        fb_d.name
                                    )));
                                }
                            }
                            format.filter = Some(filter);
                        }
                    }
                    // 🚩 `format jsno` used to fall back to text encoding and
                    // hide the typo behind a working-looking log line.
                    other => {
                        return Err(AdapterError::InvalidArgument(
                            "log format".into(),
                            format!("unknown format `{other}` (expected json, text or filter)"),
                        ));
                    }
                }
            }
            "level" => {
                // 🚦 Accepts Caddy's log levels and maps them onto the
                // process levels; the value flows through to the compiled
                // config for tooling and future filtering.
                let raw = d
                    .args
                    .first()
                    .ok_or_else(|| AdapterError::ArgumentCount("log level".into(), 1, 0))?;
                if d.args.len() != 1 {
                    return Err(AdapterError::ArgumentCount(
                        "log level".into(),
                        1,
                        d.args.len(),
                    ));
                }
                level = Some(match raw.to_ascii_lowercase().as_str() {
                    "trace" => LogLevel::Trace,
                    "debug" => LogLevel::Debug,
                    "info" => LogLevel::Info,
                    "warn" | "warning" => LogLevel::Warn,
                    "error" => LogLevel::Error,
                    other => {
                        return Err(AdapterError::InvalidArgument(
                            "log level".into(),
                            format!("unknown level `{other}`"),
                        ));
                    }
                });
            }
            // 🚩 Unknown log subdirectives (e.g. `level debug` today) must not
            // vanish: the operator would believe the setting took effect.
            other => {
                return Err(AdapterError::UnknownDirective(format!("log: {other}")));
            }
        }
    }

    Ok(LogBlock {
        output,
        format,
        level,
    })
}

// MARK: - Handler Adaptation

fn adapt_handler(d: Directive) -> Result<Handler, AdapterError> {
    match d.name.as_str() {
        "reverse_proxy" => adapt_reverse_proxy(d),
        "respond" => adapt_respond(d),
        "redir" | "redirect" => adapt_redirect(d),
        "file_server" => {
            let mut root = ".".to_string();
            let mut browse = false;
            if let Some(arg) = d.args.first() {
                if arg == "browse" {
                    // 🧭 Caddy's `file_server browse` enables directory
                    // listings without opening a block.
                    browse = true;
                } else if !arg.starts_with('@') {
                    root = arg.clone();
                }
            }

            let mut config = FileServerConfig {
                root,
                index: vec!["index.html".into()],
                browse,
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
                            config.browse =
                                browse || sub.args.first().map(|s| s == "true").unwrap_or(true)
                        }
                        // 🚩 Caddy's `precompressed` and `fs` subdirectives
                        // used to compile into a file server that quietly
                        // served without either behavior. Rejecting them is
                        // the only honest option until they are implemented.
                        "precompressed" | "fs" => {
                            // TODO(v0.3): implement precompressed sidecar
                            // lookup and custom file-system modules.
                            return Err(AdapterError::UnsupportedFeature(
                                format!("file_server {}", sub.name),
                                "Pingclair does not implement this subdirective yet".into(),
                            ));
                        }
                        other => {
                            return Err(AdapterError::UnknownDirective(format!(
                                "file_server: {other}"
                            )));
                        }
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
                    if inner_d.name.starts_with('@') {
                        // TODO(v0.3): support matcher tokens on directives
                        // inside route/handle blocks (needs per-handler
                        // conditional execution in the runtime chain).
                        return Err(AdapterError::UnsupportedFeature(
                            "route/handle matcher token".into(),
                            "matcher tokens inside route/handle blocks are not \
                             implemented yet"
                                .into(),
                        ));
                    }
                    handlers.push(adapt_handler(inner_d)?);
                }
            }
            Ok(Handler::Handle(handlers))
        }
        "basic_auth" | "basicauth" => adapt_basic_auth(d),
        "rate_limit" => adapt_rate_limit(d),
        "rewrite" => adapt_rewrite(d),
        "cors" => adapt_cors(d),
        "access_control" => adapt_access_control(d),
        // 🚫 A directive that exists in Caddy's standard set but has no
        // implementation here gets a message that says so, instead of being
        // indistinguishable from a typo.
        other => Err(if is_known_caddy_directive(other) {
            // TODO(v0.3): implement the remaining standard Caddy directives
            // (templates, try_files, php_fastcgi, handle_path, ...).
            AdapterError::UnsupportedFeature(
                other.to_string(),
                "this Caddy directive is not implemented yet".into(),
            )
        } else {
            AdapterError::UnknownDirective(other.to_string())
        }),
    }
}

/// 🧾 Whether a handler-directive name is documented Caddy syntax rather
/// than a likely typo. The list mirrors
/// `vendor/caddy-docs/markdown/caddyfile/directives.md`.
fn is_known_caddy_directive(name: &str) -> bool {
    matches!(
        name,
        "abort"
            | "acme_server"
            | "error"
            | "forward_auth"
            | "fs"
            | "handle_errors"
            | "handle_path"
            | "intercept"
            | "invoke"
            | "log_append"
            | "log_skip"
            | "log_name"
            | "map"
            | "method"
            | "metrics"
            | "php_fastcgi"
            | "push"
            | "request_body"
            | "request_header"
            | "root"
            | "templates"
            | "tracing"
            | "try_files"
            | "uri"
            | "vars"
    )
}

/// 🚦 Adapts an exact local rate-limit policy and rejects ambiguous options.
fn adapt_rate_limit(directive: Directive) -> Result<Handler, AdapterError> {
    let [requests, window] = directive.args.as_slice() else {
        return Err(AdapterError::InvalidArgument(
            directive.name,
            "expected <requests> <window> followed by an optional block".into(),
        ));
    };
    let requests = requests
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| AdapterError::InvalidArgument("rate_limit".into(), requests.clone()))?;
    let window_ms = parse_duration_ms(window)
        .filter(|value| *value >= 1_000 && value % 1_000 == 0)
        .ok_or_else(|| AdapterError::InvalidArgument("rate_limit".into(), window.clone()))?;
    let mut config = RateLimitConfig {
        requests,
        window_ms,
        burst: 0,
        key: RateLimitKey::Ip,
        dry_run: false,
    };

    if let Some(block) = directive.block {
        for option in block.directives {
            match option.name.as_str() {
                "burst" => {
                    let value = expect_one_argument(&option)?;
                    config.burst = value.parse::<u64>().map_err(|_| {
                        AdapterError::InvalidArgument(option.name.clone(), value.to_string())
                    })?;
                }
                "dry_run" => {
                    expect_no_arguments(&option)?;
                    config.dry_run = true;
                }
                "key" => {
                    config.key = match option.args.as_slice() {
                        [kind] if kind == "ip" => RateLimitKey::Ip,
                        [kind] if kind == "global" => RateLimitKey::Global,
                        [kind] if kind == "route" => RateLimitKey::Route,
                        [kind] if kind == "api_key" => RateLimitKey::ApiKey,
                        [kind] if kind == "tenant" => RateLimitKey::Tenant("X-Tenant-ID".into()),
                        [kind, name] if kind == "header" => RateLimitKey::Header(name.clone()),
                        [kind, name] if kind == "tenant" => RateLimitKey::Tenant(name.clone()),
                        _ => {
                            return Err(AdapterError::InvalidArgument(
                                option.name,
                                "expected ip, global, route, api_key, header <name>, or tenant [name]"
                                    .into(),
                            ));
                        }
                    };
                }
                _ => return Err(AdapterError::UnknownDirective(option.name)),
            }
        }
    }

    Ok(Handler::RateLimit(config))
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
    let mut upstreams = Vec::with_capacity(d.args.len());
    for arg in &d.args {
        if arg.starts_with('@') {
            continue;
        }
        // 🚫 A Unix-socket upstream (`unix//run/php.sock`) used to compile
        // into a bogus hostname that could never dial. Refuse it here instead
        // of shipping a proxy whose upstream silently never comes up.
        if arg.starts_with("unix") {
            // TODO(v0.3): support Unix-socket upstreams (unix//path).
            return Err(AdapterError::UnsupportedFeature(
                "reverse_proxy".into(),
                format!(
                    "`{arg}` is a Unix-socket upstream address; Pingclair does not \
                     support Unix-socket upstreams yet"
                ),
            ));
        }
        upstreams.push(arg.clone());
    }

    // 🌐 Caddy expands `to :9000-9003` into one upstream per port; do the
    // same before the AST is compiled so JSON and runtime see the peers.
    let upstreams = super::expand_upstream_port_ranges(upstreams);
    let mut proxy = ProxyConfig::new(upstreams);

    // Parse sub-block if present
    if let Some(block) = d.block {
        for sub in block.directives {
            match sub.name.as_str() {
                "header_up" => {
                    // header_up Key Value
                    // Value may be a {placeholder} → preserved as-is for runtime resolution
                    match sub.args.as_slice() {
                        [key, value] => {
                            proxy
                                .header_up
                                .insert(key.clone(), Expr::String(value.clone()));
                        }
                        // 🚩 A third argument used to be silently dropped, so
                        // `header_up X-Foo a b` sent only `a` upstream while
                        // looking like it sent both.
                        _ => {
                            return Err(AdapterError::ArgumentCount(
                                "header_up".into(),
                                2,
                                sub.args.len(),
                            ));
                        }
                    }
                }
                "header_down" => {
                    // 🚫 Caddy's `header_down` used to be silently dropped,
                    // leaving the operator certain a response header was being
                    // rewritten while the proxy forwarded it untouched.
                    // TODO(v0.3): implement response header rewriting.
                    return Err(AdapterError::UnsupportedFeature(
                        "reverse_proxy header_down".into(),
                        "response header rewriting is not implemented yet".into(),
                    ));
                }
                "dynamic" => {
                    // 🚫 SRV-based dynamic upstream discovery is a Caddy
                    // feature with no runtime equivalent here yet; a config
                    // naming it must not silently degrade to static upstreams.
                    // TODO(v0.3): implement SRV/dynamic upstream discovery.
                    return Err(AdapterError::UnsupportedFeature(
                        "reverse_proxy dynamic".into(),
                        "dynamic upstream discovery is not implemented yet".into(),
                    ));
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
                            connect_timeout: None,
                            first_byte_timeout: None,
                            between_reads_timeout: None,
                            read_timeout: None,
                            write_timeout: None,
                            tls: UpstreamTlsConfig::default(),
                        };
                        for t_sub in transport_block.directives {
                            match t_sub.name.as_str() {
                                "connect_timeout" => {
                                    transport.connect_timeout =
                                        Some(parse_required_duration(&t_sub)?);
                                }
                                "first_byte_timeout" => {
                                    transport.first_byte_timeout =
                                        Some(parse_required_duration(&t_sub)?);
                                }
                                "between_reads_timeout" => {
                                    transport.between_reads_timeout =
                                        Some(parse_required_duration(&t_sub)?);
                                }
                                "read_timeout" => {
                                    transport.read_timeout = Some(parse_required_duration(&t_sub)?);
                                }
                                "write_timeout" => {
                                    transport.write_timeout =
                                        Some(parse_required_duration(&t_sub)?);
                                }
                                "tls" => {
                                    expect_no_arguments(&t_sub)?;
                                    transport.tls.enable = true;
                                }
                                "tls_server_name" => {
                                    transport.tls.server_name =
                                        Some(expect_one_argument(&t_sub)?.to_string());
                                }
                                "tls_trusted_ca_certs" => {
                                    if t_sub.args.is_empty() {
                                        return Err(AdapterError::ArgumentCount(
                                            "tls_trusted_ca_certs".into(),
                                            1,
                                            0,
                                        ));
                                    }
                                    transport
                                        .tls
                                        .trusted_ca_certs
                                        .extend(t_sub.args.iter().cloned());
                                }
                                "tls_client_auth" => {
                                    // 🎫 Both halves are required together: a certificate
                                    // without its key silently becomes an anonymous
                                    // handshake that the upstream rejects much later.
                                    if t_sub.args.len() != 2 {
                                        return Err(AdapterError::ArgumentCount(
                                            "tls_client_auth".into(),
                                            2,
                                            t_sub.args.len(),
                                        ));
                                    }
                                    transport.tls.client_cert = Some(t_sub.args[0].clone());
                                    transport.tls.client_key = Some(t_sub.args[1].clone());
                                }
                                "tls_insecure_skip_verify" => {
                                    expect_no_arguments(&t_sub)?;
                                    transport.tls.insecure_skip_verify = true;
                                }
                                _ => {
                                    return Err(AdapterError::UnknownDirective(format!(
                                        "transport http: {}",
                                        t_sub.name
                                    )));
                                }
                            }
                        }
                        validate_upstream_tls(&transport.tls)?;
                        proxy.transport = Some(transport);
                    }
                }
                "cache" => {
                    proxy.cache = Some(adapt_cache_policy(&sub)?);
                }
                "retry" => {
                    proxy.retry = adapt_retry_policy(&sub)?;
                }
                "overload" => {
                    proxy.overload = adapt_overload_policy(&sub)?;
                }
                "circuit_breaker" => {
                    proxy.circuit_breaker = adapt_circuit_breaker_policy(&sub)?;
                }
                "health_check" => {
                    proxy.health_check = Some(adapt_health_check(&sub)?);
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
                    // 🧭 Caddy's `to` accepts several upstreams on one line
                    // (`to 10.0.1.1:80 10.0.1.2:80`). A block (`to host {
                    // weight 3 }`) configures exactly one upstream.
                    if let Some(to_block) = sub.block {
                        let address = sub.args.first().ok_or_else(|| {
                            AdapterError::ArgumentCount("reverse_proxy to".into(), 1, 0)
                        })?;
                        if sub.args.len() != 1 {
                            return Err(AdapterError::InvalidArgument(
                                "reverse_proxy to".into(),
                                "a block form takes exactly one upstream address".into(),
                            ));
                        }
                        for address in super::expand_upstream_port_ranges([address.clone()]) {
                            let mut upstream = ProxyUpstreamConfig {
                                address: address.clone(),
                                weight: 1,
                                backup: false,
                            };
                            for option in &to_block.directives {
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
                            proxy.upstreams.push(address.clone());
                            proxy.upstream_options.push(upstream);
                        }
                    } else {
                        if sub.args.is_empty() {
                            return Err(AdapterError::ArgumentCount(
                                "reverse_proxy to".into(),
                                1,
                                0,
                            ));
                        }
                        for address in super::expand_upstream_port_ranges(sub.args.iter().cloned())
                        {
                            proxy.upstreams.push(address.clone());
                            proxy.upstream_options.push(ProxyUpstreamConfig {
                                address: address.clone(),
                                weight: 1,
                                backup: false,
                            });
                        }
                    }
                }
                // 🚩 `lb_try_duration`, `fail_duration` and any other
                // unrecognised subdirective used to vanish here. A config
                // that names a tuning knob the runtime does not honor must
                // fail load, or the operator will tune a phantom.
                other => {
                    return Err(AdapterError::UnknownDirective(format!(
                        "reverse_proxy: {other}"
                    )));
                }
            }
        }
    }

    if proxy.upstreams.is_empty() {
        return Err(AdapterError::ArgumentCount("reverse_proxy".into(), 1, 0));
    }

    Ok(Handler::Proxy(Box::new(proxy)))
}

/// 🩺 Adapts one bounded active health-check policy.
fn adapt_health_check(directive: &Directive) -> Result<HealthCheckConfig, AdapterError> {
    if !directive.args.is_empty() {
        return Err(AdapterError::ArgumentCount(
            "health_check".into(),
            0,
            directive.args.len(),
        ));
    }
    let block = directive.block.as_ref().ok_or_else(|| {
        AdapterError::InvalidArgument("health_check".into(), "block required".into())
    })?;
    let mut health = HealthCheckConfig::default();
    for sub in &block.directives {
        match sub.name.as_str() {
            "path" => health.path = expect_one_argument(sub)?.to_string(),
            "interval" => {
                let millis = parse_required_duration(sub)?;
                if millis < 1_000 || millis % 1_000 != 0 {
                    return Err(AdapterError::InvalidArgument(
                        sub.name.clone(),
                        "interval must be a whole number of seconds".into(),
                    ));
                }
                health.interval_secs = millis / 1_000;
            }
            "timeout" => {
                let millis = parse_required_duration(sub)?;
                if millis < 1_000 || millis % 1_000 != 0 {
                    return Err(AdapterError::InvalidArgument(
                        sub.name.clone(),
                        "timeout must be a whole number of seconds".into(),
                    ));
                }
                health.timeout_secs = millis / 1_000;
            }
            "method" => {
                health.method = expect_one_argument(sub)?.to_ascii_uppercase();
            }
            "host" => health.host = Some(expect_one_argument(sub)?.to_string()),
            "header" => {
                if sub.args.len() != 2 {
                    return Err(AdapterError::ArgumentCount(
                        sub.name.clone(),
                        2,
                        sub.args.len(),
                    ));
                }
                health
                    .headers
                    .insert(sub.args[0].clone(), sub.args[1].clone());
            }
            "status" => {
                if sub.args.is_empty() {
                    return Err(AdapterError::ArgumentCount(sub.name.clone(), 1, 0));
                }
                health.expected_statuses = sub
                    .args
                    .iter()
                    .map(|value| {
                        value.parse::<u16>().map_err(|_| {
                            AdapterError::InvalidArgument(sub.name.clone(), value.clone())
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
            }
            "body" => health.expected_body = Some(expect_one_argument(sub)?.to_string()),
            "port" => {
                let raw = expect_one_argument(sub)?;
                health.port = Some(raw.parse::<u16>().map_err(|_| {
                    AdapterError::InvalidArgument(sub.name.clone(), raw.to_string())
                })?);
            }
            "consecutive_success" => {
                health.consecutive_success =
                    u32::try_from(parse_positive_usize(sub)?).map_err(|_| {
                        AdapterError::InvalidArgument(sub.name.clone(), "value is too large".into())
                    })?;
            }
            "consecutive_failure" => {
                health.consecutive_failure =
                    u32::try_from(parse_positive_usize(sub)?).map_err(|_| {
                        AdapterError::InvalidArgument(sub.name.clone(), "value is too large".into())
                    })?;
            }
            "reuse_connection" => {
                expect_no_arguments(sub)?;
                health.reuse_connection = true;
            }
            "max_response_body_bytes" => {
                health.max_response_body_bytes = parse_positive_usize(sub)?;
            }
            "slow_start" => health.slow_start_ms = parse_required_duration(sub)?,
            _ => {
                return Err(AdapterError::UnknownDirective(format!(
                    "health_check: {}",
                    sub.name
                )));
            }
        }
    }
    Ok(health)
}

/// 🔁 Adapts one bounded, idempotent-only redispatch policy.
/// 🗄️ Adapts `cache { ttl <duration> }` inside a `reverse_proxy` block.
///
/// `ttl` has no default on purpose. Deciding how long someone else's content
/// stays valid is the operator's call, and guessing it silently is how a proxy
/// ends up serving yesterday's page with nobody able to say why.
fn adapt_cache_policy(directive: &Directive) -> Result<CacheConfig, AdapterError> {
    if !directive.args.is_empty() {
        return Err(AdapterError::ArgumentCount(
            "cache".into(),
            0,
            directive.args.len(),
        ));
    }
    let block = directive
        .block
        .as_ref()
        .ok_or_else(|| AdapterError::InvalidArgument("cache".into(), "block required".into()))?;

    let mut ttl_secs = None;
    for sub in &block.directives {
        match sub.name.as_str() {
            "ttl" => {
                // ⏳ Durations arrive in milliseconds; caching reasons in seconds.
                let ms = parse_required_duration(sub)?;
                ttl_secs = Some(ms / 1000);
            }
            other => {
                return Err(AdapterError::UnknownDirective(other.to_string()));
            }
        }
    }

    let ttl_secs = ttl_secs
        .ok_or_else(|| AdapterError::InvalidArgument("cache".into(), "ttl is required".into()))?;
    Ok(CacheConfig { ttl_secs })
}

fn adapt_retry_policy(directive: &Directive) -> Result<RetryConfig, AdapterError> {
    if !directive.args.is_empty() {
        return Err(AdapterError::ArgumentCount(
            "retry".into(),
            0,
            directive.args.len(),
        ));
    }
    let block = directive
        .block
        .as_ref()
        .ok_or_else(|| AdapterError::InvalidArgument("retry".into(), "block required".into()))?;
    let mut retry = RetryConfig::default();
    for sub in &block.directives {
        match sub.name.as_str() {
            "max_attempts" => retry.max_attempts = parse_positive_usize(sub)?,
            "total_timeout" => {
                retry.total_timeout_ms = Some(parse_required_duration(sub)?);
            }
            "backoff" => {
                retry.backoff_ms = if sub.args.as_slice() == ["off"] {
                    0
                } else {
                    parse_required_duration(sub)?
                };
            }
            "status_codes" => {
                if sub.args.is_empty() {
                    return Err(AdapterError::ArgumentCount(sub.name.clone(), 1, 0));
                }
                retry.status_codes = sub
                    .args
                    .iter()
                    .map(|value| {
                        value.parse::<u16>().map_err(|_| {
                            AdapterError::InvalidArgument(sub.name.clone(), value.clone())
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
            }
            "methods" => {
                if sub.args.is_empty() {
                    return Err(AdapterError::ArgumentCount(sub.name.clone(), 1, 0));
                }
                retry.methods = sub
                    .args
                    .iter()
                    .map(|method| method.to_ascii_uppercase())
                    .collect();
            }
            _ => {
                return Err(AdapterError::UnknownDirective(format!(
                    "retry: {}",
                    sub.name
                )));
            }
        }
    }
    Ok(retry)
}

/// 🚦 Adapts bounded route and upstream admission controls.
fn adapt_overload_policy(directive: &Directive) -> Result<OverloadConfig, AdapterError> {
    if !directive.args.is_empty() {
        return Err(AdapterError::ArgumentCount(
            "overload".into(),
            0,
            directive.args.len(),
        ));
    }
    let block = directive
        .block
        .as_ref()
        .ok_or_else(|| AdapterError::InvalidArgument("overload".into(), "block required".into()))?;
    if block.directives.is_empty() {
        return Err(AdapterError::InvalidArgument(
            "overload".into(),
            "at least one limit is required".into(),
        ));
    }
    let mut overload = OverloadConfig::default();
    for sub in &block.directives {
        match sub.name.as_str() {
            "max_in_flight" => overload.max_in_flight = Some(parse_positive_usize(sub)?),
            "max_pending" => overload.max_pending = parse_positive_usize(sub)?,
            "pending_timeout" => {
                overload.pending_timeout_ms = parse_required_duration(sub)?;
            }
            "upstream_max_connections" => {
                overload.upstream_max_connections = Some(parse_positive_usize(sub)?);
            }
            _ => {
                return Err(AdapterError::UnknownDirective(format!(
                    "overload: {}",
                    sub.name
                )));
            }
        }
    }
    if overload.max_in_flight.is_none()
        && overload.max_pending == 0
        && overload.upstream_max_connections.is_none()
    {
        return Err(AdapterError::InvalidArgument(
            "overload".into(),
            "at least one active limit is required".into(),
        ));
    }
    Ok(overload)
}

/// 🔌 Adapts one per-upstream circuit-breaker policy.
fn adapt_circuit_breaker_policy(
    directive: &Directive,
) -> Result<CircuitBreakerConfig, AdapterError> {
    if !directive.args.is_empty() {
        return Err(AdapterError::ArgumentCount(
            "circuit_breaker".into(),
            0,
            directive.args.len(),
        ));
    }
    let block = directive.block.as_ref().ok_or_else(|| {
        AdapterError::InvalidArgument("circuit_breaker".into(), "block required".into())
    })?;
    if block.directives.is_empty() {
        return Err(AdapterError::InvalidArgument(
            "circuit_breaker".into(),
            "at least one threshold is required".into(),
        ));
    }
    let mut breaker = CircuitBreakerConfig::default();
    for sub in &block.directives {
        match sub.name.as_str() {
            "consecutive_failures" => {
                breaker.consecutive_failures =
                    Some(u32::try_from(parse_positive_usize(sub)?).map_err(|_| {
                        AdapterError::InvalidArgument(sub.name.clone(), "value is too large".into())
                    })?);
            }
            "error_rate_percent" => {
                breaker.error_rate_percent =
                    Some(u8::try_from(parse_positive_usize(sub)?).map_err(|_| {
                        AdapterError::InvalidArgument(sub.name.clone(), "value is too large".into())
                    })?);
            }
            "minimum_requests" => breaker.minimum_requests = parse_positive_usize(sub)?,
            "window_requests" => breaker.window_requests = parse_positive_usize(sub)?,
            "open_for" => breaker.open_duration_ms = parse_required_duration(sub)?,
            "half_open_requests" => breaker.half_open_requests = parse_positive_usize(sub)?,
            "failure_statuses" => {
                if sub.args.is_empty() {
                    return Err(AdapterError::ArgumentCount(sub.name.clone(), 1, 0));
                }
                breaker.failure_statuses = sub
                    .args
                    .iter()
                    .map(|value| {
                        value.parse::<u16>().map_err(|_| {
                            AdapterError::InvalidArgument(sub.name.clone(), value.clone())
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
            }
            _ => {
                return Err(AdapterError::UnknownDirective(format!(
                    "circuit_breaker: {}",
                    sub.name
                )));
            }
        }
    }
    if breaker.consecutive_failures.is_none() && breaker.error_rate_percent.is_none() {
        return Err(AdapterError::InvalidArgument(
            "circuit_breaker".into(),
            "consecutive_failures or error_rate_percent is required".into(),
        ));
    }
    Ok(breaker)
}

/// Parse the global `dns_refresh` argument into seconds.
///
/// `off`/`none` disable re-resolution. Everything else is a duration, and a
/// unit is mandatory: `parse_duration_ms` reads a bare number as
/// milliseconds, so accepting `dns_refresh 30` would silently install a
/// 30 ms lookup storm instead of the half-minute the operator meant. Sub-second
/// intervals are refused for the same reason rather than clamped, so the
/// mistake surfaces at load time instead of in production DNS traffic.
fn parse_dns_refresh(value: &str) -> Result<u64, AdapterError> {
    if matches!(value.to_ascii_lowercase().as_str(), "off" | "none") {
        return Ok(0);
    }

    let invalid = || {
        AdapterError::InvalidArgument(
            "dns_refresh".into(),
            format!("expected `off` or a duration of at least 1s, got `{value}`"),
        )
    };

    let millis = parse_duration_ms(value).ok_or_else(invalid)?;
    if millis < 1_000 {
        return Err(invalid());
    }
    Ok(millis / 1_000)
}

/// 🔐 Rejects upstream TLS blocks whose directives contradict each other.
///
/// Both cases below are configurations where one directive silently cancels
/// another, so the operator's stated intent and the resulting security posture
/// differ. Refusing to load is the only outcome that cannot be misread.
fn validate_upstream_tls(tls: &UpstreamTlsConfig) -> Result<(), AdapterError> {
    if tls.insecure_skip_verify && !tls.trusted_ca_certs.is_empty() {
        return Err(AdapterError::InvalidArgument(
            "tls_insecure_skip_verify".into(),
            "cannot be combined with tls_trusted_ca_certs: skipping verification \
             would make the configured trust roots meaningless"
                .into(),
        ));
    }
    if tls.insecure_skip_verify && tls.server_name.is_some() {
        return Err(AdapterError::InvalidArgument(
            "tls_insecure_skip_verify".into(),
            "cannot be combined with tls_server_name: the name would be sent as \
             SNI but never verified"
                .into(),
        ));
    }
    Ok(())
}

/// 🚩 Accepts a bare flag directive, rejecting stray arguments instead of dropping them.
fn expect_no_arguments(directive: &Directive) -> Result<(), AdapterError> {
    if directive.args.is_empty() {
        return Ok(());
    }
    Err(AdapterError::ArgumentCount(
        directive.name.clone(),
        0,
        directive.args.len(),
    ))
}

/// 🏷️ Reads exactly one argument, rejecting both none and extras.
fn expect_one_argument(directive: &Directive) -> Result<&str, AdapterError> {
    if directive.args.len() != 1 {
        return Err(AdapterError::ArgumentCount(
            directive.name.clone(),
            1,
            directive.args.len(),
        ));
    }
    Ok(directive.args[0].as_str())
}

/// ⏱️ Parses one mandatory, positive duration argument without permissive fallback.
fn parse_required_duration(directive: &Directive) -> Result<u64, AdapterError> {
    let value = directive.args.first().ok_or_else(|| {
        AdapterError::ArgumentCount(directive.name.clone(), 1, directive.args.len())
    })?;
    if directive.args.len() != 1 {
        return Err(AdapterError::ArgumentCount(
            directive.name.clone(),
            1,
            directive.args.len(),
        ));
    }
    parse_duration_ms(value)
        .filter(|millis| *millis > 0 && *millis <= 31_536_000_000)
        .ok_or_else(|| AdapterError::InvalidArgument(directive.name.clone(), value.clone()))
}

/// 🧱 Adapts one fail-closed downstream resource-limit block.
fn adapt_resource_limits(directive: &Directive) -> Result<ResourceLimitsConfig, AdapterError> {
    if !directive.args.is_empty() {
        return Err(AdapterError::ArgumentCount(
            "limits".into(),
            0,
            directive.args.len(),
        ));
    }
    let block = directive
        .block
        .as_ref()
        .ok_or_else(|| AdapterError::InvalidArgument("limits".into(), "block required".into()))?;
    let mut limits = ResourceLimitsConfig::default();
    for sub in &block.directives {
        match sub.name.as_str() {
            "header_timeout" => {
                limits.header_timeout_ms = Some(parse_required_duration(sub)?);
            }
            "body_timeout" => {
                limits.body_timeout_ms = Some(parse_required_duration(sub)?);
            }
            "idle_timeout" => {
                limits.idle_timeout_ms = Some(parse_required_duration(sub)?);
            }
            "request_timeout" => {
                limits.request_timeout_ms = Some(parse_required_duration(sub)?);
            }
            "max_headers" => {
                limits.max_header_count = Some(parse_positive_usize(sub)?);
            }
            "max_header_bytes" => {
                limits.max_header_bytes = Some(parse_positive_usize(sub)?);
            }
            "max_connections" => {
                limits.max_connections = Some(parse_positive_usize(sub)?);
            }
            "upload_bytes_per_sec" => {
                limits.upload_bytes_per_sec = Some(parse_positive_u64(sub)?);
            }
            "download_bytes_per_sec" => {
                limits.download_bytes_per_sec = Some(parse_positive_u64(sub)?);
            }
            "long_connections" => {
                limits.long_connections = adapt_long_connection_limits(sub)?;
            }
            _ => {
                return Err(AdapterError::UnknownDirective(format!(
                    "limits: {}",
                    sub.name
                )));
            }
        }
    }
    Ok(limits)
}

/// 🌊 Adapts long-connection overrides, where `off` deliberately removes a deadline.
fn adapt_long_connection_limits(
    directive: &Directive,
) -> Result<LongConnectionLimits, AdapterError> {
    if !directive.args.is_empty() {
        return Err(AdapterError::ArgumentCount(
            "long_connections".into(),
            0,
            directive.args.len(),
        ));
    }
    let block = directive.block.as_ref().ok_or_else(|| {
        AdapterError::InvalidArgument("long_connections".into(), "block required".into())
    })?;
    let mut limits = LongConnectionLimits::default();
    for sub in &block.directives {
        let value = sub
            .args
            .first()
            .ok_or_else(|| AdapterError::ArgumentCount(sub.name.clone(), 1, sub.args.len()))?;
        if sub.args.len() != 1 {
            return Err(AdapterError::ArgumentCount(
                sub.name.clone(),
                1,
                sub.args.len(),
            ));
        }
        let millis = if matches!(value.as_str(), "off" | "none") {
            0
        } else {
            parse_duration_ms(value)
                .filter(|millis| *millis > 0 && *millis <= 31_536_000_000)
                .ok_or_else(|| AdapterError::InvalidArgument(sub.name.clone(), value.clone()))?
        };
        match sub.name.as_str() {
            "idle_timeout" => limits.idle_timeout_ms = Some(millis),
            "request_timeout" => limits.request_timeout_ms = Some(millis),
            _ => {
                return Err(AdapterError::UnknownDirective(format!(
                    "long_connections: {}",
                    sub.name
                )));
            }
        }
    }
    Ok(limits)
}

/// 🔢 Parses one mandatory positive `usize` argument.
fn parse_positive_usize(directive: &Directive) -> Result<usize, AdapterError> {
    parse_positive_u64(directive).and_then(|value| {
        usize::try_from(value)
            .map_err(|_| AdapterError::InvalidArgument(directive.name.clone(), value.to_string()))
    })
}

/// 🔢 Parses one mandatory positive integer argument.
fn parse_positive_u64(directive: &Directive) -> Result<u64, AdapterError> {
    let value = directive.args.first().ok_or_else(|| {
        AdapterError::ArgumentCount(directive.name.clone(), 1, directive.args.len())
    })?;
    if directive.args.len() != 1 {
        return Err(AdapterError::ArgumentCount(
            directive.name.clone(),
            1,
            directive.args.len(),
        ));
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|parsed| *parsed > 0)
        .ok_or_else(|| AdapterError::InvalidArgument(directive.name.clone(), value.clone()))
}

/// ⏱️ Parses Caddy durations into milliseconds.
///
/// Accepts the full Go-style unit set (`ns`, `us`/`µs`, `ms`, `s`, `m`,
/// `h`, `d`), fractional values (`1.5h`) and compound values (`2h45m`).
/// A bare number is rejected: `30` would silently mean 30 ms instead of the
/// 30 seconds the operator almost certainly meant.
fn parse_duration_ms(s: &str) -> Option<u64> {
    const UNITS: [(&str, f64); 8] = [
        ("ns", 1e-6),
        ("us", 1e-3),
        ("µs", 1e-3),
        ("ms", 1.0),
        ("s", 1e3),
        ("m", 6e4),
        ("h", 3.6e6),
        ("d", 8.64e7),
    ];

    let mut rest = s.trim();
    if rest.is_empty() {
        return None;
    }
    let mut total_ms = 0.0f64;
    let mut consumed_any = false;
    while !rest.is_empty() {
        // 🧮 Read the numeric part (integer or decimal fraction).
        let number_end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        if number_end == 0 {
            return None;
        }
        let number: f64 = rest[..number_end].parse().ok()?;
        rest = &rest[number_end..];

        // 🧮 Read the unit that follows; without one the input is malformed.
        let unit = UNITS
            .iter()
            .find(|(name, _)| rest.starts_with(name))
            .map(|(name, multiplier)| (*name, *multiplier))?;
        total_ms += number * unit.1;
        rest = &rest[unit.0.len()..];
        consumed_any = true;
    }
    if !consumed_any {
        return None;
    }
    // ⚙️ Sub-millisecond durations cannot be represented in the internal
    // millisecond fields, so refuse them instead of silently truncating.
    if total_ms < 1.0 {
        return None;
    }
    Some(total_ms.round() as u64)
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
            } else {
                // 🚩 `header X-Only` used to compile into an empty header
                // operation: no set, no remove, no add. A header key without
                // a value is either a typo or a request to remove — make the
                // author say which.
                return Err(AdapterError::ArgumentCount("header".into(), 2, args.len()));
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
    if let Some(arg) = d.args.first() {
        if arg.starts_with('@') {
            matcher = Some(Matcher::Named(arg.clone()));
        } else if arg.starts_with('/') && arg.contains('*') {
            // 🧭 Caddy's inline path matcher: `reverse_proxy /api/* ...` and
            // `file_server /downloads/* { ... }` scope the directive to the
            // glob. A leading slash without a glob stays a plain argument
            // (e.g. `file_server /var/www/html` is a root).
            matcher = Some(Matcher::Path(PathMatcher {
                patterns: vec![arg.clone()],
            }));
        }
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

        Ok(merge_matcher_set(matchers))
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

/// 🧩 Merges a named matcher set the way Caddy does: matchers of the same
/// kind are OR'ed (path values, method verbs, host names, header fields of
/// the same name, query keys of the same name, remote-IP ranges) while
/// different kinds are AND'ed. The old code AND'ed everything, which made
/// `@foo { header Foo bar; header Foo baz }` impossible to satisfy.
fn merge_matcher_set(matchers: Vec<Matcher>) -> Matcher {
    use std::collections::HashMap;

    let mut header_groups: HashMap<String, Vec<HeaderMatcher>> = HashMap::new();
    let mut query_groups: HashMap<String, Vec<QueryMatcher>> = HashMap::new();
    let mut paths: Vec<String> = Vec::new();
    let mut methods: Vec<HttpMethod> = Vec::new();
    let mut hosts: Vec<String> = Vec::new();
    let mut remote_ips: Vec<String> = Vec::new();
    let mut others: Vec<Matcher> = Vec::new();

    for matcher in matchers {
        match matcher {
            Matcher::Header(header) => {
                header_groups
                    .entry(header.name.clone())
                    .or_default()
                    .push(header);
            }
            Matcher::Query(query) => {
                query_groups
                    .entry(query.name.clone())
                    .or_default()
                    .push(query);
            }
            Matcher::Path(path) => paths.extend(path.patterns),
            Matcher::Method(m) => methods.extend(m),
            Matcher::Host(h) => hosts.extend(h),
            Matcher::RemoteIp(ips) => remote_ips.extend(ips),
            other => others.push(other),
        }
    }

    let mut parts: Vec<Matcher> = Vec::new();
    for headers in header_groups.into_values() {
        let group = headers
            .into_iter()
            .map(Matcher::Header)
            .reduce(|left, right| Matcher::Or(Box::new(left), Box::new(right)))
            .expect("a header group is never empty");
        parts.push(group);
    }
    for queries in query_groups.into_values() {
        let group = queries
            .into_iter()
            .map(Matcher::Query)
            .reduce(|left, right| Matcher::Or(Box::new(left), Box::new(right)))
            .expect("a query group is never empty");
        parts.push(group);
    }
    if !paths.is_empty() {
        parts.push(Matcher::Path(PathMatcher { patterns: paths }));
    }
    if !methods.is_empty() {
        parts.push(Matcher::Method(methods));
    }
    if !hosts.is_empty() {
        parts.push(Matcher::Host(hosts));
    }
    if !remote_ips.is_empty() {
        parts.push(Matcher::RemoteIp(remote_ips));
    }
    parts.extend(others);

    let mut combined = parts.remove(0);
    for part in parts {
        combined = Matcher::And(Box::new(combined), Box::new(part));
    }
    combined
}

/// 🕳️ Maximum matcher nesting accepted from a Pingclairfile.
///
/// Blocks are capped at 100 in the parser; matchers are a separate recursion
/// and were never capped, so `not not not …` deep enough exhausted the stack
/// and aborted the process. Nothing legitimate nests more than a few deep.
const MAX_MATCHER_NESTING: usize = 32;

fn parse_single_matcher(d: &Directive) -> Result<Matcher, AdapterError> {
    parse_single_matcher_at(d, 0)
}

fn parse_single_matcher_at(d: &Directive, depth: usize) -> Result<Matcher, AdapterError> {
    if depth > MAX_MATCHER_NESTING {
        return Err(AdapterError::InvalidArgument(
            d.name.clone(),
            format!("matcher nesting exceeds the maximum depth of {MAX_MATCHER_NESTING}"),
        ));
    }
    match d.name.as_str() {
        "path" => Ok(Matcher::Path(PathMatcher {
            patterns: d.args.clone(),
        })),
        "not" => {
            let inner = if let Some(block) = &d.block {
                let mut matchers = block
                    .directives
                    .iter()
                    .map(|inner| parse_single_matcher_at(inner, depth + 1))
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
                parse_single_matcher_at(&nested, depth + 1)?
            };
            Ok(Matcher::Not(Box::new(inner)))
        }
        "method" => {
            // 🚫 Unknown verbs used to be filtered out silently, so
            // `method HEAD` produced a matcher that could never match while
            // `method GET FOO` quietly matched only GET. Every standard verb
            // is supported and anything else is a config error.
            let mut methods = Vec::with_capacity(d.args.len());
            for m in &d.args {
                let method = match m.to_uppercase().as_str() {
                    "GET" => HttpMethod::Get,
                    "POST" => HttpMethod::Post,
                    "PUT" => HttpMethod::Put,
                    "DELETE" => HttpMethod::Delete,
                    "PATCH" => HttpMethod::Patch,
                    "HEAD" => HttpMethod::Head,
                    "OPTIONS" => HttpMethod::Options,
                    other => {
                        return Err(AdapterError::InvalidArgument(
                            "method".into(),
                            format!("unknown HTTP method `{other}`"),
                        ));
                    }
                };
                methods.push(method);
            }
            Ok(Matcher::Method(methods))
        }
        "host" => {
            if d.args.is_empty() {
                return Err(AdapterError::ArgumentCount("host".into(), 1, 0));
            }
            Ok(Matcher::Host(d.args.clone()))
        }
        "query" => {
            // 🧭 `query q=1` / `query q=*`; several lines for the same key are
            // OR'ed by the set merge, different keys are AND'ed. The bare
            // `query ""` (no query string at all) is deferred to v0.3.
            let Some(spec) = d.args.first() else {
                return Err(AdapterError::ArgumentCount("query".into(), 1, 0));
            };
            if d.args.len() != 1 {
                return Err(AdapterError::ArgumentCount("query".into(), 1, d.args.len()));
            }
            if spec.is_empty() {
                // TODO(v0.3): support `query ""` (requests with no query
                // string) via a dedicated condition.
                return Err(AdapterError::UnsupportedFeature(
                    "query".into(),
                    "the empty-query matcher (`query \"\"`) is not implemented yet".into(),
                ));
            }
            let Some((name, value)) = spec.split_once('=') else {
                return Err(AdapterError::InvalidArgument(
                    "query".into(),
                    format!("expected `key=value`, got `{spec}`"),
                ));
            };
            let condition = if value == "*" {
                HeaderCondition::Exists
            } else {
                HeaderCondition::Equals(value.to_string())
            };
            Ok(Matcher::Query(QueryMatcher {
                name: name.to_string(),
                condition,
            }))
        }
        "protocol" => {
            if d.args.is_empty() {
                return Err(AdapterError::ArgumentCount("protocol".into(), 1, 0));
            }
            // 🚫 Versioned forms like `http/2+` need range comparison that the
            // runtime does not implement yet; refuse them instead of treating
            // them as an exact protocol string.
            if d.args.iter().any(|p| p.contains('/')) {
                // TODO(v0.3): implement versioned protocol matchers.
                return Err(AdapterError::UnsupportedFeature(
                    "protocol".into(),
                    "versioned protocol matchers (http/2+, grpc) are not implemented yet".into(),
                ));
            }
            Ok(Matcher::Protocol(d.args.clone()))
        }
        "remote_ip" | "client_ip" => {
            if d.args.is_empty() {
                return Err(AdapterError::ArgumentCount(d.name.clone(), 1, 0));
            }
            // 🧭 `client_ip` matches the verified client address; Pingclair
            // resolves that before routing, so both spellings share the same
            // remote-address evaluation for now.
            Ok(Matcher::RemoteIp(d.args.clone()))
        }
        "header" => {
            if d.args.is_empty() {
                return Err(AdapterError::ArgumentCount(
                    "header".into(),
                    1,
                    d.args.len(),
                ));
            }
            // 🚫 A third argument used to be silently dropped, so
            // `header Foo bar baz` matched only `bar`. Caddy matches one
            // field with one value per matcher line; write a second line for
            // an OR'ed value.
            if d.args.len() > 2 {
                return Err(AdapterError::ArgumentCount(
                    "header".into(),
                    2,
                    d.args.len(),
                ));
            }

            // 🚫 A `!` prefix means the field must NOT exist (`header !Foo`).
            let raw_name = &d.args[0];
            let negated = raw_name.starts_with('!');
            let name = raw_name.strip_prefix('!').unwrap_or(raw_name);

            let condition = if d.args.len() >= 2 {
                let val = &d.args[1];
                if val == "*" {
                    HeaderCondition::Exists
                } else if val.starts_with('*') && val.ends_with('*') && val.len() >= 2 {
                    HeaderCondition::Contains(val[1..val.len() - 1].to_string())
                } else if val.starts_with('*') {
                    // `*suffix` matches values ending with the rest.
                    HeaderCondition::EndsWith(val.strip_prefix('*').unwrap_or(val).to_string())
                } else if val.ends_with('*') {
                    // `prefix*` matches values starting with the rest.
                    HeaderCondition::StartsWith(val.strip_suffix('*').unwrap_or(val).to_string())
                } else {
                    HeaderCondition::Equals(val.clone())
                }
            } else {
                // Single arg: header exists
                HeaderCondition::Exists
            };

            let header = Matcher::Header(HeaderMatcher {
                name: name.to_string(),
                condition,
            });
            Ok(if negated {
                Matcher::Not(Box::new(header))
            } else {
                header
            })
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
        | Handler::RateLimit(_)
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
            debug
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

    /// 🧪 Adapts one `reverse_proxy` source and returns its proxy handler.
    fn proxy_from(source: &str) -> ProxyConfig {
        let directives = parse(source).expect("parses");
        let ast = adapt(directives).expect("adapts");
        let routes = ast.servers[0].inner.routes.as_ref().expect("routes");
        match &routes.inner.arms[0].inner.handler {
            Handler::Proxy(proxy) => (**proxy).clone(),
            other => panic!("expected a Proxy handler, got {other:?}"),
        }
    }

    #[test]
    fn upstream_tls_directives_reach_the_transport_block() {
        // Setup scenarios
        let proxy = proxy_from(
            r#"
            api.example.com {
                listen :80
                reverse_proxy https://backend.internal:8443 {
                    transport http {
                        tls
                        tls_server_name origin.internal
                        tls_trusted_ca_certs /etc/pingclair/internal-ca.pem
                        tls_client_auth /etc/pingclair/client.crt /etc/pingclair/client.key
                    }
                }
            }
        "#,
        );

        // Verification
        let tls = &proxy.transport.as_ref().expect("transport").tls;
        assert!(tls.enable);
        assert_eq!(tls.server_name.as_deref(), Some("origin.internal"));
        assert_eq!(tls.trusted_ca_certs, vec!["/etc/pingclair/internal-ca.pem"]);
        assert_eq!(
            tls.client_cert.as_deref(),
            Some("/etc/pingclair/client.crt")
        );
        assert_eq!(tls.client_key.as_deref(), Some("/etc/pingclair/client.key"));
        assert!(
            !tls.insecure_skip_verify,
            "verification must stay on unless it is asked for by name"
        );
    }

    #[test]
    fn several_trusted_ca_bundles_accumulate_in_order() {
        // Setup scenarios
        let proxy = proxy_from(
            r#"
            :80 {
                reverse_proxy https://backend:8443 {
                    transport http {
                        tls_trusted_ca_certs /a.pem /b.pem
                        tls_trusted_ca_certs /c.pem
                    }
                }
            }
        "#,
        );

        // Verification
        assert_eq!(
            proxy
                .transport
                .as_ref()
                .expect("transport")
                .tls
                .trusted_ca_certs,
            vec!["/a.pem", "/b.pem", "/c.pem"]
        );
    }

    /// 🧪 Adapts a source expected to be rejected, returning the error.
    fn adapt_error(source: &str) -> AdapterError {
        let directives = parse(source).expect("parses");
        adapt(directives).expect_err("must be rejected")
    }

    #[test]
    fn a_lone_client_certificate_is_rejected_at_config_time() {
        // Setup scenarios & Verification
        //
        // Accepting this would produce an anonymous handshake, and the
        // upstream's rejection would arrive as an opaque TLS alert at the
        // first request rather than as a message about the config.
        let error = adapt_error(
            r#"
            :80 {
                reverse_proxy https://backend:8443 {
                    transport http { tls_client_auth /only.crt }
                }
            }
        "#,
        );
        assert!(
            matches!(&error, AdapterError::ArgumentCount(name, 2, 1) if name == "tls_client_auth"),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn skipping_verification_cannot_be_combined_with_pinned_roots() {
        // Setup scenarios & Verification
        let error = adapt_error(
            r#"
            :80 {
                reverse_proxy https://backend:8443 {
                    transport http {
                        tls_trusted_ca_certs /internal-ca.pem
                        tls_insecure_skip_verify
                    }
                }
            }
        "#,
        );
        let message = format!("{error}");
        assert!(
            message.contains("tls_trusted_ca_certs"),
            "the diagnostic must name the directive being cancelled: {message}"
        );
    }

    #[test]
    fn skipping_verification_cannot_be_combined_with_an_sni_override() {
        // Setup scenarios & Verification
        let error = adapt_error(
            r#"
            :80 {
                reverse_proxy https://backend:8443 {
                    transport http {
                        tls_server_name origin.internal
                        tls_insecure_skip_verify
                    }
                }
            }
        "#,
        );
        let message = format!("{error}");
        assert!(
            message.contains("tls_server_name"),
            "the diagnostic must name the directive being cancelled: {message}"
        );
    }

    #[test]
    fn a_bare_tls_flag_rejects_stray_arguments() {
        // Setup scenarios & Verification
        //
        // Caddy's `tls` inside `transport http` takes no arguments. Dropping
        // an argument silently would let a typo such as `tls off` read as
        // "enable TLS".
        let error = adapt_error(
            r#"
            :80 {
                reverse_proxy backend:8443 {
                    transport http { tls off }
                }
            }
        "#,
        );
        assert!(
            matches!(&error, AdapterError::ArgumentCount(name, 0, 1) if name == "tls"),
            "unexpected error: {error:?}"
        );
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

// MARK: - P1 Fail-Closed Tests

/// 🛡️ Every P1 regression: a config that used to compile while silently
/// dropping part of what the operator asked for must now fail loudly.
#[cfg(test)]
mod fail_closed_tests {
    fn compile_err(source: &str) -> String {
        match crate::compile(source) {
            Ok(_) => panic!("config unexpectedly compiled:\n{source}"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn log_block_rejects_unknown_subdirectives() {
        let error = compile_err(
            r#"example.com {
                log {
                    rotate 7d
                }
            }"#,
        );
        assert!(
            error.contains("log: rotate"),
            "unknown log subdirective must be named; got {error}"
        );
    }

    #[test]
    fn log_block_rejects_unknown_format() {
        let error = compile_err(
            r#"example.com {
                log {
                    format jsno
                }
            }"#,
        );
        assert!(
            error.contains("jsno"),
            "`format jsno` must name the unknown format; got {error}"
        );
    }

    #[test]
    fn log_block_rejects_output_file_without_path() {
        let error = compile_err(
            r#"example.com {
                log {
                    output file
                }
            }"#,
        );
        assert!(
            error.contains("log output file"),
            "`output file` without a path must fail; got {error}"
        );
    }

    #[test]
    fn file_server_rejects_precompressed_as_unsupported() {
        let error = compile_err(
            r#"example.com {
                file_server /downloads/* {
                    precompressed
                }
            }"#,
        );
        assert!(
            error.contains("not supported by Pingclair"),
            "precompressed must be reported as unsupported Caddy syntax; got {error}"
        );
    }

    #[test]
    fn file_server_rejects_fs_as_unsupported() {
        let error = compile_err(
            r#"example.com {
                file_server /database/* {
                    fs sqlite data.sql
                }
            }"#,
        );
        assert!(
            error.contains("not supported by Pingclair"),
            "fs must be reported as unsupported Caddy syntax; got {error}"
        );
    }

    #[test]
    fn reverse_proxy_rejects_header_down_as_unsupported() {
        let error = compile_err(
            r#"example.com {
                reverse_proxy localhost:8080 {
                    header_down X-Foo bar
                }
            }"#,
        );
        assert!(
            error.contains("header_down") && error.contains("not supported"),
            "header_down must fail with a named unsupported error; got {error}"
        );
    }

    #[test]
    fn reverse_proxy_rejects_dynamic_as_unsupported() {
        let error = compile_err(
            r#"example.com {
                reverse_proxy /api/* {
                    dynamic srv _api._tcp.example.com
                }
            }"#,
        );
        assert!(
            error.contains("dynamic") && error.contains("not supported"),
            "dynamic must fail with a named unsupported error; got {error}"
        );
    }

    #[test]
    fn reverse_proxy_rejects_unknown_subdirectives() {
        let error = compile_err(
            r#"example.com {
                reverse_proxy localhost:8080 {
                    lb_try_duration 10s
                }
            }"#,
        );
        assert!(
            error.contains("lb_try_duration"),
            "unknown reverse_proxy subdirective must be named; got {error}"
        );
    }

    #[test]
    fn reverse_proxy_rejects_header_up_with_extra_arguments() {
        let error = compile_err(
            r#"example.com {
                reverse_proxy localhost:8080 {
                    header_up X-Foo a b
                }
            }"#,
        );
        assert!(
            error.contains("header_up"),
            "a third header_up argument must fail; got {error}"
        );
    }

    #[test]
    fn reverse_proxy_rejects_unix_socket_upstream() {
        let error = compile_err(
            r#"example.com {
                reverse_proxy unix//run/php/php.sock
            }"#,
        );
        assert!(
            error.contains("Unix-socket"),
            "unix// upstream must be refused with a clear message; got {error}"
        );
    }

    #[test]
    fn site_address_rejects_port_range() {
        let error = compile_err("localhost:8080-8085 {\n    respond \"x\"\n}");
        assert!(
            error.contains("port range") || error.contains("not supported"),
            "a port-range site address must fail; got {error}"
        );
    }

    #[test]
    fn site_address_rejects_network_prefix() {
        let error = compile_err("tcp/localhost:8080 {\n    respond \"x\"\n}");
        assert!(
            error.contains("network prefix") || error.contains("not supported"),
            "a tcp/ site address must fail; got {error}"
        );
    }

    #[test]
    fn debug_rejects_arguments() {
        let error = compile_err("{\n    debug fales\n}\nexample.com {\n    respond \"x\"\n}");
        assert!(
            error.contains("debug"),
            "`debug fales` must fail; got {error}"
        );
    }

    #[test]
    fn auto_https_requires_an_argument() {
        let error = compile_err("{\n    auto_https\n}\nexample.com {\n    respond \"x\"\n}");
        assert!(
            error.contains("auto_https"),
            "bare auto_https must fail; got {error}"
        );
    }

    #[test]
    fn auto_https_disable_certs_is_reported_as_unsupported() {
        let error =
            compile_err("{\n    auto_https disable_certs\n}\nexample.com {\n    respond \"x\"\n}");
        assert!(
            error.contains("not supported by Pingclair"),
            "disable_certs must be reported as unsupported Caddy syntax; got {error}"
        );
    }

    #[test]
    fn method_matcher_rejects_unknown_verbs() {
        let error =
            compile_err("example.com {\n    @x method FOO\n    handle @x { respond \"x\" }\n}");
        assert!(
            error.contains("FOO"),
            "unknown method must be named; got {error}"
        );
    }

    #[test]
    fn method_matcher_accepts_every_standard_verb() {
        let config = crate::compile(
            r#"example.com {
                @x method GET POST PUT DELETE PATCH HEAD OPTIONS
                handle @x { respond "x" }
            }"#,
        )
        .expect("all standard verbs must compile");
        assert_eq!(config.servers[0].routes.len(), 1);
    }

    #[test]
    fn header_matcher_rejects_extra_arguments() {
        let error = compile_err(
            "example.com {\n    @x header Foo bar baz\n    handle @x { respond \"x\" }\n}",
        );
        assert!(
            error.contains("header"),
            "a third header-matcher argument must fail; got {error}"
        );
    }

    #[test]
    fn header_directive_rejects_key_without_value() {
        let error = compile_err("example.com {\n    header X-Only\n}");
        assert!(
            error.contains("header"),
            "`header X-Only` without a value must fail; got {error}"
        );
    }

    #[test]
    fn admin_block_is_reported_as_unsupported() {
        let error = compile_err(
            r#"{
                admin :2019 {
                    origins http://localhost:2019
                }
            }
            example.com {
                respond "x"
            }"#,
        );
        assert!(
            error.contains("admin") && error.contains("not supported"),
            "admin block must fail with a named unsupported error; got {error}"
        );
    }

    #[test]
    fn known_caddy_global_options_are_reported_as_unsupported() {
        let error =
            compile_err("{\n    default_bind 127.0.0.1\n}\nexample.com {\n    respond \"x\"\n}");
        assert!(
            error.contains("not supported by Pingclair"),
            "default_bind must be reported as unsupported Caddy syntax; got {error}"
        );
    }

    #[test]
    fn known_caddy_directives_are_reported_as_unsupported() {
        let error = compile_err("example.com {\n    templates\n    file_server\n}");
        assert!(
            error.contains("not supported by Pingclair"),
            "templates must be reported as unsupported Caddy syntax; got {error}"
        );
    }

    #[test]
    fn typo_directives_stay_unknown_directive_errors() {
        let error = compile_err("example.com {\n    respnd \"x\"\n}");
        assert!(
            error.contains("Unknown directive 'respnd'"),
            "a typo must remain an unknown-directive error; got {error}"
        );
    }
}

// MARK: - P2 Address Semantics Tests

/// 📍 P2 regressions: a bare hostname site must not create an implicit
/// listener, a multi-listener site must keep its virtual-host name, and
/// Caddy's address forms must derive the expected listeners.
#[cfg(test)]
mod address_semantics_tests {
    use crate::compile;

    fn first_server(source: &str) -> pingclair_core::config::ServerConfig {
        compile(source)
            .expect("config must compile")
            .servers
            .into_iter()
            .next()
            .expect("at least one server")
    }

    #[test]
    fn bare_hostname_with_tls_derives_no_listener() {
        let server = first_server("example.com {\n    tls auto\n    file_server ./public\n}");
        assert!(
            server.listen.is_empty(),
            "a bare hostname must not pin a listener; got {:?}",
            server.listen
        );
        assert!(server.tls.is_some(), "tls auto must survive compilation");
        assert_eq!(server.name.as_deref(), Some("example.com"));
    }

    #[test]
    fn bare_hostname_without_tls_derives_no_listener() {
        let server = first_server("example.com {\n    file_server ./public\n}");
        assert!(
            server.listen.is_empty(),
            "a bare hostname must leave the listener to the runtime"
        );
        assert!(
            server.tls.is_some(),
            "a bare hostname must default to automatic HTTPS like Caddy"
        );
        assert!(
            server.tls.as_ref().unwrap().auto,
            "the default must be `tls auto`, not internal"
        );
    }

    #[test]
    fn auto_https_off_keeps_bare_hostname_plaintext() {
        let config =
            compile("{\n    auto_https off\n}\nexample.com {\n    file_server ./public\n}")
                .expect("compiles");
        assert!(
            config.servers[0].tls.is_none(),
            "auto_https off must suppress the automatic TLS default"
        );
    }

    #[test]
    fn explicit_schemes_still_create_listeners() {
        let https = first_server("https://example.com {\n    respond \"x\"\n}");
        assert_eq!(https.listen, vec!["0.0.0.0:443".to_string()]);
        assert!(https.tls.is_some(), "https:// must imply TLS");

        let http = first_server("http://example.com {\n    respond \"x\"\n}");
        assert_eq!(http.listen, vec!["0.0.0.0:80".to_string()]);
        assert!(http.tls.is_none(), "http:// must stay plaintext");
    }

    #[test]
    fn explicit_listen_is_not_duplicated_or_augmented() {
        let server = first_server("example.com {\n    listen :80\n    tls auto\n}");
        assert_eq!(
            server.listen,
            vec!["0.0.0.0:80".to_string()],
            "the explicit listener must appear exactly once"
        );

        let server = first_server("example.com {\n    listen :8443\n    tls auto\n}");
        assert_eq!(
            server.listen,
            vec!["0.0.0.0:8443".to_string()],
            "an explicit non-standard port must not gain an implicit :80"
        );
    }

    #[test]
    fn multi_listener_site_keeps_its_hostname() {
        let server =
            first_server("example.com {\n    listen :80\n    listen :443\n    tls auto\n}");
        assert_eq!(
            server.name.as_deref(),
            Some("example.com"),
            "a multi-listener site must stay a named virtual host"
        );
        assert_eq!(server.names, vec!["example.com".to_string()]);
    }

    #[test]
    fn bare_https_port_implies_tls() {
        let server = first_server(":443 {\n    respond \"x\"\n}");
        assert_eq!(server.name.as_deref(), Some("_"));
        assert_eq!(server.listen, vec!["0.0.0.0:443".to_string()]);
        assert!(server.tls.is_some(), ":443 must imply TLS");
    }

    #[test]
    fn multi_address_block_registers_every_hostname() {
        let server = first_server("example.com, www.example.com {\n    respond \"shared\"\n}");
        assert_eq!(
            server.name.as_deref(),
            Some("example.com"),
            "the first address is the primary name"
        );
        assert_eq!(
            server.names,
            vec!["example.com".to_string(), "www.example.com".to_string()]
        );
    }

    #[test]
    fn catch_all_schemes_get_the_conventional_listener() {
        let https = first_server("https:// {\n    respond \"x\"\n}");
        assert_eq!(https.listen, vec!["0.0.0.0:443".to_string()]);
        assert!(https.tls.is_some());

        let http = first_server("http:// {\n    respond \"x\"\n}");
        assert_eq!(http.listen, vec!["0.0.0.0:80".to_string()]);
        assert!(http.tls.is_none());
    }

    #[test]
    fn global_http_and_https_ports_parse() {
        let config = compile(
            "{\n    http_port 8080\n    https_port 8443\n}\nlocalhost {\n    respond \"x\"\n}",
        )
        .expect("port overrides must compile");
        assert_eq!(config.global.http_port, 8080);
        assert_eq!(config.global.https_port, 8443);
    }

    #[test]
    fn ip_literal_site_binds_to_the_literal() {
        let server = first_server("127.0.0.1 {\n    respond \"x\"\n}");
        assert_eq!(server.listen, vec!["127.0.0.1:80".to_string()]);
    }

    #[test]
    fn bind_directive_is_carried_separately() {
        let server = first_server("example.com {\n    bind 127.0.0.1\n    tls auto\n}");
        assert_eq!(server.bind.as_deref(), Some("127.0.0.1"));
        assert!(
            server.listen.is_empty(),
            "bind names an interface, not a listener"
        );
    }
}

// MARK: - P3 Syntax Tests

/// ✍️ P3 regressions: Caddy's single-site shorthand, environment-variable
/// expansion, glued placeholders, full durations, `root`, inline matchers
/// and the extended matcher vocabulary.
#[cfg(test)]
mod p3_syntax_tests {
    use crate::compile;
    use crate::parser::{parse, tokenize};
    use pingclair_core::config::HandlerConfig;

    fn routes(source: &str) -> Vec<pingclair_core::config::RouteConfig> {
        compile(source)
            .expect("config must compile")
            .servers
            .into_iter()
            .next()
            .expect("at least one server")
            .routes
    }

    #[test]
    fn single_site_shorthand_collects_following_directives() {
        let config = compile("localhost\n\nrespond \"Hello, world!\"").expect("shorthand compiles");
        assert_eq!(config.servers.len(), 1);
        assert_eq!(config.servers[0].name.as_deref(), Some("localhost"));
        assert_eq!(config.servers[0].routes.len(), 1);
    }

    #[test]
    fn shorthand_supports_snippets() {
        let config =
            compile("(common) {\n    header X-A b\n}\nlocalhost\n\nimport common\nrespond \"ok\"")
                .expect("snippet + shorthand compiles");
        assert_eq!(config.servers.len(), 1);
        let route = &config.servers[0].routes[0];
        match &route.handler {
            HandlerConfig::Pipeline { handlers } => {
                assert!(
                    handlers
                        .iter()
                        .any(|h| matches!(h, HandlerConfig::Headers { .. }))
                );
                assert!(
                    handlers
                        .iter()
                        .any(|h| matches!(h, HandlerConfig::Respond { .. }))
                );
            }
            other => panic!("expected a pipeline, got {other:?}"),
        }
    }

    #[test]
    fn shorthand_cannot_mix_with_braced_sites() {
        let error = compile("localhost\n\nrespond \"x\"\nexample.com {\n    respond \"y\"\n}")
            .expect_err("mixed shorthand and braced sites must fail");
        assert!(error.to_string().contains("bare (unbraced)"));
    }

    #[test]
    fn env_vars_expand_before_parsing() {
        // 🛡️ These tests run single-threaded; env mutation is sound here.
        unsafe {
            std::env::set_var("PINGCLAIR_TEST_SITE", "env.example");
            std::env::set_var("PINGCLAIR_TEST_UPSTREAMS", "127.0.0.1:9001 127.0.0.1:9002");
        }
        let config = compile("{$PINGCLAIR_TEST_SITE}\n\nrespond \"env\"").expect("env site");
        assert_eq!(config.servers[0].name.as_deref(), Some("env.example"));

        let config = compile("localhost {\n    reverse_proxy {$PINGCLAIR_TEST_UPSTREAMS}\n}")
            .expect("env upstreams");
        match &config.servers[0].routes[0].handler {
            HandlerConfig::ReverseProxy(proxy) => {
                assert_eq!(
                    proxy.upstreams,
                    vec!["127.0.0.1:9001".to_string(), "127.0.0.1:9002".to_string()]
                );
            }
            other => panic!("expected reverse proxy, got {other:?}"),
        }
    }

    #[test]
    fn env_vars_support_defaults() {
        // 🛡️ Single-threaded test; see env_vars_expand_before_parsing.
        unsafe {
            std::env::remove_var("PINGCLAIR_TEST_ABSENT_VAR");
        }
        let config =
            compile("{$PINGCLAIR_TEST_ABSENT_VAR:fallback.example} {\n    respond \"d\"\n}")
                .expect("default value expands");
        assert_eq!(config.servers[0].name.as_deref(), Some("fallback.example"));
    }

    #[test]
    fn placeholders_glued_to_words_stay_one_token() {
        let tokens = tokenize("redir https://www.{host}{uri}").unwrap();
        let words: Vec<String> = tokens
            .iter()
            .filter_map(|t| match &t.value {
                crate::parser::Token::Word(w) => Some(w.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(words, vec!["redir", "https://www.{host}{uri}"]);
    }

    #[test]
    fn glued_placeholder_redirect_compiles() {
        let config = compile("example.com {\n    redir https://www.{host}{uri}\n}")
            .expect("glued placeholders compile");
        match &config.servers[0].routes[0].handler {
            HandlerConfig::Redirect { to, .. } => {
                assert_eq!(to, "https://www.{host}{uri}");
            }
            other => panic!("expected redirect, got {other:?}"),
        }
    }

    #[test]
    fn full_duration_units_parse() {
        let config = compile(
            "example.com {\n    limits {\n        header_timeout 1.5h\n        body_timeout 2h45m\n        idle_timeout 90d\n    }\n}",
        )
        .expect("compound and fractional durations compile");
        let limits = &config.servers[0].limits;
        assert_eq!(limits.header_timeout_ms, Some(5_400_000));
        assert_eq!(limits.body_timeout_ms, Some(9_900_000));
        assert_eq!(limits.idle_timeout_ms, Some(7_776_000_000));
    }

    #[test]
    fn bare_duration_numbers_are_rejected() {
        let error = compile("example.com {\n    limits {\n        header_timeout 30\n    }\n}")
            .expect_err("a bare number must not silently mean milliseconds");
        assert!(error.to_string().contains("30"));
    }

    #[test]
    fn root_directive_reaches_bare_file_server() {
        let config = compile("example.com {\n    root /var/www\n    file_server\n}")
            .expect("root + file_server compile");
        match &config.servers[0].routes[0].handler {
            HandlerConfig::FileServer { root, .. } => {
                assert_eq!(root, "/var/www");
            }
            other => panic!("expected file server, got {other:?}"),
        }
    }

    #[test]
    fn file_server_browse_inline_enables_listings() {
        let config =
            compile("example.com {\n    file_server browse\n}").expect("inline browse compiles");
        match &config.servers[0].routes[0].handler {
            HandlerConfig::FileServer { browse, root, .. } => {
                assert!(*browse, "inline browse must enable directory listings");
                assert_eq!(root, ".", "browse must not be mistaken for a root");
            }
            other => panic!("expected file server, got {other:?}"),
        }
    }

    #[test]
    fn file_server_glob_argument_becomes_a_path_matcher() {
        let routes =
            routes("example.com {\n    file_server /downloads/* {\n        browse\n    }\n}");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].path, "/downloads/*");
    }

    #[test]
    fn header_matcher_understands_negation_and_single_stars() {
        let config = compile(
            "example.com {\n    @a header !Foo\n    @b header Foo *.example\n    @c header Foo example*\n    @d header Foo *bar*\n    handle @a { respond \"a\" }\n    handle @b { respond \"b\" }\n    handle @c { respond \"c\" }\n    handle @d { respond \"d\" }\n}",
        )
        .expect("header matcher forms compile");
        let routes = &config.servers[0].routes;
        assert_eq!(routes.len(), 4);
    }

    #[test]
    fn same_field_header_matchers_are_ored() {
        let config = compile(
            "example.com {\n    @foo {\n        header Foo bar\n        header Foo baz\n    }\n    handle @foo { respond \"hit\" }\n}",
        )
        .expect("same-field header matchers compile");
        let matcher = config.servers[0].routes[0]
            .matcher
            .as_ref()
            .expect("matcher must survive");
        let matcher = format!("{matcher:?}");
        assert!(
            matcher.contains("Or"),
            "same-field header matchers must be OR'ed, got {matcher}"
        );
    }

    #[test]
    fn multi_path_matcher_creates_one_route_per_pattern() {
        let routes = routes(
            "example.com {\n    @assets path /js/* /css/* /images/*\n    handle @assets { respond \"asset\" }\n}",
        );
        let paths: Vec<&str> = routes.iter().map(|r| r.path.as_str()).collect();
        assert!(paths.contains(&"/js/*"), "got {paths:?}");
        assert!(paths.contains(&"/css/*"), "got {paths:?}");
        assert!(paths.contains(&"/images/*"), "got {paths:?}");
    }

    #[test]
    fn extended_matcher_vocabulary_compiles() {
        let config = compile(
            "example.com {\n    @h host sub.example.com\n    @q query q=1\n    @p protocol https\n    @r remote_ip 10.0.0.0/8\n    @c client_ip 192.168.0.0/16\n    handle @h { respond \"h\" }\n    handle @q { respond \"q\" }\n    handle @p { respond \"p\" }\n    handle @r { respond \"r\" }\n    handle @c { respond \"c\" }\n}",
        )
        .expect("host/query/protocol/remote_ip/client_ip compile");
        assert_eq!(config.servers[0].routes.len(), 5);
    }

    #[test]
    fn not_inline_multi_value_is_negated_or() {
        // `not path /css/* /js/*` must mean NOT(/css/* OR /js/*).
        let config = compile(
            "example.com {\n    @na {\n        not path /css/* /js/*\n    }\n    handle @na { respond \"ok\" }\n}",
        )
        .expect("not path compiles");
        let matcher = format!(
            "{:?}",
            config.servers[0].routes[0]
                .matcher
                .as_ref()
                .expect("matcher")
        );
        assert!(
            matcher.contains("Not") && matcher.contains("Path"),
            "expected Not(Path[..]) semantics, got {matcher}"
        );
    }

    #[test]
    fn shorthand_parses_via_public_api() {
        let directives = parse("localhost\n\nrespond \"ok\"").expect("parse shorthand");
        assert_eq!(directives.len(), 2);
    }
}

// MARK: - P4 Directive Order Tests

/// 🧭 P4 regressions: Caddy's directive order must make file order
/// irrelevant, middleware must not be shadowed by terminal routes, and
/// same-name routes must sort by matcher specificity.
#[cfg(test)]
mod directive_order_tests {
    use crate::compile;
    use pingclair_core::config::HandlerConfig;

    #[test]
    fn header_runs_before_respond_regardless_of_file_order() {
        let reversed =
            compile("example.com {\n    respond \"ok\"\n    header X-A b\n}").expect("compile");
        let normal =
            compile("example.com {\n    header X-A b\n    respond \"ok\"\n}").expect("compile");

        let pipeline = |config: &pingclair_core::config::PingclairConfig| match &config.servers[0]
            .routes[0]
            .handler
        {
            HandlerConfig::Pipeline { handlers } => {
                let kinds: Vec<&str> = handlers
                    .iter()
                    .map(|h| match h {
                        HandlerConfig::Headers { .. } => "headers",
                        HandlerConfig::Respond { .. } => "respond",
                        other => panic!("unexpected handler {other:?}"),
                    })
                    .collect();
                kinds
            }
            other => panic!("expected pipeline, got {other:?}"),
        };
        assert_eq!(pipeline(&reversed), vec!["headers", "respond"]);
        assert_eq!(pipeline(&normal), vec!["headers", "respond"]);
    }

    #[test]
    fn basic_auth_runs_before_file_server() {
        let config =
            compile("example.com {\n    file_server ./public\n    basic_auth user pass\n}")
                .expect("compile");
        match &config.servers[0].routes[0].handler {
            HandlerConfig::Pipeline { handlers } => {
                assert!(matches!(handlers[0], HandlerConfig::BasicAuth { .. }));
                assert!(matches!(handlers[1], HandlerConfig::FileServer { .. }));
            }
            other => panic!("expected pipeline, got {other:?}"),
        }
    }

    #[test]
    fn terminal_handlers_run_in_reverse_caddy_priority() {
        // 🧭 Caddy: reverse_proxy beats file_server; respond beats both. The
        // pipeline lets the later handler override the body, so the order
        // must be the reverse of Caddy's priority.
        let proxy_first =
            compile("example.com {\n    reverse_proxy 127.0.0.1:9005\n    file_server\n}")
                .expect("compile");
        let HandlerConfig::Pipeline { handlers } = &proxy_first.servers[0].routes[0].handler else {
            panic!("expected a pipeline");
        };
        assert!(
            matches!(handlers[0], HandlerConfig::FileServer { .. }),
            "file_server must run first so reverse_proxy wins, got {handlers:?}"
        );
        assert!(matches!(handlers[1], HandlerConfig::ReverseProxy(_)));

        let respond_last =
            compile("example.com {\n    respond \"x\"\n    file_server\n}").expect("compile");
        let HandlerConfig::Pipeline { handlers } = &respond_last.servers[0].routes[0].handler
        else {
            panic!("expected a pipeline");
        };
        assert!(matches!(handlers[0], HandlerConfig::FileServer { .. }));
        assert!(matches!(handlers[1], HandlerConfig::Respond { .. }));
    }

    #[test]
    fn exact_handle_precedes_glob_handle() {
        let config = compile(
            "example.com {\n    handle /foo* { respond \"glob\" }\n    handle /foo { respond \"exact\" }\n}",
        )
        .expect("compile");
        assert_eq!(config.servers[0].routes[0].path, "/foo");
        assert_eq!(config.servers[0].routes[1].path, "/foo*");
    }

    #[test]
    fn middleware_route_precedes_terminal_route_with_same_matcher() {
        let config = compile(
            "example.com {\n    @api path /api/*\n    handle /api/* { respond \"api\" }\n    header @api X-A b\n}",
        )
        .expect("compile");
        let routes = &config.servers[0].routes;
        assert!(
            matches!(&routes[0].handler, HandlerConfig::Headers { .. })
                || matches!(
                    &routes[0].handler,
                    HandlerConfig::Pipeline { handlers } if handlers.iter().any(|h| matches!(h, HandlerConfig::Headers { .. }))
                ),
            "the middleware route must come first, got {:?}",
            routes[0].handler
        );
    }

    #[test]
    fn to_accepts_multiple_upstreams_on_one_line() {
        let config = compile(
            "example.com {\n    reverse_proxy /service/* {\n        to 10.0.1.1:80 10.0.1.2:80 10.0.1.3:80\n    }\n}",
        )
        .expect("multiple `to` upstreams compile");
        match &config.servers[0].routes[0].handler {
            HandlerConfig::ReverseProxy(proxy) => {
                assert_eq!(
                    proxy.upstreams,
                    vec![
                        "10.0.1.1:80".to_string(),
                        "10.0.1.2:80".to_string(),
                        "10.0.1.3:80".to_string()
                    ]
                );
            }
            other => panic!("expected reverse proxy, got {other:?}"),
        }
    }

    #[test]
    fn upstream_port_ranges_expand_like_caddy() {
        // 🌐 `:9000-9002` is Caddy shorthand for three peers; a bare `:9000`
        // stays hostless in the adapted JSON and the runtime dials loopback.
        let config = compile("example.com {\n    reverse_proxy :9000\n}\n")
            .expect("bare-port upstream compiles");
        match &config.servers[0].routes[0].handler {
            HandlerConfig::ReverseProxy(proxy) => {
                assert_eq!(proxy.upstreams, vec![":9000".to_string()]);
            }
            other => panic!("expected reverse proxy, got {other:?}"),
        }

        let ranged =
            compile("example.com {\n    reverse_proxy {\n        to :9000-9002\n    }\n}\n")
                .expect("port range compiles");
        match &ranged.servers[0].routes[0].handler {
            HandlerConfig::ReverseProxy(proxy) => {
                assert_eq!(proxy.upstreams, [":9000", ":9001", ":9002"]);
            }
            other => panic!("expected reverse proxy, got {other:?}"),
        }
    }

    #[test]
    fn rewrite_with_path_matcher_uses_caddy_semantics() {
        let config =
            compile("example.com {\n    rewrite /old /new\n}").expect("path rewrite compiles");
        let routes = &config.servers[0].routes;
        assert_eq!(
            routes[0].path, "/old",
            "the rewrite matcher must become the route path"
        );
    }

    #[test]
    fn regex_rewrite_still_compiles() {
        let config = compile("example.com {\n    rewrite \"^/api/(.*)$\" \"/v1/$1\"\n}")
            .expect("regex rewrite compiles");
        let routes = &config.servers[0].routes;
        assert_eq!(routes[0].path, "/*", "a regex rewrite stays a catch-all");
    }

    #[test]
    fn localhost_defaults_to_internal_tls() {
        let config = compile("localhost {\n    respond \"ok\"\n}").expect("localhost compiles");
        assert!(
            config.servers[0]
                .tls
                .as_ref()
                .is_some_and(|tls| tls.internal),
            "localhost must default to the internal CA"
        );

        let plain = compile("http://localhost {\n    respond \"ok\"\n}")
            .expect("explicit http stays plaintext");
        assert!(plain.servers[0].tls.is_none());
    }
}
