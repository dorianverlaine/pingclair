// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::AdapterError;
use super::addresses::{
    is_local_https_default, looks_like_unsupported_address, parse_server_address,
    reject_impossible_address,
};
use super::directives::{
    adapt_handle_path, adapt_handler, adapt_header_directive, adapt_resource_limits,
    adapt_subroute_block,
};
use super::logs::adapt_log_block;
use super::matchers::{
    parse_matcher_and_block, parse_matcher_definition, parse_route_matcher_and_block,
};
use super::options::is_wildcard_host;
use super::order::DirectiveOrder;
use super::tls::adapt_tls_directive;
use crate::parser::ast::*;
use crate::parser::caddy_ast::Directive;
use crate::parser::lexer::Location;
use std::collections::BTreeMap;

// MARK: - Server Block

/// 🧾 Validates exact, subtype-wildcard, and structured-suffix MIME patterns.
pub(super) fn is_valid_mime_pattern(pattern: &str) -> bool {
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

pub(super) fn adapt_server(
    d: Directive,
    order: &DirectiveOrder,
) -> Result<ServerBlock, AdapterError> {
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
        // 🚫 Refuse an address that cannot mean anything before deriving a
        // listener from it.
        reject_impossible_address(name)?;
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
                host: "[::]".to_string(),
                port: Some(if is_https { 443 } else { 80 }),
                force_plaintext: !is_https,
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
                && parsed.hostname != "[::]"
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
        // 🏠 A wildcard bind address is not a hostname anybody can send.
        //
        // `http://:8080` reaches here already rewritten to `[::]` by the
        // URL-stripping fallback above, and `[::]` matches none of the tests
        // before this one: it starts with `[`, and `::` is not `://`. The site
        // then ended up registered under a virtual host name no request could
        // carry, so **every request to it returned 404** — the plainest
        // Caddyfile there is, `http://:8080 { reverse_proxy … }`, served
        // nothing at all. Found on 2026-08-04 by configuring a real server
        // from a Pingclairfile rather than from JSON.
        || is_wildcard_host(&server.name)
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
                        host: "[::]".to_string(),
                        port: addr.split(':').next_back().and_then(|p| p.parse().ok()),
                        force_plaintext: addr.starts_with("http://"),
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
                "vars" => {
                    // 🧰 `vars [<matcher>] <name> <value>` and
                    // `vars { <name> <value> … }` become site-level rules.
                    // Rules are sorted least specific first (below), and
                    // every matching rule runs — so the most specific value
                    // wins, the reverse of ordinary route priority.
                    let (matcher, _) = parse_matcher_and_block(&sub_d)?;
                    let mut handler_d = sub_d.clone();
                    if matcher.is_some() {
                        if handler_d.args.is_empty() {
                            return Err(AdapterError::ArgumentCount("vars".into(), 1, 0));
                        }
                        handler_d.drop_first_arg();
                    }
                    // 🌐 `*` means "every request", which is the same as no
                    // matcher; the generic matcher rule says so by returning
                    // `None`, so drop the token here before the data reader.
                    let args = if handler_d.args.first().is_some_and(|arg| arg == "*") {
                        &handler_d.args[1..]
                    } else {
                        &handler_d.args[..]
                    };
                    let mut values = BTreeMap::new();
                    match args {
                        [] => {}
                        [name, value] => {
                            values.insert(name.clone(), value.clone());
                        }
                        _ => {
                            return Err(AdapterError::ArgumentCount("vars".into(), 2, args.len()));
                        }
                    }
                    if let Some(block) = &handler_d.block {
                        for line in &block.directives {
                            let [value] = line.args.as_slice() else {
                                return Err(AdapterError::InvalidArgument(
                                    "vars".into(),
                                    format!(
                                        "each block line needs exactly `<name> <value>`, got {} \
                                         arguments for `{}`",
                                        line.args.len(),
                                        line.name
                                    ),
                                ));
                            };
                            values.insert(line.name.clone(), value.clone());
                        }
                    }
                    if values.is_empty() {
                        return Err(AdapterError::InvalidArgument(
                            "vars".into(),
                            "at least one `<name> <value>` pair is required".into(),
                        ));
                    }
                    server.vars_routes.push(VarsRule { matcher, values });
                }
                "handle_errors" => {
                    // 🚨 `handle_errors [<codes…>] { … }` registers a
                    // server-level error route. Codes are three-digit
                    // statuses or `Nxx` ranges, ORed together; no codes means
                    // the route catches every error status. The block is a
                    // route body — directives run in file order, and `handle`
                    // blocks are mutually exclusive — exactly the shape the
                    // upstream format parses.
                    let mut codes = Vec::new();
                    let mut hundreds = Vec::new();
                    for arg in &sub_d.args {
                        if arg.len() == 3
                            && let Ok(code) = arg.parse::<u16>()
                            && (100..=599).contains(&code)
                        {
                            codes.push(code);
                        } else if arg.len() == 3
                            && let Some(digit) = arg.strip_suffix("xx")
                            && let Ok(hundred) = digit.parse::<u8>()
                        {
                            if !hundreds.contains(&hundred) {
                                hundreds.push(hundred);
                            }
                        } else {
                            return Err(AdapterError::InvalidArgument(
                                "handle_errors".into(),
                                format!("bad status value `{arg}`"),
                            ));
                        }
                    }
                    let block = sub_d.block.as_ref().ok_or_else(|| {
                        AdapterError::InvalidArgument(
                            "handle_errors".into(),
                            "a block is required".into(),
                        )
                    })?;
                    let mut handlers = Vec::new();
                    for directive in &block.directives {
                        let (matcher, _) = parse_matcher_and_block(directive)?;
                        let mut handler_d = directive.clone();
                        if matcher.is_some() {
                            if handler_d.args.is_empty() {
                                return Err(AdapterError::ArgumentCount(
                                    directive.name.clone(),
                                    1,
                                    0,
                                ));
                            }
                            handler_d.drop_first_arg();
                        }
                        let handler = adapt_handler(handler_d, &server.matchers, order)?;
                        handlers.push(HandlerElement { matcher, handler });
                    }
                    if handlers.is_empty() {
                        return Err(AdapterError::InvalidArgument(
                            "handle_errors".into(),
                            "at least one directive is required".into(),
                        ));
                    }
                    server.error_routes.push(ErrorRouteConfig {
                        codes,
                        hundreds,
                        handlers,
                    });
                }
                "compress" | "encode" => {
                    // 🎯 The first directive reading its arguments from the
                    // token cursor rather than from `args`.
                    //
                    // The behaviour is identical — this is a migration step, not
                    // a change — but the shape is the one every directive is
                    // moving to: ask the cursor for the arguments on this line,
                    // and let it decide where the line ends. `args` stays
                    // populated for the directives that have not moved yet, and
                    // for a directive this adapter synthesised, which has no
                    // tokens at all and falls back below.
                    let args: Vec<String> = match sub_d.tokens.args_cursor() {
                        Some(mut cursor) => cursor.remaining_arg_texts(),
                        None => sub_d.args.clone(),
                    };
                    // 🚫 A matcher token here asks for compression on some
                    // requests and not others, and compression is a property of
                    // the whole server: there is nowhere to record "gzip, but
                    // only under /assets". Say that. Left to fall through, the
                    // matcher reaches the coding loop below and is reported as
                    // an unknown coding, which sends the operator looking for a
                    // typo in a token that is spelled exactly right.
                    if let Some(first) = args.first()
                        && (first.starts_with('/') || first.starts_with('@'))
                    {
                        return Err(AdapterError::UnsupportedFeature(
                            format!("{} with a matcher", sub_d.name),
                            format!(
                                "`{first}` limits compression to part of the site, but \
                                 compression is configured per server rather than per \
                                 route; drop the matcher, or move those paths into their \
                                 own site block"
                            ),
                        ));
                    }
                    // 🌐 `encode * gzip` names the matcher that matches
                    // everything, which is the same as naming none. Accept and
                    // drop it, exactly as `root * /srv` does above.
                    let args = if args.first().is_some_and(|a| a == "*") {
                        &args[1..]
                    } else {
                        &args[..]
                    };
                    // Caddy spells this `encode zstd gzip`, and argument order
                    // is meaningful: it is the server's preference order when
                    // several codings are acceptable to the client.
                    //
                    // Unknown arguments are rejected rather than skipped. The
                    // old loop ignored them, so `encode gzipp` silently gave a
                    // server that still compressed (via the unconditional
                    // gzip path) and looked like it had honored the typo.
                    let mut algos = Vec::with_capacity(args.len());
                    for arg in args {
                        let algo = match arg.to_lowercase().as_str() {
                            // `off`/`none` is the only way to opt a server out
                            // of response compression, so it may not be mixed
                            // with codings.
                            "off" | "none" => {
                                if args.len() > 1 {
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
                    if args.is_empty() {
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
                // 🪵 Caddy's `log` grammar. `log { … }` configures this
                // server's default access sink; `log <name> { … }` configures
                // a *named* per-site logger with the block's own output;
                // `log <name>` (no block) fans out to a channel declared in
                // the global block; a bare `log` enables the default sink.
                "log" => match (sub_d.args.first(), sub_d.block) {
                    (None, Some(log_block)) => {
                        let log = adapt_log_block(log_block)?;
                        server.log = Some(Node::new(log, Location::synthetic()));
                    }
                    (Some(name), Some(log_block)) => {
                        if sub_d.args.len() != 1 {
                            return Err(AdapterError::ArgumentCount(
                                "log".into(),
                                1,
                                sub_d.args.len(),
                            ));
                        }
                        let mut log = adapt_log_block(log_block)?;
                        log.name = Some(name.clone());
                        server
                            .named_logs
                            .push(Node::new(log, Location::synthetic()));
                    }
                    (Some(name), None) => server.log_channels.push(name.clone()),
                    (None, None) => {
                        // 📝 A bare `log` enables the default access sink, as
                        // in Caddy, so `log_skip`/`log_append` have a logger
                        // to act on.
                        server.log = Some(Node::new(
                            LogBlock {
                                name: None,
                                rotation: Default::default(),
                                request_headers: Vec::new(),
                                response_headers: Vec::new(),
                                include_tls: false,
                                output: LogOutput::Stdout,
                                format: LogFormat::default(),
                                level: None,
                                hostnames: Vec::new(),
                                include: Vec::new(),
                                exclude: Vec::new(),
                                sampling: None,
                            },
                            Location::synthetic(),
                        ));
                    }
                },
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
                // 🛣️ `handle_path /api/* { … }` is `handle` plus stripping the
                // matched prefix before the inner handlers run. The runtime has
                // done this the whole time on both transports; only this arm
                // was missing, which is why a directive we could already
                // execute was reported as unimplemented.
                "handle_path" => {
                    let (matcher, handler) = adapt_handle_path(&sub_d, &server.matchers, order)?;
                    add_route(&mut server, matcher, handler);
                }
                "route" | "handle" => {
                    let (matcher, _) = parse_route_matcher_and_block(&sub_d)?;
                    let sorted = sub_d.name == "handle";
                    let handler = adapt_subroute_block(&sub_d, &server.matchers, order, sorted)?;
                    if matcher.is_none() {
                        default_handlers.push(handler);
                    } else {
                        add_route(&mut server, matcher, handler);
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
                    //   header /path Key "Value"
                    //   header { -Server ... }
                    //
                    // 🔴 The exact-path form used to *compile* into nonsense. The
                    // generic matcher check only accepts a leading slash when it
                    // also carries a glob, so `header /exact X-Test scoped` left
                    // `/exact` in the argument list, where the field name is read
                    // from — producing `set: { "/exact": "X-Test" }`, a header
                    // whose name is not a legal header name, and a request that
                    // got no response at all. The correct answer is 200 with
                    // `x-test: scoped`.
                    //
                    // 🎯 No argument-count condition is needed to disambiguate: an
                    // HTTP field name cannot contain `/`, so a leading slash in
                    // the first position is unambiguously a matcher, which is why
                    // the reference grammar has no such condition either.
                    //
                    // 🧹 Stopgap. The matcher token should be stripped generically,
                    // before any directive's parser runs, so that this question
                    // never reaches the directive at all. Day 26f replaces the
                    // per-directive handling with that one rule and deletes
                    // this branch.
                    let mut header_d = sub_d.clone();
                    let inline_path = header_d
                        .args
                        .first()
                        .is_some_and(|a| a.starts_with('/'))
                        .then(|| header_d.drop_first_arg().unwrap_or_default());
                    let handler = adapt_header_directive(&header_d)?;
                    let matcher = match inline_path {
                        Some(path) => Some(Matcher::Path(PathMatcher {
                            patterns: vec![path],
                        })),
                        None => parse_matcher_and_block(&sub_d)?.0,
                    };
                    if matcher.is_some() {
                        add_route(&mut server, matcher, handler);
                    } else {
                        default_handlers.push(handler);
                    }
                }
                _ => {
                    // 🏠 A name nobody registered, carrying a block, inside the
                    // braceless shorthand: that is a second site written after
                    // a first one that forgot its braces. The shorthand runs to
                    // the end of the file, so the second site was swallowed as
                    // a directive of the first — and "unknown directive
                    // 'example.com'" describes the symptom while hiding the
                    // cause.
                    if sub_d.block.is_some() && !super::registry::is_directive_name(&sub_d.name) {
                        return Err(AdapterError::InvalidArgument(
                            "site address".into(),
                            format!(
                                "`{}` looks like a second site. Bare (unbraced) directives run                                  to the end of the file, so wrap every site in {{ }} when there                                  is more than one",
                                sub_d.name
                            ),
                        ));
                    }
                    // Try to extract matcher and adapt as handler
                    let (matcher, _) = parse_matcher_and_block(&sub_d)?;
                    let mut handler_d = sub_d.clone();
                    // 🧹 The per-directive allowlist that used to live here is
                    // gone: `matcher_token` reads the first argument the same way
                    // for every directive, so `redir`, `rewrite`, `reverse_proxy`
                    // and `respond` no longer need naming — and neither do the
                    // ones nobody had thought of.
                    let inline_path_matcher = matcher.is_some()
                        && matches!(handler_d.args.first(), Some(arg) if arg.starts_with('/'));
                    if inline_path_matcher {
                        let path = handler_d.drop_first_arg().unwrap_or_default();
                        let route_matcher = Matcher::Path(PathMatcher {
                            patterns: vec![path.clone()],
                        });
                        let handler = adapt_handler(handler_d, &server.matchers, order)?;
                        add_route(&mut server, Some(route_matcher), handler);
                        continue;
                    }
                    // 🌐 Caddy's `*` matcher token matches every request and
                    // exists only to disambiguate data arguments from path
                    // matchers; it must never reach an upstream list.
                    let wildcard_matcher = handler_d.name == "reverse_proxy"
                        && handler_d.args.first().is_some_and(|a| a == "*");
                    if wildcard_matcher {
                        handler_d.drop_first_arg();
                    }
                    if matcher.is_some() {
                        if handler_d.args.is_empty() {
                            return Err(AdapterError::ArgumentCount(sub_d.name, 1, 0));
                        }
                        handler_d.drop_first_arg();
                    }

                    let handler = adapt_handler(handler_d, &server.matchers, order)?;
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
        default_handlers.sort_by_key(|handler| caddy_handler_rank(order, handler));

        let final_handler = if default_handlers.len() == 1 {
            default_handlers[0].clone()
        } else {
            Handler::Pipeline(
                default_handlers
                    .iter()
                    .map(|handler| HandlerElement {
                        matcher: None,
                        handler: handler.clone(),
                    })
                    .collect(),
            )
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

        // 🧰 `vars` rules sort least specific first, the reverse of route
        // priority: every matching rule runs, so the most specific value is
        // the last one written. The comparator mirrors upstream's
        // `sortByPath` negated, including the "same path, one with a
        // trailing wildcard" tie-break (`/foo` before `/foo*` normally,
        // after `/foo*` here).
        let standard_less = |left: &VarsRule, right: &VarsRule| -> bool {
            let path = |matcher: &Option<Matcher>| -> (String, usize) {
                match matcher {
                    Some(Matcher::Path(PathMatcher { patterns })) if patterns.len() == 1 => {
                        let pattern = &patterns[0];
                        (
                            pattern.strip_suffix('*').unwrap_or(pattern).to_string(),
                            pattern.len(),
                        )
                    }
                    _ => (String::new(), 0),
                }
            };
            let (left_trimmed, left_len) = path(&left.matcher);
            let (right_trimmed, right_len) = path(&right.matcher);
            if left_len > 0 && right_len > 0 {
                if left_trimmed == right_trimmed {
                    left_len < right_len
                } else if left_trimmed.len() == right_trimmed.len() {
                    left_trimmed < right_trimmed
                } else {
                    left_trimmed.len() > right_trimmed.len()
                }
            } else {
                left.matcher.is_some() && right.matcher.is_none()
            }
        };
        // 🔃 `vars` runs the least specific matcher first so the most
        // specific rule can overwrite it, the negation of normal order.
        server.vars_routes.sort_by(|left, right| {
            let left_first = !standard_less(left, right);
            let right_first = !standard_less(right, left);
            match (left_first, right_first) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => std::cmp::Ordering::Equal,
            }
        });
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
            default_sni: None,
        });
    }

    Ok(server)
}

/// 🧭 Maps a handler to its position in Caddy's default directive order.
/// Handlers that only modify the request/response run early; handlers that
/// write a terminal response run late.
/// 🏷️ The directive a compiled handler came from.
///
/// Ordering is defined over directive *names*, and by the time a site is
/// assembled all that is left is the handler each one produced. This is the
/// bridge, and it is deliberately a small, dumb mapping — the moment it starts
/// deciding anything, the order stops being data.
pub(super) fn handler_directive_name(handler: &Handler) -> &'static str {
    match handler {
        Handler::Headers(_) => "header",
        Handler::LogSkip => "log_skip",
        Handler::Vars(_) => "vars",
        Handler::Redirect(_) => "redir",
        Handler::Error(_) => "error",
        // 🏷️ `rewrite` and `uri` compile to the same handler and rank one
        // apart, so the handler alone cannot answer this; the config records
        // which word was written.
        Handler::Rewrite(rewrite) => rewrite.directive,
        Handler::TryFiles(_) => "try_files",
        Handler::BasicAuth(_) => "basic_auth",
        Handler::Templates => "templates",
        Handler::Handle(_) => "handle",
        Handler::HandlePath { .. } => "handle_path",
        Handler::Pipeline(_) => "route",
        Handler::Respond(_) => "respond",
        Handler::Proxy(_) => "reverse_proxy",
        Handler::Intercept(_) => "intercept",
        Handler::ForwardAuth(_) => "reverse_proxy",
        Handler::FileServer(_) => "file_server",
        // 🧭 Three of ours with no counterpart in the shared order. They are
        // middleware that guards what follows, so they belong with the other
        // guards — beside `basic_auth`, which is the one they most resemble.
        Handler::RateLimit(_) | Handler::Cors(_) | Handler::AccessControl(_) => "basic_auth",
        // 🚫 A plugin is unranked on purpose: nothing here knows what it does,
        // and unranked sorts last, after every handler that answers.
        Handler::Plugin { .. } => "",
    }
}

/// 🔢 Where a handler sits in the chain, under the order this configuration uses.
pub(super) fn caddy_handler_rank(order: &DirectiveOrder, handler: &Handler) -> usize {
    order.rank(handler_directive_name(handler))
}

pub(super) fn route_specificity(matcher: &Option<Matcher>) -> (usize, usize) {
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

// MARK: - Helpers

/// 🧭 Reports whether a handler tree already owns the terminal response path.
pub(super) fn handler_has_terminal(handler: &Handler) -> bool {
    match handler {
        Handler::Proxy(_)
        | Handler::Respond(_)
        | Handler::Error(_)
        | Handler::Redirect(_)
        | Handler::FileServer(_)
        | Handler::Templates
        | Handler::ForwardAuth(_) => true,
        Handler::Pipeline(handlers)
        | Handler::Handle(handlers)
        | Handler::HandlePath { handlers, .. } => handlers
            .iter()
            .any(|element| handler_has_terminal(&element.handler)),
        // 🗂️ `try_files` belongs here rather than with the terminals: it only
        // changes which path is asked for, and a site whose route ends there
        // has answered nothing. The `file_server` after it is the terminal.
        Handler::Headers(_)
        | Handler::BasicAuth(_)
        | Handler::RateLimit(_)
        | Handler::Rewrite(_)
        | Handler::TryFiles(_)
        | Handler::Cors(_)
        | Handler::AccessControl(_)
        | Handler::LogSkip
        | Handler::Vars(_)
        | Handler::Intercept(_)
        | Handler::Plugin { .. } => false,
    }
}

/// 🧩 Inserts matched middleware before the default terminal handler.
pub(super) fn compose_with_default_handlers(matched: Handler, defaults: &[Handler]) -> Handler {
    let terminal_index = defaults
        .iter()
        .position(handler_has_terminal)
        .unwrap_or(defaults.len());
    let mut handlers = Vec::with_capacity(defaults.len() + 1);
    handlers.extend_from_slice(&defaults[..terminal_index]);
    handlers.push(matched);
    handlers.extend_from_slice(&defaults[terminal_index..]);
    Handler::Pipeline(
        handlers
            .into_iter()
            .map(|handler| HandlerElement {
                matcher: None,
                handler,
            })
            .collect(),
    )
}

pub(super) fn add_route(server: &mut ServerBlock, matcher: Option<Matcher>, handler: Handler) {
    if server.routes.is_none() {
        server.routes = Some(Node::new(
            RouteBlock { arms: Vec::new() },
            Location::synthetic(),
        ));
    }
    let routes = server.routes.as_mut().unwrap();
    routes.inner.arms.push(Node::new(
        RouteArm { matcher, handler },
        Location::synthetic(),
    ));
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
                    .map(|element| &element.handler)
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
        let config = compile(
            "example.com {\n    file_server ./public\n    basic_auth {\n user \
             $2y$04$BjuNmKvAV.mEi7.yFrazX.S6w6OO7H0BzQfyVVFZBq/qbVXCVNX4W\n }\n}",
        )
        .expect("compile");
        match &config.servers[0].routes[0].handler {
            HandlerConfig::Pipeline { handlers } => {
                assert!(matches!(
                    handlers[0].handler,
                    HandlerConfig::BasicAuth { .. }
                ));
                assert!(matches!(
                    handlers[1].handler,
                    HandlerConfig::FileServer { .. }
                ));
            }
            other => panic!("expected pipeline, got {other:?}"),
        }
    }

    #[test]
    fn terminal_handlers_follow_caddy_priority() {
        // 🧭 Caddy: reverse_proxy beats file_server; respond beats both. The
        // pipeline stops at the first handler that answers, so the order is
        // Caddy's own priority order.
        let proxy_first =
            compile("example.com {\n    reverse_proxy 127.0.0.1:9005\n    file_server\n}")
                .expect("compile");
        let HandlerConfig::Pipeline { handlers } = &proxy_first.servers[0].routes[0].handler else {
            panic!("expected a pipeline");
        };
        assert!(
            matches!(handlers[0].handler, HandlerConfig::ReverseProxy(_)),
            "reverse_proxy must run before file_server, got {handlers:?}"
        );
        assert!(matches!(
            handlers[1].handler,
            HandlerConfig::FileServer { .. }
        ));

        let respond_first =
            compile("example.com {\n    respond \"x\"\n    file_server\n}").expect("compile");
        let HandlerConfig::Pipeline { handlers } = &respond_first.servers[0].routes[0].handler
        else {
            panic!("expected a pipeline");
        };
        assert!(matches!(handlers[0].handler, HandlerConfig::Respond { .. }));
        assert!(matches!(
            handlers[1].handler,
            HandlerConfig::FileServer { .. }
        ));
    }

    #[test]
    fn templates_directive_compiles_with_site_root() {
        let config = compile("example.com {\n    root /site\n    templates\n    file_server\n}")
            .expect("compiles");
        let HandlerConfig::Pipeline { handlers } = &config.servers[0].routes[0].handler else {
            panic!("expected a pipeline");
        };
        assert!(
            matches!(&handlers[0].handler, HandlerConfig::Templates { root: Some(root) } if root == "/site"),
            "templates must run before file_server with the site root"
        );
        assert!(matches!(
            &handlers[1].handler,
            HandlerConfig::FileServer { .. }
        ));
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
                    HandlerConfig::Pipeline { handlers } if handlers.iter().any(|element| matches!(&element.handler, HandlerConfig::Headers { .. }))
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

#[cfg(test)]
mod wildcard_site_tests {
    use crate::compile;

    /// 🏠 `http://:8080` is Caddy's plainest plaintext site and must serve
    /// every Host, exactly like a bare `:8080`.
    ///
    /// Until 2026-08-04 the explicit scheme changed the outcome: the address
    /// was rewritten to the bind wildcard `[::]` and registered as a virtual
    /// host under that name, so no request could ever match it and the site
    /// returned 404 for everything. The bare form worked, which is why unit
    /// tests never noticed — they used the bare form.
    #[test]
    fn an_explicit_scheme_on_a_bare_port_is_still_a_catch_all() {
        for address in ["http://:8080", "https://:8443", ":8080", "_:8080"] {
            let config = compile(&format!("{address} {{\n    respond \"ok\"\n}}\n"))
                .unwrap_or_else(|error| panic!("`{address}` must compile: {error}"));
            assert_eq!(
                config.servers[0].name.as_deref(),
                Some("_"),
                "`{address}` names no host, so it must be the catch-all site — \
                 a site named after a bind wildcard is one no request can reach"
            );
        }
    }

    /// 🎯 The mirror case: a real hostname must keep its name, or every site
    /// becomes a catch-all and virtual hosting stops working.
    #[test]
    fn a_named_site_keeps_its_hostname() {
        let config = compile("http://example.com:8080 {\n    respond \"ok\"\n}\n").unwrap();
        assert_eq!(config.servers[0].name.as_deref(), Some("example.com"));
    }
}
