// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 Pingclair's declarative language lowers directly to shared configuration.

use crate::attributes::{Attr, resolve_attribute};
use crate::bindings::Bindings;
use crate::syntax::{self, Call, Declaration, Position, Value};
use pingclair_core::config::{
    AccessControlConfig, AcmeServerConfig, AcmeServerPolicy, AdminConfig, BasicAuthAlgorithm,
    CircuitBreakerConfig, Encoding, ErrorRouteConfig, ForwardAuthConfig, ForwardAuthHeaderMap,
    HandlerConfig, HandlerElement, HeaderReplacement, IpRanges, Layer4Matcher, Layer4Route,
    Layer4Server, Layer4TlsMatcher, ListenerOptions, LoadBalanceConfig, LogConfig, LogFormat,
    LogOutput, LogRotation, Matcher, MatcherCondition, OverloadConfig, PRIVATE_RANGES,
    PingclairConfig, ProxyUpstream, RateLimitKey, ResourceLimitsConfig, RetryConfig,
    ReverseProxyConfig, RouteConfig, ServerConfig, TlsConfig, UpstreamTlsConfig,
    normalize_listen_addr,
};

/// 📍 Reports location and expected structure without echoing configuration values.
#[derive(Debug, thiserror::Error)]
#[error("line {line}:{column}: {message}")]
pub struct Error {
    pub(crate) line: usize,
    pub(crate) column: usize,
    pub(crate) message: String,
}

/// 🧭 Recognizes native declarations without guessing from a file extension.
pub fn is_native(source: &str) -> bool {
    let mut rest = source.trim_start();
    while let Some(comment) = rest.strip_prefix("//") {
        rest = comment
            .split_once('\n')
            .map_or("", |(_, tail)| tail)
            .trim_start();
    }
    if rest
        .strip_prefix("let")
        .is_some_and(|tail| tail.starts_with(char::is_whitespace))
    {
        return true;
    }
    if rest.starts_with('@') {
        return true;
    }
    let name_len = rest
        .bytes()
        .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        .count();
    name_len > 0
        && rest.as_bytes()[0].is_ascii_alphabetic()
        && rest[name_len..].trim_start().starts_with('(')
}

pub(super) fn adapt(source: &str) -> Result<PingclairConfig, Error> {
    let declarations = syntax::parse(source)?;
    let mut bindings = Bindings::default();
    bindings.declare(&declarations)?;
    let mut config = PingclairConfig::default();
    let mut seen = std::collections::HashSet::new();
    for declaration in &declarations {
        let call = match declaration {
            Declaration::Binding {
                attributes,
                name,
                value,
                ..
            } => {
                bindings.bind(attributes, name, value)?;
                continue;
            }
            Declaration::Component { attributes, call } => {
                if let Some(attribute) = attributes.first() {
                    let name = match resolve_attribute(attribute)? {
                        Attr::Matcher => "@Matcher",
                        Attr::Secret => "@Secret",
                    };
                    return Err(attribute.at.error(format!("{name} applies to bindings")));
                }
                bindings.expand_call(call)?
            }
        };
        if call.name == "Pingclair" {
            return Err(call.at.error(
                "the Pingclair(version: ...) header was removed; declare components at the top level",
            ));
        }
        if !matches!(call.name.as_str(), "TCPListener" | "HTTPListener")
            && !seen.insert(call.name.clone())
        {
            return Err(call.at.error("duplicate global declaration"));
        }
        match call.name.as_str() {
            "TCPListener" => config.layer4.push(listener(&call)?),
            "HTTPListener" => http_listener(&call, &mut config)?,
            "Admin" => {
                call.leaf(&["listen"])?;
                config.admin = Some(AdminConfig {
                    listen: call.string("listen")?,
                    enabled: true,
                    api_key: None,
                    origins: Vec::new(),
                    enforce_origin: false,
                });
            }
            "Metrics" => {
                call.leaf(&["enabled"])?;
                config.global.metrics = call.boolean("enabled")?;
            }
            "Shutdown" => {
                call.leaf(&["grace"])?;
                let millis = call.measure("grace", false)?;
                if millis % 1000 != 0 {
                    return Err(call.at.error("shutdown grace requires whole seconds"));
                }
                config.global.grace_period_secs = Some(millis / 1000);
            }
            _ => {
                return Err(call.at.error(
                    "unknown global declaration; expected TCPListener, Admin, Metrics, or Shutdown",
                ));
            }
        }
    }
    if config.layer4.is_empty() && config.servers.is_empty() {
        return Err(syntax::Position { line: 1, column: 1 }
            .error("expected at least one TCPListener or HTTPListener"));
    }
    Ok(config)
}

fn listener(call: &Call) -> Result<Layer4Server, Error> {
    call.labels(&["on"])?;
    let mut server = Layer4Server::new(call.string("on")?);
    let mut seen = std::collections::HashSet::new();
    for child in call.block()? {
        match child.name.as_str() {
            "Route" | "Fallback" => server.routes.push(route(child)?),
            _ => {
                return Err(child.at.error(
                    "TCPListener children must be Route, Fallback, or a component binding",
                ));
            }
        }
    }
    for child in &call.modifiers {
        if !seen.insert(&child.name) {
            return Err(child.at.error("duplicate listener modifier"));
        }
        match child.name.as_str() {
            "limits" => {
                child.leaf(&["connections", "preread", "relay"])?;
                if child.get("connections").is_some() {
                    server.max_connections = usize::try_from(child.integer("connections")?)
                        .map_err(|_| child.at.error("connection count exceeds platform range"))?;
                }
                if child.get("preread").is_some() {
                    server.preread_buffer_size =
                        usize::try_from(child.measure("preread", true)?)
                            .map_err(|_| child.at.error("buffer size exceeds platform range"))?;
                }
                if child.get("relay").is_some() {
                    server.proxy_buffer_size = usize::try_from(child.measure("relay", true)?)
                        .map_err(|_| child.at.error("buffer size exceeds platform range"))?;
                }
            }
            "timeouts" => {
                child.leaf(&["preread", "connect", "idle"])?;
                if child.get("preread").is_some() {
                    server.preread_timeout_ms = child.measure("preread", false)?;
                }
                if child.get("connect").is_some() {
                    server.proxy_connect_timeout_ms = child.measure("connect", false)?;
                }
                if child.get("idle").is_some() {
                    server.proxy_timeout_ms = child.measure("idle", false)?;
                }
            }
            "halfClose" => {
                child.leaf(&["enabled"])?;
                server.proxy_half_close = child.boolean("enabled")?;
            }
            _ => return Err(child.at.error("unknown TCPListener modifier")),
        }
    }
    Ok(server)
}

fn route(call: &Call) -> Result<Layer4Route, Error> {
    call.no_modifiers()?;
    let mut matches = Vec::new();
    if call.name == "Fallback" {
        call.labels(&[])?;
    } else {
        call.labels(&["when", "from"])?;
        if call.args.is_empty() {
            return Err(call
                .at
                .error("route requires when or from; use Fallback for an unconditional route"));
        }
        let mut matcher = Layer4Matcher::default();
        if let Some(value) = call.get("when") {
            let Value::Typed(tls) = value else {
                return Err(call.at.error("when requires .tls(...)"));
            };
            if tls.name != "tls" {
                return Err(tls
                    .at
                    .error("unsupported route condition; expected .tls(...)"));
            }
            tls.leaf(&["sni", "alpn"])?;
            matcher.tls = Some(Layer4TlsMatcher {
                sni: tls.strings("sni")?,
                alpn: tls.strings("alpn")?,
            });
        }
        matcher.remote_ip = call.strings("from")?;
        matches.push(matcher);
    }
    let body = call.block()?;
    let [proxy] = body else {
        return Err(call.at.error("route requires exactly one Proxy component"));
    };
    if proxy.name != "Proxy" {
        return Err(proxy.at.error("expected Proxy(to: ...)"));
    }
    proxy.leaf(&["to"])?;
    Ok(Layer4Route {
        matches,
        upstream: proxy.string("to")?,
    })
}

/// 🌐 One plaintext HTTP listener serving one or more sites.
fn http_listener(call: &Call, config: &mut PingclairConfig) -> Result<(), Error> {
    call.labels(&["on"])?;
    let on = call.string("on")?;
    let mut keys = vec![on.clone()];
    let mut addresses = vec![normalize_listen_addr(&on)];
    let mut protocols = None;
    let mut options = HttpListenerOptions::default();
    let mut seen = std::collections::HashSet::new();
    for modifier in &call.modifiers {
        if !seen.insert(modifier.name.clone()) {
            return Err(modifier.at.error("duplicate HTTPListener modifier"));
        }
        match modifier.name.as_str() {
            "bind" => {
                let [(None, Value::Array(items))] = modifier.args.as_slice() else {
                    return Err(modifier
                        .at
                        .error("bind takes one array of quoted addresses"));
                };
                if modifier.body.is_some() {
                    return Err(modifier.at.error("bind does not take a block"));
                }
                if items.is_empty() {
                    return Err(modifier.at.error("bind needs at least one address"));
                }
                for item in items {
                    let Value::String(address) = item else {
                        return Err(modifier.at.error("bind takes quoted addresses"));
                    };
                    let normalized = normalize_listen_addr(address);
                    if addresses.contains(&normalized) {
                        return Err(modifier.at.error(format!("duplicate address '{address}'")));
                    }
                    keys.push(address.clone());
                    addresses.push(normalized);
                }
            }
            "protocols" => {
                let [(None, Value::Array(items))] = modifier.args.as_slice() else {
                    return Err(modifier
                        .at
                        .error("protocols takes one array of .http1, .http2 and .http3"));
                };
                if modifier.body.is_some() {
                    return Err(modifier.at.error("protocols does not take a block"));
                }
                let mut names = Vec::new();
                for item in items {
                    let Value::Typed(value) = item else {
                        return Err(modifier
                            .at
                            .error("protocols takes .http1, .http2 or .http3 values"));
                    };
                    if !value.args.is_empty() {
                        return Err(value.at.error("a protocol value takes no arguments"));
                    }
                    names.push(value.name.as_str());
                }
                let mut unique = names.clone();
                unique.sort_unstable();
                unique.dedup();
                if unique.len() != names.len() {
                    return Err(modifier.at.error("duplicate protocol entry"));
                }
                if let Some(unknown) = unique
                    .iter()
                    .find(|name| !matches!(**name, "http1" | "http2" | "http3"))
                {
                    return Err(modifier.at.error(format!(
                        "unknown protocol '.{unknown}'; expected .http1, .http2 or .http3"
                    )));
                }
                if !(unique.contains(&"http1") && unique.contains(&"http2")) {
                    return Err(modifier.at.error(
                        "this build always serves h1 and h2; list `.http1` and `.http2` together and add `.http3` to offer QUIC",
                    ));
                }
                protocols = Some(unique.contains(&"http3"));
            }
            "limits" => {
                let mut bounds = ResourceLimitsConfig::default();
                apply_http_limits(modifier, &mut bounds)?;
                options.limits = Some(bounds);
            }
            "tls" => options.tls = Some(parse_tls(modifier)?),
            "accessLog" => options.log = Some(parse_access_log(modifier)?),
            _ => return Err(modifier.at.error("unknown HTTPListener modifier")),
        }
    }
    let mut servers = Vec::new();
    for child in call.block()? {
        if child.name != "Site" {
            return Err(child
                .at
                .error("HTTPListener children must be Site components"));
        }
        servers.push(site(child, &addresses, &options)?);
    }
    if servers.is_empty() {
        return Err(call.at.error("HTTPListener must contain at least one Site"));
    }
    if let Some(http3) = protocols {
        for key in keys {
            if config.global.listener_options.contains_key(&key) {
                return Err(call
                    .at
                    .error(format!("listener options for '{key}' are already declared")));
            }
            config.global.listener_options.insert(
                key,
                ListenerOptions {
                    http3: Some(http3),
                    ..ListenerOptions::default()
                },
            );
        }
    }
    config.servers.extend(servers);
    Ok(())
}

/// 🏠 One virtual host: the host it answers for and the routes it runs.
fn site(
    call: &Call,
    addresses: &[String],
    options: &HttpListenerOptions,
) -> Result<ServerConfig, Error> {
    call.labels(&["host"])?;
    let mut encodings = Vec::new();
    let mut error_pages: std::collections::BTreeMap<u16, String> =
        std::collections::BTreeMap::new();
    let mut page_positions = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for modifier in &call.modifiers {
        // 📌 `.errorPage(...)` is the one modifier a site may repeat: its key is
        // the status it claims, not the modifier's name, and a site with
        // several error pages is ordinary.
        if modifier.name != "errorPage" && !seen.insert(modifier.name.clone()) {
            return Err(modifier.at.error("duplicate Site modifier"));
        }
        match modifier.name.as_str() {
            "encode" => encodings = parse_encode(modifier)?,
            "errorPage" => {
                for (status, file) in parse_error_page(modifier)? {
                    if error_pages.insert(status, file.clone()).is_some() {
                        return Err(modifier
                            .at
                            .error(format!("status {status} already has an error page")));
                    }
                    page_positions.push((status, modifier.at));
                }
            }
            _ => {
                return Err(modifier
                    .at
                    .error("unknown Site modifier; expected .encode or .errorPage"));
            }
        }
    }
    let host = call.string("host")?;
    let body = call.block()?;
    if body.is_empty() {
        return Err(call
            .at
            .error("a Site needs at least one Route, Fallback or ErrorRoute"));
    }
    let mut routes = Vec::new();
    let mut error_routes = Vec::new();
    let mut answered_codes = std::collections::HashSet::new();
    let mut answered_hundreds = std::collections::HashSet::new();
    let mut seen_fallback = false;
    for (index, child) in body.iter().enumerate() {
        match child.name.as_str() {
            "Route" => {
                if seen_fallback {
                    return Err(child.at.error("Fallback must be the last route"));
                }
                routes.push(http_route(child)?);
            }
            // 🚨 Error routes sit wherever they read best: they are matched by
            // the status a handler raised, not by position in this list, and
            // the runtime keeps them in the order they were written.
            "ErrorRoute" => {
                let route = error_route(child)?;
                // 📎 Only a route that can answer shadows a page; one that
                // stops at middleware leaves the page in place.
                if child
                    .block()?
                    .iter()
                    .any(|component| is_terminal(&component.name))
                {
                    answered_codes.extend(route.codes.iter().copied());
                    answered_hundreds.extend(route.hundreds.iter().copied());
                }
                error_routes.push(route);
            }
            "Fallback" => {
                if seen_fallback || index + 1 != body.len() {
                    return Err(child
                        .at
                        .error("a Site may have one Fallback, and it comes last"));
                }
                seen_fallback = true;
                routes.push(fallback_route(child)?);
            }
            other => {
                return Err(child.at.error(format!(
                    "a Site contains Route, ErrorRoute and Fallback components, not {other}"
                )));
            }
        }
    }
    // 🚫 A page for a status an error route already answers is dead
    // configuration: the route runs first and cannot fall through to it. The
    // file loads, the page exists, and no request ever sees it — the shape this
    // repository refuses everywhere else.
    for (status, at) in page_positions {
        let hundred = (status / 100) as u8;
        if answered_codes.contains(&status) || answered_hundreds.contains(&hundred) {
            return Err(at.error(
                "an ErrorRoute already answers this status, so the error page can never be \
                 served; drop one of the two",
            ));
        }
    }
    // 🗜️ A site that names no coding offers none — the same reading a
    // Caddyfile without `encode` gets — so the file servers below are lowered
    // to match instead of keeping the flag that means "compression is allowed".
    if encodings.is_empty() {
        for route in &mut routes {
            crate::compiler::apply_site_compression(&mut route.handler);
        }
    }
    let (name, names) = if host == "*" {
        (Some("_".to_string()), Vec::new())
    } else {
        (Some(host.clone()), vec![host])
    };
    Ok(ServerConfig {
        name,
        names,
        listen: addresses.to_vec(),
        // 🛡️ A `.tls` listener terminates TLS; the site is not plaintext.
        plaintext_listen: if options.tls.is_some() {
            Vec::new()
        } else {
            addresses.to_vec()
        },
        tls: options.tls.clone(),
        log: options.log.clone(),
        // 🧜 `.encode(...)` is the only thing that turns compression on; the
        // legacy gzip default on `ServerConfig` applies to old JSON only.
        encodings,
        limits: options.limits.clone().unwrap_or_default(),
        routes,
        error_routes,
        error_pages,
        ..ServerConfig::default()
    })
}

/// 🚨 `.errorPage(for:, file:)`: the page served for one error status.
fn parse_error_page(modifier: &Call) -> Result<Vec<(u16, String)>, Error> {
    modifier.leaf(&["for", "file"])?;
    let file = modifier.string("file")?;
    let Some(Value::Array(items)) = modifier.get("for") else {
        return Err(modifier.at.error("errorPage takes for: [...]"));
    };
    if items.is_empty() {
        return Err(modifier.at.error("for: needs at least one status"));
    }
    let mut pages = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for item in items {
        let status = match item {
            Value::Typed(value) if value.name == "status" => {
                let status = exact_status(value)?;
                // 🚫 The model holds one code per entry, so a class here would
                // have to guess which of a hundred statuses it meant. The
                // Caddyfile's `error_page` has the same shape, and `ErrorRoute`
                // is the spelling that takes a class.
                if !(400..=599).contains(&status) {
                    return Err(value
                        .at
                        .error("an error page is served for 400..=599; list the codes"));
                }
                status
            }
            _ => {
                return Err(modifier.at.error(
                    "errorPage takes .status(<code>) values; a class such as .serverError \
                     belongs in ErrorRoute(for:)",
                ));
            }
        };
        if !seen.insert(status) {
            return Err(modifier.at.error(format!("status {status} appears twice")));
        }
        pages.push((status, file.clone()));
    }
    Ok(pages)
}

/// 🚨 `ErrorRoute(for:) { … }`: what to answer once a handler raised a status.
fn error_route(call: &Call) -> Result<ErrorRouteConfig, Error> {
    call.labels(&["for"])?;
    call.no_modifiers()?;
    let (codes, hundreds) = status_selectors(call)?;
    let body = call.block()?;
    // 🧵 Unlike a normal route, a body that stops at middleware is complete:
    // the error response already exists, so those components shape the answer
    // the runtime was about to write.
    Ok(ErrorRouteConfig {
        codes,
        hundreds,
        handlers: route_elements(body, call.at, Ending::MiddlewareAllowed)?,
    })
}

/// 🚨 Reads `for: [...]` into the exact codes and whole classes it names.
fn status_selectors(call: &Call) -> Result<(Vec<u16>, Vec<u8>), Error> {
    let Some(Value::Array(items)) = call.get("for") else {
        return Err(call.at.error(
            "ErrorRoute takes for: [.status(404), .serverError, …]; use .anyError for every status",
        ));
    };
    if items.is_empty() {
        return Err(call
            .at
            .error("for: needs at least one status; .anyError covers every error status"));
    }
    let mut codes = Vec::new();
    let mut hundreds = Vec::new();
    let mut any = false;
    for item in items {
        let Value::Typed(value) = item else {
            return Err(call.at.error(
                "for: takes .status(<code>) and .clientError/.serverError/.anyError values",
            ));
        };
        match value.name.as_str() {
            "status" => {
                let status = exact_status(value)?;
                if !(400..=599).contains(&status) {
                    return Err(value.at.error(
                        "an error route runs for 400..=599; a successful status is not an error",
                    ));
                }
                if !codes.contains(&status) {
                    codes.push(status);
                }
            }
            class @ ("clientError" | "serverError") => {
                value.leaf(&[])?;
                let hundred = if class == "clientError" { 4 } else { 5 };
                if !hundreds.contains(&hundred) {
                    hundreds.push(hundred);
                }
            }
            "anyError" => {
                value.leaf(&[])?;
                any = true;
            }
            // 🔮 Named now, meaningful later: the response matchers behind
            // `Intercept` are the call site that can see a successful status.
            other @ ("informational" | "success" | "redirect") => {
                return Err(value.at.error(format!(
                    "'.{other}' never reaches an error route; the response matchers are the \
                     call site that can see it"
                )));
            }
            other => {
                return Err(value.at.error(format!(
                    "unknown status selector '.{other}'; expected .status(<code>), \
                     .clientError, .serverError or .anyError"
                )));
            }
        }
    }
    if any && (!codes.is_empty() || !hundreds.is_empty()) {
        return Err(call
            .at
            .error(".anyError already covers every error status; list it alone"));
    }
    Ok((codes, hundreds))
}

/// 🚨 The one status code a `.status(...)` selector names.
fn exact_status(value: &Call) -> Result<u16, Error> {
    let [(None, Value::Number(code))] = value.args.as_slice() else {
        return Err(value
            .at
            .error(".status takes one code such as .status(404)"));
    };
    u16::try_from(*code).map_err(|_| value.at.error("status must fit in 0..=65535"))
}

/// 🗜️ `.encode(.zstd, .gzip)`: the codings this site may produce, most
/// preferred first.
fn parse_encode(modifier: &Call) -> Result<Vec<Encoding>, Error> {
    modifier.no_modifiers()?;
    if modifier.body.is_some() {
        return Err(modifier.at.error("encode does not take a block"));
    }
    if modifier.args.is_empty() {
        return Err(modifier.at.error(
            "encode needs at least one coding; a site with no .encode already offers no compression",
        ));
    }
    let mut encodings = Vec::new();
    for (label, value) in &modifier.args {
        if label.is_some() {
            return Err(modifier
                .at
                .error("encode takes unlabeled codings such as .encode(.zstd, .gzip)"));
        }
        let Value::Typed(coding) = value else {
            return Err(modifier.at.error("encode takes .zstd and .gzip values"));
        };
        if !coding.args.is_empty() {
            return Err(coding.at.error("a coding takes no arguments"));
        }
        let encoding = match coding.name.as_str() {
            "zstd" => Encoding::Zstd,
            "gzip" => Encoding::Gzip,
            // 🚫 Brotli is refused by name rather than dropped: a coding that
            // silently disappears looks identical to a working one until the
            // first client that asked for it.
            "br" => {
                return Err(coding
                    .at
                    .error("brotli is not implemented; use .zstd or .gzip"));
            }
            other => {
                return Err(coding.at.error(format!(
                    "unknown coding '.{other}'; expected .zstd or .gzip"
                )));
            }
        };
        if encodings.contains(&encoding) {
            return Err(coding.at.error("duplicate coding"));
        }
        encodings.push(encoding);
    }
    Ok(encodings)
}

/// 🌐 Listener-level settings a modifier chain may carry.
#[derive(Default)]
struct HttpListenerOptions {
    limits: Option<ResourceLimitsConfig>,
    tls: Option<TlsConfig>,
    log: Option<LogConfig>,
}

/// 🔐 The `.tls(...)` variants this build serves.
fn parse_tls(modifier: &Call) -> Result<TlsConfig, Error> {
    let [(None, Value::Typed(variant))] = modifier.args.as_slice() else {
        return Err(modifier
            .at
            .error("tls takes one variant: .automatic, .internal or .files"));
    };
    if modifier.body.is_some() {
        return Err(modifier.at.error("tls does not take a block"));
    }
    match variant.name.as_str() {
        "internal" => {
            variant.leaf(&[])?;
            Ok(TlsConfig {
                internal: true,
                ..TlsConfig::default()
            })
        }
        "automatic" => {
            variant.leaf(&["email"])?;
            let acme_email = if variant.get("email").is_some() {
                Some(variant.string("email")?)
            } else {
                None
            };
            Ok(TlsConfig {
                auto: true,
                acme_email,
                ..TlsConfig::default()
            })
        }
        "files" => {
            variant.leaf(&["certificate", "key"])?;
            Ok(TlsConfig {
                cert: Some(variant.string("certificate")?),
                key: Some(variant.string("key")?),
                ..TlsConfig::default()
            })
        }
        other => Err(variant.at.error(format!(
            "unknown TLS variant '.{other}'; expected .automatic, .internal or .files"
        ))),
    }
}

/// 🪵 The `.accessLog(...)` settings this build serves.
fn parse_access_log(modifier: &Call) -> Result<LogConfig, Error> {
    modifier.leaf(&[
        "output",
        "format",
        "level",
        "hostnames",
        "include",
        "exclude",
        "sampling",
        "rotation",
    ])?;
    for unsupported in [
        "level",
        "hostnames",
        "include",
        "exclude",
        "sampling",
        "rotation",
    ] {
        if modifier.get(unsupported).is_some() {
            return Err(modifier.at.error(format!(
                "{unsupported} in an access log is not implemented yet"
            )));
        }
    }
    let output = match modifier.get("output") {
        None => LogOutput::Stdout,
        Some(Value::Typed(value)) => match value.name.as_str() {
            "stdout" => {
                value.leaf(&[])?;
                LogOutput::Stdout
            }
            "stderr" => {
                value.leaf(&[])?;
                LogOutput::Stderr
            }
            "file" => {
                let [(None, Value::String(path))] = value.args.as_slice() else {
                    return Err(value.at.error("file takes one quoted path"));
                };
                LogOutput::File(path.clone())
            }
            other => {
                return Err(value.at.error(format!(
                    "unknown log output '.{other}'; expected .stdout, .stderr or .file"
                )));
            }
        },
        Some(_) => {
            return Err(modifier
                .at
                .error("output takes .stdout, .stderr or .file(...)"));
        }
    };
    let format = match modifier.get("format") {
        None => LogFormat::Text,
        Some(Value::Typed(value)) => match value.name.as_str() {
            "console" => {
                value.leaf(&[])?;
                LogFormat::Text
            }
            "json" => {
                value.leaf(&[])?;
                LogFormat::Json
            }
            other => {
                return Err(value.at.error(format!(
                    "unknown log format '.{other}'; expected .console or .json"
                )));
            }
        },
        Some(_) => {
            return Err(modifier.at.error("format takes .console or .json"));
        }
    };
    Ok(LogConfig {
        output,
        format,
        level: None,
        exclude_fields: Vec::new(),
        rotation: LogRotation::default(),
        request_headers: Vec::new(),
        response_headers: Vec::new(),
        include_tls: false,
        hostnames: Vec::new(),
        include: Vec::new(),
        exclude: Vec::new(),
        sampling: None,
    })
}

/// 🧱 The listener-level bounds a `.limits(...)` modifier sets.
fn apply_http_limits(call: &Call, limits: &mut ResourceLimitsConfig) -> Result<(), Error> {
    call.leaf(&[
        "headerTimeout",
        "bodyTimeout",
        "idleTimeout",
        "requestTimeout",
        "maxHeaders",
        "maxHeaderBytes",
        "maxConnections",
        "uploadBytesPerSecond",
        "downloadBytesPerSecond",
        "longConnections",
    ])?;
    if call.get("longConnections").is_some() {
        return Err(call
            .at
            .error("longConnections overrides are not implemented yet"));
    }
    if call.get("headerTimeout").is_some() {
        limits.header_timeout_ms = Some(call.measure("headerTimeout", false)?);
    }
    if call.get("bodyTimeout").is_some() {
        limits.body_timeout_ms = Some(call.measure("bodyTimeout", false)?);
    }
    if call.get("idleTimeout").is_some() {
        limits.idle_timeout_ms = Some(call.measure("idleTimeout", false)?);
    }
    if call.get("requestTimeout").is_some() {
        limits.request_timeout_ms = Some(call.measure("requestTimeout", false)?);
    }
    if call.get("maxHeaders").is_some() {
        limits.max_header_count = Some(http_count(call, "maxHeaders")?);
    }
    if call.get("maxHeaderBytes").is_some() {
        limits.max_header_bytes = Some(http_count(call, "maxHeaderBytes")?);
    }
    if call.get("maxConnections").is_some() {
        limits.max_connections = Some(http_count(call, "maxConnections")?);
    }
    if call.get("uploadBytesPerSecond").is_some() {
        limits.upload_bytes_per_sec = Some(call.measure("uploadBytesPerSecond", true)?);
    }
    if call.get("downloadBytesPerSecond").is_some() {
        limits.download_bytes_per_sec = Some(call.measure("downloadBytesPerSecond", true)?);
    }
    Ok(())
}

fn http_count(call: &Call, key: &str) -> Result<usize, Error> {
    usize::try_from(call.integer(key)?)
        .map_err(|_| call.at.error(format!("{key} exceeds the platform range")))
}

/// 🧭 An unconditional HTTP route: ordered middleware ending in one terminal.
fn fallback_route(call: &Call) -> Result<RouteConfig, Error> {
    call.labels(&[])?;
    call.no_modifiers()?;
    let body = call.block()?;
    Ok(RouteConfig {
        path: "/*".to_string(),
        handler: route_handler(body, call.at)?,
        methods: None,
        matcher: None,
    })
}

/// 🧭 A conditional HTTP route: `when:` plus ordered components.
fn http_route(call: &Call) -> Result<RouteConfig, Error> {
    call.labels(&["when"])?;
    call.no_modifiers()?;
    let Some(condition) = call.get("when") else {
        return Err(call
            .at
            .error("Route requires when:; use Fallback for an unconditional route"));
    };
    let (matcher, primary) = http_condition(condition, call.at)?;
    let body = call.block()?;
    Ok(RouteConfig {
        path: primary.unwrap_or_else(|| "/*".to_string()),
        handler: route_handler(body, call.at)?,
        methods: None,
        matcher: Some(matcher),
    })
}

/// 🧵 One route body: middleware in writing order, then the handler that
/// answers the request.
///
/// 🧭 The order is the meaning. A body with one component lowers to that
/// handler, exactly as a single-directive Caddyfile site does; two or more
/// become a pipeline the runtime walks front to back.
fn route_handler(body: &[Call], at: Position) -> Result<HandlerConfig, Error> {
    let mut handlers = route_elements(body, at, Ending::Terminal)?;
    if handlers.len() == 1 {
        return Ok(handlers.remove(0).handler);
    }
    Ok(HandlerConfig::Pipeline { handlers })
}

/// 🅿️ Whether a body may stop at middleware, or has to name who answers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ending {
    /// 🧵 A normal route: the last component answers.
    Terminal,
    /// 🚨 An error route: stopping at middleware leaves the runtime's own error
    /// answer in place with those changes applied.
    MiddlewareAllowed,
}

/// 🧵 One body as the ordered elements the runtime walks.
fn route_elements(
    body: &[Call],
    at: Position,
    ending: Ending,
) -> Result<Vec<HandlerElement>, Error> {
    let Some((last, middleware)) = body.split_last() else {
        return Err(at.error(format!(
            "a route needs at least one component; end it with {TERMINALS}"
        )));
    };
    if ending == Ending::Terminal && !is_terminal(&last.name) {
        return Err(last.at.error(format!(
            "a route must end with a component that answers the request: {TERMINALS}; {} only changes it",
            last.name
        )));
    }
    for child in middleware {
        if is_terminal(&child.name) {
            return Err(child.at.error(format!(
                "{} answers the request on its own, so the components after it can never run",
                child.name
            )));
        }
    }
    let mut handlers = Vec::with_capacity(body.len());
    for child in body {
        handlers.push(HandlerElement::plain(http_handler(child)?));
    }
    Ok(handlers)
}

/// 🅿️ The components that answer a request, named once for every refusal.
const TERMINALS: &str = "Respond, ServeFiles, Proxy, Redirect, Fail, ServeMetrics or ACMEServer";

/// 🅿️ Whether a component writes a response, and therefore ends a route.
fn is_terminal(name: &str) -> bool {
    matches!(
        name,
        "Respond" | "ServeFiles" | "Proxy" | "Redirect" | "Fail" | "ServeMetrics" | "ACMEServer"
    )
}

/// 🎛️ Whether a typed value names an HTTP condition.
///
/// 📌 The one list both readers consult: `http_condition` below is what turns a
/// name into a matcher, and a `@Matcher` binding is accepted on the strength of
/// this predicate before anything uses it. Two lists would let a condition bind
/// and then fail on the line that uses it, or refuse to bind at all — which is
/// what happened to every HTTP condition until the corpus wrote one down.
pub(crate) fn is_http_condition(name: &str) -> bool {
    matches!(
        name,
        "path"
            | "host"
            | "method"
            | "header"
            | "query"
            | "protocol"
            | "clientIP"
            | "remoteIP"
            | "variable"
            | "file"
            | "all"
            | "any"
            | "not"
    )
}

/// 🎛️ A typed HTTP condition, lowered onto the shared matcher model.
fn http_condition(value: &Value, at: Position) -> Result<(Matcher, Option<String>), Error> {
    let Value::Typed(call) = value else {
        return Err(at.error("a condition is a typed value such as .path(exact: \"/x\")"));
    };
    match call.name.as_str() {
        "path" => path_condition(call),
        "host" => {
            let [(None, Value::Array(items))] = call.args.as_slice() else {
                return Err(call.at.error("host takes one array of names"));
            };
            let mut hosts = Vec::new();
            for item in items {
                let Value::String(host) = item else {
                    return Err(call.at.error("host takes an array of names"));
                };
                hosts.push(host.clone());
            }
            if hosts.is_empty() {
                return Err(call.at.error("host needs at least one name"));
            }
            Ok((Matcher::Host(hosts), None))
        }
        "method" => {
            if call.args.is_empty() {
                return Err(call
                    .at
                    .error("method needs at least one .get/.post/... value"));
            }
            let mut methods = Vec::new();
            for (label, item) in call.args.as_slice() {
                if label.is_some() {
                    return Err(call
                        .at
                        .error("method takes unlabeled .get/.post/... values"));
                }
                let Value::Typed(value) = item else {
                    return Err(call
                        .at
                        .error("method takes unlabeled .get/.post/... values"));
                };
                methods.push(method_name(value)?.to_string());
            }
            Ok((Matcher::Method { methods }, None))
        }
        "all" | "any" => conjunction_or_disjunction(call),
        "not" => {
            let [(None, item)] = call.args.as_slice() else {
                return Err(call.at.error("not takes one condition"));
            };
            let (matcher, _) = http_condition(item, call.at)?;
            Ok((Matcher::Not(Box::new(matcher)), None))
        }
        "header" => header_or_query_condition(call, true),
        "query" => header_or_query_condition(call, false),
        "protocol" => protocol_condition(call),
        "clientIP" => address_condition(call, true),
        "remoteIP" => address_condition(call, false),
        "variable" => variable_condition(call),
        "file" => file_condition(call).map(|matcher| (matcher, None)),
        other => Err(call.at.error(format!(
            "unknown condition '.{other}'; expected .path, .host, .method, .header, .query, .protocol, .clientIP, .remoteIP, .variable, .file, .all, .any or .not"
        ))),
    }
}

/// 📁 The `.path(...)` variants: exact, segment prefix, glob and regex.
fn path_condition(call: &Call) -> Result<(Matcher, Option<String>), Error> {
    if let [(None, Value::Typed(regex))] = call.args.as_slice() {
        if regex.name != "regex" {
            return Err(regex.at.error(format!(
                "unknown path condition '.{}'; expected .regex",
                regex.name
            )));
        }
        let [(None, Value::String(pattern))] = regex.args.as_slice() else {
            return Err(regex.at.error("regex takes one pattern string"));
        };
        return Ok((
            Matcher::PathRegexp {
                name: None,
                pattern: pattern.clone(),
            },
            None,
        ));
    }
    call.leaf(&["exact", "prefix", "glob"])?;
    let mut chosen = Vec::new();
    for label in ["exact", "prefix", "glob"] {
        if call.get(label).is_some() {
            chosen.push(label);
        }
    }
    let [label] = chosen.as_slice() else {
        return Err(call
            .at
            .error("path requires exactly one of exact:, prefix:, glob: or .regex(...)"));
    };
    let text = call.string(label)?;
    if text.is_empty() {
        return Err(call.at.error(format!("{label} path must not be empty")));
    }
    if *label != "glob" && text.contains('*') {
        return Err(call.at.error(format!(
            "a {label} path cannot contain '*'; use glob: for wildcard patterns"
        )));
    }
    let (patterns, primary) = if *label == "prefix" {
        if text != "/" && text.ends_with('/') {
            return Err(call
                .at
                .error("a prefix must not end with '/'; write the parent path instead"));
        }
        let patterns = if text == "/" {
            vec!["/".to_string(), "/*".to_string()]
        } else {
            vec![text.clone(), format!("{text}/*")]
        };
        // 🧭 The route index needs a pattern that covers the whole subtree;
        // the matcher above still decides the exact semantics.
        let primary = if text == "/" {
            "/*".to_string()
        } else {
            format!("{text}*")
        };
        (patterns, Some(primary))
    } else {
        (vec![text.clone()], Some(text.clone()))
    };
    Ok((Matcher::Path { patterns }, primary))
}

/// 🔗 `.all([...])` and `.any([...])`, folded into an `And`/`Or` tree.
fn conjunction_or_disjunction(call: &Call) -> Result<(Matcher, Option<String>), Error> {
    let [(None, Value::Array(items))] = call.args.as_slice() else {
        return Err(call
            .at
            .error(format!("{} takes one array of conditions", call.name)));
    };
    if items.is_empty() {
        return Err(call
            .at
            .error(format!("{} needs at least one condition", call.name)));
    }
    let and = call.name == "all";
    let mut folded = None;
    let mut primary = None;
    for item in items {
        let (matcher, item_primary) = http_condition(item, call.at)?;
        if primary.is_none() {
            primary = item_primary;
        }
        folded = Some(match folded {
            None => matcher,
            Some(left) if and => Matcher::And(Box::new(left), Box::new(matcher)),
            Some(left) => Matcher::Or(Box::new(left), Box::new(matcher)),
        });
    }
    let folded = folded.expect("the array is non-empty");
    Ok((folded, if and { primary } else { None }))
}

/// 🏷️ `.header(...)` and `.query(...)`: one name and one typed predicate.
fn header_or_query_condition(
    call: &Call,
    is_header: bool,
) -> Result<(Matcher, Option<String>), Error> {
    let noun = if is_header { "header" } else { "query" };
    if is_header && let [(None, Value::Typed(regex))] = call.args.as_slice() {
        if regex.name != "regex" {
            return Err(regex.at.error(format!(
                "unknown header condition '.{}'; expected .regex",
                regex.name
            )));
        }
        regex.leaf(&["name", "pattern"])?;
        return Ok((
            Matcher::HeaderRegexp {
                name: None,
                field: regex.string("name")?,
                pattern: regex.string("pattern")?,
            },
            None,
        ));
    }
    call.leaf(&[
        "name",
        "value",
        "exists",
        "startsWith",
        "endsWith",
        "contains",
    ])?;
    let name = call.string("name")?;
    let mut predicates = Vec::new();
    for label in ["value", "exists", "startsWith", "endsWith", "contains"] {
        if call.get(label).is_some() {
            predicates.push(label);
        }
    }
    let [predicate] = predicates.as_slice() else {
        return Err(call.at.error(format!(
            "{noun} needs exactly one predicate: value:, exists:, startsWith:, endsWith: or contains:"
        )));
    };
    let condition = match *predicate {
        "value" => MatcherCondition::Equals(call.string("value")?),
        "exists" => {
            if !call.boolean("exists")? {
                return Err(call.at.error(format!(
                    "exists: false needs .not(...); write .not(.{noun}(name: \"…\", exists: true))"
                )));
            }
            MatcherCondition::Exists
        }
        "startsWith" => MatcherCondition::StartsWith(call.string("startsWith")?),
        "endsWith" => MatcherCondition::EndsWith(call.string("endsWith")?),
        "contains" => MatcherCondition::Contains(call.string("contains")?),
        _ => unreachable!(),
    };
    let matcher = if is_header {
        Matcher::Header { name, condition }
    } else {
        Matcher::Query { name, condition }
    };
    Ok((matcher, None))
}

/// 🌐 `.protocol(.http1, .http2, .http3)`: which protocols the route accepts.
fn protocol_condition(call: &Call) -> Result<(Matcher, Option<String>), Error> {
    if call.args.is_empty() {
        return Err(call
            .at
            .error("protocol needs at least one of .http1, .http2 or .http3"));
    }
    let mut names: Vec<String> = Vec::new();
    for (label, item) in call.args.as_slice() {
        if label.is_some() {
            return Err(call
                .at
                .error("protocol takes unlabeled .http1/.http2/.http3 values"));
        }
        let Value::Typed(value) = item else {
            return Err(call
                .at
                .error("protocol takes unlabeled .http1/.http2/.http3 values"));
        };
        if !value.args.is_empty() {
            return Err(value.at.error("a protocol value takes no arguments"));
        }
        let name = match value.name.as_str() {
            "http1" | "http2" | "http3" => value.name.clone(),
            other => {
                return Err(value.at.error(format!(
                    "unknown protocol '.{other}'; expected .http1, .http2 or .http3"
                )));
            }
        };
        if names.contains(&name) {
            return Err(value.at.error("duplicate protocol entry"));
        }
        names.push(name);
    }
    Ok((Matcher::Protocol(names), None))
}

/// 🔌 `.clientIP([...])` and `.remoteIP([...])`, with `.privateRanges`.
fn address_condition(call: &Call, client: bool) -> Result<(Matcher, Option<String>), Error> {
    let noun = if client { "clientIP" } else { "remoteIP" };
    let [(None, Value::Array(items))] = call.args.as_slice() else {
        return Err(call.at.error(format!(
            "{noun} takes one array of CIDRs, optionally including .privateRanges"
        )));
    };
    if items.is_empty() {
        return Err(call.at.error(format!("{noun} needs at least one range")));
    }
    let mut ranges = Vec::new();
    for item in items {
        match item {
            Value::String(range) => ranges.push(range.clone()),
            Value::Typed(value) if value.name == "privateRanges" && value.args.is_empty() => {
                ranges.extend(PRIVATE_RANGES.iter().map(|range| (*range).to_string()));
            }
            _ => {
                return Err(call
                    .at
                    .error(format!("{noun} takes CIDR strings or .privateRanges")));
            }
        }
    }
    let ranges = IpRanges::parse(ranges).map_err(|error| call.at.error(error.to_string()))?;
    let matcher = if client {
        Matcher::ClientIp(ranges)
    } else {
        Matcher::RemoteIp(ranges)
    };
    Ok((matcher, None))
}

/// 📦 `.variable(name:, values:)`: a request-scoped variable match.
fn variable_condition(call: &Call) -> Result<(Matcher, Option<String>), Error> {
    call.leaf(&["name", "values"])?;
    let name = call.string("name")?;
    let values = call.strings("values")?;
    if values.is_empty() {
        return Err(call.at.error("variable needs at least one value"));
    }
    Ok((Matcher::Vars { name, values }, None))
}

/// 📂 `.file(candidates:, root:, policy:)`: whether a candidate exists on disk.
///
/// 📌 The same candidate vocabulary as `TryFiles` below, and for the same
/// reason: one reader for one concept. A condition on file existence is what
/// the `try_files` shorthand is built out of.
fn file_condition(call: &Call) -> Result<Matcher, Error> {
    let files = file_candidates(call)?;
    let root = if call.get("root").is_some() {
        Some(call.string("root")?)
    } else {
        None
    };
    let try_policy = file_policy(call)?;
    Ok(Matcher::File {
        try_files: files,
        root,
        try_policy,
        // 🐘 The `.php` split belongs to the FastCGI expansion, which knows
        // what it is splitting; a hand-written condition says what it means
        // by naming its candidates.
        split_path: Vec::new(),
    })
}

/// 📂 `candidates:` — literal paths and the request path itself.
///
/// 🚫 Two things are refused by name rather than passed through: `{…}` because
/// the language has typed sources instead of interpolation, and `*` because
/// glob candidates are unimplemented in this build (#21) and would have to be
/// silently treated as a literal `*` in a filename.
fn file_candidates(call: &Call) -> Result<Vec<String>, Error> {
    call.leaf(&["candidates", "root", "policy"])?;
    let Some(Value::Array(items)) = call.get("candidates") else {
        return Err(call
            .at
            .error("candidates takes an array such as [.requestPath, \"/index.html\"]"));
    };
    if items.is_empty() {
        return Err(call.at.error("candidates needs at least one entry"));
    }
    let mut files = Vec::new();
    for item in items {
        files.push(file_candidate(item, call.at)?);
    }
    Ok(files)
}

/// 📂 One candidate, as the matcher spells it.
fn file_candidate(value: &Value, at: Position) -> Result<String, Error> {
    match value {
        // 🔤 A literal path. No interpolation: `{path}` spelled by hand is the
        // engine's own vocabulary, and `.requestPath` is the typed spelling of
        // exactly that idea.
        Value::String(path) => Ok(with_kept_query(candidate_path(path, at)?, false)),
        Value::Typed(source) => {
            match source.name.as_str() {
                // 🌐 The request path itself.
                "requestPath" => {
                    source.leaf(&["appending", "keepQuery"])?;
                    let appending = if source.get("appending").is_some() {
                        source.string("appending")?
                    } else {
                        String::new()
                    };
                    let keep_query = if source.get("keepQuery").is_some() {
                        source.boolean("keepQuery")?
                    } else {
                        false
                    };
                    // 🌐 Only the part the author wrote is checked: the `{path}`
                    // head is the typed source's own lowering.
                    let suffix = if appending.is_empty() {
                        String::new()
                    } else {
                        candidate_path(&appending, source.at)?
                    };
                    Ok(with_kept_query(format!("{{path}}{suffix}"), keep_query))
                }
                // 🔤 A fixed path. Typed rather than a plain string because it
                // can carry `keepQuery:`; a string cannot say that.
                "path" => {
                    let (path, keep_query) = match source.args.as_slice() {
                        [(None, Value::String(path))] => (path.clone(), false),
                        [
                            (None, Value::String(path)),
                            (Some(label), Value::Bool(keep)),
                        ] if label == "keepQuery" => (path.clone(), *keep),
                        _ => {
                            return Err(source.at.error(
                                ".path takes a quoted path, and optionally keepQuery: true",
                            ));
                        }
                    };
                    source.no_modifiers()?;
                    if source.body.is_some() {
                        return Err(source.at.error(".path does not take a block"));
                    }
                    Ok(with_kept_query(
                        candidate_path(&path, source.at)?,
                        keep_query,
                    ))
                }
                other => Err(source.at.error(format!(
                    "unknown candidate '.{other}'; expected .requestPath, \
                         .requestPath(appending: \"…\") or .path(\"…\", keepQuery: true)"
                ))),
            }
        }
        _ => Err(at.error(
            "a candidate is a quoted path, .requestPath(appending: \"…\") or \
             .path(\"…\", keepQuery: true)",
        )),
    }
}

/// 📂 One literal candidate path, checked for the spellings this build refuses.
fn candidate_path(path: &str, at: Position) -> Result<String, Error> {
    if path.is_empty() {
        return Err(at.error("a candidate must not be empty"));
    }
    if path.contains('{') || path.contains('}') {
        return Err(at.error(
            "candidates do not interpolate; write .requestPath for the request path, or \
             .requestPath(appending: \"…\") for it plus a suffix",
        ));
    }
    if path.contains('*') {
        return Err(at.error(
            "glob candidates are not implemented in this build, and a literal `*` in a path \
             is not what this would mean; write the paths out",
        ));
    }
    if path.contains('?') {
        return Err(at.error(
            "a candidate is a path; `keepQuery: true` on a typed candidate is how the request's \
             query string is carried into the rewrite",
        ));
    }
    Ok(path.to_string())
}

/// 📌 The query flag travels as the matcher's own `?` marker — the same thing
/// the Caddyfile spelling compiles to.
fn with_kept_query(path: String, keep_query: bool) -> String {
    if keep_query {
        format!("{path}?{{query}}")
    } else {
        path
    }
}

/// 🗂️ `policy:` — how several existing candidates are ranked.
fn file_policy(call: &Call) -> Result<Option<String>, Error> {
    let Some(value) = call.get("policy") else {
        return Ok(None);
    };
    let Value::Typed(policy) = value else {
        return Err(call
            .at
            .error("policy takes a typed value such as .mostRecentlyModified"));
    };
    policy.leaf(&[])?;
    Ok(Some(
        match policy.name.as_str() {
            "firstExist" => "first_exist",
            "firstExistFallback" => "first_exist_fallback",
            "largestSize" => "largest_size",
            "smallestSize" => "smallest_size",
            "mostRecentlyModified" => "most_recently_modified",
            other => {
                return Err(policy.at.error(format!(
                    "unknown file policy '.{other}'; expected .firstExist, .firstExistFallback, \
                     .largestSize, .smallestSize or .mostRecentlyModified"
                )));
            }
        }
        .to_string(),
    ))
}

/// 🗂️ `TryFiles(candidates:, root:, policy:)`: rewrite to the first candidate
/// that exists, then stand down so the next component serves it.
///
/// 📌 Lowered exactly the way the Caddyfile's `try_files` is — a first-match
/// group of `file` matcher plus a rewrite to the file the matcher picked. One
/// implementation, so the two spellings cannot drift (that drift is what #21
/// was, and the fix was to delete the second lookup rather than maintain it).
fn try_files(call: &Call) -> Result<HandlerConfig, Error> {
    let files = file_candidates(call)?;
    let root = if call.get("root").is_some() {
        Some(call.string("root")?)
    } else {
        None
    };
    let try_policy = file_policy(call)?;
    // 🧭 A candidate carrying the query gets its own group, because the rewrite
    // target differs; the plain candidates share one. The groups are mutually
    // exclusive, so only the first matching rewrite runs.
    let group = |candidates: Vec<String>, query: &str| HandlerElement {
        matcher: Some(Matcher::File {
            try_files: candidates,
            root: root.clone(),
            try_policy: try_policy.clone(),
            split_path: Vec::new(),
        }),
        handler: HandlerConfig::Rewrite {
            strip_prefix: None,
            strip_suffix: None,
            replace: Some(format!("{{http.matchers.file.relative}}{query}")),
            regex: None,
            regex_replace: None,
            method: None,
        },
    };
    let mut elements = Vec::new();
    let mut plain: Vec<String> = Vec::new();
    for candidate in files {
        match candidate.split_once('?') {
            Some((file, query)) => {
                if !plain.is_empty() {
                    elements.push(group(std::mem::take(&mut plain), ""));
                }
                elements.push(group(vec![file.to_string()], &format!("?{query}")));
            }
            None => plain.push(candidate),
        }
    }
    if !plain.is_empty() {
        elements.push(group(plain, ""));
    }
    Ok(HandlerConfig::FirstMatch { handlers: elements })
}

/// 🔤 The HTTP method one typed `.get`/`.post`/… value names.
fn method_name(value: &Call) -> Result<&'static str, Error> {
    if !value.args.is_empty() {
        return Err(value.at.error("a method value takes no arguments"));
    }
    Ok(match value.name.as_str() {
        "get" => "GET",
        "post" => "POST",
        "put" => "PUT",
        "delete" => "DELETE",
        "patch" => "PATCH",
        "head" => "HEAD",
        "options" => "OPTIONS",
        other => {
            return Err(value.at.error(format!(
                "unknown method '.{other}'; expected .get, .post, .put, .delete, .patch, .head or .options"
            )));
        }
    })
}

/// 🔖 One labeled quoted argument, refused when it is missing or mistyped.
fn labeled_string(call: &Call, key: &str) -> Result<String, Error> {
    match call.get(key) {
        Some(Value::String(value)) => Ok(value.clone()),
        _ => Err(call.at.error(format!("{key} requires a quoted string"))),
    }
}

/// 🧰 The HTTP components: terminals that answer, middleware that changes.
fn http_handler(call: &Call) -> Result<HandlerConfig, Error> {
    match call.name.as_str() {
        "Respond" => {
            call.leaf(&["body", "status"])?;
            let status = match call.get("status") {
                Some(_) => u16::try_from(call.integer("status")?)
                    .map_err(|_| call.at.error("status must fit in 0..=65535"))?,
                None => 200,
            };
            Ok(HandlerConfig::Respond {
                status,
                body: Some(call.string("body")?),
                headers: std::collections::BTreeMap::new(),
            })
        }
        "ServeFiles" => serve_files(call),
        "Proxy" => proxy(call),
        "Redirect" => redirect(call),
        "Fail" => fail(call),
        "ServeMetrics" => serve_metrics(call),
        "RequestHeader" => request_headers(call),
        "ResponseHeader" => response_headers(call),
        "Rewrite" => rewrite(call),
        "BasicAuth" => basic_auth(call),
        "TryFiles" => try_files(call),
        "RateLimit" => rate_limit(call),
        "AccessControl" => access_control(call),
        "CORS" => cors(call),
        "SetVariable" => set_variable(call),
        "LimitRequestBody" => limit_request_body(call),
        "SkipLog" => skip_log(call),
        "Templates" => templates(call),
        "ForwardAuth" => forward_auth(call),
        "ACMEServer" => acme_server(call),
        _ => Err(call.at.error(
            "unknown HTTP component; expected a terminal (Respond, ServeFiles, Proxy, Redirect, \
             Fail, ServeMetrics, ACMEServer) or middleware (RequestHeader, ResponseHeader, \
             Rewrite, BasicAuth, RateLimit, AccessControl, CORS, SetVariable, LimitRequestBody, \
             SkipLog, Templates, ForwardAuth, TryFiles)",
        )),
    }
}

/// 🧩 `Templates(root:)`: renders the files later components serve.
fn templates(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(&["root"])?;
    let root = if call.get("root").is_some() {
        Some(call.string("root")?)
    } else {
        None
    };
    Ok(HandlerConfig::Templates { root })
}

/// 🔐 `ForwardAuth(to:, uri:, copyHeaders:)`: one auth round trip up front.
fn forward_auth(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(&["to", "uri", "copyHeaders"])?;
    let upstream = call.string("to")?;
    let uri = call.string("uri")?;
    let mut copy_headers: Vec<ForwardAuthHeaderMap> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let copied: &[Value] = match call.get("copyHeaders") {
        None => &[],
        Some(Value::Array(items)) => {
            if items.is_empty() {
                return Err(call
                    .at
                    .error("copyHeaders must not be empty; leave it out instead"));
            }
            items
        }
        Some(_) => {
            return Err(call.at.error(
                "copyHeaders takes an array of field names and .rename(\"From\", to: \"To\") values",
            ));
        }
    };
    for item in copied {
        let (from, to) = match item {
            Value::String(field) => (field.clone(), None),
            Value::Typed(rename) if rename.name == "rename" => {
                let [(None, Value::String(from)), rest @ ..] = rename.args.as_slice() else {
                    return Err(rename.at.error(".rename takes a field name and to: \"…\""));
                };
                if rest.len() != 1 {
                    return Err(rename.at.error(".rename takes a field name and to: \"…\""));
                }
                (from.clone(), Some(labeled_string(rename, "to")?))
            }
            _ => {
                return Err(call.at.error(
                    "copyHeaders takes field names and .rename(\"From\", to: \"To\") values",
                ));
            }
        };
        if !seen.insert(from.clone()) {
            return Err(call.at.error(format!("'{from}' is copied twice")));
        }
        copy_headers.push(ForwardAuthHeaderMap { from, to });
    }
    let config = ForwardAuthConfig {
        upstream,
        uri,
        copy_headers,
        upstream_tls: None,
    };
    Ok(HandlerConfig::ReverseProxy(Box::new(
        config.as_reverse_proxy_subrequest(),
    )))
}

/// 🏛️ `ACMEServer(ca:, lifetime:, signWithRoot:, challenges:, allow:, deny:)`.
///
/// 📌 Written for parity with the Caddyfile spelling: the runtime refuses to
/// start a site that carries one, so this parses, validates and serialises, and
/// the refusal to run stays where it always was.
fn acme_server(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(&[
        "ca",
        "lifetime",
        "signWithRoot",
        "challenges",
        "allow",
        "deny",
    ])?;
    let ca = if call.get("ca").is_some() {
        Some(call.string("ca")?)
    } else {
        None
    };
    let lifetime_secs = if call.get("lifetime").is_some() {
        let millis = call.measure("lifetime", false)?;
        if millis == 0 || millis % 1000 != 0 {
            return Err(call.at.error("lifetime is at least one whole second"));
        }
        Some(millis / 1000)
    } else {
        None
    };
    let sign_with_root = if call.get("signWithRoot").is_some() {
        call.boolean("signWithRoot")?
    } else {
        false
    };
    let challenges = match call.get("challenges") {
        None => None,
        Some(_) => Some(call.strings("challenges")?),
    };
    Ok(HandlerConfig::AcmeServer(Box::new(AcmeServerConfig {
        ca,
        lifetime_secs,
        sign_with_root,
        challenges,
        allow: acme_policy(call, "allow")?,
        deny: acme_policy(call, "deny")?,
    })))
}

/// 🧭 One `allow:`/`deny:` policy: the names and networks a server issues for.
fn acme_policy(call: &Call, key: &str) -> Result<Option<AcmeServerPolicy>, Error> {
    let Some(value) = call.get(key) else {
        return Ok(None);
    };
    let Value::Typed(policy) = value else {
        return Err(call
            .at
            .error(format!("{key} takes .policy(domains:, ipRanges:)")));
    };
    if policy.name != "policy" {
        return Err(policy.at.error(format!(
            "unknown {key} policy '.{}'; expected .policy(domains:, ipRanges:)",
            policy.name
        )));
    }
    policy.leaf(&["domains", "ipRanges"])?;
    let domains = policy.strings("domains")?;
    let ip_ranges = policy.strings("ipRanges")?;
    if domains.is_empty() && ip_ranges.is_empty() {
        return Err(policy
            .at
            .error("a policy needs at least one domain or IP range"));
    }
    Ok(Some(AcmeServerPolicy { domains, ip_ranges }))
}

/// 🔐 `BasicAuth(users:, algorithm:, realm:)`: one guard, many credentials.
fn basic_auth(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(&["users", "algorithm", "realm"])?;
    let algorithm = match call.get("algorithm") {
        None => BasicAuthAlgorithm::Bcrypt,
        Some(Value::Typed(value)) => {
            if !value.args.is_empty() {
                return Err(value.at.error("an algorithm takes no arguments"));
            }
            match value.name.as_str() {
                "bcrypt" => BasicAuthAlgorithm::Bcrypt,
                "argon2id" => BasicAuthAlgorithm::Argon2id,
                other => {
                    return Err(value.at.error(format!(
                        "unknown algorithm '.{other}'; expected .bcrypt or .argon2id"
                    )));
                }
            }
        }
        Some(_) => return Err(call.at.error("algorithm takes .bcrypt or .argon2id")),
    };
    let realm = if call.get("realm").is_some() {
        call.string("realm")?
    } else {
        pingclair_core::config::default_auth_realm()
    };
    let Some(Value::Array(users)) = call.get("users") else {
        return Err(call
            .at
            .error("users takes an array of .user(\"name\", hash: \"…\") values"));
    };
    if users.is_empty() {
        return Err(call.at.error("users needs at least one entry"));
    }
    let mut seen = std::collections::HashSet::new();
    let mut credentials = Vec::new();
    for user in users {
        let Value::Typed(user) = user else {
            return Err(call
                .at
                .error("users takes .user(\"name\", hash: \"…\") values"));
        };
        if user.name != "user" {
            return Err(user
                .at
                .error("users takes .user(\"name\", hash: \"…\") values"));
        }
        let [(None, Value::String(name)), rest @ ..] = user.args.as_slice() else {
            return Err(user.at.error(".user takes a name and hash: \"…\""));
        };
        if rest.len() != 1 {
            return Err(user.at.error(".user takes a name and hash: \"…\""));
        }
        if !seen.insert(name.clone()) {
            return Err(user.at.error(format!("'{name}' appears twice in users")));
        }
        // 🔑 The hash is checked against the declared algorithm here, exactly
        // as the Caddyfile path does: a plaintext password must fail at load,
        // never at the first login attempt.
        let credential = crate::compiler::compile_basic_auth_credential(
            name,
            &labeled_string(user, "hash")?,
            algorithm,
        )
        .map_err(|error| user.at.error(error.to_string()))?;
        credentials.push(credential);
    }
    Ok(HandlerConfig::BasicAuth { realm, credentials })
}

/// ⏱️ `RateLimit(requests:, per:, key:, burst:, dryRun:)`.
fn rate_limit(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(&["requests", "per", "key", "burst", "dryRun"])?;
    let Some(_) = call.get("requests") else {
        return Err(call.at.error("RateLimit requires requests:"));
    };
    let requests = call.integer("requests")?;
    if requests == 0 {
        return Err(call.at.error("requests must be at least 1"));
    }
    let Some(_) = call.get("per") else {
        return Err(call
            .at
            .error("RateLimit requires per:, such as per: .minutes(1)"));
    };
    let window_ms = call.measure("per", false)?;
    if window_ms % 1000 != 0 {
        return Err(call.at.error("a rate limit window is whole seconds"));
    }
    let window_secs = window_ms / 1000;
    if window_secs == 0 {
        return Err(call.at.error("a rate limit window is at least one second"));
    }
    let key = match call.get("key") {
        None => RateLimitKey::Ip,
        Some(Value::Typed(value)) => {
            let argument = |value: &Call| -> Result<String, Error> {
                let [(None, Value::String(name))] = value.args.as_slice() else {
                    return Err(value
                        .at
                        .error(format!(".{} takes one quoted header name", value.name)));
                };
                Ok(name.clone())
            };
            match value.name.as_str() {
                kind @ ("ip" | "global" | "route" | "apiKey") => {
                    value.leaf(&[])?;
                    match kind {
                        "ip" => RateLimitKey::Ip,
                        "global" => RateLimitKey::Global,
                        "route" => RateLimitKey::Route,
                        _ => RateLimitKey::ApiKey,
                    }
                }
                "header" => RateLimitKey::Header(argument(value)?),
                "tenant" => RateLimitKey::Tenant(argument(value)?),
                other => {
                    return Err(value.at.error(format!(
                        "unknown rate limit key '.{other}'; expected .ip, .global, .route, \
                         .apiKey, .header(\"X-Name\") or .tenant(\"X-Name\")"
                    )));
                }
            }
        }
        Some(_) => {
            return Err(call
                .at
                .error("key takes a typed value such as .ip or .header(\"X-Tenant-ID\")"));
        }
    };
    let burst = if call.get("burst").is_some() {
        call.integer("burst")?
    } else {
        0
    };
    let dry_run = if call.get("dryRun").is_some() {
        call.boolean("dryRun")?
    } else {
        false
    };
    Ok(HandlerConfig::RateLimit {
        requests,
        window_secs,
        // 🔑 Kept for documents written before the key was a field; the key
        // itself is what the runtime reads.
        by_ip: matches!(key, RateLimitKey::Ip),
        burst,
        key: Some(key),
        dry_run,
    })
}

/// 🛡️ `AccessControl(...)`: allow and deny rules ahead of the terminal.
fn access_control(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(&[
        "allowedIPs",
        "deniedIPs",
        "allowedReferers",
        "deniedReferers",
        "allowedUserAgents",
        "deniedUserAgents",
    ])?;
    if call.args.is_empty() {
        return Err(call
            .at
            .error("AccessControl needs at least one rule; a rule-less guard guards nothing"));
    }
    Ok(HandlerConfig::AccessControl(AccessControlConfig {
        allowed_ips: call.strings("allowedIPs")?,
        denied_ips: call.strings("deniedIPs")?,
        allowed_referers: call.strings("allowedReferers")?,
        denied_referers: call.strings("deniedReferers")?,
        allowed_user_agents: call.strings("allowedUserAgents")?,
        denied_user_agents: call.strings("deniedUserAgents")?,
    }))
}

/// 🌐 `CORS(origins:, methods:, headers:, exposedHeaders:, allowCredentials:, maxAge:)`.
fn cors(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(&[
        "origins",
        "methods",
        "headers",
        "exposedHeaders",
        "allowCredentials",
        "maxAge",
    ])?;
    let Some(Value::Array(origins)) = call.get("origins") else {
        return Err(call.at.error("CORS requires origins: [...]"));
    };
    let mut allowed_origins = Vec::new();
    for origin in origins {
        let Value::String(origin) = origin else {
            return Err(call.at.error("origins takes quoted origins"));
        };
        allowed_origins.push(origin.clone());
    }
    if allowed_origins.is_empty() {
        return Err(call.at.error("origins needs at least one origin"));
    }
    let allowed_methods = match call.get("methods") {
        None => pingclair_core::config::default_cors_methods(),
        Some(Value::Array(methods)) => {
            if methods.is_empty() {
                return Err(call.at.error("methods must not be empty"));
            }
            let mut names = Vec::new();
            for method in methods {
                let Value::Typed(value) = method else {
                    return Err(call
                        .at
                        .error("methods takes unlabeled .get/.post/... values"));
                };
                names.push(method_name(value)?.to_string());
            }
            names
        }
        Some(_) => {
            return Err(call
                .at
                .error("methods takes an array of .get/.post/... values"));
        }
    };
    let allowed_headers = match call.get("headers") {
        None => pingclair_core::config::default_cors_headers(),
        Some(_) => call.strings("headers")?,
    };
    let exposed_headers = call.strings("exposedHeaders")?;
    let allow_credentials = if call.get("allowCredentials").is_some() {
        call.boolean("allowCredentials")?
    } else {
        false
    };
    let max_age = if call.get("maxAge").is_some() {
        let max_age_ms = call.measure("maxAge", false)?;
        if max_age_ms % 1000 != 0 {
            return Err(call.at.error("maxAge is whole seconds"));
        }
        max_age_ms / 1000
    } else {
        pingclair_core::config::default_cors_max_age()
    };
    Ok(HandlerConfig::Cors {
        allowed_origins,
        allowed_methods,
        allowed_headers,
        exposed_headers,
        allow_credentials,
        max_age,
    })
}

/// 🧰 `SetVariable(name:, value:)`: one request-scoped variable.
fn set_variable(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(&["name", "value"])?;
    let name = call.string("name")?;
    // 📌 An empty value is a value: it clears a variable a site-level rule
    // set, which is a thing an operator really does write.
    let value = call.string("value")?;
    let mut values = std::collections::BTreeMap::new();
    values.insert(name, value);
    Ok(HandlerConfig::Vars { values })
}

/// 📥 `LimitRequestBody(max:, readTimeout:, writeTimeout:, set:)`.
fn limit_request_body(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(&["max", "readTimeout", "writeTimeout", "set"])?;
    if call.args.is_empty() {
        return Err(call.at.error(
            "LimitRequestBody needs at least one of max:, readTimeout:, writeTimeout: or set:",
        ));
    }
    let max_size = if call.get("max").is_some() {
        Some(call.measure("max", true)?)
    } else {
        None
    };
    let read_timeout_ms = if call.get("readTimeout").is_some() {
        Some(call.measure("readTimeout", false)?)
    } else {
        None
    };
    let write_timeout_ms = if call.get("writeTimeout").is_some() {
        Some(call.measure("writeTimeout", false)?)
    } else {
        None
    };
    let set = match call.get("set") {
        None => None,
        Some(Value::String(body)) if body.is_empty() => {
            return Err(call
                .at
                .error("set: \"\" would replace the body with nothing; leave set: out instead"));
        }
        Some(Value::String(body)) => Some(body.clone()),
        Some(_) => return Err(call.at.error("set requires a quoted string")),
    };
    Ok(HandlerConfig::RequestBody {
        max_size,
        read_timeout_ms,
        write_timeout_ms,
        set,
    })
}

/// 🙈 `SkipLog()`: this request is left out of the access log.
fn skip_log(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(&[])?;
    Ok(HandlerConfig::LogSkip)
}

/// 🏷️ The header operations one component carries, in writing order.
#[derive(Default)]
struct HeaderOps {
    set: std::collections::BTreeMap<String, String>,
    add: std::collections::BTreeMap<String, Vec<String>>,
    remove: Vec<String>,
    replace: Vec<HeaderReplacement>,
    set_if_absent: std::collections::BTreeMap<String, String>,
}

/// 🏷️ `RequestHeader(...)`: rewrites the request later handlers read.
fn request_headers(call: &Call) -> Result<HandlerConfig, Error> {
    let ops = header_ops(call, false)?;
    Ok(HandlerConfig::RequestHeaders {
        set: ops.set,
        add: ops.add,
        remove: ops.remove,
        replace: ops.replace,
    })
}

/// 🏷️ `ResponseHeader(...)`: rewrites the response on its way to the client.
fn response_headers(call: &Call) -> Result<HandlerConfig, Error> {
    let ops = header_ops(call, true)?;
    Ok(HandlerConfig::Headers {
        set: ops.set,
        add: ops.add,
        remove: ops.remove,
        replace: ops.replace,
        default_set: ops.set_if_absent,
        require: None,
    })
}

/// 🏷️ Reads the action list both header components share.
///
/// One reader because the two components differ in *which message* they edit,
/// never in how an action is written — two readers would be two chances to
/// disagree, which is exactly how the Caddyfile's `?` prefix once reached the
/// request side of a format that refuses it.
fn header_ops(call: &Call, response_side: bool) -> Result<HeaderOps, Error> {
    if call.body.is_some() {
        return Err(call.at.error(format!(
            "{} does not take a block; write one action per call",
            call.name
        )));
    }
    call.no_modifiers()?;
    let actions = if call.args.is_empty() {
        return Err(call.at.error(format!(
            "{} needs at least one action such as .set(\"X-Name\", \"value\")",
            call.name
        )));
    } else {
        &call.args
    };
    let mut ops = HeaderOps::default();
    let mut claimed = std::collections::HashSet::new();
    for (label, value) in actions {
        let (None, Value::Typed(action)) = (label, value) else {
            return Err(call.at.error(format!(
                "{} takes unlabeled actions such as .set(\"X-Name\", \"value\")",
                call.name
            )));
        };
        match action.name.as_str() {
            "set" => {
                let (field, value) = header_pair(action)?;
                claim_once(&mut claimed, &field, call)?;
                ops.set.insert(field, value);
            }
            "setIfAbsent" => {
                if !response_side {
                    return Err(action.at.error(
                        "setIfAbsent inspects the finished response; a request header has nothing to inspect yet",
                    ));
                }
                let (field, value) = header_pair(action)?;
                claim_once(&mut claimed, &field, call)?;
                ops.set_if_absent.insert(field, value);
            }
            // 📋 Repeating this action is the point: two cookies are two
            // values of one field, and folding them into one line is the bug
            // RFC 6265 §3 forbids.
            "append" => {
                let (field, value) = header_pair(action)?;
                ops.add.entry(field).or_default().push(value);
            }
            "remove" => {
                let [(None, Value::String(field))] = action.args.as_slice() else {
                    return Err(action.at.error("remove takes one quoted field name"));
                };
                ops.remove.push(field.clone());
            }
            "replace" => {
                let [(None, Value::String(field)), rest @ ..] = action.args.as_slice() else {
                    return Err(action
                        .at
                        .error("replace takes a field name, pattern: and with:"));
                };
                if rest.len() != 2 {
                    return Err(action
                        .at
                        .error("replace takes a field name, pattern: and with:"));
                }
                ops.replace.push(HeaderReplacement {
                    field: field.clone(),
                    search_regexp: labeled_string(action, "pattern")?,
                    replace: labeled_string(action, "with")?,
                });
            }
            other => {
                return Err(action.at.error(format!(
                    "unknown header action '.{other}'; expected .set, .append, .remove{} or .replace",
                    if response_side { ", .setIfAbsent" } else { "" }
                )));
            }
        }
    }
    Ok(ops)
}

/// 🏷️ Reads the two unlabeled operands of `.set`/`.append`/`.setIfAbsent`.
fn header_pair(action: &Call) -> Result<(String, String), Error> {
    let [(None, Value::String(field)), (None, Value::String(value))] = action.args.as_slice()
    else {
        return Err(action.at.error(format!(
            ".{} takes a quoted field name and a quoted value",
            action.name
        )));
    };
    Ok((field.clone(), value.clone()))
}

/// 🚫 Refuses a second map-backed action for one field.
///
/// `set` and `setIfAbsent` are stored as maps, so a repeated field would keep
/// one of the two values without saying which. A caller who means to write the
/// field twice can write a second component, where the order is visible.
fn claim_once(
    claimed: &mut std::collections::HashSet<String>,
    field: &str,
    call: &Call,
) -> Result<(), Error> {
    if !claimed.insert(field.to_string()) {
        return Err(call.at.error(format!(
            "'{field}' is set twice in one {}; one field takes one .set or .setIfAbsent",
            call.name
        )));
    }
    Ok(())
}

/// ✂️ `Rewrite(...)`: exactly one path or method edit, where it is written.
///
/// 📌 One operation per component is deliberate. The shared model can carry
/// several at once and applies them in a fixed order of its own, so a
/// component that set two would read as the order they were written and mean
/// something else; two components in a row say what they mean.
fn rewrite(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(&["to", "stripPrefix", "stripSuffix", "path", "method"])?;
    let [(label, value)] = call.args.as_slice() else {
        return Err(call.at.error(
            "Rewrite takes exactly one operation: to:, stripPrefix:, stripSuffix:, path: or method:",
        ));
    };
    let mut strip_prefix = None;
    let mut strip_suffix = None;
    let mut replace = None;
    let mut regex = None;
    let mut regex_replace = None;
    let mut method = None;
    match (label.as_deref(), value) {
        (Some("to"), Value::String(path)) => replace = Some(path.clone()),
        (Some("stripPrefix"), Value::String(prefix)) => strip_prefix = Some(prefix.clone()),
        (Some("stripSuffix"), Value::String(suffix)) => strip_suffix = Some(suffix.clone()),
        (Some("path"), Value::Typed(pattern)) if pattern.name == "regex" => {
            pattern.leaf(&["pattern", "replacement"])?;
            regex = Some(pattern.string("pattern")?);
            regex_replace = Some(pattern.string("replacement")?);
        }
        (Some("method"), Value::Typed(verb)) => method = Some(method_name(verb)?.to_string()),
        (Some("to" | "stripPrefix" | "stripSuffix"), _) => {
            return Err(call.at.error("this operation takes one quoted string"));
        }
        (Some("path"), _) => {
            return Err(call
                .at
                .error("path takes .regex(pattern: \"…\", replacement: \"…\")"));
        }
        (Some("method"), _) => {
            return Err(call.at.error("method takes one value such as .put"));
        }
        _ => unreachable!("leaf checked the labels"),
    }
    Ok(HandlerConfig::Rewrite {
        strip_prefix,
        strip_suffix,
        replace,
        regex,
        regex_replace,
        method,
    })
}

/// 📂 `.ServeFiles(root:, browse:, index:)`: the static file handler.
fn serve_files(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(&["root", "browse", "index"])?;
    let root = call.string("root")?;
    let browse = if call.get("browse").is_some() {
        call.boolean("browse")?
    } else {
        false
    };
    let index = if call.get("index").is_some() {
        call.strings("index")?
    } else {
        vec!["index.html".to_string()]
    };
    if index.is_empty() {
        return Err(call.at.error("index needs at least one file name"));
    }
    Ok(HandlerConfig::FileServer {
        root,
        index,
        browse,
        browse_limit: None,
        // 🗜️ Allowed here, and lowered by the site's own coding list: a site
        // without `.encode` turns this off after the routes are built, exactly
        // as `encode off` does for a file server written in a Pingclairfile.
        compress: true,
        precompressed: Vec::new(),
        hide: Vec::new(),
        status: None,
        pass_thru: false,
        canonical_uris: true,
        etag_file_extensions: Vec::new(),
    })
}

/// 🌐 `.Proxy(to:)`: the reverse proxy with the build's bare defaults.
fn proxy(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(&["to"])?;
    let mut upstreams = Vec::new();
    match call.get("to") {
        Some(Value::String(address)) => upstreams.push(address.clone()),
        Some(Value::Array(items)) => {
            for item in items {
                let Value::String(address) = item else {
                    return Err(call.at.error("to takes quoted addresses"));
                };
                upstreams.push(address.clone());
            }
        }
        _ => {
            return Err(call
                .at
                .error("Proxy requires to: \"host:port\" or to: [\"host:port\", ...]"));
        }
    }
    if upstreams.is_empty() {
        return Err(call.at.error("Proxy needs at least one upstream"));
    }
    let upstream_options = upstreams
        .iter()
        .map(|address| ProxyUpstream {
            address: address.clone(),
            weight: 1,
            backup: false,
        })
        .collect();
    Ok(HandlerConfig::ReverseProxy(Box::new(ReverseProxyConfig {
        upstreams,
        fastcgi: None,
        dynamic_upstream: None,
        rewrite_method: None,
        rewrite_uri: None,
        request_buffer_bytes: None,
        response_buffer_bytes: None,
        upstream_versions: None,
        handle_response: Vec::new(),
        subrequest: None,
        upstream_options,
        load_balance: LoadBalanceConfig::default(),
        health_check: None,
        max_fails: None,
        fail_duration_ms: None,
        headers_up: std::collections::BTreeMap::new(),
        headers_down: std::collections::BTreeMap::new(),
        headers_down_add: std::collections::BTreeMap::new(),
        headers_down_remove: Vec::new(),
        headers_down_default: std::collections::BTreeMap::new(),
        headers_down_replace: Vec::new(),
        headers_up_remove: Vec::new(),
        headers_up_add: std::collections::BTreeMap::new(),
        headers_up_replace: Vec::new(),
        flush_interval: None,
        read_timeout: None,
        write_timeout: None,
        connect_timeout: None,
        first_byte_timeout: None,
        between_reads_timeout: None,
        retry: Box::new(RetryConfig {
            max_attempts: 16,
            total_timeout_ms: None,
            backoff_ms: 0,
            retry_match: Vec::new(),
        }),
        overload: Box::new(OverloadConfig {
            max_in_flight: None,
            max_pending: 0,
            pending_timeout_ms: 1000,
            upstream_max_connections: None,
        }),
        circuit_breaker: Box::new(CircuitBreakerConfig {
            consecutive_failures: None,
            error_rate_percent: None,
            minimum_requests: 20,
            window_requests: 100,
            open_duration_ms: 30_000,
            half_open_requests: 1,
            failure_statuses: Vec::new(),
        }),
        upstream_tls: Box::new(UpstreamTlsConfig::default()),
        cache: None,
    })))
}

/// ➡️ `.Redirect(to:, status:)`: the redirect statuses the RFC names.
fn redirect(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(&["to", "status"])?;
    let to = call.string("to")?;
    let code = match call.get("status") {
        None => 302,
        Some(Value::Typed(value)) => {
            if !value.args.is_empty() {
                return Err(value.at.error("a redirect status takes no arguments"));
            }
            match value.name.as_str() {
                "permanent" => 301,
                "temporary" => 302,
                "seeOther" => 303,
                "temporaryRedirect" => 307,
                "permanentRedirect" => 308,
                other => {
                    return Err(value.at.error(format!(
                        "unknown redirect status '.{other}'; expected .permanent, .temporary, .seeOther, .temporaryRedirect or .permanentRedirect"
                    )));
                }
            }
        }
        Some(_) => {
            return Err(call
                .at
                .error("status takes a redirect status such as .permanent"));
        }
    };
    Ok(HandlerConfig::Redirect { to, code })
}

/// 🚨 `.Fail(status:, message:)`: raise an error response.
fn fail(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(&["status", "message"])?;
    let status = match call.get("status") {
        None => 500,
        Some(_) => u16::try_from(call.integer("status")?)
            .map_err(|_| call.at.error("status must fit in 0..=65535"))?,
    };
    let message = if call.get("message").is_some() {
        Some(call.string("message")?)
    } else {
        None
    };
    Ok(HandlerConfig::Error { status, message })
}

/// 📊 `.ServeMetrics()`: answer with the Prometheus endpoint.
fn serve_metrics(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(&["disableOpenMetrics"])?;
    let disable_openmetrics = if call.get("disableOpenMetrics").is_some() {
        call.boolean("disableOpenMetrics")?
    } else {
        false
    };
    Ok(HandlerConfig::Metrics {
        disable_openmetrics,
    })
}

impl Call {
    fn get(&self, name: &str) -> Option<&Value> {
        self.args
            .iter()
            .find(|(key, _)| key.as_deref() == Some(name))
            .map(|(_, value)| value)
    }
    fn labels(&self, allowed: &[&str]) -> Result<(), Error> {
        if self
            .args
            .iter()
            .any(|(key, _)| !key.as_deref().is_some_and(|key| allowed.contains(&key)))
        {
            return Err(self.at.error("unknown or missing argument label"));
        }
        Ok(())
    }
    fn leaf(&self, allowed: &[&str]) -> Result<(), Error> {
        self.labels(allowed)?;
        self.no_modifiers()?;
        if self.body.is_some() {
            return Err(self.at.error("this declaration does not accept a block"));
        }
        Ok(())
    }
    fn no_modifiers(&self) -> Result<(), Error> {
        if !self.modifiers.is_empty() {
            return Err(self.at.error("this component does not accept modifiers"));
        }
        Ok(())
    }
    fn block(&self) -> Result<&[Call], Error> {
        self.body
            .as_deref()
            .ok_or_else(|| self.at.error("expected a configuration block"))
    }
    fn string(&self, key: &str) -> Result<String, Error> {
        match self.get(key) {
            Some(Value::String(value)) => Ok(value.clone()),
            _ => Err(self.at.error(format!("{key} requires a quoted string"))),
        }
    }
    fn integer(&self, key: &str) -> Result<u64, Error> {
        match self.get(key) {
            Some(Value::Number(value)) => Ok(*value),
            _ => Err(self.at.error(format!("{key} requires an unsigned integer"))),
        }
    }
    fn boolean(&self, key: &str) -> Result<bool, Error> {
        match self.get(key) {
            Some(Value::Bool(value)) => Ok(*value),
            _ => Err(self.at.error(format!("{key} requires true or false"))),
        }
    }
    fn strings(&self, key: &str) -> Result<Vec<String>, Error> {
        let Some(value) = self.get(key) else {
            return Ok(Vec::new());
        };
        let Value::Array(values) = value else {
            return Err(self.at.error(format!("{key} requires an array of strings")));
        };
        if values.is_empty() {
            return Err(self.at.error(format!("{key} must not be empty")));
        }
        values
            .iter()
            .map(|value| match value {
                Value::String(value) => Ok(value.clone()),
                _ => Err(self.at.error(format!("{key} requires an array of strings"))),
            })
            .collect()
    }
    fn measure(&self, key: &str, bytes: bool) -> Result<u64, Error> {
        let Some(Value::Typed(value)) = self.get(key) else {
            return Err(self.at.error(format!("{key} requires an explicit unit")));
        };
        let [(None, Value::Number(number))] = value.args.as_slice() else {
            return Err(value.at.error("unit requires one unsigned integer"));
        };
        let factor = match (bytes, value.name.as_str()) {
            (true, "bytes") => 1,
            (true, "kibibytes") => 1024,
            (true, "mebibytes") => 1024 * 1024,
            (false, "milliseconds") => 1,
            (false, "seconds") => 1000,
            (false, "minutes") => 60_000,
            (false, "hours") => 3_600_000,
            _ => return Err(value.at.error("unknown unit or wrong unit type")),
        };
        number
            .checked_mul(factor)
            .ok_or_else(|| value.at.error("unit value exceeds supported range"))
    }
}

#[cfg(test)]
#[path = "frontend_tests.rs"]
mod tests;
