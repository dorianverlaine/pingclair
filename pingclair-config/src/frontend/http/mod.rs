// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌐 The HTTP surface: listeners, sites, routing and listener policy.

mod conditions;
mod handlers;
mod tls;

pub(crate) use conditions::{TRY_FILES_LABELS, is_http_condition};
pub(crate) use handlers::{
    ACCESS_CONTROL_LABELS, ACME_SERVER_LABELS, BASIC_AUTH_LABELS, CORS_LABELS, FAIL_LABELS,
    FILE_SERVER_LABELS, FORWARD_AUTH_LABELS, LIMIT_BODY_LABELS, METRICS_LABELS, PROXY_LABELS,
    RATE_LIMIT_LABELS, REDIRECT_LABELS, RESPOND_LABELS, REWRITE_LABELS, SET_VARIABLE_LABELS,
    TEMPLATES_LABELS,
};
pub(crate) use tls::TLS_LABELS;

use super::log::{LogScope, parse_log};
use super::*;
use conditions::http_condition;
use handlers::http_handler;
use tls::parse_tls;

/// 🏷️ The argument labels an HTTP listener accepts.
pub(crate) const HTTP_LISTENER_LABELS: &[&str] = &["on"];

/// 🌐 One plaintext HTTP listener serving one or more sites.
pub(super) fn http_listener(call: &Call, config: &mut PingclairConfig) -> Result<(), Error> {
    call.labels(HTTP_LISTENER_LABELS)?;
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
            "underscoreHeaders" => {
                options.underscore_headers = Some(parse_underscore_headers(modifier)?);
            }
            "trustedProxies" => {
                let trusted = parse_trusted_proxies(modifier, "trustedProxies")?;
                options.trusted_proxies = trusted.ranges;
                options.client_ip_headers = trusted.headers;
            }
            "tls" => {
                let parsed = parse_tls(modifier, None)?;
                options.tls = Some(parsed.config);
                options.ocsp_stapling_off |= parsed.ocsp_stapling_off;
            }
            "accessLog" => options.log = Some(parse_log(modifier, LogScope::HttpAccess)?),
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
        let (server, site_ocsp) = site(child, &addresses, &options)?;
        // 📴 `ocspStapling: .off` names a process-wide record: this build
        // never staples, so writing it at either level records the state that
        // is already in force.
        if site_ocsp {
            config.global.ocsp_stapling_off = true;
        }
        servers.push(server);
    }
    if options.ocsp_stapling_off {
        config.global.ocsp_stapling_off = true;
    }
    if servers.is_empty() {
        return Err(call.at.error("HTTPListener must contain at least one Site"));
    }
    // 🧭 One listener's options, gathered from every modifier above. Written
    // under each address the listener serves, because that is what the runtime
    // and the Admin JSON look them up by.
    let listener_options = ListenerOptions {
        expected_underscore_headers: options.underscore_headers.clone(),
        http3: protocols,
        trusted_proxies: options.trusted_proxies.clone(),
        client_ip_headers: options.client_ip_headers.clone(),
        ..ListenerOptions::default()
    };
    if listener_options != ListenerOptions::default() {
        for key in keys {
            if config.global.listener_options.contains_key(&key) {
                return Err(call
                    .at
                    .error(format!("listener options for '{key}' are already declared")));
            }
            config
                .global
                .listener_options
                .insert(key, listener_options.clone());
        }
    }
    config.servers.extend(servers);
    Ok(())
}

/// 🏷️ The argument labels a site accepts.
pub(crate) const SITE_LABELS: &[&str] = &["host"];

/// 🏠 One virtual host: the host it answers for and the routes it runs.
fn site(
    call: &Call,
    addresses: &[String],
    options: &HttpListenerOptions,
) -> Result<(ServerConfig, bool), Error> {
    call.labels(SITE_LABELS)?;
    let mut encodings = Vec::new();
    let mut error_pages: std::collections::BTreeMap<u16, String> =
        std::collections::BTreeMap::new();
    let mut page_positions = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut site_tls: Option<tls::ParsedTls> = None;
    let mut http3: Option<(bool, Position)> = None;
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
            "tls" => site_tls = Some(parse_tls(modifier, options.tls.as_ref())?),
            "http3" => {
                modifier.leaf(&["enabled"])?;
                http3 = Some((modifier.boolean("enabled")?, modifier.at));
            }
            _ => {
                return Err(modifier
                    .at
                    .error("unknown Site modifier; expected .encode, .errorPage, .tls or .http3"));
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
                // 📎 Only a route that *always* answers shadows a page. One
                // that stops at middleware leaves the page in place, and one
                // that may answer — a file server that lets a miss through —
                // leaves the page exactly where a miss lands.
                if child
                    .block()?
                    .iter()
                    .any(|component| answers(component) == Answers::Always)
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
    // 🔐 A site's `.tls(...)` starts from its listener's configuration and
    // overrides what it writes down. `.http3(enabled:)` is the one site-only
    // setting, and it needs a TLS configuration to attach to.
    let (mut effective_tls, ocsp_stapling_off) = match site_tls {
        Some(parsed) => (Some(parsed.config), parsed.ocsp_stapling_off),
        None => (options.tls.clone(), false),
    };
    if let Some((enabled, at)) = http3 {
        let Some(config) = effective_tls.as_mut() else {
            return Err(
                at.error("http3 exists only on a TLS site; add .tls(...) here or on the listener")
            );
        };
        config.http3 = enabled;
    }
    let (name, names) = if host == "*" {
        (Some("_".to_string()), Vec::new())
    } else {
        (Some(host.clone()), vec![host])
    };
    Ok((
        ServerConfig {
            name,
            names,
            listen: addresses.to_vec(),
            // 🛡️ A `.tls` listener (or site) terminates TLS; the site is not
            // plaintext.
            plaintext_listen: if effective_tls.is_some() {
                Vec::new()
            } else {
                addresses.to_vec()
            },
            tls: effective_tls,
            log: options.log.clone(),
            // 🧜 `.encode(...)` is the only thing that turns compression on;
            // the legacy gzip default on `ServerConfig` applies to old JSON
            // only.
            encodings,
            limits: options.limits.clone().unwrap_or_default(),
            routes,
            error_routes,
            error_pages,
            ..ServerConfig::default()
        },
        ocsp_stapling_off,
    ))
}

/// 🏷️ The argument labels `parse_error_page` accepts, named once for the parser and `describe`.
pub(crate) const ERROR_PAGE_LABELS: &[&str] = &["for", "file"];

/// 🚨 `.errorPage(for:, file:)`: the page served for one error status.
fn parse_error_page(modifier: &Call) -> Result<Vec<(u16, String)>, Error> {
    modifier.leaf(ERROR_PAGE_LABELS)?;
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

/// 🏷️ The argument labels `error_route` accepts, named once for the parser and `describe`.
pub(crate) const ERROR_ROUTE_LABELS: &[&str] = &["for"];

/// 🚨 `ErrorRoute(for:) { … }`: what to answer once a handler raised a status.
fn error_route(call: &Call) -> Result<ErrorRouteConfig, Error> {
    call.labels(ERROR_ROUTE_LABELS)?;
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
    /// 🛡️ Underscore-named fields this listener keeps; `None` inherits the
    /// file-level `UnderscoreHeaders([…])`.
    underscore_headers: Option<Vec<String>>,
    /// 🛡️ Proxies this listener believes and the fields it reads the client
    /// address from. Each half is `None` when the modifier did not name it, so
    /// the other half still comes from the file-level `TrustedProxies(…)`.
    trusted_proxies: Option<Vec<String>>,
    client_ip_headers: Option<Vec<String>>,
    /// 📴 Recorded from any `.tls(ocspStapling: .off)` on this listener or one
    /// of its sites; the record is process-wide because no per-site stapling
    /// exists to configure.
    ocsp_stapling_off: bool,
}

/// 🏷️ The argument labels `.accessLog` accepts, named once for the parser and
/// `describe`.
pub(crate) use super::log::ACCESS_LOG_LABELS;

/// 🏷️ The argument labels `apply_http_limits` accepts, named once for the parser and `describe`.
pub(crate) const HTTP_LIMITS_LABELS: &[&str] = &[
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
];

/// 🧱 The listener-level bounds a `.limits(...)` modifier sets.
fn apply_http_limits(call: &Call, limits: &mut ResourceLimitsConfig) -> Result<(), Error> {
    call.leaf(HTTP_LIMITS_LABELS)?;
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
    if ending == Ending::Terminal && answers(last) == Answers::Never {
        return Err(last.at.error(format!(
            "a route must end with a component that answers the request: {TERMINALS}; {} only changes it",
            last.name
        )));
    }
    for child in middleware {
        if answers(child) == Answers::Always {
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

/// 🅿️ What a component does to the control flow, read from its own options.
///
/// 📌 A name is not enough, and the review found the case that proves it:
/// `ServeFiles(passThru: true)` answers when the file exists and hands the
/// request on when it does not, so a component written after it *is* reachable
/// — and a route may also end there, because a miss falls through to whatever
/// the site does with an unanswered request. The old name-based rule refused
/// the first and the second was refused as "middleware". `PHPFastCGI` is the
/// same shape for the extensions it proxies, which is why it used to need a
/// special case; it is one of the `Maybe`s now.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answers {
    /// Always writes a response: nothing after it can run.
    Always,
    /// Answers for some requests and stands down for the rest.
    Maybe,
    /// Only changes the request, or the response of what follows.
    Never,
}

fn answers(call: &Call) -> Answers {
    match call.name.as_str() {
        // ➡️ A file server that lets a miss through is a step, not an answer.
        "ServeFiles" if matches!(call.get("passThru"), Some(Value::Bool(true))) => Answers::Maybe,
        // 🐘 Answers for the extensions it split off, stands down otherwise.
        "PHPFastCGI" => Answers::Maybe,
        "Respond" | "ServeFiles" | "Proxy" | "Redirect" | "Fail" | "ServeMetrics"
        | "ACMEServer" => Answers::Always,
        _ => Answers::Never,
    }
}
