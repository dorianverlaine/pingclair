// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 Pingclair's declarative language lowers directly to shared configuration.

use crate::attributes::{Attr, resolve_attribute};
use crate::bindings::Bindings;
use crate::syntax::{self, Call, Declaration, Position, Value};
use pingclair_core::config::{
    AdminConfig, CircuitBreakerConfig, HandlerConfig, IpRanges, Layer4Matcher, Layer4Route,
    Layer4Server, Layer4TlsMatcher, ListenerOptions, LoadBalanceConfig, LogConfig, LogFormat,
    LogOutput, LogRotation, Matcher, MatcherCondition, OverloadConfig, PRIVATE_RANGES,
    PingclairConfig, ProxyUpstream, ResourceLimitsConfig, RetryConfig, ReverseProxyConfig,
    RouteConfig, ServerConfig, TlsConfig, UpstreamTlsConfig, normalize_listen_addr,
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
    if let Some(modifier) = call.modifiers.first() {
        return Err(modifier.at.error("Site modifiers are not implemented yet"));
    }
    let host = call.string("host")?;
    let body = call.block()?;
    if body.is_empty() {
        return Err(call.at.error("a Site needs at least one Route or Fallback"));
    }
    let mut routes = Vec::new();
    let mut seen_fallback = false;
    for (index, child) in body.iter().enumerate() {
        match child.name.as_str() {
            "Route" => {
                if seen_fallback {
                    return Err(child.at.error("Fallback must be the last route"));
                }
                routes.push(http_route(child)?);
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
                    "a Site contains Route and Fallback components, not {other}"
                )));
            }
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
        // 🧜 No `Encode` component yet: the site offers no compression, which is
        // what a Caddyfile without an `encode` directive compiles to. The legacy
        // gzip default on `ServerConfig` only applies to old JSON without the field.
        encodings: Vec::new(),
        limits: options.limits.clone().unwrap_or_default(),
        routes,
        ..ServerConfig::default()
    })
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

/// 🧭 An unconditional HTTP route: one terminal handler.
fn fallback_route(call: &Call) -> Result<RouteConfig, Error> {
    call.labels(&[])?;
    call.no_modifiers()?;
    let body = call.block()?;
    let [handler] = body else {
        return Err(call.at.error("Fallback requires exactly one handler"));
    };
    Ok(RouteConfig {
        path: "/*".to_string(),
        handler: http_handler(handler)?,
        methods: None,
        matcher: None,
    })
}

/// 🧭 A conditional HTTP route: `when:` plus exactly one handler.
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
    let [handler] = body else {
        return Err(call.at.error("Route requires exactly one handler"));
    };
    Ok(RouteConfig {
        path: primary.unwrap_or_else(|| "/*".to_string()),
        handler: http_handler(handler)?,
        methods: None,
        matcher: Some(matcher),
    })
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
                if !value.args.is_empty() {
                    return Err(value.at.error("a method value takes no arguments"));
                }
                let method = match value.name.as_str() {
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
                };
                methods.push(method.to_string());
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
        "file" => Err(call
            .at
            .error("the file matcher needs its typed-candidate design; it follows in its own batch")),
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

/// 🧰 HTTP terminal components; `Respond` is the first one implemented.
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
        _ => Err(call.at.error(
            "unknown HTTP handler; expected Respond, ServeFiles, Proxy, Redirect, Fail or ServeMetrics",
        )),
    }
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
        // 🧜 No `Encode` component yet: the site offers no compression, which is
        // what a Caddyfile without an `encode` directive compiles to.
        compress: false,
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
