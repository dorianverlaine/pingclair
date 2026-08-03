// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🏗️ Compiler for the Pingclair configuration DSL.
//!
//! This module converts the AST into a runtime `PingclairConfig`.

use crate::parser::ast::*;
use pingclair_core::config::Encoding as CoreEncoding;
use pingclair_core::config::{
    AccessControlConfig as CoreAccessControlConfig, AdminConfig,
    AutoHttpsMode as CoreAutoHttpsMode, HandlerConfig, LoadBalanceConfig, LogConfig,
    LogFormat as CoreLogFormat, LogOutput as CoreLogOutput, Matcher as CoreMatcher,
    MatcherCondition, PingclairConfig, ProxyUpstream, RateLimitKey as CoreRateLimitKey,
    ReverseProxyConfig, RouteConfig, ServerConfig, TlsConfig, default_encodings,
    default_gzip_types,
};
use pingclair_core::server::{MAX_BCRYPT_COST, bcrypt_hash_cost};
use std::collections::{HashMap, HashSet};
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
        let block = &server_node.inner;
        let mut server_config = compile_server(block)?;
        // 🌐 Caddy serves any named site over HTTPS by default: a bare
        // hostname with no explicit scheme/listen and automatic HTTPS
        // enabled gets `tls auto` (localhost/IP sites already get the
        // internal authority from the adapter). `http://` sites keep their
        // explicit plaintext listener.
        if server_config.tls.is_none()
            && block.listens.is_empty()
            && config.global.auto_https != CoreAutoHttpsMode::Off
            && block
                .names
                .iter()
                .any(|name| !name.is_empty() && name != "_")
        {
            let internal = block.names.iter().any(|name| {
                name == "localhost"
                    || name.ends_with(".localhost")
                    || name.parse::<std::net::IpAddr>().is_ok()
            });
            server_config.tls = Some(TlsConfig {
                auto: !internal,
                internal,
                ..Default::default()
            });
        }
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

    // 🌐 Port overrides flow straight into the runtime config; every
    // hard-coded 80/443 derivation consults these instead.
    if let Some(port) = global.http_port {
        config.global.http_port = port;
    }
    if let Some(port) = global.https_port {
        config.global.https_port = port;
    }
    if let Some(enabled) = global.metrics {
        config.global.metrics = enabled;
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

    if let Some(secs) = global.dns_refresh_secs {
        config.global.dns_refresh_secs = secs;
    }

    Ok(())
}

/// 🗜️ Lowers the `encode` directive into the runtime's coding preference list.
///
/// The grammar accepts `br` because Caddyfiles in the wild write it, but the
/// reverse-proxy body filter has no streaming Brotli encoder. Rejecting it
/// here is deliberate: the alternative is to drop it from the list and quietly
/// serve gzip, which looks identical in a smoke test and is only discovered
/// much later, from a `Content-Encoding` that was never asked for.
fn compile_encodings(server: &ServerBlock) -> CompileResult<Vec<CoreEncoding>> {
    let Some(algos) = &server.compress else {
        return Ok(default_encodings());
    };

    let mut encodings = Vec::with_capacity(algos.len());
    for algo in algos {
        encodings.push(match algo {
            CompressionAlgo::Gzip => CoreEncoding::Gzip,
            CompressionAlgo::Zstd => CoreEncoding::Zstd,
            CompressionAlgo::Br => {
                return Err(CompileError::UnsupportedFeature {
                    feature: "`encode br`: Brotli is not implemented for proxied responses; \
                              use `encode zstd gzip`"
                        .to_string(),
                });
            }
        });
    }
    Ok(encodings)
}

fn compile_server(server: &ServerBlock) -> CompileResult<ServerConfig> {
    let mut config = ServerConfig {
        name: Some(server.name.clone()),
        names: server.names.clone(),
        bind: server.bind.clone(),
        listen: Vec::new(),
        proxy_protocol_listen: Vec::new(),
        routes: Vec::new(),
        tls: None,
        log: None,
        client_max_body_size: 1024 * 1024, // 1MB default
        limits: pingclair_core::config::ResourceLimitsConfig {
            header_timeout_ms: server.limits.header_timeout_ms,
            body_timeout_ms: server.limits.body_timeout_ms,
            idle_timeout_ms: server.limits.idle_timeout_ms,
            request_timeout_ms: server.limits.request_timeout_ms,
            max_header_count: server.limits.max_header_count,
            max_header_bytes: server.limits.max_header_bytes,
            max_connections: server.limits.max_connections,
            upload_bytes_per_sec: server.limits.upload_bytes_per_sec,
            download_bytes_per_sec: server.limits.download_bytes_per_sec,
            long_connections: pingclair_core::config::LongConnectionLimits {
                idle_timeout_ms: server.limits.long_connections.idle_timeout_ms,
                request_timeout_ms: server.limits.long_connections.request_timeout_ms,
            },
        },
        security: Default::default(),
        gzip_types: if server.gzip_types.is_empty() {
            default_gzip_types()
        } else {
            server.gzip_types.clone()
        },
        encodings: compile_encodings(server)?,
        error_pages: server.error_pages.iter().cloned().collect(),
    };

    // Listen addresses
    for listen in &server.listens {
        let addr = if let Some(port) = listen.port {
            format!("{}:{}", listen.host, port)
        } else {
            listen.host.clone()
        };
        if listen.proxy_protocol && !config.proxy_protocol_listen.contains(&addr) {
            config.proxy_protocol_listen.push(addr.clone());
        }
        config.listen.push(addr);

        // 🔐 Set TLS based on scheme or the conventional HTTPS ports. A bare
        // `:443`/`:8443` listener is HTTPS in Caddy (and in this runtime's
        // `server_requires_tls`), so the compiled config must say so too;
        // otherwise ACME provisioning and the port-80 companion never start.
        if listen.scheme == Scheme::Https || listen.port.is_some_and(|p| matches!(p, 443 | 8443)) {
            config.tls = Some(TlsConfig::default());
        }
    }

    // 🔐 The explicit directive merges with the HTTPS scheme without losing either source.
    if let Some(tls) = &server.tls {
        if tls.off {
            config.tls = None;
        } else {
            let mut merged = config.tls.take().unwrap_or_default();
            merged.auto = merged.auto || tls.auto;
            merged.internal = merged.internal || tls.internal;
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

    // 📍 The `bind` directive names the interface, not a listener. Keeping it
    // separate from `listen` lets the runtime derive 443/80 for a hostname
    // site (e.g. `example.com { bind 127.0.0.1; tls auto }`) instead of a
    // bare `127.0.0.1` being mistaken for a complete listen address.
    config.bind = server.bind.clone();

    // Log configuration
    if let Some(log) = &server.log {
        config.log = Some(compile_log(&log.inner)?);
    }

    // Routes
    if let Some(routes) = &server.routes {
        for arm in &routes.inner.arms {
            config.routes.extend(compile_route_arm(
                &arm.inner,
                &server.matchers,
                server.root.as_deref(),
            )?);
        }
    }

    // 📂 Hand the `root` directive to every file server that did not name its
    // own root. Caddy's `file_server` takes no root argument; the site root
    // comes from `root`, so a bare `file_server` must inherit it.
    if let Some(site_root) = &server.root {
        for route in &mut config.routes {
            apply_site_root(&mut route.handler, site_root);
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
                        Expr::Ident(id) if id == "internal" => {
                            tls.internal = true;
                        }
                        Expr::Map(map) => {
                            if let Some(Expr::Bool(b)) = map.get("auto") {
                                tls.auto = *b;
                            }
                            if let Some(Expr::Bool(b)) = map.get("internal") {
                                tls.internal = *b;
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

/// 📂 Recursively replaces a file server's default root with the site root.
fn apply_site_root(handler: &mut pingclair_core::config::HandlerConfig, site_root: &str) {
    match handler {
        pingclair_core::config::HandlerConfig::FileServer { root, .. } => {
            if root == "." {
                *root = site_root.to_string();
            }
        }
        pingclair_core::config::HandlerConfig::Pipeline { handlers }
        | pingclair_core::config::HandlerConfig::Handle { handlers }
        | pingclair_core::config::HandlerConfig::HandlePath { handlers, .. } => {
            for inner in handlers {
                apply_site_root(inner, site_root);
            }
        }
        _ => {}
    }
}

/// 🛡️ Rejects TLS combinations that cannot have deterministic runtime behavior.
pub fn validate_config(config: &PingclairConfig) -> CompileResult<()> {
    for rule in &config.global.trusted_proxies {
        if rule.parse::<ipnet::IpNet>().is_err() && rule.parse::<std::net::IpAddr>().is_err() {
            return Err(CompileError::InvalidServer {
                message: format!("trusted_proxies contains invalid IP or CIDR `{rule}`"),
            });
        }
    }
    validate_proxy_protocol_listeners(config)?;

    for server in &config.servers {
        let limits = &server.limits;
        let positive_durations = [
            ("header_timeout_ms", limits.header_timeout_ms),
            ("body_timeout_ms", limits.body_timeout_ms),
            ("idle_timeout_ms", limits.idle_timeout_ms),
            ("request_timeout_ms", limits.request_timeout_ms),
        ];
        if let Some((name, _)) = positive_durations
            .into_iter()
            .find(|(_, value)| value.is_some_and(|value| value == 0 || value > 31_536_000_000))
        {
            return Err(CompileError::InvalidServer {
                message: format!("{name} must be between 1 ms and 365 days"),
            });
        }
        for (name, value) in [
            (
                "long_connections.idle_timeout_ms",
                limits.long_connections.idle_timeout_ms,
            ),
            (
                "long_connections.request_timeout_ms",
                limits.long_connections.request_timeout_ms,
            ),
        ] {
            if value.is_some_and(|value| value > 31_536_000_000) {
                return Err(CompileError::InvalidServer {
                    message: format!("{name} must be off, zero, or at most 365 days"),
                });
            }
        }
        if limits
            .max_header_count
            .is_some_and(|value| value == 0 || value > 256)
        {
            return Err(CompileError::InvalidServer {
                message: "max_header_count must be between 1 and 256".to_string(),
            });
        }
        if limits
            .max_header_bytes
            .is_some_and(|value| value == 0 || value > 1_048_575)
        {
            return Err(CompileError::InvalidServer {
                message: "max_header_bytes must be between 1 and 1048575".to_string(),
            });
        }
        if limits.max_connections == Some(0) {
            return Err(CompileError::InvalidServer {
                message: "max_connections must be greater than zero".to_string(),
            });
        }
        if limits.upload_bytes_per_sec == Some(0) || limits.download_bytes_per_sec == Some(0) {
            return Err(CompileError::InvalidServer {
                message: "bandwidth limits must be greater than zero".to_string(),
            });
        }

        for route in &server.routes {
            validate_proxy_protection_handler(&route.handler)?;
            reject_unimplemented_handler(&route.handler)?;
        }

        let Some(tls) = &server.tls else {
            continue;
        };

        if tls.cert.is_some() != tls.key.is_some() {
            return Err(CompileError::InvalidServer {
                message: "TLS cert and key must be specified together".to_string(),
            });
        }

        if !tls.internal {
            continue;
        }

        if tls.auto || tls.cert.is_some() || tls.acme_email.is_some() {
            return Err(CompileError::InvalidServer {
                message: "tls internal cannot be combined with auto, cert/key, or an ACME email"
                    .to_string(),
            });
        }

        let name = server.name.as_deref().unwrap_or_default();
        if name.is_empty() || name == "_" || name.contains('*') || name.starts_with(':') {
            return Err(CompileError::InvalidServer {
                message: "tls internal requires a concrete server name".to_string(),
            });
        }
    }

    Ok(())
}

/// 🚫 Rejects handlers the server cannot actually execute.
///
/// A configuration that validates and then does nothing is the worst of both
/// worlds: the operator believes a rule is in force and no error ever says
/// otherwise. `plugin` was exactly that — `{"type":"plugin","name":"totally-
/// fictional"}` passed validation, and at request time the H1/H2 dispatcher
/// fell through to a catch-all that returned "not handled" without a word in
/// the log. A route meant to authenticate or filter would simply be absent.
///
/// The plugin system is a stub, not a feature (`pingclair-plugin` has no
/// callers), so the honest answer is to refuse the configuration up front.
/// Living here rather than in the DSL adapter is deliberate: the Admin API
/// deserializes straight into core types, so an adapter-only check is a
/// bypass — see the note on `validate_config` being the single validation path.
fn reject_unimplemented_handler(handler: &HandlerConfig) -> CompileResult<()> {
    match handler {
        HandlerConfig::Plugin { name, .. } => Err(CompileError::InvalidRoute {
            message: format!(
                "handler `plugin` is not implemented, so the route named `{name}` would \
                 silently do nothing; the plugin system is planned but unwired"
            ),
        }),
        HandlerConfig::Templates { .. } => Ok(()),
        HandlerConfig::Pipeline { handlers }
        | HandlerConfig::Handle { handlers }
        | HandlerConfig::HandlePath { handlers, .. } => {
            for handler in handlers {
                reject_unimplemented_handler(handler)?;
            }
            Ok(())
        }
        HandlerConfig::HandleErrors { errors } => {
            for handlers in errors.values() {
                for handler in handlers {
                    reject_unimplemented_handler(handler)?;
                }
            }
            Ok(())
        }
        HandlerConfig::TryFiles { fallback, .. } => match fallback {
            Some(fallback) => reject_unimplemented_handler(fallback),
            None => Ok(()),
        },
        // 🧭 Named exhaustively rather than with a wildcard: a new handler
        // variant must force a decision here about whether it is executable,
        // instead of defaulting to "allowed" and shipping as a silent no-op.
        HandlerConfig::FileServer { .. }
        | HandlerConfig::ReverseProxy(_)
        | HandlerConfig::Redirect { .. }
        | HandlerConfig::Rewrite { .. }
        | HandlerConfig::Respond { .. }
        | HandlerConfig::Headers { .. }
        | HandlerConfig::BasicAuth { .. }
        | HandlerConfig::RateLimit { .. }
        | HandlerConfig::Cors { .. }
        | HandlerConfig::AccessControl(_) => Ok(()),
    }
}

/// 🛡️ Rejects unsafe retry, overload, and circuit-breaker policies.
fn validate_proxy_protection_handler(handler: &HandlerConfig) -> CompileResult<()> {
    match handler {
        HandlerConfig::ReverseProxy(proxy) => {
            // ⏳ A zero TTL would admit entries that are stale on arrival, and an
            // unbounded one would pin a response past any plausible deployment.
            // Both are configuration mistakes rather than useful settings.
            if let Some(cache) = &proxy.cache
                && (cache.ttl_secs == 0 || cache.ttl_secs > 31_536_000)
            {
                return Err(CompileError::InvalidRoute {
                    message: "cache ttl must be between 1 second and 365 days".to_string(),
                });
            }

            let retry = &proxy.retry;
            if !(1..=16).contains(&retry.max_attempts) {
                return Err(CompileError::InvalidRoute {
                    message: "retry max_attempts must be between 1 and 16".to_string(),
                });
            }
            if retry
                .total_timeout_ms
                .is_some_and(|value| value == 0 || value > 31_536_000_000)
            {
                return Err(CompileError::InvalidRoute {
                    message: "retry total_timeout_ms must be between 1 ms and 365 days".to_string(),
                });
            }
            if retry.backoff_ms > 31_536_000_000 {
                return Err(CompileError::InvalidRoute {
                    message: "retry backoff_ms must not exceed 365 days".to_string(),
                });
            }
            if retry
                .total_timeout_ms
                .is_some_and(|total| retry.max_attempts > 1 && retry.backoff_ms >= total)
            {
                return Err(CompileError::InvalidRoute {
                    message: "retry backoff_ms must be shorter than total_timeout_ms".to_string(),
                });
            }
            if retry
                .status_codes
                .iter()
                .any(|status| !(400..=599).contains(status))
            {
                return Err(CompileError::InvalidRoute {
                    message: "retry status_codes must contain only 4xx or 5xx values".to_string(),
                });
            }
            if retry.status_codes.len() > 200
                || retry.status_codes.iter().collect::<HashSet<_>>().len()
                    != retry.status_codes.len()
            {
                return Err(CompileError::InvalidRoute {
                    message: "retry status_codes must be unique and contain at most 200 values"
                        .to_string(),
                });
            }
            const IDEMPOTENT_METHODS: [&str; 6] =
                ["GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"];
            if let Some(method) = retry
                .methods
                .iter()
                .find(|method| !IDEMPOTENT_METHODS.contains(&method.as_str()))
            {
                return Err(CompileError::InvalidRoute {
                    message: format!(
                        "retry method {method} is not idempotent; v0.2 does not replay it"
                    ),
                });
            }
            if retry.methods.len() > IDEMPOTENT_METHODS.len()
                || retry.methods.iter().collect::<HashSet<_>>().len() != retry.methods.len()
            {
                return Err(CompileError::InvalidRoute {
                    message: "retry methods must be unique".to_string(),
                });
            }

            let overload = &proxy.overload;
            if overload
                .max_in_flight
                .is_some_and(|value| value == 0 || value > 1_000_000)
                || overload
                    .upstream_max_connections
                    .is_some_and(|value| value == 0 || value > 1_000_000)
                || overload.max_pending > 1_000_000
            {
                return Err(CompileError::InvalidRoute {
                    message: "overload limits must be between 1 and 1000000".to_string(),
                });
            }
            if overload.max_pending > 0 && overload.max_in_flight.is_none() {
                return Err(CompileError::InvalidRoute {
                    message: "overload max_pending requires max_in_flight".to_string(),
                });
            }
            if **overload != pingclair_core::config::OverloadConfig::default()
                && overload.max_in_flight.is_none()
                && overload.max_pending == 0
                && overload.upstream_max_connections.is_none()
            {
                return Err(CompileError::InvalidRoute {
                    message: "overload requires at least one active limit".to_string(),
                });
            }
            if overload.max_pending > 0
                && (overload.pending_timeout_ms == 0
                    || overload.pending_timeout_ms > 31_536_000_000)
            {
                return Err(CompileError::InvalidRoute {
                    message:
                        "overload pending_timeout_ms must be between 1 ms and 365 days when queuing"
                            .to_string(),
                });
            }

            let breaker = &proxy.circuit_breaker;
            if !breaker.enabled()
                && **breaker != pingclair_core::config::CircuitBreakerConfig::default()
            {
                return Err(CompileError::InvalidRoute {
                    message: "circuit_breaker requires consecutive_failures or error_rate_percent"
                        .to_string(),
                });
            }
            if breaker
                .consecutive_failures
                .is_some_and(|value| value == 0 || value > 1_000_000)
            {
                return Err(CompileError::InvalidRoute {
                    message: "circuit_breaker consecutive_failures must be between 1 and 1000000"
                        .to_string(),
                });
            }
            if breaker
                .error_rate_percent
                .is_some_and(|value| !(1..=100).contains(&value))
            {
                return Err(CompileError::InvalidRoute {
                    message: "circuit_breaker error_rate_percent must be between 1 and 100"
                        .to_string(),
                });
            }
            if breaker.enabled()
                && (breaker.minimum_requests == 0
                    || breaker.window_requests == 0
                    || breaker.minimum_requests > breaker.window_requests
                    || breaker.window_requests > 10_000)
            {
                return Err(CompileError::InvalidRoute {
                    message:
                        "circuit_breaker requires 1 <= minimum_requests <= window_requests <= 10000"
                            .to_string(),
                });
            }
            if breaker.enabled()
                && (breaker.open_duration_ms == 0
                    || breaker.open_duration_ms > 31_536_000_000
                    || breaker.half_open_requests == 0
                    || breaker.half_open_requests > 1_000)
            {
                return Err(CompileError::InvalidRoute {
                    message: "circuit_breaker recovery values are outside their safe bounds"
                        .to_string(),
                });
            }
            if breaker
                .failure_statuses
                .iter()
                .any(|status| !(400..=599).contains(status))
                || breaker.failure_statuses.len() > 200
                || breaker
                    .failure_statuses
                    .iter()
                    .collect::<HashSet<_>>()
                    .len()
                    != breaker.failure_statuses.len()
            {
                return Err(CompileError::InvalidRoute {
                    message: "circuit_breaker failure_statuses must be unique 4xx or 5xx values"
                        .to_string(),
                });
            }

            if let Some(health) = &proxy.health_check {
                validate_health_check(health)?;
            }
            validate_upstream_tls(&proxy.upstream_tls)?;
        }
        HandlerConfig::RateLimit {
            requests,
            window_secs,
            burst,
            key,
            ..
        } => {
            if *requests == 0 || *requests > 1_000_000_000 {
                return Err(CompileError::InvalidRoute {
                    message: "rate_limit requests must be between 1 and 1000000000".to_string(),
                });
            }
            if *window_secs == 0 || *window_secs > 86_400 {
                return Err(CompileError::InvalidRoute {
                    message: "rate_limit window_secs must be between 1 and 86400".to_string(),
                });
            }
            if *burst > 1_000_000_000 || requests.checked_add(*burst).is_none() {
                return Err(CompileError::InvalidRoute {
                    message: "rate_limit burst must not exceed 1000000000".to_string(),
                });
            }
            if let Some(CoreRateLimitKey::Header(name) | CoreRateLimitKey::Tenant(name)) = key
                && (name.len() > 128 || http::HeaderName::from_bytes(name.as_bytes()).is_err())
            {
                return Err(CompileError::InvalidRoute {
                    message: "rate_limit key header must be a valid HTTP field name".to_string(),
                });
            }
        }
        HandlerConfig::Pipeline { handlers }
        | HandlerConfig::Handle { handlers }
        | HandlerConfig::HandlePath { handlers, .. } => {
            for handler in handlers {
                validate_proxy_protection_handler(handler)?;
            }
        }
        HandlerConfig::HandleErrors { errors } => {
            for handlers in errors.values() {
                for handler in handlers {
                    validate_proxy_protection_handler(handler)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// 🩺 Rejects health probes that are ambiguous, unbounded, or unsafe to send.
fn validate_health_check(health: &pingclair_core::config::HealthCheckConfig) -> CompileResult<()> {
    if !health.path.starts_with('/')
        || health.path.bytes().any(|byte| byte.is_ascii_control())
        || health.path.len() > 8_192
    {
        return Err(CompileError::InvalidRoute {
            message: "health_check path must be a control-free absolute path".to_string(),
        });
    }
    if health.interval == 0
        || health.interval > 86_400
        || health.timeout == 0
        || health.timeout > 86_400
    {
        return Err(CompileError::InvalidRoute {
            message: "health_check interval and timeout must be between 1 and 86400 seconds"
                .to_string(),
        });
    }
    if !matches!(health.method.as_str(), "GET" | "HEAD" | "OPTIONS") {
        return Err(CompileError::InvalidRoute {
            message: "health_check method must be GET, HEAD, or OPTIONS".to_string(),
        });
    }
    if health.method == "HEAD" && health.expected_body.is_some() {
        return Err(CompileError::InvalidRoute {
            message: "health_check cannot validate a response body with method HEAD".to_string(),
        });
    }
    if health.host.as_ref().is_some_and(|host| {
        host.is_empty() || host.len() > 253 || host.bytes().any(|byte| byte.is_ascii_control())
    }) {
        return Err(CompileError::InvalidRoute {
            message: "health_check host must be a non-empty, control-free hostname".to_string(),
        });
    }
    if health.headers.len() > 64
        || health.headers.iter().any(|(name, value)| {
            let managed =
                name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("connection");
            name.is_empty()
                || managed
                || name.len() > 256
                || !name.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(
                            byte,
                            b'!' | b'#'
                                | b'$'
                                | b'%'
                                | b'&'
                                | b'\''
                                | b'*'
                                | b'+'
                                | b'-'
                                | b'.'
                                | b'^'
                                | b'_'
                                | b'`'
                                | b'|'
                                | b'~'
                        )
                })
                || value.len() > 8_192
                || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
        })
    {
        return Err(CompileError::InvalidRoute {
            message: "health_check headers contain an invalid or oversized name/value".to_string(),
        });
    }
    let failure_threshold = health.consecutive_failure.unwrap_or(health.threshold);
    if !(1..=1_000_000).contains(&health.consecutive_success)
        || !(1..=1_000_000).contains(&failure_threshold)
    {
        return Err(CompileError::InvalidRoute {
            message: "health_check consecutive thresholds must be between 1 and 1000000"
                .to_string(),
        });
    }
    if health.expected_statuses.is_empty()
        || health.expected_statuses.len() > 500
        || health
            .expected_statuses
            .iter()
            .any(|status| !(100..=599).contains(status))
        || health
            .expected_statuses
            .iter()
            .collect::<HashSet<_>>()
            .len()
            != health.expected_statuses.len()
    {
        return Err(CompileError::InvalidRoute {
            message: "health_check expected_statuses must be unique HTTP status codes".to_string(),
        });
    }
    if health.port == Some(0)
        || health.max_response_body_bytes == 0
        || health.max_response_body_bytes > 1_048_576
        || health
            .expected_body
            .as_ref()
            .is_some_and(|body| body.is_empty() || body.len() > health.max_response_body_bytes)
        || health.slow_start_ms > 86_400_000
    {
        return Err(CompileError::InvalidRoute {
            message:
                "health_check port, body bound, expected body, or slow_start is outside safe bounds"
                    .to_string(),
        });
    }
    Ok(())
}

/// 🧭 Rejects PROXY protocol listener declarations that cannot be honoured.
///
/// Three ways this can be written wrong, each of which would otherwise leave a
/// listener the operator believes is protected accepting anything:
///
/// - naming an address that is not listened on, usually a typo;
/// - two servers sharing a port and disagreeing about it, since a port is one
///   socket and can only have one answer;
/// - requiring the header with no `trusted_proxies`, which would reject every
///   connection because no peer can ever be authorised to send one.
fn validate_proxy_protocol_listeners(config: &PingclairConfig) -> CompileResult<()> {
    let mut requires: HashSet<&str> = HashSet::new();
    let mut listens: HashSet<&str> = HashSet::new();

    for server in &config.servers {
        for address in &server.listen {
            listens.insert(address.as_str());
        }
        for address in &server.proxy_protocol_listen {
            if !server.listen.iter().any(|listen| listen == address) {
                return Err(CompileError::InvalidServer {
                    message: format!(
                        "proxy_protocol is declared on `{address}`, which this server does not listen on"
                    ),
                });
            }
            requires.insert(address.as_str());
        }
    }

    // 🔌 A port is a single socket. If one server wants the header there and
    // another does not, there is no configuration that satisfies both, and
    // picking either one silently would be a security decision made by
    // accident.
    for server in &config.servers {
        for address in &server.listen {
            let declared = server.proxy_protocol_listen.iter().any(|a| a == address);
            if requires.contains(address.as_str()) && !declared {
                return Err(CompileError::InvalidServer {
                    message: format!(
                        "listener `{address}` is shared by servers that disagree about \
                         proxy_protocol; declare it on every server bound to that address"
                    ),
                });
            }
        }
    }

    if !requires.is_empty() && config.global.trusted_proxies.is_empty() {
        return Err(CompileError::InvalidServer {
            message: "proxy_protocol requires at least one trusted_proxies rule".to_string(),
        });
    }
    Ok(())
}

/// 🔐 Rejects upstream TLS settings whose parts cancel each other out.
///
/// The Pingclairfile adapter refuses the same combinations, but this is the
/// check that protects the JSON path — the Admin API accepts a configuration
/// document directly and never passes through the adapter, so a rule enforced
/// only there is a rule an operator can post straight past.
fn validate_upstream_tls(tls: &pingclair_core::config::UpstreamTlsConfig) -> CompileResult<()> {
    if let Err(message) = tls.client_identity() {
        return Err(CompileError::InvalidRoute {
            message: message.to_string(),
        });
    }
    if tls.insecure_skip_verify && !tls.trusted_ca_certs.is_empty() {
        return Err(CompileError::InvalidRoute {
            message: "upstream_tls cannot set insecure_skip_verify together with \
                      trusted_ca_certs: the configured roots would never be consulted"
                .to_string(),
        });
    }
    if tls.insecure_skip_verify && tls.server_name.is_some() {
        return Err(CompileError::InvalidRoute {
            message: "upstream_tls cannot set insecure_skip_verify together with \
                      server_name: the name would be sent as SNI but never verified"
                .to_string(),
        });
    }
    if tls
        .trusted_ca_certs
        .iter()
        .any(|path| path.trim().is_empty())
    {
        return Err(CompileError::InvalidRoute {
            message: "upstream_tls trusted_ca_certs entries must be non-empty paths".to_string(),
        });
    }
    Ok(())
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

    // Carry the `format filter { fields { x delete } }` exclusions through.
    // These used to be parsed and then dropped here, so the directive was
    // accepted and silently ignored.
    let exclude_fields = log
        .format
        .filter
        .as_ref()
        .map(|filter| filter.exclude.clone())
        .unwrap_or_default();

    Ok(LogConfig {
        output,
        format,
        level: log.level.map(|level| match level {
            crate::parser::ast::LogLevel::Trace => "trace".to_string(),
            crate::parser::ast::LogLevel::Debug => "debug".to_string(),
            crate::parser::ast::LogLevel::Info => "info".to_string(),
            crate::parser::ast::LogLevel::Warn => "warn".to_string(),
            crate::parser::ast::LogLevel::Error => "error".to_string(),
        }),
        exclude_fields,
    })
}

/// 🕳️ Maximum matcher nesting, mirroring the block-nesting cap in `parser.rs`.
///
/// Matchers are a *separate* recursion from blocks and were never given the
/// same bound, so `not not not …` five thousand deep exhausted the stack and,
/// under a release profile that aborts on panic, took the process with it.
/// Nothing legitimate nests matchers more than a handful deep.
const MAX_MATCHER_DEPTH: usize = 32;

fn compile_route_arm(
    arm: &RouteArm,
    matchers: &HashMap<String, Matcher>,
    root: Option<&str>,
) -> CompileResult<Vec<RouteConfig>> {
    // 🧭 A matcher may carry several path patterns (`path /js/* /css/*`).
    // Each pattern becomes its own router entry so every one of them routes;
    // the compiled matcher stays attached so non-path conditions still apply.
    let patterns = arm
        .matcher
        .as_ref()
        .map(|m| path_patterns(m, matchers, 0))
        .unwrap_or_default();

    // Compile matcher conditions
    let matcher = arm
        .matcher
        .as_ref()
        .map(|m| compile_matcher(m, matchers, 0))
        .transpose()?;

    // Compile handler
    let handler = compile_handler(&arm.handler, root)?;

    if patterns.is_empty() {
        return Ok(vec![RouteConfig {
            path: "/*".to_string(),
            handler,
            methods: None,
            matcher,
        }]);
    }
    Ok(patterns
        .into_iter()
        .map(|path| RouteConfig {
            path,
            handler: handler.clone(),
            methods: None,
            matcher: matcher.clone(),
        })
        .collect())
}

/// 🧭 Collects every path pattern reachable from a matcher, following named
/// references and both sides of `and`/`or` combinations.
fn path_patterns(
    matcher: &Matcher,
    matchers: &HashMap<String, Matcher>,
    depth: usize,
) -> Vec<String> {
    if depth > MAX_MATCHER_DEPTH {
        return Vec::new();
    }
    match matcher {
        Matcher::Path(pm) => pm.patterns.clone(),
        Matcher::Named(name) => matchers
            .get(name)
            .map(|m| path_patterns(m, matchers, depth + 1))
            .unwrap_or_default(),
        Matcher::And(left, right) | Matcher::Or(left, right) => {
            let mut patterns = path_patterns(left, matchers, depth + 1);
            patterns.extend(path_patterns(right, matchers, depth + 1));
            patterns
        }
        _ => Vec::new(),
    }
}

fn compile_matcher(
    matcher: &Matcher,
    matchers: &HashMap<String, Matcher>,
    depth: usize,
) -> CompileResult<CoreMatcher> {
    if depth > MAX_MATCHER_DEPTH {
        return Err(CompileError::InvalidRoute {
            message: format!("matcher nesting exceeds the maximum depth of {MAX_MATCHER_DEPTH}"),
        });
    }
    Ok(match matcher {
        Matcher::Named(name) => {
            // 🚨 An unresolved name used to fall through to `path /*`, which
            // matches *everything*. So `handle @admin_onlyy` — one typo — turned
            // a restricted route into an open one, and the configuration
            // validated cleanly. A name that does not resolve is a mistake, and
            // the only safe reading of a mistake in a matcher is to refuse.
            let Some(inner) = matchers.get(name) else {
                return Err(CompileError::InvalidRoute {
                    message: format!(
                        "matcher `{}` is not defined; define it or fix the name \
                         (an unresolved matcher would otherwise match every request)",
                        // The stored name already carries its `@`.
                        name.strip_prefix('@').map_or(name.as_str(), |bare| bare)
                    ),
                });
            };
            compile_matcher(inner, matchers, depth + 1)?
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
                .map(|m| format!("{m:?}").to_uppercase())
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
            Box::new(compile_matcher(left, matchers, depth + 1)?),
            Box::new(compile_matcher(right, matchers, depth + 1)?),
        ),
        Matcher::Or(left, right) => CoreMatcher::Or(
            Box::new(compile_matcher(left, matchers, depth + 1)?),
            Box::new(compile_matcher(right, matchers, depth + 1)?),
        ),
        Matcher::Not(inner) => {
            CoreMatcher::Not(Box::new(compile_matcher(inner, matchers, depth + 1)?))
        }
    })
}

fn compile_handler(handler: &Handler, root: Option<&str>) -> CompileResult<HandlerConfig> {
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
                health_check: proxy.health_check.as_ref().map(|health| {
                    Box::new(pingclair_core::config::HealthCheckConfig {
                        path: health.path.clone(),
                        interval: health.interval_secs,
                        timeout: health.timeout_secs,
                        threshold: health.consecutive_failure,
                        method: health.method.clone(),
                        host: health.host.clone(),
                        headers: health.headers.clone(),
                        expected_statuses: health.expected_statuses.clone(),
                        expected_body: health.expected_body.clone(),
                        port: health.port,
                        consecutive_success: health.consecutive_success,
                        consecutive_failure: Some(health.consecutive_failure),
                        reuse_connection: health.reuse_connection,
                        max_response_body_bytes: health.max_response_body_bytes,
                        slow_start_ms: health.slow_start_ms,
                    })
                }),
                headers_up: HashMap::new(),
                headers_down: HashMap::new(),
                flush_interval: None,
                read_timeout: None,
                write_timeout: None,
                connect_timeout: None,
                first_byte_timeout: None,
                between_reads_timeout: None,
                cache: proxy.cache.as_ref().map(|cache| {
                    Box::new(pingclair_core::config::CacheConfig {
                        ttl_secs: cache.ttl_secs,
                    })
                }),
                retry: Box::new(pingclair_core::config::RetryConfig {
                    max_attempts: proxy.retry.max_attempts,
                    total_timeout_ms: proxy.retry.total_timeout_ms,
                    backoff_ms: proxy.retry.backoff_ms,
                    status_codes: proxy.retry.status_codes.clone(),
                    methods: proxy.retry.methods.clone(),
                }),
                overload: Box::new(pingclair_core::config::OverloadConfig {
                    max_in_flight: proxy.overload.max_in_flight,
                    max_pending: proxy.overload.max_pending,
                    pending_timeout_ms: proxy.overload.pending_timeout_ms,
                    upstream_max_connections: proxy.overload.upstream_max_connections,
                }),
                circuit_breaker: Box::new(pingclair_core::config::CircuitBreakerConfig {
                    consecutive_failures: proxy.circuit_breaker.consecutive_failures,
                    error_rate_percent: proxy.circuit_breaker.error_rate_percent,
                    minimum_requests: proxy.circuit_breaker.minimum_requests,
                    window_requests: proxy.circuit_breaker.window_requests,
                    open_duration_ms: proxy.circuit_breaker.open_duration_ms,
                    half_open_requests: proxy.circuit_breaker.half_open_requests,
                    failure_statuses: proxy.circuit_breaker.failure_statuses.clone(),
                }),
                upstream_tls: Box::new(pingclair_core::config::UpstreamTlsConfig::default()),
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
                config.connect_timeout = transport.connect_timeout.map(|ms| ms as i64);
                config.first_byte_timeout = transport.first_byte_timeout.map(|ms| ms as i64);
                config.between_reads_timeout = transport.between_reads_timeout.map(|ms| ms as i64);
                config.read_timeout = transport.read_timeout.map(|ms| ms as i64);
                config.write_timeout = transport.write_timeout.map(|ms| ms as i64);
                config.upstream_tls = Box::new(pingclair_core::config::UpstreamTlsConfig {
                    enable: transport.tls.enable,
                    server_name: transport.tls.server_name.clone(),
                    trusted_ca_certs: transport.tls.trusted_ca_certs.clone(),
                    client_cert: transport.tls.client_cert.clone(),
                    client_key: transport.tls.client_key.clone(),
                    insecure_skip_verify: transport.tls.insecure_skip_verify,
                });
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
            let compiled: Result<Vec<_>, _> = handlers
                .iter()
                .map(|handler| compile_handler(handler, root))
                .collect();
            Ok(HandlerConfig::Pipeline {
                handlers: compiled?,
            })
        }

        Handler::FileServer(fs) => Ok(HandlerConfig::FileServer {
            root: fs.root.clone(),
            index: fs.index.clone(),
            browse: fs.browse,
            browse_limit: None,
            compress: fs.compress,
        }),

        Handler::Templates => Ok(HandlerConfig::Templates {
            root: root.map(str::to_string),
        }),

        Handler::Handle(sub_handlers) => {
            // Recursively compile each sub-handler in the Handle block
            let mut compiled = Vec::new();
            for h in sub_handlers {
                compiled.push(compile_handler(h, root)?);
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

        Handler::RateLimit(config) => Ok(HandlerConfig::RateLimit {
            requests: config.requests,
            window_secs: config.window_ms / 1_000,
            by_ip: matches!(config.key, RateLimitKey::Ip),
            burst: config.burst,
            key: Some(match &config.key {
                RateLimitKey::Ip => CoreRateLimitKey::Ip,
                RateLimitKey::Global => CoreRateLimitKey::Global,
                RateLimitKey::Route => CoreRateLimitKey::Route,
                RateLimitKey::ApiKey => CoreRateLimitKey::ApiKey,
                RateLimitKey::Header(name) => CoreRateLimitKey::Header(name.clone()),
                RateLimitKey::Tenant(name) => CoreRateLimitKey::Tenant(name.clone()),
            }),
            dry_run: config.dry_run,
        }),

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
                    _ => format!("{e:?}"),
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
    fn active_health_check_reaches_compiled_runtime_config() {
        let ast = crate::parser::compile(
            r#"
            api.example.com {
                reverse_proxy https://origin.internal:8443 {
                    health_check {
                        path /ready
                        interval 2s
                        timeout 1s
                        method GET
                        host health.internal
                        header X-Probe pingclair
                        status 200 204
                        body ready
                        port 9443
                        consecutive_success 2
                        consecutive_failure 4
                        reuse_connection
                        max_response_body_bytes 4096
                        slow_start 15s
                    }
                }
            }
        "#,
        )
        .unwrap();
        let config = compile_ast(&ast).unwrap();
        validate_config(&config).unwrap();
        let HandlerConfig::ReverseProxy(proxy) = &config.servers[0].routes[0].handler else {
            panic!("expected reverse proxy");
        };
        let health = proxy.health_check.as_ref().expect("health check");
        assert_eq!(health.path, "/ready");
        assert_eq!(health.interval, 2);
        assert_eq!(health.method, "GET");
        assert_eq!(health.host.as_deref(), Some("health.internal"));
        assert_eq!(
            health.headers.get("X-Probe").map(String::as_str),
            Some("pingclair")
        );
        assert_eq!(health.expected_statuses, [200, 204]);
        assert_eq!(health.expected_body.as_deref(), Some("ready"));
        assert_eq!(health.port, Some(9443));
        assert_eq!(health.consecutive_success, 2);
        assert_eq!(health.consecutive_failure, Some(4));
        assert!(health.reuse_connection);
        assert_eq!(health.max_response_body_bytes, 4096);
        assert_eq!(health.slow_start_ms, 15_000);
    }

    #[test]
    fn json_health_check_validation_cannot_bypass_the_adapter() {
        let mut config: PingclairConfig = serde_json::from_value(serde_json::json!({
            "servers": [{
                "listen": ["127.0.0.1:8080"],
                "routes": [{
                    "path": "/*",
                    "handler": {
                        "type": "reverse_proxy",
                        "upstreams": ["127.0.0.1:9000"],
                        "health_check": {
                            "path": "/health",
                            "method": "POST"
                        }
                    }
                }]
            }]
        }))
        .unwrap();
        let error = validate_config(&config).unwrap_err().to_string();
        assert!(error.contains("method must be GET, HEAD, or OPTIONS"));

        let HandlerConfig::ReverseProxy(proxy) = &mut config.servers[0].routes[0].handler else {
            panic!("expected reverse proxy");
        };
        proxy.health_check.as_mut().unwrap().method = "GET".to_string();
        proxy.health_check.as_mut().unwrap().max_response_body_bytes = 0;
        let error = validate_config(&config).unwrap_err().to_string();
        assert!(error.contains("outside safe bounds"));
    }

    #[test]
    fn exact_rate_limit_reaches_compiled_runtime_config() {
        let ast = crate::parser::compile(
            r#"
            api.example.com {
                rate_limit 5 60s {
                    burst 2
                    key tenant X-Tenant
                    dry_run
                }
                respond "ok"
            }
        "#,
        )
        .unwrap();
        let config = compile_ast(&ast).unwrap();
        validate_config(&config).unwrap();
        let HandlerConfig::Pipeline { handlers } = &config.servers[0].routes[0].handler else {
            panic!("expected middleware pipeline");
        };
        let HandlerConfig::RateLimit {
            requests,
            window_secs,
            burst,
            key,
            dry_run,
            ..
        } = &handlers[0]
        else {
            panic!("expected rate limiter");
        };
        assert_eq!((*requests, *window_secs, *burst), (5, 60, 2));
        assert_eq!(key, &Some(CoreRateLimitKey::Tenant("X-Tenant".to_string())));
        assert!(*dry_run);
    }

    #[test]
    fn json_rate_limit_validation_cannot_bypass_the_adapter() {
        let config: PingclairConfig = serde_json::from_value(serde_json::json!({
            "servers": [{
                "listen": ["127.0.0.1:8080"],
                "routes": [{
                    "path": "/*",
                    "handler": {
                        "type": "rate_limit",
                        "requests": 5,
                        "window_secs": 60,
                        "by_ip": false,
                        "burst": 2,
                        "key": {"header": "bad header"},
                        "dry_run": false
                    }
                }]
            }]
        }))
        .unwrap();

        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn json_proxy_protocol_validation_cannot_bypass_the_adapter() {
        // 🧭 The Admin API posts this document straight into the core types, so
        // every rule the Pingclairfile adapter enforces has to hold here too.
        let mut config = PingclairConfig::default();
        config.servers.push(ServerConfig {
            listen: vec!["0.0.0.0:443".to_string()],
            proxy_protocol_listen: vec!["0.0.0.0:443".to_string()],
            ..Default::default()
        });

        // Requiring the header with nothing trusted would reject every peer.
        assert!(validate_config(&config).is_err());

        config.global.trusted_proxies = vec!["not-a-network".to_string()];
        assert!(validate_config(&config).is_err());

        config.global.trusted_proxies = vec!["127.0.0.1/32".to_string()];
        assert!(validate_config(&config).is_ok());

        // An address that is not listened on is a typo, not a no-op.
        config.servers[0].proxy_protocol_listen = vec!["0.0.0.0:8443".to_string()];
        assert!(validate_config(&config).is_err());

        // Two servers on one socket cannot disagree about it.
        config.servers[0].proxy_protocol_listen = vec!["0.0.0.0:443".to_string()];
        config.servers.push(ServerConfig {
            listen: vec!["0.0.0.0:443".to_string()],
            ..Default::default()
        });
        assert!(validate_config(&config).is_err());
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

// MARK: - Fail-closed handler validation

/// 🚫 The `plugin` handler is parsed but not wired to anything, so a route
/// using it would accept traffic and silently do nothing. These tests pin the
/// rejection to `validate_config` — the single validation path — rather than
/// to the Caddyfile adapter, because a JSON config reaches the same structs
/// without ever touching the DSL. A guard that only lives in the adapter is
/// not a guard.
#[cfg(test)]
mod fail_closed_handler_tests {
    use super::*;
    use pingclair_core::config::{HandlerConfig, PingclairConfig, RouteConfig, ServerConfig};

    fn plugin() -> HandlerConfig {
        HandlerConfig::Plugin {
            name: "not-a-real-plugin".to_string(),
            args: vec![],
        }
    }

    fn harmless() -> HandlerConfig {
        HandlerConfig::Respond {
            status: 200,
            body: Some("ok".to_string()),
            headers: std::collections::HashMap::new(),
        }
    }

    fn config_with(handler: HandlerConfig) -> PingclairConfig {
        PingclairConfig {
            servers: vec![ServerConfig {
                listen: vec!["0.0.0.0:8080".to_string()],
                routes: vec![RouteConfig {
                    path: "/*".to_string(),
                    handler,
                    methods: None,
                    matcher: None,
                }],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn rejection_for(handler: HandlerConfig) -> String {
        match validate_config(&config_with(handler)) {
            Ok(()) => panic!("an unimplemented handler was accepted"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn a_bare_plugin_route_is_rejected_by_name() {
        let message = rejection_for(plugin());
        assert!(
            message.contains("not-a-real-plugin"),
            "the rejection must name the offending route: {message}"
        );
        assert!(
            message.contains("plugin"),
            "the rejection must name the handler: {message}"
        );
    }

    #[test]
    fn a_plugin_nested_in_any_container_is_still_rejected() {
        // 🪆 Each of these wraps other handlers, so the guard has to recurse.
        // A container that forgets to recurse turns the fail-closed rule into
        // "fails closed only at the top level", which is the same as off for
        // any real configuration.
        let containers: Vec<(&str, HandlerConfig)> = vec![
            (
                "pipeline",
                HandlerConfig::Pipeline {
                    handlers: vec![harmless(), plugin()],
                },
            ),
            (
                "handle",
                HandlerConfig::Handle {
                    handlers: vec![plugin()],
                },
            ),
            (
                "handle_path",
                HandlerConfig::HandlePath {
                    prefix: "/api".to_string(),
                    handlers: vec![harmless(), plugin()],
                },
            ),
            (
                "try_files fallback",
                HandlerConfig::TryFiles {
                    files: vec!["{path}".to_string()],
                    fallback: Some(Box::new(plugin())),
                },
            ),
            (
                "handle_errors",
                HandlerConfig::HandleErrors {
                    errors: [(404u16, vec![plugin()])].into_iter().collect(),
                },
            ),
            (
                "two containers deep",
                HandlerConfig::Handle {
                    handlers: vec![HandlerConfig::Pipeline {
                        handlers: vec![harmless(), plugin()],
                    }],
                },
            ),
            (
                "a try_files fallback inside a pipeline",
                HandlerConfig::Pipeline {
                    handlers: vec![HandlerConfig::TryFiles {
                        files: vec!["{path}".to_string()],
                        fallback: Some(Box::new(plugin())),
                    }],
                },
            ),
        ];

        for (description, handler) in containers {
            let message = rejection_for(handler);
            assert!(
                message.contains("not-a-real-plugin"),
                "a plugin nested in {description} was not reported: {message}"
            );
        }
    }

    #[test]
    fn implemented_handlers_are_left_alone() {
        // 🛡️ Fail-closed is only useful if it does not also reject working
        // configurations; otherwise the pressure is to remove the guard.
        let allowed = vec![
            harmless(),
            HandlerConfig::Pipeline {
                handlers: vec![harmless(), harmless()],
            },
            HandlerConfig::TryFiles {
                files: vec!["{path}".to_string()],
                fallback: None,
            },
            HandlerConfig::TryFiles {
                files: vec!["{path}".to_string()],
                fallback: Some(Box::new(harmless())),
            },
            HandlerConfig::HandleErrors {
                errors: [(404u16, vec![harmless()])].into_iter().collect(),
            },
        ];
        for handler in allowed {
            validate_config(&config_with(handler))
                .expect("an implemented handler must still compile");
        }
    }
}
