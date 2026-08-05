// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::AdapterError;
use super::args::{
    expect_no_arguments, expect_one_argument, parse_positive_u64, parse_positive_usize,
    parse_required_duration,
};
use crate::parser::ast::*;
use crate::parser::caddy_ast::Directive;

// MARK: - reverse_proxy Full Block Parsing

/// Adapt a `reverse_proxy` directive with full sub-block support.
///
/// Handles:
/// - `reverse_proxy host:port` (simple, args-only)
/// - `reverse_proxy { to host:port { weight 3 }; to host:port { backup } }`
/// - `reverse_proxy host:port { header_up K V; flush_interval -1; transport http { ... } }`
pub(super) fn adapt_reverse_proxy(d: Directive) -> Result<Handler, AdapterError> {
    // Collect upstreams from args (filter out matcher @names)
    let mut upstreams = Vec::with_capacity(d.args.len());
    for arg in &d.args {
        if arg.starts_with('@') {
            continue;
        }
        // 🧭 A leading `/` in the argument list is a path matcher token in
        // Caddy (`reverse_proxy /ws 127.0.0.1:9001`), never an upstream
        // address. Site-level adaptation strips it before this function
        // runs; a token that still reaches here (for example inside a
        // `route`/`handle` block) must fail load instead of becoming a
        // hostname that can never dial.
        if arg.starts_with('/') {
            return Err(AdapterError::UnsupportedFeature(
                "reverse_proxy".into(),
                format!(
                    "`{arg}` is an inline path matcher; matcher tokens inside \
                     route/handle blocks are not implemented yet"
                ),
            ));
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
    let upstreams = crate::adapter::expand_upstream_port_ranges(upstreams);
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
                // 🩺 The format spells health checking as flat `health_*`
                // options rather than a block. Both reach the same
                // configuration; refusing the flat form would mean refusing the
                // spelling every real configuration actually uses.
                name if name.starts_with("health_") => {
                    let check = proxy.health_check.get_or_insert_with(Default::default);
                    match name {
                        // 🧭 `health_uri` carries a query string too; we keep
                        // the whole thing, because dropping the query would
                        // probe a different endpoint than the one written.
                        "health_uri" | "health_path" => {
                            check.path = expect_one_argument(&sub)?.to_string();
                        }
                        "health_port" => {
                            check.port =
                                Some(parse_positive_u64(&sub)?.try_into().map_err(|_| {
                                    AdapterError::InvalidArgument(
                                        name.into(),
                                        "a port must be between 1 and 65535".into(),
                                    )
                                })?);
                        }
                        "health_method" => {
                            check.method = expect_one_argument(&sub)?.to_ascii_uppercase();
                        }
                        // 🧭 Whole seconds only, exactly as the block form
                        // requires. Two spellings of one setting must not
                        // accept two different value ranges.
                        "health_interval" => {
                            check.interval_secs = whole_seconds(&sub)?;
                        }
                        "health_timeout" => {
                            check.timeout_secs = whole_seconds(&sub)?;
                        }
                        "health_body" => {
                            check.expected_body = Some(expect_one_argument(&sub)?.to_string());
                        }
                        "health_passes" => {
                            check.consecutive_success = parse_positive_u64(&sub)? as u32;
                        }
                        "health_fails" => {
                            check.consecutive_failure = parse_positive_u64(&sub)? as u32;
                        }
                        "health_status" => {
                            let raw = expect_one_argument(&sub)?;
                            // 🧭 A class such as `2xx` stands for the whole
                            // hundred, which is how the format lets an operator
                            // say "any success" without listing five codes.
                            check.expected_statuses = expand_status_class(raw, name)?;
                        }
                        "health_headers" => {
                            let Some(block) = sub.block.as_ref() else {
                                return Err(AdapterError::InvalidArgument(
                                    name.into(),
                                    "expected a block of header names and values".into(),
                                ));
                            };
                            for header in &block.directives {
                                let value = header.args.first().cloned().unwrap_or_default();
                                check.headers.insert(header.name.clone(), value);
                            }
                        }
                        other => {
                            return Err(AdapterError::UnsupportedFeature(
                                format!("reverse_proxy {other}"),
                                "Pingclair does not implement this health-check option yet".into(),
                            ));
                        }
                    }
                }
                // 🔁 Load balancing retries, flat, for the same reason.
                "lb_retries" => {
                    proxy.retry.max_attempts = parse_positive_usize(&sub)?;
                }
                "lb_try_duration" => {
                    proxy.retry.total_timeout_ms = Some(parse_required_duration(&sub)?);
                }
                "lb_try_interval" => {
                    proxy.retry.backoff_ms = parse_required_duration(&sub)?;
                }
                "lb_policy" => {
                    let policy = sub
                        .args
                        .first()
                        .ok_or_else(|| AdapterError::ArgumentCount("lb_policy".into(), 1, 0))?;
                    match policy.as_str() {
                        "round_robin" | "random" | "least_conn" | "ip_hash" | "first" => {
                            // 🚫 These take no argument. Accepting a stray one
                            // would let `lb_policy ip_hash X-User` read as
                            // "hash on X-User" when it does nothing of the sort.
                            if sub.args.len() > 1 {
                                return Err(AdapterError::ArgumentCount(
                                    format!("lb_policy {policy}"),
                                    1,
                                    sub.args.len(),
                                ));
                            }
                            proxy.lb_policy = Some(policy.clone());
                        }
                        // 🔑 Caddy's hashing policies name the field they hash.
                        // The name is mandatory: `lb_policy cookie` with no
                        // cookie named would hash the same empty string for
                        // every client and quietly pin the whole site to one
                        // backend.
                        "header" | "cookie" | "query" => {
                            let Some(field) = sub.args.get(1) else {
                                return Err(AdapterError::InvalidArgument(
                                    format!("lb_policy {policy}"),
                                    format!(
                                        "`{policy}` needs the name to hash, e.g. `lb_policy {policy} X-Session`"
                                    ),
                                ));
                            };
                            if sub.args.len() > 2 {
                                return Err(AdapterError::ArgumentCount(
                                    format!("lb_policy {policy}"),
                                    2,
                                    sub.args.len(),
                                ));
                            }
                            proxy.lb_policy = Some(policy.clone());
                            proxy.lb_hash_key = Some(field.clone());
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
                        for address in
                            crate::adapter::expand_upstream_port_ranges([address.clone()])
                        {
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
                        for address in
                            crate::adapter::expand_upstream_port_ranges(sub.args.iter().cloned())
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
                // 🚫 A name the format defines but this proxy does not
                // implement says so, instead of reading as a typo. An operator
                // who wrote `request_buffers` spelled it correctly.
                other if is_known_proxy_option(other) => {
                    return Err(AdapterError::UnsupportedFeature(
                        format!("reverse_proxy {other}"),
                        "Pingclair does not implement this reverse_proxy option yet".into(),
                    ));
                }
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
pub(super) fn adapt_health_check(directive: &Directive) -> Result<HealthCheckConfig, AdapterError> {
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
pub(super) fn adapt_cache_policy(directive: &Directive) -> Result<CacheConfig, AdapterError> {
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
    let mut max_size_bytes = None;
    for sub in &block.directives {
        match sub.name.as_str() {
            "ttl" => {
                // ⏳ Durations arrive in milliseconds; caching reasons in seconds.
                let ms = parse_required_duration(sub)?;
                ttl_secs = Some(ms / 1000);
            }
            // 📏 The ceiling on stored bytes, written as a plain integer to
            // match every other byte limit in this grammar (`max_response_body`,
            // the `limits` block). Zero is rejected by `parse_positive_usize`
            // rather than read as "unlimited": an operator who writes
            // `max_size 0` far more likely meant "off", and guessing between
            // the two is the silent-misconfiguration shape this project
            // fails closed on. To disable caching, remove the `cache` block.
            "max_size" => {
                max_size_bytes = Some(parse_positive_usize(sub)?);
            }
            other => {
                return Err(AdapterError::UnknownDirective(other.to_string()));
            }
        }
    }

    let ttl_secs = ttl_secs
        .ok_or_else(|| AdapterError::InvalidArgument("cache".into(), "ttl is required".into()))?;
    Ok(CacheConfig {
        ttl_secs,
        // 📏 The default lives in `pingclair-core` so the DSL and a
        // hand-written JSON document cannot drift to different ceilings.
        max_size_bytes: max_size_bytes
            .unwrap_or_else(pingclair_core::config::default_cache_max_size_bytes),
    })
}

pub(super) fn adapt_retry_policy(directive: &Directive) -> Result<RetryConfig, AdapterError> {
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
pub(super) fn adapt_overload_policy(directive: &Directive) -> Result<OverloadConfig, AdapterError> {
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
pub(super) fn adapt_circuit_breaker_policy(
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

/// 🔐 Rejects upstream TLS blocks whose directives contradict each other.
///
/// Both cases below are configurations where one directive silently cancels
/// another, so the operator's stated intent and the resulting security posture
/// differ. Refusing to load is the only outcome that cannot be misread.
pub(super) fn validate_upstream_tls(tls: &UpstreamTlsConfig) -> Result<(), AdapterError> {
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

/// 🧾 Reverse-proxy options the format defines, whether or not we implement
/// them.
///
/// Separating "we do not have this" from "you misspelled that" is the whole
/// job of this list: the two need different answers from the operator, and a
/// message that confuses them sends people looking for a typo in a word they
/// typed correctly.
fn is_known_proxy_option(name: &str) -> bool {
    matches!(
        name,
        "lb_retry_match"
            | "health_upstream"
            | "health_request_body"
            | "health_follow_redirects"
            | "max_fails"
            | "fail_duration"
            | "unhealthy_request_count"
            | "unhealthy_status"
            | "unhealthy_latency"
            | "request_buffers"
            | "response_buffers"
            | "stream_buffer_size"
            | "stream_timeout"
            | "stream_close_delay"
            | "trusted_proxies"
            | "method"
            | "rewrite"
            | "handle_response"
            | "replace_status"
            | "verbose_logs"
            | "proxy_protocol"
            | "forward_proxy_url"
            | "network_proxy"
    )
}

/// 🔢 Expands a status class such as `2xx` into the codes it stands for.
fn expand_status_class(raw: &str, directive: &str) -> Result<Vec<u16>, AdapterError> {
    if let Ok(code) = raw.parse::<u16>() {
        return Ok(vec![code]);
    }
    if let Some(hundreds) = raw
        .strip_suffix("xx")
        .and_then(|head| head.parse::<u16>().ok())
        && (1..=5).contains(&hundreds)
    {
        let base = hundreds * 100;
        return Ok((base..base + 100).collect());
    }
    Err(AdapterError::InvalidArgument(
        directive.into(),
        format!("`{raw}` is not a status code or a class such as `2xx`"),
    ))
}

/// ⏱️ A duration the health check can express, in whole seconds.
///
/// The configuration carries seconds, so a value like `1500ms` cannot be
/// represented — and rounding it would give an operator a probe interval they
/// did not ask for, quietly.
fn whole_seconds(directive: &Directive) -> Result<u64, AdapterError> {
    let millis = parse_required_duration(directive)?;
    if millis < 1_000 || millis % 1_000 != 0 {
        return Err(AdapterError::InvalidArgument(
            directive.name.clone(),
            "must be a whole number of seconds".into(),
        ));
    }
    Ok(millis / 1_000)
}
