// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::AdapterError;
use super::args::{
    expect_no_arguments, expect_one_argument, parse_duration_ms, parse_positive_u64,
    parse_positive_usize, parse_required_duration,
};
use crate::parser::ast::*;
use crate::parser::caddy_ast::Directive;
use pingclair_core::config::{ResponseHandlerConfig, ResponseMatcher};
use std::collections::HashMap;

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
        // 🏗️ A Unix-socket upstream (`unix//run/php.sock`, `unix+h2c//run/app.sock`)
        // passes through as its dial string; the proxy runtime parses it into a
        // Unix-domain peer, so it must never be turned into a hostname here.
        upstreams.push(arg.clone());
    }

    // 🌐 Caddy expands `to :9000-9003` into one upstream per port; do the
    // same before the AST is compiled so JSON and runtime see the peers.
    let upstreams = crate::adapter::expand_upstream_port_ranges(upstreams);
    let mut proxy = ProxyConfig::new(upstreams);
    // 🧭 Response matchers defined inside the block (`@500 status 500`) are
    // a separate namespace from request matchers: they match the upstream
    // response, and `handle_response`/`replace_status` reference them.
    let mut response_matchers: HashMap<String, ResponseMatcher> = HashMap::new();

    // Parse sub-block if present
    if let Some(block) = d.block {
        for sub in block.directives {
            match sub.name.as_str() {
                name if name.starts_with('@') => {
                    response_matchers.insert(name.to_string(), parse_response_matcher(&sub)?);
                }
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
                    // 🧭 DNS-driven upstreams replace the fixed peer list:
                    // `a` resolves one name's address records, `srv` resolves
                    // RFC 2782 records whose targets carry the ports.
                    proxy.dynamic = Some(parse_dynamic_upstream(&sub)?);
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
                    // transport fastcgi { split .php; env FOO bar }
                    match sub.args.first().map(String::as_str).unwrap_or("http") {
                        "http" => {
                            if let Some(transport_block) = &sub.block {
                                let mut transport = TransportConfig {
                                    connect_timeout: None,
                                    first_byte_timeout: None,
                                    between_reads_timeout: None,
                                    read_timeout: None,
                                    write_timeout: None,
                                    tls: UpstreamTlsConfig::default(),
                                };
                                for t_sub in &transport_block.directives {
                                    match t_sub.name.as_str() {
                                        "connect_timeout" => {
                                            transport.connect_timeout =
                                                Some(parse_required_duration(t_sub)?);
                                        }
                                        "first_byte_timeout" => {
                                            transport.first_byte_timeout =
                                                Some(parse_required_duration(t_sub)?);
                                        }
                                        "between_reads_timeout" => {
                                            transport.between_reads_timeout =
                                                Some(parse_required_duration(t_sub)?);
                                        }
                                        "read_timeout" => {
                                            transport.read_timeout =
                                                Some(parse_required_duration(t_sub)?);
                                        }
                                        "write_timeout" => {
                                            transport.write_timeout =
                                                Some(parse_required_duration(t_sub)?);
                                        }
                                        "tls" => {
                                            expect_no_arguments(t_sub)?;
                                            transport.tls.enable = true;
                                        }
                                        "tls_server_name" => {
                                            transport.tls.server_name =
                                                Some(expect_one_argument(t_sub)?.to_string());
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
                                            // 🎫 Both halves are required together: a
                                            // certificate without its key silently
                                            // becomes an anonymous handshake that the
                                            // upstream rejects much later.
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
                                            expect_no_arguments(t_sub)?;
                                            transport.tls.insecure_skip_verify = true;
                                        }
                                        // 🔌 Caddy's transport spells the connect and
                                        // response-header timeouts under different
                                        // names; both map onto the same runtime knobs.
                                        "dial_timeout" => {
                                            transport.connect_timeout =
                                                Some(parse_required_duration(t_sub)?);
                                        }
                                        "response_header_timeout" => {
                                            transport.first_byte_timeout =
                                                Some(parse_required_duration(t_sub)?);
                                        }
                                        // 🧭 Tuning knobs without a runtime equivalent
                                        // are kept verbatim in the compiled config and
                                        // logged at startup; accepting them silently
                                        // would tell an operator a knob took effect.
                                        other @ ("read_buffer"
                                        | "write_buffer"
                                        | "max_response_header"
                                        | "dial_fallback_delay"
                                        | "expect_continue_timeout"
                                        | "resolvers"
                                        | "versions"
                                        | "compression"
                                        | "max_conns_per_host"
                                        | "keepalive_idle_conns_per_host"
                                        | "keepalive_interval"
                                        | "tls_renegotiation"
                                        | "tls_except_ports") => {
                                            proxy
                                                .transport_options
                                                .insert(other.to_string(), t_sub.args.join(" "));
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
                        "fastcgi" => {
                            let mut fastcgi = pingclair_core::config::FastCgiTransportConfig {
                                root: None,
                                split_path: Vec::new(),
                                env: std::collections::BTreeMap::new(),
                                resolve_root_symlink: false,
                                dial_timeout_ms: None,
                                read_timeout_ms: None,
                                write_timeout_ms: None,
                                capture_stderr: false,
                            };
                            if let Some(transport_block) = &sub.block {
                                for t_sub in &transport_block.directives {
                                    match t_sub.name.as_str() {
                                        "root" => {
                                            fastcgi.root =
                                                Some(expect_one_argument(t_sub)?.to_string());
                                        }
                                        "split" => {
                                            if t_sub.args.is_empty() {
                                                return Err(AdapterError::ArgumentCount(
                                                    "transport fastcgi split".into(),
                                                    1,
                                                    0,
                                                ));
                                            }
                                            fastcgi.split_path = t_sub.args.clone();
                                        }
                                        "env" => match t_sub.args.as_slice() {
                                            [key, value] => {
                                                fastcgi.env.insert(key.clone(), value.clone());
                                            }
                                            _ => {
                                                return Err(AdapterError::ArgumentCount(
                                                    "transport fastcgi env".into(),
                                                    2,
                                                    t_sub.args.len(),
                                                ));
                                            }
                                        },
                                        "resolve_root_symlink" => {
                                            expect_no_arguments(t_sub)?;
                                            fastcgi.resolve_root_symlink = true;
                                        }
                                        "dial_timeout" => {
                                            fastcgi.dial_timeout_ms =
                                                Some(parse_required_duration(t_sub)?);
                                        }
                                        "read_timeout" => {
                                            fastcgi.read_timeout_ms =
                                                Some(parse_required_duration(t_sub)?);
                                        }
                                        "write_timeout" => {
                                            fastcgi.write_timeout_ms =
                                                Some(parse_required_duration(t_sub)?);
                                        }
                                        "capture_stderr" => {
                                            expect_no_arguments(t_sub)?;
                                            fastcgi.capture_stderr = true;
                                        }
                                        other => {
                                            return Err(AdapterError::UnknownDirective(format!(
                                                "transport fastcgi: {other}"
                                            )));
                                        }
                                    }
                                }
                            }
                            validate_fastcgi_split_path(&fastcgi.split_path)?;
                            proxy.fastcgi = Some(fastcgi);
                        }
                        other => {
                            return Err(AdapterError::UnsupportedFeature(
                                "reverse_proxy transport".into(),
                                format!("`{other}` is not a supported transport"),
                            ));
                        }
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
                "lb_retry_match" => {
                    apply_retry_match(&mut proxy.retry, &sub)?;
                }
                "replace_status" => {
                    proxy
                        .handle_response
                        .push(parse_replace_status(&sub, &response_matchers)?);
                }
                "handle_response" => {
                    proxy
                        .handle_response
                        .push(parse_handle_response(&sub, &response_matchers)?);
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
                        // ⚖️ Caddy's weighted form carries one weight per
                        // upstream on the same line; the weights land on the
                        // existing per-upstream options, so runtime selection
                        // honors them through the native weighted backend.
                        "weighted_round_robin" => {
                            let weights = sub
                                .args
                                .iter()
                                .skip(1)
                                .map(|value| {
                                    value.parse::<u32>().map_err(|_| {
                                        AdapterError::InvalidArgument(
                                            "lb_policy weighted_round_robin".into(),
                                            format!("`{value}` is not a weight"),
                                        )
                                    })
                                })
                                .collect::<Result<Vec<_>, _>>()?;
                            if weights.is_empty() {
                                return Err(AdapterError::ArgumentCount(
                                    "lb_policy weighted_round_robin".into(),
                                    2,
                                    sub.args.len(),
                                ));
                            }
                            if weights.len() != proxy.upstream_options.len() {
                                return Err(AdapterError::InvalidArgument(
                                    "lb_policy weighted_round_robin".into(),
                                    format!(
                                        "{} weights were given for {} upstreams",
                                        weights.len(),
                                        proxy.upstream_options.len()
                                    ),
                                ));
                            }
                            for (option, weight) in proxy.upstream_options.iter_mut().zip(weights) {
                                option.weight = weight;
                            }
                            proxy.lb_policy = Some("round_robin".to_string());
                        }
                        _ => {
                            return Err(AdapterError::InvalidArgument(
                                "lb_policy".into(),
                                policy.clone(),
                            ));
                        }
                    }
                }
                // 🧭 `method` and `rewrite` rewrite the upstream request,
                // exactly as Caddy's reverse_proxy does.
                "method" => {
                    proxy.rewrite_method = Some(expect_one_argument(&sub)?.to_ascii_uppercase());
                }
                "rewrite" => {
                    proxy.rewrite_uri = Some(expect_one_argument(&sub)?.to_string());
                }
                // 🧱 Buffer ceilings are accepted for Caddyfile compatibility
                // and kept visible in the compiled config; Pingclair streams
                // bodies and never buffers them whole.
                "request_buffers" => {
                    proxy.request_buffer_bytes = Some(parse_buffer_size(&sub)?);
                }
                "response_buffers" => {
                    proxy.response_buffer_bytes = Some(parse_buffer_size(&sub)?);
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

    if proxy.upstreams.is_empty() && proxy.dynamic.is_none() {
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
            | "stream_buffer_size"
            | "stream_timeout"
            | "stream_close_delay"
            | "trusted_proxies"
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

// MARK: - Dynamic Upstreams

/// 🧭 Parses one `dynamic` subdirective into the DNS source it names.
///
/// The first argument selects the record family (`a` or `srv`); the optional
/// block carries the source's knobs. A positional name and port are accepted
/// for the compact spelling (`dynamic a foo 9000`), mirroring Caddy.
fn parse_dynamic_upstream(
    d: &Directive,
) -> Result<pingclair_core::config::DynamicUpstreamConfig, AdapterError> {
    let source = d
        .args
        .first()
        .ok_or_else(|| AdapterError::ArgumentCount("dynamic".into(), 1, d.args.len()))?;
    match source.as_str() {
        "a" => Ok(pingclair_core::config::DynamicUpstreamConfig::A(
            parse_dynamic_addr(d)?,
        )),
        "srv" => Ok(pingclair_core::config::DynamicUpstreamConfig::Srv(
            parse_dynamic_srv(d)?,
        )),
        other => Err(AdapterError::InvalidArgument(
            "dynamic source".into(),
            format!(
                "`{other}` is not a DNS source; use `a` for address records or \
                 `srv` for service records"
            ),
        )),
    }
}

/// 📜 Reads the A-record source, accepting both the compact and block forms.
fn parse_dynamic_addr(
    d: &Directive,
) -> Result<pingclair_core::config::DynamicAddrUpstream, AdapterError> {
    let mut name = d.args.get(1).cloned();
    let mut port = d
        .args
        .get(2)
        .map(|value| parse_port("dynamic port", value))
        .transpose()?;
    let mut refresh_secs = None;
    let mut resolvers = Vec::new();
    let mut dial_timeout_ms = None;
    let mut versions = None;

    if let Some(block) = &d.block {
        for sub in &block.directives {
            match sub.name.as_str() {
                "name" => {
                    name = Some(expect_one_argument(sub)?.to_string());
                }
                "port" => {
                    port = Some(parse_port("port", expect_one_argument(sub)?)?);
                }
                "refresh" => {
                    refresh_secs = Some(whole_seconds(sub)?);
                }
                "resolvers" => {
                    resolvers = parse_resolvers(&sub.args)?;
                }
                "dial_timeout" => {
                    dial_timeout_ms = Some(parse_required_duration(sub)?);
                }
                "dial_fallback_delay" => {
                    let _ = parse_signed_duration(sub)?;
                    return Err(AdapterError::UnsupportedFeature(
                        "dynamic a dial_fallback_delay".into(),
                        "Hickory has no exact RFC 6555 resolver-dial fallback hook".into(),
                    ));
                }
                "versions" => {
                    let value = expect_one_argument(sub)?;
                    if !matches!(value, "ipv4" | "ipv6" | "ip4" | "ip6" | "ip") {
                        return Err(AdapterError::InvalidArgument(
                            "versions".into(),
                            format!("`{value}` is not `ipv4` or `ipv6`"),
                        ));
                    }
                    versions = Some(value.to_string());
                }
                other => {
                    return Err(AdapterError::UnsupportedFeature(
                        "dynamic a".into(),
                        format!("`{other}` is not a dynamic A-source option"),
                    ));
                }
            }
        }
    }

    let name = name.ok_or_else(|| {
        AdapterError::InvalidArgument("dynamic a".into(), "a dynamic A source needs a name".into())
    })?;
    Ok(pingclair_core::config::DynamicAddrUpstream {
        name,
        port: port.unwrap_or(80),
        refresh_secs,
        resolvers,
        dial_timeout_ms,
        fallback_delay_ms: None,
        versions,
    })
}

/// 🧾 Reads the SRV source, accepting both the compact and block forms.
fn parse_dynamic_srv(
    d: &Directive,
) -> Result<pingclair_core::config::DynamicSrvUpstream, AdapterError> {
    let mut name = d.args.get(1).cloned();
    let mut service = None;
    let mut proto = None;
    let mut refresh_secs = None;
    let mut resolvers = Vec::new();
    let mut dial_timeout_ms = None;
    let mut grace_period_ms = None;

    if let Some(block) = &d.block {
        for sub in &block.directives {
            match sub.name.as_str() {
                "name" => {
                    name = Some(expect_one_argument(sub)?.to_string());
                }
                "service" => {
                    service = Some(expect_one_argument(sub)?.to_string());
                }
                "proto" => {
                    proto = Some(expect_one_argument(sub)?.to_string());
                }
                "refresh" => {
                    refresh_secs = Some(whole_seconds(sub)?);
                }
                "resolvers" => {
                    resolvers = parse_resolvers(&sub.args)?;
                }
                "dial_timeout" => {
                    dial_timeout_ms = Some(parse_required_duration(sub)?);
                }
                "dial_fallback_delay" => {
                    let _ = parse_signed_duration(sub)?;
                    return Err(AdapterError::UnsupportedFeature(
                        "dynamic srv dial_fallback_delay".into(),
                        "Hickory has no exact RFC 6555 resolver-dial fallback hook".into(),
                    ));
                }
                "grace_period" => {
                    grace_period_ms = Some(parse_required_duration(sub)?);
                }
                other => {
                    return Err(AdapterError::UnsupportedFeature(
                        "dynamic srv".into(),
                        format!("`{other}` is not a dynamic SRV-source option"),
                    ));
                }
            }
        }
    }

    let name = name.ok_or_else(|| {
        AdapterError::InvalidArgument(
            "dynamic srv".into(),
            "a dynamic SRV source needs a name".into(),
        )
    })?;
    if service.is_some() != proto.is_some() {
        return Err(AdapterError::InvalidArgument(
            "dynamic srv".into(),
            "`service` and `proto` must be set together; otherwise give the \
             full SRV name in `name`"
                .into(),
        ));
    }
    Ok(pingclair_core::config::DynamicSrvUpstream {
        name,
        service,
        proto,
        refresh_secs,
        resolvers,
        dial_timeout_ms,
        fallback_delay_ms: None,
        grace_period_ms,
    })
}

/// 🔌 Parses a dial port out of one argument.
fn parse_port(label: &str, value: &str) -> Result<u16, AdapterError> {
    value.parse::<u16>().map_err(|_| {
        AdapterError::InvalidArgument(label.into(), format!("`{value}` is not a port"))
    })
}

/// 📡 Validates explicit resolver addresses, which must be IP literals.
fn parse_resolvers(args: &[String]) -> Result<Vec<String>, AdapterError> {
    if args.is_empty() {
        return Err(AdapterError::InvalidArgument(
            "resolvers".into(),
            "at least one resolver address is required".into(),
        ));
    }
    for arg in args {
        if arg.parse::<std::net::IpAddr>().is_err() {
            return Err(AdapterError::InvalidArgument(
                "resolvers".into(),
                format!("`{arg}` is not an IP address"),
            ));
        }
    }
    Ok(args.to_vec())
}

/// ⏱️ Parses a duration that may be negative (Caddy's `-1s` disables the
/// RFC 6555 fast-fallback delay).
fn parse_signed_duration(directive: &Directive) -> Result<i64, AdapterError> {
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
    if let Some(rest) = value.strip_prefix('-') {
        return parse_duration_ms(rest)
            .map(|millis| -(millis as i64))
            .ok_or_else(|| AdapterError::InvalidArgument(directive.name.clone(), value.clone()));
    }
    parse_duration_ms(value)
        .map(|millis| millis as i64)
        .ok_or_else(|| AdapterError::InvalidArgument(directive.name.clone(), value.clone()))
}

// MARK: - Retry Match

/// 🔁 Folds one `lb_retry_match` into the route's retry policy.
///
/// Caddy spells the same setting three ways: a bare expression
/// (`lb_retry_match \`{rp.status_code} == 504\``), a named form
/// (`lb_retry_match expression \`...\`` / `path /foo*`), and a block mixing
/// `method`, `path`, `header`, and `expression`. Method and path forms map
/// onto runtime fields; status and method expressions are folded into the
/// status/method lists; anything the runtime cannot evaluate (response
/// headers, transport errors, request functions) is kept verbatim in
/// `expressions` and logged at startup.
fn apply_retry_match(retry: &mut RetryConfig, directive: &Directive) -> Result<(), AdapterError> {
    let mut apply = |kind: &str, args: &[String]| -> Result<(), AdapterError> {
        match kind {
            "path" => {
                let pattern = args.first().ok_or_else(|| {
                    AdapterError::ArgumentCount("lb_retry_match path".into(), 1, args.len())
                })?;
                retry.path_patterns.push(pattern.clone());
            }
            "method" => {
                if args.is_empty() {
                    return Err(AdapterError::ArgumentCount(
                        "lb_retry_match method".into(),
                        1,
                        args.len(),
                    ));
                }
                retry.methods = args
                    .iter()
                    .map(|method| method.to_ascii_uppercase())
                    .collect();
            }
            "header" => {
                if args.len() != 2 {
                    return Err(AdapterError::ArgumentCount(
                        "lb_retry_match header".into(),
                        2,
                        args.len(),
                    ));
                }
                retry
                    .expressions
                    .push(format!("header({{'{}': '{}'}})", args[0], args[1]));
            }
            "expression" => {
                let expression = args.first().ok_or_else(|| {
                    AdapterError::ArgumentCount("lb_retry_match expression".into(), 1, args.len())
                })?;
                fold_retry_expression(retry, expression);
            }
            other => {
                return Err(AdapterError::InvalidArgument(
                    "lb_retry_match".into(),
                    format!("`{other}` is not a retry-match form"),
                ));
            }
        }
        Ok(())
    };

    if let Some(block) = &directive.block {
        for sub in &block.directives {
            apply(&sub.name, &sub.args)?;
        }
        return Ok(());
    }

    // 🧭 One-line spellings: `lb_retry_match <form> <arg>` or a bare CEL
    // expression when the first argument is not a known form name.
    if directive.args.len() >= 2
        && matches!(
            directive.args[0].as_str(),
            "path" | "method" | "header" | "expression"
        )
    {
        apply(&directive.args[0], &directive.args[1..])?;
    } else if let Some(expression) = directive.args.first() {
        fold_retry_expression(retry, expression);
    }
    Ok(())
}

/// 🧾 Folds one CEL retry expression into the mappable fields, keeping the
/// raw text when the runtime cannot evaluate it.
fn fold_retry_expression(retry: &mut RetryConfig, raw: &str) {
    let expression = raw.trim().trim_matches('`');
    let mut mapped = false;

    if let Some((_, rest)) = expression.split_once("method('")
        && let Some(method) = rest.split('\'').next()
    {
        retry.methods = vec![method.to_ascii_uppercase()];
        mapped = true;
    }

    if let Some((_, rest)) = expression.split_once("{rp.status_code} in [") {
        if let Some(codes) = rest.strip_suffix(']') {
            retry.status_codes.extend(
                codes
                    .split(',')
                    .filter_map(|code| code.trim().parse::<u16>().ok()),
            );
            mapped = true;
        }
    } else if let Some((_, rest)) = expression.split_once("{rp.status_code} == ") {
        if let Some(code) = rest
            .split_whitespace()
            .next()
            .and_then(|code| code.parse::<u16>().ok())
        {
            retry.status_codes.push(code);
            mapped = true;
        }
    } else if let Some((_, rest)) = expression.split_once("{rp.status_code} >= ")
        && let Some(bound) = rest
            .split_whitespace()
            .next()
            .and_then(|code| code.parse::<u16>().ok())
    {
        retry.status_codes.extend(bound..=599);
        mapped = true;
    }

    // 🧭 A pure status/method expression is fully represented by the folds
    // above. Anything mentioning response headers, transport errors, or the
    // request functions stays verbatim so startup can say it is not evaluated.
    let unmappable = [
        "{rp.header.",
        "{rp.is_transport_error",
        "header(",
        "query(",
        "protocol(",
        "path(",
        "host(",
    ]
    .iter()
    .any(|needle| expression.contains(needle));
    if !mapped || unmappable {
        retry.expressions.push(expression.to_string());
    }
    // 🧭 Several expressions may fold the same status ranges (`>= 500` and
    // `in [502, 503]` overlap); the compiled list stays unique so validation
    // and runtime selection agree on one set.
    retry.status_codes.sort_unstable();
    retry.status_codes.dedup();
}

/// 🧱 Parses a Caddy buffer size (`4KB`, `10MB`, `unlimited`) into bytes,
/// with `-1` standing for unlimited.
fn parse_buffer_size(directive: &Directive) -> Result<i64, AdapterError> {
    let value = expect_one_argument(directive)?;
    if value == "unlimited" {
        return Ok(-1);
    }
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let number: i64 = value[..split]
        .parse()
        .map_err(|_| AdapterError::InvalidArgument(directive.name.clone(), value.to_string()))?;
    let multiplier = match value[split..].to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1_024,
        "m" | "mb" => 1_024 * 1_024,
        "g" | "gb" => 1_024 * 1_024 * 1_024,
        unit => {
            return Err(AdapterError::InvalidArgument(
                directive.name.clone(),
                format!("`{unit}` is not a byte unit (b/kb/mb/gb)"),
            ));
        }
    };
    Ok(number * multiplier)
}

// MARK: - Response Handling

/// 🧭 Collects the ordered response-handler entries of a block that defines
/// response matchers plus `replace_status`/`handle_response`, moving
/// matcherless entries last exactly like Caddy. Shared by `reverse_proxy`
/// and the standalone `intercept` handler.
pub(super) fn collect_response_handlers(
    block: &crate::parser::caddy_ast::Block,
) -> Result<Vec<ResponseHandlerConfig>, AdapterError> {
    let mut matchers: HashMap<String, ResponseMatcher> = HashMap::new();
    let mut ordered = Vec::new();
    let mut matcherless = Vec::new();
    for sub in &block.directives {
        if sub.name.starts_with('@') {
            matchers.insert(sub.name.clone(), parse_response_matcher(sub)?);
            continue;
        }
        match sub.name.as_str() {
            "replace_status" => ordered.push(parse_replace_status(sub, &matchers)?),
            "handle_response" => {
                let entry = parse_handle_response(sub, &matchers)?;
                if entry.matcher.is_some() {
                    ordered.push(entry);
                } else {
                    matcherless.push(entry);
                }
            }
            other => {
                return Err(AdapterError::UnknownDirective(format!(
                    "response interception: {other}"
                )));
            }
        }
    }
    ordered.extend(matcherless);
    Ok(ordered)
}

/// 🧭 Adapts the standalone `intercept` handler: a block of response
/// matchers and response handlers that wraps the response of later handlers.
pub(super) fn adapt_intercept(d: Directive) -> Result<Handler, AdapterError> {
    let block = d.block.as_ref().ok_or_else(|| {
        AdapterError::InvalidArgument("intercept".into(), "block required".into())
    })?;
    if !d.args.is_empty() {
        return Err(AdapterError::ArgumentCount(
            "intercept".into(),
            0,
            d.args.len(),
        ));
    }
    Ok(Handler::Intercept(collect_response_handlers(block)?))
}

/// 🧭 Parses one named response matcher (`@name status 500` or a block of
/// `status`/`header` lines).
fn parse_response_matcher(d: &Directive) -> Result<ResponseMatcher, AdapterError> {
    let mut matcher = ResponseMatcher::default();
    let mut status = |args: &[String]| -> Result<(), AdapterError> {
        if args.is_empty() {
            return Err(AdapterError::ArgumentCount("status".into(), 1, 0));
        }
        for value in args {
            if let Some(class) = value.strip_suffix("xx") {
                let class: u16 = class
                    .parse()
                    .map_err(|_| AdapterError::InvalidArgument("status".into(), value.clone()))?;
                if !(1..=5).contains(&class) {
                    return Err(AdapterError::InvalidArgument(
                        "status".into(),
                        value.clone(),
                    ));
                }
                matcher.status_codes.push(class);
            } else {
                let code: u16 = value
                    .parse()
                    .map_err(|_| AdapterError::InvalidArgument("status".into(), value.clone()))?;
                if !(100..=599).contains(&code) {
                    return Err(AdapterError::InvalidArgument(
                        "status".into(),
                        value.clone(),
                    ));
                }
                matcher.status_codes.push(code);
            }
        }
        Ok(())
    };
    let mut header = |args: &[String]| -> Result<(), AdapterError> {
        let (name, patterns) = args
            .split_first()
            .ok_or_else(|| AdapterError::ArgumentCount("header".into(), 1, args.len()))?;
        if name.is_empty() || name.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(AdapterError::InvalidArgument(
                "header".into(),
                format!("`{name}` is not a header name"),
            ));
        }
        matcher
            .headers
            .entry(name.clone())
            .or_default()
            .extend(patterns.iter().cloned());
        Ok(())
    };

    if let Some(block) = &d.block {
        for sub in &block.directives {
            match sub.name.as_str() {
                "status" => status(&sub.args)?,
                "header" => header(&sub.args)?,
                other => {
                    return Err(AdapterError::UnknownDirective(format!(
                        "response matcher: {other}"
                    )));
                }
            }
        }
    } else {
        match d.args.as_slice() {
            [kind, rest @ ..] => match kind.as_str() {
                "status" => status(rest)?,
                "header" => header(rest)?,
                other => {
                    return Err(AdapterError::InvalidArgument(
                        d.name.clone(),
                        format!("`{other}` is not `status` or `header`"),
                    ));
                }
            },
            _ => {
                return Err(AdapterError::InvalidArgument(
                    d.name.clone(),
                    "a response matcher needs `status` or `header`".into(),
                ));
            }
        }
    }
    Ok(matcher)
}

/// 🔢 Parses `replace_status [@matcher] <status>` into a status-only entry.
fn parse_replace_status(
    d: &Directive,
    matchers: &HashMap<String, ResponseMatcher>,
) -> Result<ResponseHandlerConfig, AdapterError> {
    let (matcher, status) = match d.args.as_slice() {
        [name, status] if name.starts_with('@') => (matchers.get(name).cloned(), status.clone()),
        [status] => (None, status.clone()),
        _ => {
            return Err(AdapterError::ArgumentCount(
                "replace_status".into(),
                1,
                d.args.len(),
            ));
        }
    };
    Ok(ResponseHandlerConfig {
        matcher,
        status_code: Some(status),
        handlers: Vec::new(),
    })
}

/// 🧭 Parses one `handle_response [@matcher] { … }` entry.
fn parse_handle_response(
    d: &Directive,
    matchers: &HashMap<String, ResponseMatcher>,
) -> Result<ResponseHandlerConfig, AdapterError> {
    let matcher = match d.args.as_slice() {
        [] => None,
        [name] if name.starts_with('@') => Some(matchers.get(name).cloned().ok_or_else(|| {
            AdapterError::InvalidArgument(
                "handle_response".into(),
                format!("unknown response matcher `{name}`"),
            )
        })?),
        _ => {
            return Err(AdapterError::ArgumentCount(
                "handle_response".into(),
                1,
                d.args.len(),
            ));
        }
    };
    let block = d.block.as_ref().ok_or_else(|| {
        AdapterError::InvalidArgument("handle_response".into(), "block required".into())
    })?;
    if block.directives.is_empty() {
        return Err(AdapterError::InvalidArgument(
            "handle_response".into(),
            "at least one response handler is required".into(),
        ));
    }
    let handlers = block
        .directives
        .iter()
        .map(adapt_response_handler)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ResponseHandlerConfig {
        matcher,
        status_code: None,
        handlers,
    })
}

/// 🛡️ Refuses non-ASCII split delimiters.
///
/// Matching is byte-wise ASCII case-insensitive, exactly like the upstream
/// transport; a Unicode delimiter would silently never match, so it is
/// refused rather than stored.
pub(super) fn validate_fastcgi_split_path(split_path: &[String]) -> Result<(), AdapterError> {
    if let Some(non_ascii) = split_path.iter().find(|split| !split.is_ascii()) {
        return Err(AdapterError::InvalidArgument(
            "transport fastcgi split".into(),
            format!("split path `{non_ascii}` contains non-ASCII characters"),
        ));
    }
    Ok(())
}

/// 🧭 Adapts one directive that may appear inside a `handle_response` block
/// into the shared handler configuration.
fn adapt_response_handler(
    d: &Directive,
) -> Result<pingclair_core::config::HandlerConfig, AdapterError> {
    match d.name.as_str() {
        "respond" => {
            let handler = super::directives::adapt_respond(d.clone())?;
            let Handler::Respond(config) = handler else {
                unreachable!("the respond adapter returns a Respond handler")
            };
            let body = match config.body {
                Some(Expr::String(value)) => Some(value),
                Some(other) => {
                    return Err(AdapterError::InvalidArgument(
                        "respond".into(),
                        format!("unsupported response body expression {other:?}"),
                    ));
                }
                None => None,
            };
            Ok(pingclair_core::config::HandlerConfig::Respond {
                status: config.status,
                body,
                headers: config.headers,
            })
        }
        "copy_response" => {
            let status_code = d
                .args
                .first()
                .map(|value| {
                    value.parse::<u16>().map_err(|_| {
                        AdapterError::InvalidArgument("copy_response".into(), value.clone())
                    })
                })
                .transpose()?;
            Ok(pingclair_core::config::HandlerConfig::CopyResponse { status_code })
        }
        "copy_response_headers" => {
            let mut include = Vec::new();
            let mut exclude = Vec::new();
            if let Some(block) = &d.block {
                for sub in &block.directives {
                    match sub.name.as_str() {
                        "include" => include.extend(sub.args.iter().cloned()),
                        "exclude" => exclude.extend(sub.args.iter().cloned()),
                        other => {
                            return Err(AdapterError::UnknownDirective(format!(
                                "copy_response_headers: {other}"
                            )));
                        }
                    }
                }
            } else {
                include.extend(d.args.iter().cloned());
            }
            Ok(pingclair_core::config::HandlerConfig::CopyResponseHeaders { include, exclude })
        }
        "header" => {
            let handler = super::directives::adapt_header_directive(d)?;
            let Handler::Headers(config) = handler else {
                unreachable!("the header adapter returns a Headers handler")
            };
            Ok(pingclair_core::config::HandlerConfig::Headers {
                set: config.set,
                add: config.add,
                remove: config.remove,
            })
        }
        "error" => {
            let handler = super::directives::adapt_error_directive(d)?;
            let Handler::Error(config) = handler else {
                unreachable!("the error adapter returns an Error handler")
            };
            Ok(pingclair_core::config::HandlerConfig::Error {
                status: config.status,
                message: config.message,
            })
        }
        "vars" => {
            let handler = super::directives::adapt_vars_directive(d)?;
            let Handler::Vars(config) = handler else {
                unreachable!("the vars adapter returns a Vars handler")
            };
            Ok(pingclair_core::config::HandlerConfig::Vars {
                values: config.values,
            })
        }
        // 📂 `root * /errors` inside a response subroute sets the document
        // root the file server that follows serves from.
        "root" => {
            let args = if d.args.first().is_some_and(|arg| arg == "*") {
                &d.args[1..]
            } else {
                &d.args[..]
            };
            let [root] = args else {
                return Err(AdapterError::ArgumentCount("root".into(), 1, args.len()));
            };
            let mut values = std::collections::BTreeMap::new();
            values.insert("root".to_string(), root.clone());
            Ok(pingclair_core::config::HandlerConfig::Vars { values })
        }
        // 🧭 `rewrite * /{http.reverse_proxy.status_code}.html` retargets the
        // request inside the response subroute before `file_server` runs.
        "rewrite" => {
            let handler = super::directives::adapt_rewrite(d.clone())?;
            let Handler::Rewrite(config) = handler else {
                unreachable!("the rewrite adapter returns a Rewrite handler")
            };
            if config.regex.is_some() || config.regex_replace.is_some() {
                return Err(AdapterError::UnsupportedFeature(
                    "handle_response rewrite".into(),
                    "only a plain `<replacement>` rewrite is supported in response subroutes yet"
                        .into(),
                ));
            }
            Ok(pingclair_core::config::HandlerConfig::Rewrite {
                strip_prefix: None,
                strip_suffix: None,
                replace: config.replace,
                regex: config.regex,
                regex_replace: config.regex_replace,
            })
        }
        // 📂 `file_server` in a response subroute serves the rewritten path
        // from the root declared by the `root` handler that preceded it.
        "file_server" => {
            if d.block.is_some() || !d.args.is_empty() {
                return Err(AdapterError::UnsupportedFeature(
                    "handle_response file_server".into(),
                    "only a bare `file_server` is supported in response subroutes yet".into(),
                ));
            }
            Ok(pingclair_core::config::HandlerConfig::FileServer {
                root: ".".to_string(),
                index: vec!["index.html".to_string()],
                browse: false,
                browse_limit: None,
                compress: true,
                precompressed: Vec::new(),
                hide: Vec::new(),
                status: None,
                pass_thru: false,
                canonical_uris: true,
                etag_file_extensions: Vec::new(),
            })
        }
        other => Err(AdapterError::UnsupportedFeature(
            "handle_response".into(),
            format!("`{other}` is not a supported response handler yet"),
        )),
    }
}
