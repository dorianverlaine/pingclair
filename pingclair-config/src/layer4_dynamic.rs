// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ Common dynamic L4 validation for every configuration entry point.

use crate::compiler::{CompileError, CompileResult};
use pingclair_core::config::{Layer4Dns, Layer4Dynamic, Layer4Route, PingclairConfig};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

fn invalid(message: impl Into<String>) -> CompileError {
    CompileError::InvalidServer {
        message: message.into(),
    }
}

pub(crate) fn validate_pools(config: &PingclairConfig) -> CompileResult<()> {
    let policies: HashSet<_> = config
        .layer4
        .iter()
        .flat_map(|server| &server.routes)
        .filter_map(|route| route.dynamic.as_ref())
        .collect();
    if policies.len() > 256 {
        return Err(invalid("layer4 exceeds 256 distinct dynamic pools"));
    }
    Ok(())
}

pub(crate) fn validate_source(route: &Layer4Route) -> CompileResult<()> {
    match (&route.dynamic, route.upstream.is_empty()) {
        (Some(Layer4Dynamic::A(dns)), true) => validate_dns(dns),
        (None, false) => Ok(()),
        (Some(_), false) | (None, true) => Err(invalid(
            "layer4 proxy requires exactly one static upstream or dynamic source",
        )),
    }
}

fn validate_dns(dns: &Layer4Dns) -> CompileResult<()> {
    let name = dns.name.strip_suffix('.').unwrap_or(&dns.name);
    if name.is_empty()
        || name.len() > 253
        || name.parse::<IpAddr>().is_ok()
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(invalid(
            "layer4 dynamic name requires a fixed ASCII DNS name, not an IP, wildcard, URL or variable",
        ));
    }
    if dns.port == 0 {
        return Err(invalid("layer4 dynamic port must be between 1 and 65535"));
    }
    if let Some(resolvers) = &dns.resolvers {
        if resolvers.is_empty() || resolvers.len() > 4 {
            return Err(invalid(
                "layer4 dynamic resolvers requires 1 to 4 numeric endpoints",
            ));
        }
        for resolver in resolvers {
            let endpoint = resolver
                .parse::<IpAddr>()
                .map(|ip| SocketAddr::new(ip, 53))
                .or_else(|_| resolver.parse::<SocketAddr>());
            if !endpoint.is_ok_and(|address| address.port() != 0) {
                return Err(invalid(
                    "layer4 dynamic resolver requires a numeric IP or IP:port with a nonzero port",
                ));
            }
        }
    }
    if dns.stale_ms > 300_000 {
        return Err(invalid("layer4 dynamic stale must be between 0 and 300s"));
    }
    if dns
        .valid_ms
        .is_some_and(|valid| valid == 0 || valid > i64::MAX as u64 - dns.stale_ms)
    {
        return Err(invalid(
            "layer4 dynamic valid must be a positive duration within the timer range",
        ));
    }
    if let Some(ranges) = &dns.allow_ip {
        if ranges.is_empty() {
            return Err(invalid(
                "layer4 dynamic allow_ip requires a nonempty CIDR list",
            ));
        }
        // 🛡️ One rule, one implementation: the runtime re-checks the same ranges
        // before it publishes an answer, through this same function.
        for range in ranges {
            pingclair_core::config::allowance(range)
                .map_err(|error| invalid(format!("layer4 dynamic allow_ip {error}")))?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "layer4_dynamic_tests.rs"]
mod tests;
