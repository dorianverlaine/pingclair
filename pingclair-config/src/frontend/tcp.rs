// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ The TCP listener: raw bytes, routed by SNI or peer address.
//!
//! 📌 Named `tcp` rather than `layer4` because the crate already has a
//! `layer4.rs` — the compile-stage module that turns analysed L4 blocks into
//! configuration. Two files called `layer4.rs` doing different jobs is a tab
//! nobody can read.

use super::log::{LogScope, parse_log};
use super::*;

/// 🏷️ The argument labels a TCP listener accepts.
pub(crate) const TCP_LISTENER_LABELS: &[&str] = &["on"];

/// 🏷️ The labels an L4 route accepts (`Fallback` takes none).
pub(crate) const L4_ROUTE_LABELS: &[&str] = &["when"];

/// 🏷️ Listener policies share their labels with the language catalogue.
pub(crate) const TCP_LIMIT_LABELS: &[&str] = &["maxConnections", "preread", "relay"];
pub(crate) const TCP_TIMEOUT_LABELS: &[&str] = &["preread", "connect", "idle"];
pub(crate) const TCP_HALF_CLOSE_LABELS: &[&str] = &["enabled"];

/// 🏷️ What an L4 `Proxy` accepts: a destination and nothing else — the
/// dynamic sources and header policy are HTTP-proxy vocabulary.
pub(crate) const L4_PROXY_LABELS: &[&str] = &["to"];

pub(super) fn listener(call: &Call) -> Result<Layer4Server, Error> {
    call.labels(TCP_LISTENER_LABELS)?;
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
                child.leaf(TCP_LIMIT_LABELS)?;
                if child.get("maxConnections").is_some() {
                    server.max_connections = usize::try_from(child.integer("maxConnections")?)
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
                child.leaf(TCP_TIMEOUT_LABELS)?;
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
                child.leaf(TCP_HALF_CLOSE_LABELS)?;
                server.proxy_half_close = child.boolean("enabled")?;
            }
            "sessionLog" => server.log = Some(parse_log(child, LogScope::TcpSession)?),
            _ => return Err(child.at.error("unknown TCPListener modifier")),
        }
    }
    Ok(server)
}

pub(super) fn route(call: &Call) -> Result<Layer4Route, Error> {
    call.no_modifiers()?;
    let mut matches = Vec::new();
    if call.name == "Fallback" {
        call.labels(&[])?;
    } else {
        call.labels(L4_ROUTE_LABELS)?;
        let value = call.get("when").ok_or_else(|| {
            call.at
                .error("route requires when; use Fallback for an unconditional route")
        })?;
        matches = condition(value, call.at)?;
    }
    let body = call.block()?;
    let [proxy] = body else {
        return Err(call.at.error("route requires exactly one Proxy component"));
    };
    if proxy.name != "Proxy" {
        return Err(proxy.at.error("expected Proxy(to: ...)"));
    }
    proxy.leaf(L4_PROXY_LABELS)?;
    Ok(Layer4Route {
        dynamic: None,
        matches,
        upstream: proxy.string("to")?,
    })
}

fn condition(value: &Value, at: Position) -> Result<Vec<Layer4Matcher>, Error> {
    let Value::Typed(call) = value else {
        return Err(
            at.error("TCP when requires .tls(...), .from([...]), .all([...]) or .any([...])")
        );
    };
    call.no_modifiers()?;
    if call.body.is_some() {
        return Err(call.at.error("a condition does not accept a block"));
    }
    match call.name.as_str() {
        "tls" => {
            call.leaf(&["sni", "alpn"])?;
            Ok(vec![Layer4Matcher {
                tls: Some(Layer4TlsMatcher {
                    sni: call.strings("sni")?,
                    alpn: call.strings("alpn")?,
                }),
                ..Default::default()
            }])
        }
        "from" => {
            let [(None, Value::Array(values))] = call.args.as_slice() else {
                return Err(call
                    .at
                    .error("from requires one nonempty array of IP addresses or CIDRs"));
            };
            if values.is_empty() {
                return Err(call
                    .at
                    .error("from requires at least one IP address or CIDR"));
            }
            let remote_ip = values
                .iter()
                .map(|value| match value {
                    Value::String(value) => Ok(value.clone()),
                    _ => Err(call.at.error("from requires IP address or CIDR strings")),
                })
                .collect::<Result<_, _>>()?;
            Ok(vec![Layer4Matcher {
                remote_ip,
                ..Default::default()
            }])
        }
        "all" | "any" => {
            let [(None, Value::Array(values))] = call.args.as_slice() else {
                return Err(call
                    .at
                    .error("all and any require one nonempty array of conditions"));
            };
            if values.is_empty() {
                return Err(call.at.error("all and any require at least one condition"));
            }
            let mut result = if call.name == "all" {
                vec![Layer4Matcher::default()]
            } else {
                Vec::new()
            };
            for value in values {
                let alternatives = condition(value, call.at)?;
                if call.name == "any" {
                    if result.len() + alternatives.len() > 4096 {
                        return Err(call
                            .at
                            .error("TCP condition expansion exceeds 4096 matcher sets"));
                    }
                    result.extend(alternatives);
                } else {
                    if result.len().saturating_mul(alternatives.len()) > 4096 {
                        return Err(call
                            .at
                            .error("TCP condition expansion exceeds 4096 matcher sets"));
                    }
                    let mut combined = Vec::new();
                    for left in &result {
                        for right in &alternatives {
                            // 🛡️ The shared schema has one TLS and one peer condition per set.
                            // Repeated fields cannot be concatenated: that would turn AND into OR.
                            if (left.tls.is_some() && right.tls.is_some())
                                || (!left.remote_ip.is_empty() && !right.remote_ip.is_empty())
                            {
                                return Err(call.at.error("a TCP all condition accepts one tls and one from condition per matcher set"));
                            }
                            combined.push(Layer4Matcher {
                                tls: left.tls.clone().or_else(|| right.tls.clone()),
                                remote_ip: if left.remote_ip.is_empty() {
                                    right.remote_ip.clone()
                                } else {
                                    left.remote_ip.clone()
                                },
                            });
                        }
                    }
                    result = combined;
                }
            }
            Ok(result)
        }
        _ => Err(call
            .at
            .error("unsupported TCP condition; expected .tls, .from, .all or .any")),
    }
}
