// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ Shared L4 validation; JSON, DSL, reload and admin use the same gate.

use crate::compiler::{CompileError, CompileResult};
use pingclair_core::config::{PingclairConfig, covering_wildcard, normalize_listen_addr};
use std::net::{IpAddr, SocketAddr};

fn invalid(message: impl Into<String>) -> CompileError {
    CompileError::InvalidServer {
        message: message.into(),
    }
}

pub(crate) fn validate(config: &PingclairConfig) -> CompileResult<()> {
    if config.layer4.is_empty() {
        return Ok(());
    }
    validate_declarations(config)?;
    // 🚧 Remove this gate only with the listener, reload and shutdown integration.
    Err(CompileError::UnsupportedFeature {
        feature: "layer4 TCP listeners are not implemented yet; the configuration library can represent declarations, but this build cannot run them".into(),
    })
}

fn validate_declarations(config: &PingclairConfig) -> CompileResult<()> {
    let http: Vec<String> = config
        .servers
        .iter()
        .flat_map(|s| s.listen_addresses(config.global.http_port, config.global.https_port))
        .collect();
    let mut listeners = Vec::new();
    for server in &config.layer4 {
        let address = normalize_listen_addr(&server.listen)
            .parse::<SocketAddr>()
            .map_err(|_| {
                invalid(format!(
                    "layer4 listener {} requires an IP address and port",
                    server.listen
                ))
            })?;
        if address.port() == 0 {
            return Err(invalid("layer4 listener port must be nonzero"));
        }
        for other in listeners.iter().chain(http.iter()) {
            let same = *other == address.to_string();
            let covered =
                address.ip().is_unspecified() && covering_wildcard(other, &[address]).is_some();
            let covering = other
                .parse::<SocketAddr>()
                .ok()
                .filter(|other| other.ip().is_unspecified())
                .is_some_and(|other| covering_wildcard(&address.to_string(), &[other]).is_some());
            if same || covered || covering {
                return Err(invalid(format!(
                    "layer4 listener {address} overlaps TCP listener {other}"
                )));
            }
        }
        listeners.push(address.to_string());
        if server.preread_buffer_size == 0 || server.proxy_buffer_size == 0 {
            return Err(invalid("layer4 buffer sizes must be nonzero"));
        }
        if [
            server.preread_timeout_ms,
            server.proxy_connect_timeout_ms,
            server.proxy_timeout_ms,
        ]
        .into_iter()
        .any(|n| n > i64::MAX as u64)
        {
            return Err(invalid("layer4 timeout exceeds the supported timer range"));
        }
        if server.routes.is_empty() {
            return Err(invalid("layer4 listener requires a route"));
        }
        for (index, route) in server.routes.iter().enumerate() {
            if route.matches.is_empty() && index + 1 != server.routes.len() {
                return Err(invalid("layer4 unconditional route must be last"));
            }
            let upstream = &route.upstream;
            let valid = upstream
                .parse::<SocketAddr>()
                .map(|a| a.port() != 0)
                .unwrap_or_else(|_| {
                    upstream.rsplit_once(':').is_some_and(|(host, port)| {
                        !host.is_empty()
                            && host.bytes().all(|b| {
                                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')
                            })
                            && port.parse::<u16>().is_ok_and(|p| p != 0)
                    })
                });
            if !valid {
                return Err(invalid(format!(
                    "layer4 proxy requires one static host:port, got {upstream}"
                )));
            }
            for matcher in &route.matches {
                if matcher.tls.is_none() && matcher.remote_ip.is_empty() {
                    return Err(invalid("layer4 matcher set must not be empty"));
                }
                for ip in &matcher.remote_ip {
                    if ip.parse::<IpAddr>().is_err() && ip.parse::<ipnet::IpNet>().is_err() {
                        return Err(invalid(format!(
                            "layer4 remote_ip contains invalid IP or CIDR {ip}"
                        )));
                    }
                }
                if let Some(tls) = &matcher.tls {
                    if tls.sni.iter().any(|s| {
                        s.is_empty()
                            || !s.bytes().all(|b| {
                                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')
                            })
                    }) {
                        return Err(invalid(
                            "layer4 sni requires exact ASCII names; wildcards and regex are unsupported",
                        ));
                    }
                    if tls.alpn.iter().any(|s| s.is_empty() || s.len() > 255) {
                        return Err(invalid(
                            "layer4 alpn requires identifiers of 1 to 255 bytes",
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "layer4_tests.rs"]
mod tests;
