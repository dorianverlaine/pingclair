// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌐 TCP DNS identity and lifetime policy, separate from HTTP refresh semantics.

use crate::frontend::{Error, duration_millis, parse_port};
use crate::syntax::{Position, Value};
use pingclair_core::config::{Layer4Dns, Layer4Dynamic, Layer4IpVersions};

pub(super) fn parse(value: &Value, at: Position) -> Result<Layer4Dynamic, Error> {
    let Value::Typed(source) = value else {
        return Err(at.error("TCP dynamic requires .a(...)"));
    };
    if source.name != "a" {
        return Err(source.at.error("TCP dynamic supports only .a(...)"));
    }
    source.no_modifiers()?;
    if source.body.is_some() {
        return Err(source.at.error("a dynamic source does not accept a block"));
    }
    let mut name = None;
    let mut seen = std::collections::HashSet::new();
    for (label, value) in &source.args {
        match label.as_deref() {
            None => {
                let Value::String(value) = value else { return Err(source.at.error(".a requires one quoted DNS name")); };
                if name.replace(value.clone()).is_some() { return Err(source.at.error(".a requires exactly one DNS name")); }
            }
            Some(label @ ("port" | "resolvers" | "versions" | "valid" | "stale" | "allowIP")) => {
                if !seen.insert(label) { return Err(source.at.error("duplicate TCP dynamic setting")); }
            }
            Some(_) => return Err(source.at.error("unknown TCP dynamic setting; expected port, resolvers, versions, valid, stale or allowIP")),
        }
    }
    let name = name.ok_or_else(|| source.at.error(".a requires one quoted DNS name"))?;
    let port = parse_port(
        source
            .get("port")
            .ok_or_else(|| source.at.error(".a requires port:"))?,
        "port",
        source.at,
    )?;
    let versions = match source.get("versions") {
        None => Layer4IpVersions::Ip,
        Some(Value::Typed(case)) => {
            case.leaf(&[])?;
            match case.name.as_str() {
                "ipv4" => Layer4IpVersions::Ipv4,
                "ipv6" => Layer4IpVersions::Ipv6,
                "ip" => Layer4IpVersions::Ip,
                _ => return Err(case.at.error("versions requires .ipv4, .ipv6 or .ip")),
            }
        }
        Some(_) => return Err(source.at.error("versions requires .ipv4, .ipv6 or .ip")),
    };
    Ok(Layer4Dynamic::A(Layer4Dns {
        name,
        port,
        versions,
        resolvers: source
            .get("resolvers")
            .map(|_| source.strings("resolvers"))
            .transpose()?,
        allow_ip: source
            .get("allowIP")
            .map(|_| source.strings("allowIP"))
            .transpose()?,
        valid_ms: source
            .get("valid")
            .map(|value| duration_millis(value, "valid", source.at))
            .transpose()?,
        stale_ms: source
            .get("stale")
            .map(|value| duration_millis(value, "stale", source.at))
            .transpose()?
            .unwrap_or(60_000),
    }))
}
