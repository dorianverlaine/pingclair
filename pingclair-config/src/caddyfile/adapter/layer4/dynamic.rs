// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌐 Explicit TCP DNS sources retain nginx-style valid and stale lifetimes.

use super::{Result, children, duration, expect_one_argument, invalid};
use crate::caddyfile::parser::caddy_ast::Directive;
use pingclair_core::config::{Layer4Dns, Layer4Dynamic, Layer4IpVersions};

pub(super) fn source(proxy: &Directive) -> Result<(String, Option<Layer4Dynamic>)> {
    if proxy.block.is_none() {
        return Ok((expect_one_argument(proxy)?.into(), None));
    }
    if !proxy.args.is_empty() {
        return Err(invalid(
            proxy,
            "proxy requires exactly one static or dynamic source",
        ));
    }
    let [source] = children(proxy)? else {
        return Err(invalid(proxy, "proxy requires exactly one dynamic source"));
    };
    if source.name != "dynamic" || source.args.as_slice() != ["a"] {
        return Err(invalid(source, "TCP proxy supports dynamic a only"));
    }
    let mut seen = std::collections::HashSet::new();
    let mut config = Layer4Dns {
        name: String::new(),
        port: 0,
        resolvers: None,
        versions: Layer4IpVersions::Ip,
        valid_ms: None,
        stale_ms: 60_000,
        allow_ip: None,
    };
    for option in children(source)? {
        if !seen.insert(option.name.as_str()) {
            return Err(invalid(option, "duplicate TCP dynamic setting"));
        }
        if option.block.is_some() {
            return Err(invalid(option, "dynamic option does not accept a block"));
        }
        match option.name.as_str() {
            "name" => config.name = expect_one_argument(option)?.into(),
            "port" => {
                config.port = expect_one_argument(option)?
                    .parse()
                    .ok()
                    .filter(|port| *port > 0)
                    .ok_or_else(|| invalid(option, "port must be between 1 and 65535"))?
            }
            "versions" => {
                config.versions = match expect_one_argument(option)? {
                    "ipv4" => Layer4IpVersions::Ipv4,
                    "ipv6" => Layer4IpVersions::Ipv6,
                    "ip" => Layer4IpVersions::Ip,
                    _ => return Err(invalid(option, "versions requires ipv4, ipv6 or ip")),
                }
            }
            "valid" => config.valid_ms = Some(duration(option)?),
            "stale" => config.stale_ms = duration(option)?,
            "resolvers" | "allow_ip" => {
                if option.args.is_empty() {
                    return Err(invalid(option, "dynamic option requires a nonempty list"));
                }
                if option.name == "resolvers" {
                    config.resolvers = Some(option.args.clone());
                } else {
                    config.allow_ip = Some(option.args.clone());
                }
            }
            _ => return Err(invalid(option, "unknown TCP dynamic setting")),
        }
    }
    if !seen.contains("name") || !seen.contains("port") {
        return Err(invalid(source, "dynamic a requires name and port"));
    }
    Ok((String::new(), Some(Layer4Dynamic::A(config))))
}
