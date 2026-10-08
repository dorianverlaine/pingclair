// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔌 Caddy-style blocks with nginx stream option names and numeric units.

use super::{AdapterError, args::expect_one_argument};
use crate::parser::caddy_ast::Directive;
use pingclair_core::config::{Layer4Matcher, Layer4Route, Layer4Server, Layer4TlsMatcher};
use std::collections::{HashMap, HashSet};

type Result<T> = std::result::Result<T, AdapterError>;

fn invalid(d: &Directive, reason: &str) -> AdapterError {
    AdapterError::InvalidArgument(d.name.clone(), reason.into())
}

fn children(d: &Directive) -> Result<&[Directive]> {
    d.block
        .as_ref()
        .map(|b| b.directives.as_slice())
        .ok_or_else(|| invalid(d, "expected a block"))
}

fn unsupported(d: &Directive) -> AdapterError {
    let reason = match d.name.as_str() {
        "matching_timeout" => "use nginx preread_timeout; matching_timeout has different semantics",
        "idle_timeout" => "use nginx proxy_timeout; idle_timeout has different semantics",
        _ => "outside the supported Layer 4 configuration subset",
    };
    AdapterError::UnsupportedFeature(d.name.clone(), reason.into())
}

pub(super) fn adapt(d: &Directive) -> Result<Vec<Layer4Server>> {
    if !d.args.is_empty() {
        return Err(invalid(d, "expected no arguments"));
    }
    let mut servers = Vec::new();
    for listener in children(d)? {
        if !listener.args.is_empty() {
            return Err(invalid(listener, "use one listener address per block"));
        }
        let mut server = Layer4Server::new(listener.name.clone());
        let mut matchers = HashMap::new();
        let mut options = HashSet::new();
        // 🔎 Resolve definitions first so routes may reference a later matcher.
        for item in children(listener)? {
            if item.name.starts_with('@') {
                if item.name.len() == 1 || matchers.contains_key(&item.name) {
                    return Err(invalid(item, "empty or duplicate matcher name"));
                }
                let mut set = Layer4Matcher::default();
                if item.args.is_empty() {
                    for condition in children(item)? {
                        condition_into(condition, &mut set)?;
                    }
                } else {
                    let mut condition = item.clone();
                    condition.name = condition.args.remove(0);
                    condition_into(&condition, &mut set)?;
                }
                if set == Layer4Matcher::default() {
                    return Err(invalid(item, "empty matcher set"));
                }
                matchers.insert(item.name.clone(), set);
            }
        }
        for item in children(listener)? {
            if item.name.starts_with('@') {
                continue;
            }
            if item.name == "route" {
                let mut sets = Vec::new();
                for name in &item.args {
                    sets.push(
                        matchers
                            .get(name)
                            .cloned()
                            .ok_or_else(|| invalid(item, &format!("undefined matcher {name}")))?,
                    );
                }
                let handlers = children(item)?;
                if handlers.len() != 1 {
                    return Err(invalid(item, "expected exactly one proxy handler"));
                }
                let proxy = &handlers[0];
                if proxy.name != "proxy" {
                    return Err(unsupported(proxy));
                }
                if proxy.block.is_some() {
                    return Err(unsupported(proxy));
                }
                server.routes.push(Layer4Route {
                    matches: sets,
                    upstream: expect_one_argument(proxy)?.into(),
                });
                continue;
            }
            if !options.insert(&item.name) {
                return Err(invalid(item, "duplicate option"));
            }
            if item.name == "log" {
                if !item.args.is_empty() {
                    return Err(invalid(
                        item,
                        "L4 supports one unnamed log block per listener",
                    ));
                }
                let block = item
                    .block
                    .clone()
                    .unwrap_or(crate::parser::caddy_ast::Block {
                        directives: Vec::new(),
                    });
                let log = super::logs::adapt_log_block(block)?;
                server.log = Some(
                    crate::compiler::compile_log(&log)
                        .map_err(|e| invalid(item, &e.to_string()))?,
                );
                continue;
            }
            if item.block.is_some() {
                return Err(invalid(item, "option does not accept a block"));
            }
            match item.name.as_str() {
                "preread_timeout" => server.preread_timeout_ms = duration(item)?,
                "proxy_connect_timeout" => server.proxy_connect_timeout_ms = duration(item)?,
                "proxy_timeout" => server.proxy_timeout_ms = duration(item)?,
                "preread_buffer_size" => server.preread_buffer_size = size(item)?,
                "proxy_buffer_size" => server.proxy_buffer_size = size(item)?,
                "proxy_half_close" => {
                    server.proxy_half_close = match expect_one_argument(item)? {
                        "on" => true,
                        "off" => false,
                        _ => return Err(invalid(item, "expected on or off")),
                    }
                }
                _ => return Err(unsupported(item)),
            }
        }
        servers.push(server);
    }
    if servers.is_empty() {
        return Err(invalid(d, "expected at least one listener"));
    }
    Ok(servers)
}

fn condition_into(d: &Directive, set: &mut Layer4Matcher) -> Result<()> {
    match d.name.as_str() {
        "remote_ip" => {
            if !set.remote_ip.is_empty() || d.args.is_empty() || d.block.is_some() {
                return Err(invalid(d, "expected one nonempty remote_ip condition"));
            }
            set.remote_ip.clone_from(&d.args);
        }
        "tls" => {
            if set.tls.is_some() {
                return Err(invalid(d, "duplicate TLS condition"));
            }
            let mut tls = Layer4TlsMatcher::default();
            if !d.args.is_empty() {
                if d.block.is_some() {
                    return Err(invalid(d, "use arguments or a TLS block"));
                }
                tls_values(&d.args[0], &d.args[1..], &mut tls, d)?;
            } else if let Some(block) = &d.block {
                for sub in &block.directives {
                    if sub.block.is_some() {
                        return Err(invalid(sub, "unexpected nested block"));
                    }
                    tls_values(&sub.name, &sub.args, &mut tls, sub)?;
                }
            }
            set.tls = Some(tls);
        }
        _ => return Err(unsupported(d)),
    }
    Ok(())
}

fn tls_values(
    name: &str,
    values: &[String],
    tls: &mut Layer4TlsMatcher,
    d: &Directive,
) -> Result<()> {
    let target = match name {
        "sni" => &mut tls.sni,
        "alpn" => &mut tls.alpn,
        _ => return Err(unsupported(d)),
    };
    if values.is_empty() || !target.is_empty() {
        return Err(invalid(d, "empty or duplicate TLS condition"));
    }
    target.extend_from_slice(values);
    Ok(())
}

fn size(d: &Directive) -> Result<usize> {
    let raw = expect_one_argument(d)?;
    let (digits, multiplier) = match raw.as_bytes().last() {
        Some(b'k' | b'K') => (&raw[..raw.len() - 1], 1024usize),
        Some(b'm' | b'M') => (&raw[..raw.len() - 1], 1024usize * 1024),
        _ => (raw, 1),
    };
    // 📏 nginx ngx_parse_size uses binary k/m units, unlike the HTTP log parser.
    digits
        .parse::<usize>()
        .ok()
        .filter(|_| digits.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|n| n.checked_mul(multiplier))
        .filter(|n| *n > 0)
        .ok_or_else(|| {
            invalid(
                d,
                "expected a positive byte size with optional k or m suffix",
            )
        })
}

fn duration(d: &Directive) -> Result<u64> {
    let raw = expect_one_argument(d)?;
    let mut rest = raw;
    let mut total = 0u64;
    let mut previous = u64::MAX;
    // ⏱️ nginx millisecond directives interpret a bare integer as seconds.
    while !rest.is_empty() {
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        let n = rest[..end]
            .parse::<u64>()
            .map_err(|_| invalid(d, "invalid duration"))?;
        rest = &rest[end..];
        let (unit, factor) = if rest.is_empty() {
            ("", 1000)
        } else {
            [
                ("ms", 1),
                ("s", 1000),
                ("m", 60_000),
                ("h", 3_600_000),
                ("d", 86_400_000),
                ("w", 604_800_000),
            ]
            .into_iter()
            .find(|(unit, _)| rest.starts_with(unit))
            .ok_or_else(|| invalid(d, "expected integer ms, s, m, h, d or w units"))?
        };
        if factor >= previous {
            return Err(invalid(d, "duration units must decrease"));
        }
        previous = factor;
        total = n
            .checked_mul(factor)
            .and_then(|n| total.checked_add(n))
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or_else(|| invalid(d, "duration overflow"))?;
        rest = &rest[unit.len()..];
    }
    if raw.is_empty() {
        return Err(invalid(d, "empty duration"));
    }
    Ok(total)
}
