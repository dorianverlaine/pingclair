// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Configuration adapters

pub mod caddyfile;
// 📦 `import` in its own module: a self-contained concern, and one fewer thing
// in a file that is already too large to navigate.
pub mod imports;
pub mod json;

pub use caddyfile::registry::{
    implemented_names, is_implemented_directive, recognised_but_unimplemented,
};
pub use caddyfile::{AdapterError, adapt};
pub use json::JsonAdapter;

/// 🌐 Expands Caddy-style upstream port ranges into one address per port.
///
/// Caddy accepts `to :9000-9003` (and `host:9000-9003`) as a shortcut for
/// several upstreams on consecutive ports. Each range expands into explicit
/// addresses so the load balancer sees one peer per port, exactly as if the
/// operator had typed them out. Addresses without a range pass through
/// unchanged.
pub fn expand_upstream_port_ranges(addresses: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut expanded = Vec::new();
    for address in addresses {
        match split_upstream_range(&address) {
            Some((host, start, end)) if end >= start => {
                for port in start..=end {
                    expanded.push(format!("{host}:{port}"));
                }
            }
            _ => expanded.push(address),
        }
    }
    expanded
}

/// 🧭 Splits `host:start-end` (or `:start-end`) into its host prefix and
/// port bounds. Returns `None` when the address has no port range.
fn split_upstream_range(address: &str) -> Option<(String, u16, u16)> {
    // The port separator is the last colon outside a bracketed IPv6 literal.
    let colon = match address.rfind(']') {
        Some(bracket) => address[bracket..].rfind(':').map(|offset| bracket + offset),
        None => address.rfind(':'),
    }?;
    let (host, port_part) = address.split_at(colon);
    let (start, end) = port_part[1..].split_once('-')?;
    let start: u16 = start.parse().ok()?;
    let end: u16 = end.parse().ok()?;
    if end < start {
        return None;
    }
    // 🧭 Keep the host prefix exactly as written (`:9000-9002` stays
    // hostless); the runtime normalizes an empty host to loopback, matching
    // Caddy's adapt output and dial behavior.
    Some((host.to_string(), start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_port_ranges_expand_to_loopback() {
        let expanded = expand_upstream_port_ranges([":9000-9002".to_string()]);
        assert_eq!(expanded, [":9000", ":9001", ":9002"]);
    }

    #[test]
    fn host_port_ranges_expand_in_order() {
        let expanded = expand_upstream_port_ranges(["10.0.0.1:8080-8081".to_string()]);
        assert_eq!(expanded, ["10.0.0.1:8080", "10.0.0.1:8081"]);
    }

    #[test]
    fn addresses_without_ranges_pass_through() {
        let expanded = expand_upstream_port_ranges([
            "127.0.0.1:9000".to_string(),
            "localhost:8443".to_string(),
        ]);
        assert_eq!(expanded, ["127.0.0.1:9000", "localhost:8443"]);
    }

    #[test]
    fn reversed_ranges_are_left_alone() {
        let expanded = expand_upstream_port_ranges([":9000-8000".to_string()]);
        assert_eq!(expanded, [":9000-8000".to_string()]);
    }
}
