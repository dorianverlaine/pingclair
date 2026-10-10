// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ The one definition of which destinations a configured DNS answer may name.
//!
//! Two readers ask the same question about the same configuration: the validator
//! refuses a broad allowance while the configuration loads, and the L4 runtime
//! re-checks every answer before it publishes a snapshot. A table written out
//! twice drifts, and the direction it drifts in decides whether the runtime
//! dials an address the validator would have refused.
//!
//! 📌 So the tables and both rules live here. [`allowance`] compiles one
//! configured range, and [`is_public_unicast`] classifies one answer address;
//! the callers add only the reader's own context (a line, or an `io::Error`).

use ipnet::{IpNet, Ipv4Net};
use std::net::IpAddr;
use std::sync::LazyLock;

// 🌐 IANA special-purpose registries, reviewed 2026-10-09 (registry revision 2025-10-09).
// https://www.iana.org/assignments/iana-ipv4-special-registry/
// https://www.iana.org/assignments/iana-ipv6-special-registry/
// Conditional reachability (Teredo and 6to4) requires an explicit allowance.
pub const NONPUBLIC_RANGES: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "2001::/23",
    "2001:db8::/32",
    "2002::/16",
    "3fff::/20",
];

/// 🌐 The registries' own exceptions: prefixes recorded as globally reachable
/// even though they sit inside a special-purpose block.
pub const PUBLIC_EXCEPTIONS: &[&str] = &[
    "192.0.0.9/32",
    "192.0.0.10/32",
    "64:ff9b::/96",
    "2001:1::1/128",
    "2001:1::2/128",
    "2001:1::3/128",
    "2001:3::/32",
    "2001:4:112::/48",
    "2001:20::/28",
    "2001:30::/28",
];

/// 🚪 Loopback and link-local: an allowance may grant them, but only by naming
/// a range that fits entirely inside the class. Nothing reaches them by accident.
pub const SENSITIVE_RANGES: &[&str] = &["127.0.0.0/8", "169.254.0.0/16", "::1/128", "fe80::/10"];

static RESERVED: LazyLock<Vec<IpNet>> = LazyLock::new(|| nets(NONPUBLIC_RANGES));
static EXCEPTIONS: LazyLock<Vec<IpNet>> = LazyLock::new(|| nets(PUBLIC_EXCEPTIONS));
static SENSITIVE: LazyLock<Vec<IpNet>> = LazyLock::new(|| nets(SENSITIVE_RANGES));
static GLOBAL_V6: LazyLock<IpNet> = LazyLock::new(|| "2000::/3".parse().expect("literal CIDR"));

fn nets(values: &[&str]) -> Vec<IpNet> {
    values
        .iter()
        .map(|value| value.parse().expect("literal CIDR"))
        .collect()
}

/// 🚫 A configured allowance that cannot be used, with the reason a reader can
/// print: the validator prefixes it with the option, the runtime wraps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidAllowance {
    /// Neither an address nor a CIDR range.
    NotARange,
    /// An IPv6 range that would grant IPv4 addresses wholesale.
    BroadlyMapped,
    /// Covers a sensitive class without fitting inside it.
    BroadSensitiveClass,
}

impl std::fmt::Display for InvalidAllowance {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::NotARange => "is not an IP address or CIDR range",
            Self::BroadlyMapped => "cannot broadly cover IPv4-mapped IPv6",
            Self::BroadSensitiveClass => {
                "covering loopback or link-local must fit entirely within that class"
            }
        })
    }
}

impl std::error::Error for InvalidAllowance {}

/// 🌐 Compiles one configured allowance: parse, canonicalize, then refuse a
/// range that would grant a sensitive class more room than it claims.
pub fn allowance(text: &str) -> Result<IpNet, InvalidAllowance> {
    let net = text
        .parse::<IpNet>()
        .map_err(|_| InvalidAllowance::NotARange)?;
    let net = canonical(net)?;
    for class in SENSITIVE.iter() {
        if (net.contains(&class.network()) || class.contains(&net.network()))
            && !class.contains(&net)
        {
            return Err(InvalidAllowance::BroadSensitiveClass);
        }
    }
    Ok(net)
}

/// 🌐 Whether a name may point at this address without an explicit allowance:
/// public unicast, by the registries above, with the mapped form folded in.
pub fn is_public_unicast(address: IpAddr) -> bool {
    let ip = address.to_canonical();
    EXCEPTIONS.iter().any(|net| net.contains(&ip))
        || ((!ip.is_ipv6() || GLOBAL_V6.contains(&ip))
            && !RESERVED.iter().any(|net| net.contains(&ip)))
}

/// 🌐 Folds `::ffff:0:0/96` into the IPv4 range it stands for, so both families
/// meet the same policy. A prefix shorter than the mapped block would hand over
/// IPv4 addresses the allowance never named, and is refused.
fn canonical(net: IpNet) -> Result<IpNet, InvalidAllowance> {
    if let IpNet::V6(v6) = net {
        let mapped: IpNet = "::ffff:0:0/96".parse().expect("literal CIDR");
        if net.contains(&mapped.network()) || mapped.contains(&net.network()) {
            if v6.prefix_len() < 96 {
                return Err(InvalidAllowance::BroadlyMapped);
            }
            return Ok(Ipv4Net::new(
                v6.network().to_ipv4_mapped().expect("mapped subnet"),
                v6.prefix_len() - 96,
            )
            .expect("IPv4 prefix")
            .into());
        }
    }
    Ok(net)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🚫 A range that covers a sensitive class without fitting inside it would
    /// grant that class to every answer, so it is refused; a range that fits
    /// grants exactly what it names.
    #[test]
    fn allowances_cannot_incidentally_grant_loopback_or_link_local() {
        for refused in [
            "0.0.0.0/0",
            "::/0",
            "::ffff:0:0/96",
            "::fffe:0:0/95",
            "fe00::/8",
            "126.0.0.0/7",
            "169.0.0.0/8",
            "::/127",
            "not-a-range",
        ] {
            assert!(allowance(refused).is_err(), "{refused}");
        }
        for accepted in [
            "127.0.0.0/8",
            "169.254.0.0/16",
            "::1/128",
            "fe80::/10",
            "10.20.0.0/16",
            "fc00::/7",
            "::ffff:127.0.0.1/128",
            "::ffff:169.254.0.0/112",
        ] {
            assert!(allowance(accepted).is_ok(), "{accepted}");
        }
    }

    /// 🌐 Mapped IPv6 is the same address as its IPv4 form, in both directions.
    #[test]
    fn mapped_allowances_and_answers_agree_with_their_ipv4_form() {
        let allowed = allowance("::ffff:127.0.0.1/128").unwrap();
        assert!(allowed.contains(&"127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_public_unicast("8.8.8.8".parse().unwrap()));
        assert!(is_public_unicast("::ffff:8.8.8.8".parse().unwrap()));
        assert!(!is_public_unicast("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!is_public_unicast("10.0.0.1".parse().unwrap()));
    }
}
