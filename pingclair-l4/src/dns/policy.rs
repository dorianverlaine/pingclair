// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ Compiled destination policy applied to the complete DNS answer before publication.

use ipnet::{IpNet, Ipv4Net};
use std::io;
use std::net::SocketAddr;
use std::sync::LazyLock;

// 🌐 IANA special-purpose registries, reviewed 2026-10-09 (registry revision 2025-10-09).
// https://www.iana.org/assignments/iana-ipv4-special-registry/
// https://www.iana.org/assignments/iana-ipv6-special-registry/
// Conditional reachability (Teredo and 6to4) requires an explicit allowance.
const NONPUBLIC: &[&str] = &[
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
const PUBLIC_EXCEPTIONS: &[&str] = &[
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
static RESERVED: LazyLock<Vec<IpNet>> = LazyLock::new(|| nets(NONPUBLIC));
static EXCEPTIONS: LazyLock<Vec<IpNet>> = LazyLock::new(|| nets(PUBLIC_EXCEPTIONS));
static SENSITIVE: LazyLock<Vec<IpNet>> =
    LazyLock::new(|| nets(&["127.0.0.0/8", "169.254.0.0/16", "::1/128", "fe80::/10"]));
static GLOBAL_V6: LazyLock<IpNet> = LazyLock::new(|| "2000::/3".parse().expect("literal CIDR"));

fn nets(values: &[&str]) -> Vec<IpNet> {
    values
        .iter()
        .map(|value| value.parse().expect("literal CIDR"))
        .collect()
}

pub(super) fn canonical_net(net: IpNet) -> io::Result<IpNet> {
    if let IpNet::V6(v6) = net {
        let mapped: IpNet = "::ffff:0:0/96".parse().expect("literal CIDR");
        if net.contains(&mapped.network()) || mapped.contains(&net.network()) {
            if v6.prefix_len() < 96 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "broad mapped IPv6 allowance",
                ));
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

pub(super) struct Policy {
    allow: Vec<IpNet>,
    own: Vec<SocketAddr>,
}

impl Policy {
    pub fn prepare(allow: Option<&[String]>, own: &[SocketAddr]) -> io::Result<Self> {
        if allow.is_some_and(<[String]>::is_empty) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty DNS address allowance",
            ));
        }
        let mut compiled = Vec::new();
        for value in allow.unwrap_or_default() {
            let net = canonical_net(value.parse().map_err(io::Error::other)?)?;
            for class in SENSITIVE.iter() {
                if (net.contains(&class.network()) || class.contains(&net.network()))
                    && !class.contains(&net)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "broad loopback or link-local allowance",
                    ));
                }
            }
            compiled.push(net);
        }
        Ok(Self {
            allow: compiled,
            own: own.to_vec(),
        })
    }

    pub fn permits(&self, address: SocketAddr) -> bool {
        let ip = address.ip().to_canonical();
        if ip.is_unspecified()
            || ip.is_multicast()
            || self.own.iter().any(|own| {
                own.port() == address.port()
                    && (own.ip().to_canonical() == ip
                        || (own.ip().is_unspecified() && ip.is_loopback()))
            })
        {
            return false;
        }
        let public = EXCEPTIONS.iter().any(|net| net.contains(&ip))
            || ((!ip.is_ipv6() || GLOBAL_V6.contains(&ip))
                && !RESERVED.iter().any(|net| net.contains(&ip)));
        public || self.allow.iter().any(|net| net.contains(&ip))
    }
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
