// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌐 Address ranges for the `remote_ip` and `client_ip` matchers, parsed once.
//!
//! A configuration lists ranges as text (`10.0.0.0/8`, `192.0.2.7`). The text
//! never changes between requests, so it is turned into networks the moment a
//! configuration is built or read, and a request only ever asks "is this
//! address inside one of them?". The ranges used to be re-parsed from text on
//! every request that reached the matcher.
//!
//! 🛡️ Because the only way to build one is through parsing, a value of this
//! type cannot hold a malformed range. A typo such as `10.0.0.0/33` is refused
//! when the configuration loads — from a Pingclairfile, JSON, or the Admin API
//! — instead of quietly becoming a range that matches nothing, which for a
//! block list means letting through the address it was meant to stop.

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::net::IpAddr;

/// 🌐 A parsed list of IP addresses and CIDR ranges.
///
/// The original spellings are kept beside the parsed networks so the value
/// serializes back to exactly what the author wrote (`192.0.2.7`, not
/// `192.0.2.7/32`); equality compares those spellings for the same reason.
#[derive(Debug, Clone)]
pub struct IpRanges {
    source: Vec<String>,
    networks: Box<[IpNet]>,
}

/// 🚫 The first entry that is neither an address nor a CIDR range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidIpRange(pub String);

impl std::fmt::Display for InvalidIpRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid IP address or CIDR range `{}`", self.0)
    }
}

impl std::error::Error for InvalidIpRange {}

impl IpRanges {
    /// 🌐 Parses every entry, refusing the list at the first malformed one.
    ///
    /// A bare address becomes a single-address network, so matching has one
    /// shape to check rather than two.
    pub fn parse<I, S>(entries: I) -> Result<Self, InvalidIpRange>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let source: Vec<String> = entries.into_iter().map(Into::into).collect();
        let networks = source
            .iter()
            .map(|entry| {
                entry
                    .parse::<IpNet>()
                    .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                    .map_err(|_| InvalidIpRange(entry.clone()))
            })
            .collect::<Result<Box<[IpNet]>, _>>()?;
        Ok(Self { source, networks })
    }

    /// 🏎️ Whether `address` falls inside any range. Runs on the request path:
    /// no parsing and no allocation, just a prefix comparison per range.
    pub fn contains(&self, address: IpAddr) -> bool {
        self.networks
            .iter()
            .any(|network| network.contains(&address))
    }

    /// 📝 The ranges as the configuration spelled them.
    pub fn as_strings(&self) -> &[String] {
        &self.source
    }
}

impl PartialEq for IpRanges {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

impl Serialize for IpRanges {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.source.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for IpRanges {
    /// 🛡️ A JSON config and an Admin API reload are refused on a malformed
    /// range exactly as a Pingclairfile is.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let entries = Vec::<String>::deserialize(deserializer)?;
        Self::parse(entries).map_err(serde::de::Error::custom)
    }
}

// MARK: - Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test address parses")
    }

    #[test]
    fn matches_ranges_and_exact_addresses() {
        let ranges = IpRanges::parse(["10.0.0.0/8", "192.0.2.7", "2001:db8::/32"]).unwrap();
        assert!(ranges.contains(ip("10.1.2.3")));
        assert!(ranges.contains(ip("192.0.2.7")));
        assert!(ranges.contains(ip("2001:db8::1")));
        assert!(!ranges.contains(ip("192.0.2.8")));
        assert!(!ranges.contains(ip("11.0.0.1")));
    }

    /// 🚫 A malformed entry must not become a range that matches nothing.
    #[test]
    fn refuses_a_malformed_entry() {
        assert_eq!(
            IpRanges::parse(["10.0.0.0/8", "10.0.0.0/33"]).unwrap_err(),
            InvalidIpRange("10.0.0.0/33".into())
        );
        assert!(serde_json::from_str::<IpRanges>(r#"["not-an-ip"]"#).is_err());
    }

    #[test]
    fn serializes_the_original_spelling() {
        let ranges = IpRanges::parse(["192.0.2.7", "10.0.0.0/8"]).unwrap();
        let json = serde_json::to_string(&ranges).unwrap();
        assert_eq!(json, r#"["192.0.2.7","10.0.0.0/8"]"#);
        assert_eq!(serde_json::from_str::<IpRanges>(&json).unwrap(), ranges);
    }
}
