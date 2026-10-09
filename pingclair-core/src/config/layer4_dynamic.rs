// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌐 Declarative DNS policy; resolver state belongs to the L4 runtime.

use serde::{Deserialize, Serialize};

/// 🌐 An explicitly tagged L4 address source.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Layer4Dynamic {
    /// 📍 A and AAAA records with a fixed destination port.
    A(Layer4Dns),
}

/// 🌐 Fixed DNS and address policy for one dynamic pool.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layer4Dns {
    /// 🏷️ A fixed DNS name; client metadata cannot supply it.
    pub name: String,
    /// 📍 A nonzero port which DNS responses cannot change.
    pub port: u16,
    /// 🌐 Numeric resolver endpoints; omission selects the system configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolvers: Option<Vec<String>>,
    /// 🌐 Address families queried by the background resolver.
    #[serde(default)]
    pub versions: Layer4IpVersions,
    /// ⏱️ An optional positive override for the answer's minimum TTL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_ms: Option<u64>,
    /// ⏳ Additional grace after freshness expires, bounded to five minutes.
    #[serde(default = "stale")]
    pub stale_ms: u64,
    /// 🛡️ Additional allowed destination CIDRs; omission permits public unicast only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_ip: Option<Vec<String>>,
}

/// 🌐 A closed set prevents silent fallback from unknown family names.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer4IpVersions {
    /// 🌐 Query A records only.
    Ipv4,
    /// 🌐 Query AAAA records only.
    Ipv6,
    /// 🌐 Query both address families.
    #[default]
    Ip,
}

fn stale() -> u64 {
    60_000
}
