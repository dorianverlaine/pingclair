// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔌 Declarative TCP routing shared by configuration and the future L4 runtime.

use serde::{Deserialize, Serialize};

/// 🔌 One plain TCP listener; TLS belongs to the selected upstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layer4Server {
    /// 📍 An IP socket address, with `:port` denoting a wildcard.
    pub listen: String,
    /// ⏱️ One deadline for classification, in milliseconds.
    #[serde(default = "preread_timeout")]
    pub preread_timeout_ms: u64,
    /// 📦 Maximum bytes retained while classifying the connection.
    #[serde(default = "buffer_size")]
    pub preread_buffer_size: usize,
    /// ⏱️ Maximum upstream connection time, in milliseconds.
    #[serde(default = "connect_timeout")]
    pub proxy_connect_timeout_ms: u64,
    /// ⏱️ Maximum inactivity between I/O operations, in milliseconds.
    #[serde(default = "proxy_timeout")]
    pub proxy_timeout_ms: u64,
    /// 🌊 Whether EOF shuts down only the corresponding write direction.
    #[serde(default)]
    pub proxy_half_close: bool,
    /// 📦 Relay buffer capacity for each direction.
    #[serde(default = "buffer_size")]
    pub proxy_buffer_size: usize,
    /// 🧭 Routes retain declaration order; the first match wins.
    pub routes: Vec<Layer4Route>,
}

/// 🧭 A route selects one upstream without interpreting HTTP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layer4Route {
    /// 🔎 Alternative matcher sets; an empty list is unconditional.
    #[serde(default)]
    pub matches: Vec<Layer4Matcher>,
    /// 📍 One static host and port; resolution belongs to provisioning.
    pub upstream: String,
}

/// 🔎 Conditions within a set are ANDed; values within a condition are ORed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layer4Matcher {
    /// 🔐 TLS metadata required by this set, including a bare TLS match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<Layer4TlsMatcher>,
    /// 🛡️ Literal peer addresses or CIDRs, compiled at load time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_ip: Vec<String>,
}

/// 🔐 Exact SNI and ALPN matches; this does not negotiate TLS.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layer4TlsMatcher {
    /// 🏷️ Exact case-insensitive hostnames; ECH exposes only the outer name.
    #[serde(default)]
    pub sni: Vec<String>,
    /// 🤝 Exact case-sensitive protocol identifiers offered by the client.
    #[serde(default)]
    pub alpn: Vec<String>,
}

fn preread_timeout() -> u64 {
    30_000
}
fn connect_timeout() -> u64 {
    60_000
}
fn proxy_timeout() -> u64 {
    600_000
}
fn buffer_size() -> usize {
    16 * 1024
}

impl Layer4Server {
    /// 🔌 Starts a declaration with nginx stream defaults.
    pub fn new(listen: String) -> Self {
        Self {
            listen,
            preread_timeout_ms: preread_timeout(),
            preread_buffer_size: buffer_size(),
            proxy_connect_timeout_ms: connect_timeout(),
            proxy_timeout_ms: proxy_timeout(),
            proxy_half_close: false,
            proxy_buffer_size: buffer_size(),
            routes: Vec::new(),
        }
    }
}
