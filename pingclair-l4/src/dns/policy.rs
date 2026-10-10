// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ Compiled destination policy applied to the complete DNS answer before publication.
//!
//! 📌 The tables and the allowance rule live in
//! [`pingclair_core::config::address_policy`], because the validator asks the
//! same question while the configuration loads. What stays here is the part
//! only the runtime can answer: which destinations are this process's own.

use ipnet::IpNet;
use pingclair_core::config::{allowance, is_public_unicast};
use std::io;
use std::net::SocketAddr;

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
        let compiled = allow
            .unwrap_or_default()
            .iter()
            .map(|value| allowance(value).map_err(io::Error::other))
            .collect::<io::Result<Vec<_>>>()?;
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
        is_public_unicast(ip) || self.allow.iter().any(|net| net.contains(&ip))
    }
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
