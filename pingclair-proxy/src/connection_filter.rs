// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use async_trait::async_trait;
use ipnet::IpNet;
use pingora_core::listeners::ConnectionFilter;
use std::net::SocketAddr;

// MARK: - Connection Filter

/// Connection filter that blocks requests from specific IP addresses/CIDRs
#[derive(Debug)]
pub struct PingclairConnectionFilter {
    blocked_cidrs: Vec<IpNet>,
}

impl PingclairConnectionFilter {
    /// 🛡️ Creates a filter over networks that were parsed once at startup.
    ///
    /// 📌 Parsing belongs to configuration: `validate_config` refuses an entry
    /// that is not an address or CIDR, so every string reaching the listener
    /// is already a network. This used to parse again here and drop a bad
    /// entry with a warning, which turned a typo in a block list into an
    /// address that was never blocked.
    pub fn new(blocked_cidrs: Vec<IpNet>) -> Self {
        if !blocked_cidrs.is_empty() {
            tracing::info!(
                count = blocked_cidrs.len(),
                "🛡️ Initialized L4 connection filter"
            );
        }

        Self { blocked_cidrs }
    }
    /// Synchronous blocklist check for a peer socket address.
    ///
    /// The QUIC (UDP) path has no async `ConnectionFilter` hook, so it
    /// consults this directly from the datagram loop.
    pub fn allows(&self, addr: &SocketAddr) -> bool {
        if self.blocked_cidrs.is_empty() {
            return true;
        }

        let ip = addr.ip();
        for cidr in &self.blocked_cidrs {
            if cidr.contains(&ip) {
                tracing::debug!("🚫 Blocked connection from {} (matched {})", ip, cidr);
                return false;
            }
        }
        true
    }
}

// MARK: - ConnectionFilter Trait

#[async_trait]
impl ConnectionFilter for PingclairConnectionFilter {
    /// Determines if a connection from the given address should be accepted.
    ///
    /// checks the source IP against the configured blocklist.
    ///
    /// - Parameter addr_opt: The socket address of the client connection.
    /// - Returns: `true` if the connection is allowed, `false` if blocked.
    async fn should_accept(&self, addr_opt: Option<&SocketAddr>) -> bool {
        match addr_opt {
            Some(addr) => self.allows(addr),
            None => true,
        }
    }
}

// MARK: - Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_filter() {
        // Block loopback and a specific CIDR
        let blocked = vec![
            "127.0.0.1/32".parse().unwrap(),
            "192.168.1.0/24".parse().unwrap(),
        ];
        let filter = PingclairConnectionFilter::new(blocked);

        // Blocked IPs
        let addr1: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert!(!filter.should_accept(Some(&addr1)).await);

        let addr2: SocketAddr = "192.168.1.50:9000".parse().unwrap();
        assert!(!filter.should_accept(Some(&addr2)).await);

        // Allowed IPs
        let addr3: SocketAddr = "10.0.0.1:80".parse().unwrap();
        assert!(filter.should_accept(Some(&addr3)).await);

        // Edge case: Allowed IP just outside CIDR
        let addr4: SocketAddr = "192.168.2.1:80".parse().unwrap();
        assert!(filter.should_accept(Some(&addr4)).await);
    }

    #[tokio::test]
    async fn test_empty_filter() {
        let filter = PingclairConnectionFilter::new(Vec::new());
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert!(filter.should_accept(Some(&addr)).await);
    }
}
