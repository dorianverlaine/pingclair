use async_trait::async_trait;
use pingora_core::listeners::ConnectionFilter;
use std::net::{IpAddr, SocketAddr};
// use std::sync::Arc; // Removed unused import
use ipnet::IpNet;

/// Connection filter that blocks requests from specific IP addresses/CIDRs
#[derive(Debug)]
pub struct PingclairConnectionFilter {
    blocked_cidrs: Vec<IpNet>,
}

impl PingclairConnectionFilter {
    /// Create a new connection filter
    pub fn new(blocked_ips: &[String]) -> Self {
        let mut blocked_cidrs = Vec::new();
        
        for ip_str in blocked_ips {
            match ip_str.parse::<IpNet>() {
                Ok(cidr) => blocked_cidrs.push(cidr),
                Err(_) => {
                    // Try parsing as single IP
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        blocked_cidrs.push(IpNet::from(ip));
                    } else {
                        tracing::warn!("⚠️ Invalid blocked IP/CIDR: {}", ip_str);
                    }
                }
            }
        }
        
        if !blocked_cidrs.is_empty() {
            tracing::info!("🛡️ Initialized L4 connection filter with {} blocked CIDR(s)", blocked_cidrs.len());
        }

        Self { blocked_cidrs }
    }
}

#[async_trait]
impl ConnectionFilter for PingclairConnectionFilter {
    async fn should_accept(&self, addr_opt: Option<&SocketAddr>) -> bool {
        if self.blocked_cidrs.is_empty() {
            return true;
        }

        if let Some(addr) = addr_opt {
            let ip = addr.ip();
            for cidr in &self.blocked_cidrs {
                if cidr.contains(&ip) {
                    tracing::debug!("🚫 Blocked connection from {} (matched {})", ip, cidr);
                    return false;
                }
            }
        }
        
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_filter() {
        // Block loopback and a specific CIDR
        let blocked = vec![
            "127.0.0.1".to_string(), 
            "192.168.1.0/24".to_string()
        ];
        let filter = PingclairConnectionFilter::new(&blocked);

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
        let filter = PingclairConnectionFilter::new(&[]);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert!(filter.should_accept(Some(&addr)).await);
    }
}
