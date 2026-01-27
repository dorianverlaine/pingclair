//! Pingclair Reverse Proxy Module
//!
//! This crate provides reverse proxy functionality including:
//! - Upstream management
//! - Load balancing strategies
//! - Health checking
//! - Rate limiting

pub mod health_check;
pub mod rate_limit;
pub mod metrics;
pub mod quic;
mod load_balancer;
mod upstream;

pub mod server;

pub use health_check::HealthChecker;
pub use rate_limit::{RateLimiter, RateLimitConfig, RateLimitInfo};
pub use load_balancer::{LoadBalancer, Strategy};
pub use upstream::{Upstream, UpstreamPool};
pub use server::PingclairProxy;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_round_robin() {
        let u1 = Upstream::new("127.0.0.1:8001");
        let u2 = Upstream::new("127.0.0.1:8002");
        let pool = Arc::new(UpstreamPool::new(vec![u1, u2]));
        let lb = LoadBalancer::new(pool, Strategy::RoundRobin);

        let s1 = lb.select(None).unwrap();
        let s2 = lb.select(None).unwrap();
        let s3 = lb.select(None).unwrap();

        assert_eq!(s1.addr, "127.0.0.1:8001");
        assert_eq!(s2.addr, "127.0.0.1:8002");
        assert_eq!(s3.addr, "127.0.0.1:8001");
    }

    #[test]
    fn test_least_conn() {
        let u1 = Upstream::new("127.0.0.1:8001"); // 0 conn
        let u2 = Upstream::new("127.0.0.1:8002"); // 0 conn
        
        // Artificially increase connections on u1
        u1.inc_connections();
        
        let pool = Arc::new(UpstreamPool::new(vec![u1, u2]));
        let lb = LoadBalancer::new(pool, Strategy::LeastConn);

        // Should pick u2 (0 connections)
        let s1 = lb.select(None).unwrap();
        assert_eq!(s1.addr, "127.0.0.1:8002");
        
        // Increase connections on u2 manually (simulating active usage)
        s1.inc_connections();
        s1.inc_connections(); 
        // Now u1=1, u2=2
        
        // Should pick u1
        let s2 = lb.select(None).unwrap();
        assert_eq!(s2.addr, "127.0.0.1:8001");
    }

    #[test]
    fn test_ip_hash() {
        let u1 = Upstream::new("127.0.0.1:8001");
        let u2 = Upstream::new("127.0.0.1:8002");
        let u3 = Upstream::new("127.0.0.1:8003");
        
        let pool = Arc::new(UpstreamPool::new(vec![u1, u2, u3]));
        let lb = LoadBalancer::new(pool, Strategy::IpHash);

        let client_a = "192.168.1.1".as_bytes();
        let client_b = "192.168.1.2".as_bytes();
        
        // Consistent hashing for Client A
        let s1 = lb.select(Some(client_a)).unwrap();
        let s2 = lb.select(Some(client_a)).unwrap();
        assert_eq!(s1.addr, s2.addr);
        
        // Different (likely) for Client B
        let s3 = lb.select(Some(client_b)).unwrap();
        assert!(["127.0.0.1:8001", "127.0.0.1:8002", "127.0.0.1:8003"].contains(&s3.addr.as_str()));
    }
}
