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
pub mod connection_filter;

pub mod server;

pub use health_check::HealthChecker;
pub use rate_limit::{RateLimiter, RateLimitConfig, RateLimitInfo};
pub use load_balancer::{LoadBalancer, Strategy};
pub use upstream::Upstream;
pub use server::PingclairProxy;
pub use connection_filter::PingclairConnectionFilter;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_robin() {
        let u1 = Upstream::new("127.0.0.1:8001").unwrap();
        let u2 = Upstream::new("127.0.0.1:8002").unwrap();
        
        let lb = LoadBalancer::new(vec![u1, u2], Strategy::RoundRobin);

        let s1 = lb.select(None).unwrap();
        let s2 = lb.select(None).unwrap();
        let s3 = lb.select(None).unwrap();

        // Check addresses (using display for generic SocketAddr match)
        assert_eq!(s1.addr.to_string(), "127.0.0.1:8001");
        assert_eq!(s2.addr.to_string(), "127.0.0.1:8002");
        assert_eq!(s3.addr.to_string(), "127.0.0.1:8001");
    }

    // TODO: Re-enable these tests when we implement other strategies wrapping native
    /*
    #[test]
    fn test_least_conn() { ... }
    
    #[test]
    fn test_ip_hash() { ... }
    */
}
