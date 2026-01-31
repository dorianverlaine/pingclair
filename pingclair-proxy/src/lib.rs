//! Pingclair Reverse Proxy Module
//!
//! This crate provides reverse proxy functionality including:
//! - Upstream management
//! - Load balancing strategies
//! - Health checking
//! - Rate limiting

// MARK: - Modules

pub mod health_check;
pub mod rate_limit;
pub mod metrics;
pub mod quic;
mod load_balancer;
mod upstream;
pub mod connection_filter;
pub mod server;

// MARK: - Exports

pub use health_check::HealthChecker;
pub use rate_limit::{RateLimiter, RateLimitConfig, RateLimitInfo};
pub use load_balancer::{LoadBalancer, Strategy};
pub use upstream::Upstream;
pub use server::PingclairProxy;
pub use connection_filter::PingclairConnectionFilter;

// MARK: - Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_robin() {
        // Setup scenarios
        let upstream1 = Upstream::new("127.0.0.1:8001").unwrap();
        let upstream2 = Upstream::new("127.0.0.1:8002").unwrap();
        
        let load_balancer = LoadBalancer::new(vec![upstream1, upstream2], Strategy::RoundRobin);

        // Verification
        let s1 = load_balancer.select(None).unwrap();
        let s2 = load_balancer.select(None).unwrap();
        let s3 = load_balancer.select(None).unwrap();

        // Check addresses (using display for generic SocketAddr match)
        assert_eq!(s1.addr.to_string(), "127.0.0.1:8001");
        assert_eq!(s2.addr.to_string(), "127.0.0.1:8002");
        assert_eq!(s3.addr.to_string(), "127.0.0.1:8001");
    }
}
