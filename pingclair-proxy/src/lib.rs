//! Pingclair Reverse Proxy Module
//!
//! This crate provides reverse proxy functionality including:
//! - Upstream management
//! - Load balancing strategies
//! - Health checking
//! - Rate limiting

// MARK: - Modules

pub mod access_log;
pub mod alt_svc;
pub mod connection_filter;
pub mod encoding;
pub mod health_check;
mod http_policy;
mod load_balancer;
pub mod metrics;
pub mod quic;
pub mod rate_limit;
pub mod redaction;
pub mod server;
mod upstream;

// MARK: - Exports

pub use connection_filter::PingclairConnectionFilter;
pub use health_check::HealthChecker;
pub use load_balancer::{FAIL_COOLDOWN, LoadBalancer, Strategy};
pub use rate_limit::{RateLimitConfig, RateLimitInfo, RateLimiter};
pub use server::PingclairProxy;
pub use upstream::Upstream;

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
