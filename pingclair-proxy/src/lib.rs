// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Pingclair Reverse Proxy Module
//!
//! This crate provides reverse proxy functionality including:
//! - Upstream management
//! - Load balancing strategies
//! - Health checking
//! - Rate limiting

// MARK: - Modules

pub mod access_log;
mod acme_challenge;
pub mod alt_svc;
mod body_buffer;
mod cache_policy;
mod cache_vary;
pub mod client_auth;
pub mod connection_filter;
pub mod dns;
pub mod drain;
pub mod dynamic_upstream;
pub mod encoding;
mod fastcgi;
mod header_limits;
pub mod health_check;
mod http_policy;
pub mod listener_generation;
pub mod load_balancer;
pub mod metrics;
pub mod overload;
pub mod proxy_protocol;
mod proxy_status;
pub mod quic;
pub mod rate_limit;
pub mod readiness;
pub mod redaction;
mod response_encoding;
mod retry;
pub mod server;
mod subrequest;
pub mod tls_identity;
pub mod tls_name_alert;
pub mod upstream;
pub mod upstream_failure;
pub mod upstream_tls;

// MARK: - Exports

pub use connection_filter::PingclairConnectionFilter;
pub use header_limits::protocol_header_list_limit;
pub use health_check::HealthChecker;
pub use load_balancer::{DnsRefresh, FAIL_COOLDOWN, LoadBalancer, Strategy, UpstreamEntry};
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
