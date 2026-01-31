//! Native Rate Limiting for Pingclair
//!
//! Implements high-performance rate limiting using Pingora's native `pingora-limits` crate.
//! Utilizes probabilistic data structures (Count-Min Sketch) for efficient, lock-minimized rate estimation.

use std::time::Duration;
use std::sync::Arc;
use pingora_limits::rate::Rate;
use pingora_limits::rate::PROPORTIONAL_RATE_ESTIMATE_CALC_FN;

// MARK: - Configuration

/// Configuration for the Rate Limiter.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum allowed requests per time window.
    pub requests_per_window: u64,
    
    /// The duration of the sliding window for rate estimation.
    pub window: Duration,
    
    /// If true, limits are applied per IP address. If false, a global limit is applied.
    pub by_ip: bool,
    
    /// Burst allowance.
    /// Note: `pingora-limits` uses a smoothed rate estimator, so "burst" is implicitly handled
    /// by the windowing logic rather than a strict token bucket capacity.
    pub burst: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_window: 100,
            window: Duration::from_secs(60),
            by_ip: true,
            burst: 10,
        }
    }
}

// MARK: - Rate Limiter

/// A high-performance rate limiter wrapping Pingora's native `Rate` estimator.
///
/// Designed for high concurrency, it avoids heavy locking by using atomic operations
/// and probabilistic counting.
pub struct RateLimiter {
    /// The configuration for this limiter.
    pub config: RateLimitConfig,
    
    /// The underlying native rate estimator.
    rate_estimator: Rate,
}

impl RateLimiter {
    /// Creates a new `RateLimiter` with the given configuration.
    ///
    /// - Parameter config: The `RateLimitConfig` defining limits and window.
    /// - Returns: An `Arc` wrapped `RateLimiter` ready for shared use.
    pub fn new(config: RateLimitConfig) -> Arc<Self> {
        // Initialize Pingora's Rate estimator with the configured window.
        // The window defines the granularity of the sliding window estimation.
        let rate_estimator = Rate::new(config.window);
        
        Arc::new(Self {
            config,
            rate_estimator,
        })
    }
    
    /// Checks if a request should be allowed based on the current rate.
    ///
    /// - Parameter key: An optional key (e.g., IP address) to track usage against.
    ///   If `None` or if `by_ip` is false, falls back to a global "unknown" or "global" key.
    /// - Returns: `Ok(())` if allowed, `Err(RateLimitInfo)` if the limit is exceeded.
    ///
    /// **Algorithm:**
    /// 1. Observes (increments) the counter for the given key.
    /// 2. Calculates the current Requests Per Second (RPS) using a proportional estimate.
    /// 3. Compares the estimated RPS against the configured limit (normalized to RPS).
    pub fn check(&self, key: Option<&str>) -> Result<(), RateLimitInfo> {
        // Determine the lookup key
        let lookup_key = if self.config.by_ip {
            key.unwrap_or("unknown")
        } else {
            "global"
        };
        
        // 1. Observe: Register this request event
        self.rate_estimator.observe(&lookup_key, 1);
        
        // 2. Estimate: Calculate current rate (events per second)
        let current_rps = self.rate_estimator.rate_with(&lookup_key, PROPORTIONAL_RATE_ESTIMATE_CALC_FN);
        
        // 3. Limit: Convert limit to RPS (Requests / WindowSeconds)
        let limit_rps = self.config.requests_per_window as f64 / self.config.window.as_secs_f64();
        
        // 4. Decision: Check if we strictly exceed the limit
        if current_rps > limit_rps {
             return Err(RateLimitInfo {
                limit: self.config.requests_per_window,
                remaining: 0, // Probabilistic estimator does not track exact "remaining" count
                reset_after: self.config.window,
            });
        }
        
        Ok(())
    }
}

// MARK: - Status Info

/// Detailed information about a rate limit violation or status.
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    /// The configured maximum requests per window.
    pub limit: u64,
    
    /// estimated remaining requests (approximated).
    pub remaining: u64,
    
    /// Duration until the limit window resets.
    pub reset_after: Duration,
}

impl RateLimitInfo {
    /// Converts the status info into standard HTTP RateLimit headers.
    ///
    /// - Returns: A vector of (HeaderName, HeaderValue) tuples.
    pub fn to_headers(&self) -> Vec<(String, String)> {
        vec![
            ("X-RateLimit-Limit".to_string(), self.limit.to_string()),
            ("X-RateLimit-Remaining".to_string(), self.remaining.to_string()),
            ("Retry-After".to_string(), self.reset_after.as_secs().to_string()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rate_limiter_basic() {
        let config = RateLimitConfig {
            requests_per_window: 10,
            window: Duration::from_secs(1), // 10 RPS
            by_ip: true,
            burst: 0,
        };
        
        let limiter = RateLimiter::new(config);
        
        // Should allow 10 requests easily
        for _ in 0..10 {
            assert!(limiter.check(Some("192.168.1.1")).is_ok());
        }
        
        // Stress test: Eventually should block
        let mut blocked = false;
        for _ in 0..20 {
             if limiter.check(Some("192.168.1.1")).is_err() {
                 blocked = true;
                 break;
             }
        }
        assert!(blocked, "Should have rate limited eventual requests");
    }
    
    #[test]
    fn test_rate_limiter_different_ips() {
        let config = RateLimitConfig {
            requests_per_window: 5,
            window: Duration::from_secs(1),
            by_ip: true,
            burst: 0,
        };
        
        let limiter = RateLimiter::new(config);
        
        // Use up limit for IP1
        for _ in 0..5 { // Reduced from 10 to ensure we don't accidentally hit global probability collisions in test
            let _ = limiter.check(Some("192.168.1.1"));
        }
        
        // IP2 should still be allowed
        assert!(limiter.check(Some("192.168.1.2")).is_ok());
    }
}
