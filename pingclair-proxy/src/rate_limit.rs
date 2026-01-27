//! Rate limiting module for Pingclair
//!
//! Implements token bucket algorithm for rate limiting requests.
//! Supports per-IP, per-route, and global rate limits.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use std::sync::Arc;

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per window
    pub requests_per_window: u64,
    /// Time window duration
    pub window: Duration,
    /// Whether to limit by IP address
    pub by_ip: bool,
    /// Burst size (extra requests allowed in short time)
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

/// Token bucket for rate limiting
#[derive(Debug)]
struct TokenBucket {
    /// Available tokens
    tokens: f64,
    /// Last update time
    last_update: Instant,
    /// Maximum capacity (burst size)
    capacity: f64,
    /// Token refill rate per second
    refill_rate: f64,
}

impl TokenBucket {
    fn new(capacity: u64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity as f64,
            last_update: Instant::now(),
            capacity: capacity as f64,
            refill_rate,
        }
    }
    
    /// Try to consume a token, returns true if allowed
    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
    
    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_update = now;
    }
    
    /// Get remaining tokens
    fn remaining(&self) -> u64 {
        self.tokens as u64
    }
    
    /// Get reset time in seconds
    fn reset_after(&self) -> Duration {
        if self.tokens >= self.capacity {
            Duration::ZERO
        } else {
            let tokens_needed = self.capacity - self.tokens;
            Duration::from_secs_f64(tokens_needed / self.refill_rate)
        }
    }
}

/// Rate limiter using token bucket algorithm
pub struct RateLimiter {
    pub config: RateLimitConfig,
    /// Per-key buckets (IP address or route)
    buckets: RwLock<HashMap<String, TokenBucket>>,
    /// Global bucket (if by_ip is false)
    global_bucket: RwLock<TokenBucket>,
}

impl RateLimiter {
    /// Create a new rate limiter with config
    pub fn new(config: RateLimitConfig) -> Arc<Self> {
        let refill_rate = config.requests_per_window as f64 / config.window.as_secs_f64();
        let capacity = config.requests_per_window + config.burst;
        
        Arc::new(Self {
            config: config.clone(),
            buckets: RwLock::new(HashMap::new()),
            global_bucket: RwLock::new(TokenBucket::new(capacity, refill_rate)),
        })
    }
    
    /// Check if a request should be allowed
    /// Returns Ok(()) if allowed, Err(RateLimitInfo) if rate limited
    pub fn check(&self, key: Option<&str>) -> Result<(), RateLimitInfo> {
        if self.config.by_ip {
            let key = key.unwrap_or("unknown");
            self.check_key(key)
        } else {
            self.check_global()
        }
    }
    
    fn check_key(&self, key: &str) -> Result<(), RateLimitInfo> {
        let mut buckets = self.buckets.write();
        
        let bucket = buckets.entry(key.to_string()).or_insert_with(|| {
            let refill_rate = self.config.requests_per_window as f64 / self.config.window.as_secs_f64();
            let capacity = self.config.requests_per_window + self.config.burst;
            TokenBucket::new(capacity, refill_rate)
        });
        
        if bucket.try_consume() {
            Ok(())
        } else {
            Err(RateLimitInfo {
                limit: self.config.requests_per_window,
                remaining: bucket.remaining(),
                reset_after: bucket.reset_after(),
            })
        }
    }
    
    fn check_global(&self) -> Result<(), RateLimitInfo> {
        let mut bucket = self.global_bucket.write();
        
        if bucket.try_consume() {
            Ok(())
        } else {
            Err(RateLimitInfo {
                limit: self.config.requests_per_window,
                remaining: bucket.remaining(),
                reset_after: bucket.reset_after(),
            })
        }
    }
    
    /// Clean up old buckets to prevent memory leak
    /// Should be called periodically
    pub fn cleanup(&self, max_age: Duration) {
        let mut buckets = self.buckets.write();
        let now = Instant::now();
        
        buckets.retain(|_, bucket| {
            now.duration_since(bucket.last_update) < max_age
        });
    }
}

/// Information about rate limit status
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    /// Maximum requests per window
    pub limit: u64,
    /// Remaining requests in current window
    pub remaining: u64,
    /// Time until rate limit resets
    pub reset_after: Duration,
}

impl RateLimitInfo {
    /// Format as HTTP headers
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
    fn test_rate_limiter_allows_under_limit() {
        let config = RateLimitConfig {
            requests_per_window: 10,
            window: Duration::from_secs(60),
            by_ip: true,
            burst: 0,
        };
        
        let limiter = RateLimiter::new(config);
        
        // Should allow 10 requests
        for _ in 0..10 {
            assert!(limiter.check(Some("192.168.1.1")).is_ok());
        }
        
        // 11th request should be rate limited
        assert!(limiter.check(Some("192.168.1.1")).is_err());
    }
    
    #[test]
    fn test_rate_limiter_different_ips() {
        let config = RateLimitConfig {
            requests_per_window: 5,
            window: Duration::from_secs(60),
            by_ip: true,
            burst: 0,
        };
        
        let limiter = RateLimiter::new(config);
        
        // Use up limit for IP1
        for _ in 0..5 {
            assert!(limiter.check(Some("192.168.1.1")).is_ok());
        }
        assert!(limiter.check(Some("192.168.1.1")).is_err());
        
        // IP2 should still have its own limit
        for _ in 0..5 {
            assert!(limiter.check(Some("192.168.1.2")).is_ok());
        }
    }
}
