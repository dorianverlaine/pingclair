// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚦 Exact, bounded local rate limiting for Pingclair.

use http::HeaderMap;
use parking_lot::Mutex;
use pingclair_core::config::RateLimitKey;
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_TRACKED_KEYS: usize = 65_536;
const PRUNE_EVERY_CHECKS: u64 = 1_024;

// MARK: - Configuration

/// 🚦 Defines one process-local token-bucket policy.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// 🎟️ Sets the steady quota refilled during one window.
    pub requests_per_window: u64,
    /// ⏱️ Sets the interval needed to refill the steady quota.
    pub window: Duration,
    /// 🔑 Selects the request identity charged by this limiter.
    pub key: RateLimitKey,
    /// 💥 Adds immediately usable capacity above the steady quota.
    pub burst: u64,
    /// 🧪 Counts and reports excess traffic without rejecting it.
    pub dry_run: bool,
    /// 🛣️ Names the route used by route-keyed policies.
    pub route: String,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_window: 100,
            window: Duration::from_secs(60),
            key: RateLimitKey::Ip,
            burst: 10,
            dry_run: false,
            route: String::new(),
        }
    }
}

// MARK: - Rate Limiter

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
}

#[derive(Debug, Default)]
struct BucketStore {
    buckets: HashMap<u64, Bucket>,
    checks: u64,
}

/// 🚦 Enforces exact token-bucket admission with bounded per-key state.
pub struct RateLimiter {
    /// 🧭 Exposes immutable policy needed by the protocol adapters.
    pub config: RateLimitConfig,
    buckets: Mutex<BucketStore>,
}

impl RateLimiter {
    /// 🏗️ Creates a shared limiter whose state starts empty.
    pub fn new(config: RateLimitConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            buckets: Mutex::new(BucketStore::default()),
        })
    }

    /// 🔎 Charges the configured identity and returns exact response metadata.
    pub fn check_request(
        &self,
        verified_client_ip: &str,
        headers: &HeaderMap,
    ) -> RateLimitDecision {
        let key = self.request_key(verified_client_ip, headers);
        self.check_key_at(key, Instant::now())
    }

    fn request_key(&self, verified_client_ip: &str, headers: &HeaderMap) -> u64 {
        let (namespace, value) = match &self.config.key {
            RateLimitKey::Ip => ("ip", verified_client_ip),
            RateLimitKey::Global => ("global", "global"),
            RateLimitKey::Route => ("route", self.config.route.as_str()),
            RateLimitKey::ApiKey => {
                let value = bearer_token(headers)
                    .or_else(|| header_text(headers, "x-api-key"))
                    .unwrap_or("<missing>");
                ("api_key", value)
            }
            RateLimitKey::Header(name) => {
                ("header", header_text(headers, name).unwrap_or("<missing>"))
            }
            RateLimitKey::Tenant(name) => {
                ("tenant", header_text(headers, name).unwrap_or("<missing>"))
            }
        };

        let mut hasher = DefaultHasher::new();
        namespace.hash(&mut hasher);
        value.hash(&mut hasher);
        hasher.finish()
    }

    fn check_key_at(&self, key: u64, now: Instant) -> RateLimitDecision {
        let capacity = self
            .config
            .requests_per_window
            .saturating_add(self.config.burst);
        let refill_per_second =
            self.config.requests_per_window as f64 / self.config.window.as_secs_f64();
        let idle_ttl = self
            .config
            .window
            .saturating_mul(2)
            .max(Duration::from_secs(60));
        let mut store = self.buckets.lock();
        store.checks = store.checks.wrapping_add(1);

        // 🧹 This request-path pruner removes keys idle for two windows every 1,024 checks.
        if store.checks.is_multiple_of(PRUNE_EVERY_CHECKS) {
            prune_idle_buckets(&mut store.buckets, now, idle_ttl);
        }
        if !store.buckets.contains_key(&key) && store.buckets.len() >= MAX_TRACKED_KEYS {
            prune_idle_buckets(&mut store.buckets, now, idle_ttl);
            if store.buckets.len() >= MAX_TRACKED_KEYS {
                return self.decision(true, 0, self.config.window, self.config.window);
            }
        }

        let bucket = store.buckets.entry(key).or_insert(Bucket {
            tokens: capacity as f64,
            last_refill: now,
            last_seen: now,
        });
        let elapsed = now.saturating_duration_since(bucket.last_refill);
        bucket.tokens =
            (bucket.tokens + elapsed.as_secs_f64() * refill_per_second).min(capacity as f64);
        bucket.last_refill = now;
        bucket.last_seen = now;

        let exceeded = bucket.tokens < 1.0;
        if !exceeded {
            bucket.tokens -= 1.0;
        }
        let remaining = bucket.tokens.floor().max(0.0) as u64;
        let reset_after =
            duration_for_tokens(capacity as f64 - bucket.tokens, refill_per_second, false);
        let retry_after = duration_for_tokens(1.0 - bucket.tokens, refill_per_second, true);
        self.decision(exceeded, remaining, reset_after, retry_after)
    }

    fn decision(
        &self,
        exceeded: bool,
        remaining: u64,
        reset_after: Duration,
        retry_after: Duration,
    ) -> RateLimitDecision {
        RateLimitDecision {
            reject: exceeded && !self.config.dry_run,
            info: RateLimitInfo {
                limit: self
                    .config
                    .requests_per_window
                    .saturating_add(self.config.burst),
                remaining,
                reset_after,
                retry_after: exceeded.then_some(retry_after),
                dry_run: self.config.dry_run,
            },
        }
    }
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 4_096)
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = header_text(headers, "authorization")?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token)
        .filter(|token| !token.is_empty())
}

fn duration_for_tokens(tokens: f64, refill_per_second: f64, at_least_one: bool) -> Duration {
    let seconds = (tokens.max(0.0) / refill_per_second).ceil() as u64;
    Duration::from_secs(if at_least_one {
        seconds.max(1)
    } else {
        seconds
    })
}

fn prune_idle_buckets(buckets: &mut HashMap<u64, Bucket>, now: Instant, idle_ttl: Duration) {
    buckets.retain(|_, bucket| now.saturating_duration_since(bucket.last_seen) < idle_ttl);
}

// MARK: - Status Info

/// 📊 Carries the admission decision and exact quota counters.
#[derive(Debug, Clone)]
pub struct RateLimitDecision {
    /// 🚫 Indicates whether the protocol adapter must return HTTP 429.
    pub reject: bool,
    /// 📈 Supplies response metadata for allowed, dry-run, and rejected requests.
    pub info: RateLimitInfo,
}

/// 📊 Describes the exact state after charging one request.
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    /// 🎟️ Reports the total immediate bucket capacity, including burst.
    pub limit: u64,
    /// 🪙 Reports whole tokens immediately available to the next request.
    pub remaining: u64,
    /// ⏳ Reports seconds until the bucket is full again.
    pub reset_after: Duration,
    /// 🛑 Reports when a rejected request can safely retry.
    pub retry_after: Option<Duration>,
    /// 🧪 Indicates that excess requests are only observed.
    pub dry_run: bool,
}

impl RateLimitInfo {
    /// 🧾 Converts exact state into interoperable rate-limit response fields.
    pub fn to_headers(&self) -> Vec<(String, String)> {
        let mut headers = vec![
            ("RateLimit-Limit".to_string(), self.limit.to_string()),
            (
                "RateLimit-Remaining".to_string(),
                self.remaining.to_string(),
            ),
            (
                "RateLimit-Reset".to_string(),
                self.reset_after.as_secs().to_string(),
            ),
        ];
        if let Some(retry_after) = self.retry_after {
            headers.push(("Retry-After".to_string(), retry_after.as_secs().to_string()));
        }
        if self.dry_run {
            headers.push(("RateLimit-Dry-Run".to_string(), "true".to_string()));
        }
        headers
    }
}

// MARK: - Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn config(requests: u64, burst: u64) -> RateLimitConfig {
        RateLimitConfig {
            requests_per_window: requests,
            window: Duration::from_secs(60),
            key: RateLimitKey::Ip,
            burst,
            dry_run: false,
            route: "/api".into(),
        }
    }

    #[test]
    fn burst_capacity_has_an_exact_boundary() {
        let limiter = RateLimiter::new(config(5, 2));
        let started = Instant::now();

        // 🧪 The base quota plus two burst tokens admits exactly seven requests.
        for request in 1..=7 {
            let decision = limiter.check_key_at(1, started);
            assert!(!decision.reject, "request {request} must fit");
            assert_eq!(decision.info.remaining, 7 - request);
        }
        let rejected = limiter.check_key_at(1, started);
        assert!(rejected.reject);
        assert_eq!(rejected.info.remaining, 0);
        assert_eq!(rejected.info.retry_after, Some(Duration::from_secs(12)));
    }

    #[test]
    fn steady_quota_refills_exactly_after_one_window() {
        let limiter = RateLimiter::new(config(5, 2));
        let started = Instant::now();
        for _ in 0..7 {
            assert!(!limiter.check_key_at(1, started).reject);
        }

        let refilled = limiter.check_key_at(1, started + Duration::from_secs(60));
        assert!(!refilled.reject);
        assert_eq!(refilled.info.remaining, 4);
    }

    #[test]
    fn dry_run_counts_excess_without_rejecting_it() {
        let mut policy = config(1, 0);
        policy.dry_run = true;
        let limiter = RateLimiter::new(policy);
        let started = Instant::now();
        assert!(!limiter.check_key_at(1, started).reject);

        let excess = limiter.check_key_at(1, started);
        assert!(!excess.reject);
        assert_eq!(excess.info.remaining, 0);
        assert_eq!(excess.info.retry_after, Some(Duration::from_secs(60)));
        assert!(
            excess
                .info
                .to_headers()
                .contains(&("RateLimit-Dry-Run".into(), "true".into()))
        );
    }

    #[test]
    fn configured_header_values_receive_independent_buckets() {
        let mut policy = config(1, 0);
        policy.key = RateLimitKey::Header("X-Plan".into());
        let limiter = RateLimiter::new(policy);
        let mut first = HeaderMap::new();
        first.insert("x-plan", "starter".parse().unwrap());
        let mut second = HeaderMap::new();
        second.insert("x-plan", "enterprise".parse().unwrap());

        assert!(!limiter.check_request("127.0.0.1", &first).reject);
        assert!(limiter.check_request("127.0.0.1", &first).reject);
        assert!(!limiter.check_request("127.0.0.1", &second).reject);
    }

    #[test]
    fn api_key_tenant_and_route_sources_are_independent() {
        let mut api_policy = config(1, 0);
        api_policy.key = RateLimitKey::ApiKey;
        let api_limiter = RateLimiter::new(api_policy);
        let mut first_api = HeaderMap::new();
        first_api.insert("authorization", "Bearer alpha".parse().unwrap());
        let mut second_api = HeaderMap::new();
        second_api.insert("x-api-key", "bravo".parse().unwrap());
        assert!(!api_limiter.check_request("127.0.0.1", &first_api).reject);
        assert!(api_limiter.check_request("127.0.0.1", &first_api).reject);
        assert!(!api_limiter.check_request("127.0.0.1", &second_api).reject);

        let mut tenant_policy = config(1, 0);
        tenant_policy.key = RateLimitKey::Tenant("X-Tenant-ID".into());
        let tenant_limiter = RateLimiter::new(tenant_policy);
        let mut first_tenant = HeaderMap::new();
        first_tenant.insert("x-tenant-id", "tenant-a".parse().unwrap());
        let mut second_tenant = HeaderMap::new();
        second_tenant.insert("x-tenant-id", "tenant-b".parse().unwrap());
        assert!(
            !tenant_limiter
                .check_request("127.0.0.1", &first_tenant)
                .reject
        );
        assert!(
            !tenant_limiter
                .check_request("127.0.0.1", &second_tenant)
                .reject
        );

        let headers = HeaderMap::new();
        let mut first_route_policy = config(1, 0);
        first_route_policy.key = RateLimitKey::Route;
        let first_route = RateLimiter::new(first_route_policy);
        let mut second_route_policy = config(1, 0);
        second_route_policy.key = RateLimitKey::Route;
        second_route_policy.route = "/other".into();
        let second_route = RateLimiter::new(second_route_policy);
        assert_ne!(
            first_route.request_key("127.0.0.1", &headers),
            second_route.request_key("127.0.0.1", &headers)
        );
    }

    #[test]
    fn idle_bucket_pruner_removes_rotated_identity_state() {
        let limiter = RateLimiter::new(config(1, 0));
        let started = Instant::now();
        assert!(!limiter.check_key_at(1, started).reject);
        {
            let mut store = limiter.buckets.lock();
            prune_idle_buckets(
                &mut store.buckets,
                started + Duration::from_secs(121),
                Duration::from_secs(120),
            );
            assert!(store.buckets.is_empty());
        }
        assert!(
            !limiter
                .check_key_at(1, started + Duration::from_secs(121))
                .reject
        );
    }
}
