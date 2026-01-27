//! Load balancing strategies

use crate::upstream::{Upstream, UpstreamPool};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Load balancing strategy
#[derive(Debug, Clone, Copy, Default)]
pub enum Strategy {
    /// Round-robin selection
    #[default]
    RoundRobin,
    /// Random selection
    Random,
    /// Least connections
    LeastConn,
    /// IP hash based
    IpHash,
    /// Always first available
    First,
}

/// Load balancer for upstream selection
pub struct LoadBalancer {
    pool: Arc<UpstreamPool>,
    strategy: Strategy,
    counter: AtomicUsize,
}

impl LoadBalancer {
    /// Create a new load balancer
    pub fn new(pool: Arc<UpstreamPool>, strategy: Strategy) -> Self {
        Self {
            pool,
            strategy,
            counter: AtomicUsize::new(0),
        }
    }

    /// Select an upstream based on the strategy
    /// 
    /// `key` is optional data (like Client IP) for hash-based strategies
    pub fn select(&self, key: Option<&[u8]>) -> Option<Arc<Upstream>> {
        let healthy = self.pool.healthy();
        if healthy.is_empty() {
            return None;
        }

        match self.strategy {
            Strategy::RoundRobin => {
                let idx = self.counter.fetch_add(1, Ordering::Relaxed) % healthy.len();
                healthy.get(idx).cloned()
            }
            Strategy::Random => {
                use std::collections::hash_map::RandomState;
                use std::hash::{BuildHasher, Hasher};
                let idx = RandomState::new().build_hasher().finish() as usize % healthy.len();
                healthy.get(idx).cloned()
            }
            Strategy::First => healthy.first().cloned(),
            Strategy::LeastConn => {
                // Find upstream with minimum active connections
                healthy.iter()
                    .min_by_key(|u| u.connections())
                    .cloned()
            }
            Strategy::IpHash => {
                if let Some(key_bytes) = key {
                    let mut hasher = DefaultHasher::new();
                    key_bytes.hash(&mut hasher);
                    let hash = hasher.finish();
                    let idx = hash as usize % healthy.len();
                    healthy.get(idx).cloned()
                } else {
                    // Fallback to round robin if no key provided
                    let idx = self.counter.fetch_add(1, Ordering::Relaxed) % healthy.len();
                    healthy.get(idx).cloned()
                }
            }
        }
    }
}
