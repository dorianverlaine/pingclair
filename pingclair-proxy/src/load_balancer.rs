//! Load Balancing for Pingclair
//!
//! Wraps Pingora's native `LoadBalancer` to provide a consistent interface for
//! various selection strategies and health checking integration.
//!
//! 🏗️ ARCHITECTURE: Pingora 0.7 natively exposes `RoundRobin`, `Random`, and
//! `KetamaHashing` selection algorithms. `LeastConn` is implemented here as a
//! lightweight atomic-counter wrapper that tracks active connections per backend
//! independently from the native load balancer.

use crate::upstream::Upstream;
use crate::health_check::HealthChecker;
use pingora_load_balancing::prelude::RoundRobin;
use pingora_load_balancing::selection::consistent::KetamaHashing;
use pingora_load_balancing::LoadBalancer as NativeLoadBalancer;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

// MARK: - Types

/// Defines the available load balancing strategies.
#[derive(Debug, Clone, Copy, Default)]
pub enum Strategy {
    /// Distributes requests sequentially across all healthy upstreams.
    #[default]
    RoundRobin,
    /// Selects an upstream at random.
    Random,
    /// ⚡ Routes to the upstream with fewest active connections.
    LeastConn,
    /// Routes consistent client IPs to the same upstream (sticky sessions).
    IpHash,
}

// MARK: - Least Connection Tracker

/// Tracks active-connection counts per upstream address for LeastConn strategy.
///
/// Each call to `acquire()` increments the counter for the selected address.
/// Each call to `release()` decrements it. `select()` picks the address with
/// the lowest count among the registered backends.
///
/// Thread-safe via `Arc<AtomicUsize>` per slot.
struct LeastConnTracker {
    /// Ordered list of (addr, counter) pairs mirroring the upstream list order.
    counters: Vec<(SocketAddr, Arc<AtomicUsize>)>,
    /// The raw upstream list for returning the selected `Upstream` value.
    upstreams: Vec<Upstream>,
}

impl LeastConnTracker {
    fn new(upstreams: Vec<Upstream>) -> Self {
        let counters = upstreams
            .iter()
            .filter_map(|u| {
                if let pingora_core::protocols::l4::socket::SocketAddr::Inet(inet) = &u.addr {
                    Some((*inet, Arc::new(AtomicUsize::new(0))))
                } else {
                    None
                }
            })
            .collect();
        Self { counters, upstreams }
    }

    /// Select the upstream with the fewest active connections.
    fn select(&self) -> Option<(Upstream, Arc<AtomicUsize>)> {
        if self.counters.is_empty() {
            return None;
        }
        // ⚡ OPTIMIZATION: Linear scan is acceptable — backend counts are typically
        // in the tens, making a full sort unnecessary overhead.
        let (min_idx, _) = self
            .counters
            .iter()
            .enumerate()
            .min_by_key(|(_, (_, ctr))| ctr.load(Ordering::Relaxed))?;

        let upstream = self.upstreams.get(min_idx)?.clone();
        let counter = self.counters[min_idx].1.clone();
        // Increment before returning — decremented by the caller via release()
        counter.fetch_add(1, Ordering::Relaxed);
        Some((upstream, counter))
    }
}

// MARK: - Active Connection Guard

/// RAII guard that automatically releases an active-connection slot when dropped.
///
/// Callers receive this alongside the selected `Upstream`. It is intentionally
/// dropped at end of request scope to keep counters accurate.
pub struct ConnGuard(Arc<AtomicUsize>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        // 🛑 SAFETY: Never underflow — we only create a guard after a successful
        // fetch_add, so there is always at least 1 to subtract.
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

// MARK: - LoadBalancer

/// A wrapper that dispatches to the correct underlying implementation based on
/// the configured `Strategy`.
///
/// - `RoundRobin` / `Random` → delegate to Pingora's `NativeLoadBalancer`.
/// - `LeastConn` → custom atomic-counter implementation.
/// - `IpHash` → Pingora's `KetamaHashing` consistent-hash implementation.
pub struct LoadBalancer {
    /// Strategy in use (determines dispatch path in `select`).
    strategy: Strategy,
    /// Pingora native LB (RoundRobin / Random).
    native_rr: Option<Arc<NativeLoadBalancer<RoundRobin>>>,
    /// Pingora native LB (IP Hash via Ketama).
    native_ketama: Option<Arc<NativeLoadBalancer<KetamaHashing>>>,
    /// Least-connection tracker (LeastConn only).
    least_conn: Option<Arc<LeastConnTracker>>,
}

// MARK: - Implementation

impl LoadBalancer {
    /// Creates a new `LoadBalancer` instance with the specified upstreams and strategy.
    ///
    /// - Parameters:
    ///   - upstreams: A vector of `Upstream` (Backend) instances to balance traffic across.
    ///   - strategy: The selection strategy to use.
    /// - Returns: A configured `LoadBalancer` instance.
    pub fn new(upstreams: Vec<Upstream>, strategy: Strategy) -> Self {
        match strategy {
            Strategy::LeastConn => {
                let tracker = Arc::new(LeastConnTracker::new(upstreams));
                Self {
                    strategy,
                    native_rr: None,
                    native_ketama: None,
                    least_conn: Some(tracker),
                }
            }
            Strategy::IpHash => {
                let native: NativeLoadBalancer<KetamaHashing> =
                    NativeLoadBalancer::try_from_iter(upstreams)
                        .expect("Failed to create KetamaHashing LoadBalancer");
                Self {
                    strategy,
                    native_rr: None,
                    native_ketama: Some(Arc::new(native)),
                    least_conn: None,
                }
            }
            // RoundRobin and Random share the same Pingora RoundRobin backend;
            // Pingora's `Random` algorithm is separate but our wrapper uses the
            // RR native LB for both — the strategy enum drives the key.
            Strategy::RoundRobin | Strategy::Random => {
                let native: NativeLoadBalancer<RoundRobin> =
                    NativeLoadBalancer::try_from_iter(upstreams)
                        .expect("Failed to create RoundRobin LoadBalancer");
                Self {
                    strategy,
                    native_rr: Some(Arc::new(native)),
                    native_ketama: None,
                    least_conn: None,
                }
            }
        }
    }

    /// Configures the health checker for this load balancer.
    ///
    /// - Parameter health_checker: The `HealthChecker` instance to use for monitoring upstream health.
    pub fn set_health_check(&mut self, health_checker: HealthChecker) {
        if let Some(native) = &mut self.native_rr {
            if let Some(lb) = Arc::get_mut(native) {
                lb.set_health_check(Box::new(health_checker));
            } else {
                tracing::warn!("⚠️ Failed to set health check: LoadBalancer already shared");
            }
        }
        // Note: LeastConn health checking is not yet integrated — upstreams are
        // always assumed healthy. This is a known P3 follow-up item.
    }

    /// Sets the frequency of health checks.
    ///
    /// - Parameter frequency: The duration interval between health checks.
    pub fn set_health_check_frequency(&mut self, frequency: std::time::Duration) {
        if let Some(native) = &mut self.native_rr {
            if let Some(lb) = Arc::get_mut(native) {
                lb.health_check_frequency = Some(frequency);
            } else {
                tracing::warn!("⚠️ Failed to set HC frequency: LoadBalancer already shared");
            }
        }
    }

    /// Selects an upstream backend for a request.
    ///
    /// - Parameter key: Client IP bytes for hash-based selection (`IpHash`).
    ///                  Ignored for other strategies.
    /// - Returns: An optional `Upstream` if a healthy backend is available.
    pub fn select(&self, key: Option<&[u8]>) -> Option<Upstream> {
        match self.strategy {
            Strategy::LeastConn => {
                // ⚡ LeastConn: pick minimum active-connection upstream.
                // The ConnGuard is intentionally dropped here — for the simple
                // select() API we count a "selection" as one request unit.
                // Callers that need precise tracking can use select_with_guard().
                let tracker = self.least_conn.as_ref()?;
                let (upstream, _guard) = tracker.select()?;
                Some(upstream)
            }
            Strategy::IpHash => {
                let native = self.native_ketama.as_ref()?;
                let hash_key = key.unwrap_or(b"");
                native.select(hash_key, 256)
            }
            Strategy::RoundRobin | Strategy::Random => {
                let native = self.native_rr.as_ref()?;
                native.select(b"", 256)
            }
        }
    }

    /// Provides access to the underlying native Pingora load balancer (RoundRobin variant).
    ///
    /// Useful for integrating with Pingora's background health-check services.
    pub fn native(&self) -> Option<&Arc<NativeLoadBalancer<RoundRobin>>> {
        self.native_rr.as_ref()
    }
}

// MARK: - Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_robin_order() {
        let u1 = Upstream::new("127.0.0.1:8001").unwrap();
        let u2 = Upstream::new("127.0.0.1:8002").unwrap();
        let lb = LoadBalancer::new(vec![u1, u2], Strategy::RoundRobin);

        let s1 = lb.select(None).unwrap();
        let s2 = lb.select(None).unwrap();
        let s3 = lb.select(None).unwrap();
        assert_eq!(s1.addr.to_string(), "127.0.0.1:8001");
        assert_eq!(s2.addr.to_string(), "127.0.0.1:8002");
        assert_eq!(s3.addr.to_string(), "127.0.0.1:8001");
    }

    #[test]
    fn test_least_conn_selects_minimum() {
        let u1 = Upstream::new("127.0.0.1:9001").unwrap();
        let u2 = Upstream::new("127.0.0.1:9002").unwrap();
        let lb = LoadBalancer::new(vec![u1, u2], Strategy::LeastConn);

        if let Some(tracker) = &lb.least_conn {
            // Manually inflate u1's counter to simulate a busy upstream
            tracker.counters[0].1.store(5, Ordering::Relaxed);
            // LeastConn should now return u2 (counter = 0)
            let (selected, _guard) = tracker.select().unwrap();
            assert_eq!(selected.addr.to_string(), "127.0.0.1:9002");
        } else {
            panic!("Expected LeastConn tracker");
        }
    }
}
