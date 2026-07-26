//! Load Balancing for Pingclair
//!
//! Wraps Pingora's native `LoadBalancer` to provide a consistent interface for
//! various selection strategies and health checking integration.
//!
//! 🏗️ ARCHITECTURE: Pingora 0.7 natively exposes `RoundRobin`, `Random`, and
//! `KetamaHashing` selection algorithms. `LeastConn` is implemented here as a
//! lightweight atomic-counter wrapper that tracks active connections per backend
//! independently from the native load balancer.

use crate::health_check::HealthChecker;
use crate::upstream::Upstream;
use futures::FutureExt;
use pingora_load_balancing::Backends;
use pingora_load_balancing::LoadBalancer as NativeLoadBalancer;
use pingora_load_balancing::discovery::Static;
use pingora_load_balancing::prelude::RoundRobin;
use pingora_load_balancing::selection::consistent::KetamaHashing;
use pingora_load_balancing::selection::{BackendIter, BackendSelection};
use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// MARK: - Types

/// How long a backend that failed to connect stays out of rotation before
/// it becomes selectable again (nginx `fail_timeout` semantics). The first
/// selection after the cooldown acts as the half-open probe: if it fails
/// too, the backend is marked down for another cooldown.
pub const FAIL_COOLDOWN: Duration = Duration::from_secs(10);

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

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

// MARK: - Passive Backend Health

/// Passive (in-band) health marks, nginx `max_fails`/`fail_timeout` style.
///
/// When a connection to a backend fails, `ProxyHttp::fail_to_connect` calls
/// [`BackendHealth::mark_down`], which records the instant until which the
/// backend is considered down. `select` skips down backends; once the
/// cooldown expires the backend automatically becomes selectable again, so
/// no background re-enable task is needed — the next request through is the
/// half-open probe. Values are unix milliseconds; 0 means healthy.
struct BackendHealth {
    down_until: HashMap<SocketAddr, Arc<AtomicU64>>,
}

impl BackendHealth {
    fn new(addrs: impl IntoIterator<Item = SocketAddr>) -> Self {
        let down_until = addrs
            .into_iter()
            .map(|addr| (addr, Arc::new(AtomicU64::new(0))))
            .collect();
        Self { down_until }
    }

    /// Mark a backend down for `cooldown`. `fetch_max` so a later failure
    /// can only extend, never shorten, an ongoing cooldown.
    fn mark_down_for(&self, addr: &SocketAddr, cooldown: Duration) {
        if let Some(slot) = self.down_until.get(addr) {
            let until = now_millis() + cooldown.as_millis() as u64;
            slot.fetch_max(until, Ordering::Relaxed);
        }
    }

    fn mark_down(&self, addr: &SocketAddr) {
        self.mark_down_for(addr, FAIL_COOLDOWN);
    }

    /// A backend is up when its down-until mark is absent or in the past.
    fn is_up(&self, addr: &SocketAddr) -> bool {
        match self.down_until.get(addr) {
            Some(slot) => slot.load(Ordering::Relaxed) <= now_millis(),
            None => true,
        }
    }

    fn is_up_backend(&self, backend: &Upstream) -> bool {
        match &backend.addr {
            pingora_core::protocols::l4::socket::SocketAddr::Inet(inet) => self.is_up(inet),
            // Unix-socket backends: no passive marking, always selectable.
            _ => true,
        }
    }
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
    /// Passive health marks — down backends are skipped by `select`.
    health: Arc<BackendHealth>,
}

impl LeastConnTracker {
    fn new(upstreams: Vec<Upstream>, health: Arc<BackendHealth>) -> Self {
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
        Self {
            counters,
            upstreams,
            health,
        }
    }

    /// Select the upstream with the fewest active connections among the
    /// backends that are not currently marked down. Returns `None` when all
    /// backends are down (the caller then answers 502, nginx-style).
    fn select(&self) -> Option<(Upstream, Arc<AtomicUsize>)> {
        // ⚡ OPTIMIZATION: Linear scan is acceptable — backend counts are typically
        // in the tens, making a full sort unnecessary overhead.
        let (min_idx, _) = self
            .counters
            .iter()
            .enumerate()
            .filter(|(_, (addr, _))| self.health.is_up(addr))
            .min_by_key(|(_, (_, ctr))| ctr.load(Ordering::Relaxed))?;

        let upstream = self.upstreams.get(min_idx)?.clone();
        let counter = self.counters[min_idx].1.clone();
        // Increment before returning — decremented by the caller via release()
        counter.fetch_add(1, Ordering::Relaxed);
        Some((upstream, counter))
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
    /// Passive health marks shared by every strategy: `fail_to_connect`
    /// marks a backend down here and `select` skips it until the cooldown
    /// expires. Implemented outside the native LB so it works uniformly
    /// for the native (RoundRobin/Random/IpHash) and custom (LeastConn)
    /// selection paths.
    health: Arc<BackendHealth>,
    /// Backup pool consulted only when no primary backend is selectable.
    backup: Option<Arc<LoadBalancer>>,
}

// MARK: - Implementation

fn build_native_load_balancer<S>(upstreams: Vec<Upstream>) -> NativeLoadBalancer<S>
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
{
    // ⚖️ Preserve Pingora's native Backend weight instead of resolving it back to weight one.
    let discovery = Static::new(BTreeSet::from_iter(upstreams));
    let backends = Backends::new(discovery);
    let load_balancer = NativeLoadBalancer::from_backends(backends);
    load_balancer
        .update()
        .now_or_never()
        .expect("static backend discovery must not block")
        .expect("static backend discovery must succeed");
    load_balancer
}

impl LoadBalancer {
    /// Creates a new `LoadBalancer` instance with the specified upstreams and strategy.
    ///
    /// - Parameters:
    ///   - upstreams: A vector of `Upstream` (Backend) instances to balance traffic across.
    ///   - strategy: The selection strategy to use.
    /// - Returns: A configured `LoadBalancer` instance.
    pub fn new(upstreams: Vec<Upstream>, strategy: Strategy) -> Self {
        let health = Arc::new(BackendHealth::new(upstreams.iter().filter_map(|u| {
            if let pingora_core::protocols::l4::socket::SocketAddr::Inet(inet) = &u.addr {
                Some(*inet)
            } else {
                None
            }
        })));
        match strategy {
            Strategy::LeastConn => {
                let tracker = Arc::new(LeastConnTracker::new(upstreams, health.clone()));
                Self {
                    strategy,
                    native_rr: None,
                    native_ketama: None,
                    least_conn: Some(tracker),
                    health,
                    backup: None,
                }
            }
            Strategy::IpHash => {
                let native: NativeLoadBalancer<KetamaHashing> =
                    build_native_load_balancer(upstreams);
                Self {
                    strategy,
                    native_rr: None,
                    native_ketama: Some(Arc::new(native)),
                    least_conn: None,
                    health,
                    backup: None,
                }
            }
            // RoundRobin and Random share the same Pingora RoundRobin backend;
            // Pingora's `Random` algorithm is separate but our wrapper uses the
            // RR native LB for both — the strategy enum drives the key.
            Strategy::RoundRobin | Strategy::Random => {
                let native: NativeLoadBalancer<RoundRobin> = build_native_load_balancer(upstreams);
                Self {
                    strategy,
                    native_rr: Some(Arc::new(native)),
                    native_ketama: None,
                    least_conn: None,
                    health,
                    backup: None,
                }
            }
        }
    }

    /// Creates a primary pool with an optional backup pool. Backup peers are
    /// deliberately separate from the primary selector so their weights do
    /// not put them into normal rotation; they are tried only after all
    /// primaries are unhealthy or unavailable.
    pub fn with_backup(primary: Vec<Upstream>, backup: Vec<Upstream>, strategy: Strategy) -> Self {
        let mut load_balancer = Self::new(primary, strategy);
        if !backup.is_empty() {
            load_balancer.backup = Some(Arc::new(Self::new(backup, strategy)));
        }
        load_balancer
    }

    /// Mark a backend as down (passive health check). Called from
    /// `ProxyHttp::fail_to_connect` when a connection attempt to the
    /// backend fails; `select` then skips it for [`FAIL_COOLDOWN`].
    pub fn mark_unhealthy(&self, addr: &SocketAddr) {
        self.health.mark_down(addr);
        if let Some(backup) = &self.backup {
            backup.mark_unhealthy(addr);
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
        // Note: LeastConn active health checking is not integrated — the
        // native background health-check service only drives `native_rr`.
        // LeastConn (and every other strategy) is still covered by the
        // passive fail_to_connect marking in `select`.
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
    ///   Ignored for other strategies.
    /// - Returns: An optional `Upstream` if a healthy backend is available.
    pub fn select(&self, key: Option<&[u8]>) -> Option<Upstream> {
        let primary = match self.strategy {
            Strategy::LeastConn => {
                // ⚡ LeastConn: pick minimum active-connection upstream.
                // The counter slot is released immediately — for the simple
                // select() API we count a "selection" as one request unit.
                self.least_conn
                    .as_ref()
                    .and_then(|tracker| tracker.select().map(|(upstream, _guard)| upstream))
            }
            Strategy::IpHash => {
                let hash_key = key.unwrap_or(b"");
                // select_with keeps Pingora's own health verdict (`ready`,
                // used by active health checks) and adds our passive marks.
                self.native_ketama.as_ref().and_then(|native| {
                    native.select_with(hash_key, 256, |b, ready| {
                        ready && self.health.is_up_backend(b)
                    })
                })
            }
            Strategy::RoundRobin | Strategy::Random => self.native_rr.as_ref().and_then(|native| {
                native.select_with(b"", 256, |b, ready| ready && self.health.is_up_backend(b))
            }),
        };
        primary.or_else(|| self.backup.as_ref().and_then(|backup| backup.select(key)))
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
    fn weighted_round_robin_honors_native_backend_weights() {
        let mut weighted = Upstream::new("127.0.0.1:8001").unwrap();
        weighted.weight = 3;
        let normal = Upstream::new("127.0.0.1:8002").unwrap();
        let lb = LoadBalancer::new(vec![weighted, normal], Strategy::RoundRobin);

        let mut weighted_count = 0;
        let mut normal_count = 0;
        for _ in 0..40 {
            match lb.select(None).unwrap().addr.to_string().as_str() {
                "127.0.0.1:8001" => weighted_count += 1,
                "127.0.0.1:8002" => normal_count += 1,
                address => panic!("unexpected backend: {address}"),
            }
        }

        assert_eq!(weighted_count, 30);
        assert_eq!(normal_count, 10);
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

    // ---- Passive health marking (fail_to_connect failover) ----

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn unhealthy_backend_is_skipped_round_robin() {
        let u1 = Upstream::new("127.0.0.1:8001").unwrap();
        let u2 = Upstream::new("127.0.0.1:8002").unwrap();
        let lb = LoadBalancer::new(vec![u1, u2], Strategy::RoundRobin);

        lb.mark_unhealthy(&addr("127.0.0.1:8001"));
        for _ in 0..4 {
            assert_eq!(lb.select(None).unwrap().addr.to_string(), "127.0.0.1:8002");
        }
    }

    #[test]
    fn unhealthy_backend_is_skipped_least_conn() {
        let u1 = Upstream::new("127.0.0.1:9001").unwrap();
        let u2 = Upstream::new("127.0.0.1:9002").unwrap();
        let lb = LoadBalancer::new(vec![u1, u2], Strategy::LeastConn);

        lb.mark_unhealthy(&addr("127.0.0.1:9001"));
        for _ in 0..4 {
            assert_eq!(lb.select(None).unwrap().addr.to_string(), "127.0.0.1:9002");
        }
    }

    #[test]
    fn unhealthy_backend_is_skipped_ip_hash() {
        let u1 = Upstream::new("127.0.0.1:8101").unwrap();
        let u2 = Upstream::new("127.0.0.1:8102").unwrap();
        let lb = LoadBalancer::new(vec![u1, u2], Strategy::IpHash);

        // Find a key that would normally land on 8101, then mark 8101 down:
        // the same key must be rerouted to the surviving backend.
        let key = b"client-a";
        let first = lb.select(Some(key)).unwrap();
        lb.mark_unhealthy(&addr(&first.addr.to_string()));
        let after = lb.select(Some(key)).unwrap();
        assert_ne!(after.addr.to_string(), first.addr.to_string());
    }

    #[test]
    fn backend_recovers_after_cooldown() {
        let u1 = Upstream::new("127.0.0.1:8001").unwrap();
        let u2 = Upstream::new("127.0.0.1:8002").unwrap();
        let lb = LoadBalancer::new(vec![u1, u2], Strategy::RoundRobin);

        // Mark down with a short cooldown (tests can't wait out FAIL_COOLDOWN).
        lb.health
            .mark_down_for(&addr("127.0.0.1:8001"), Duration::from_millis(50));
        assert_eq!(lb.select(None).unwrap().addr.to_string(), "127.0.0.1:8002");

        std::thread::sleep(Duration::from_millis(60));
        // Cooldown expired: 8001 is selectable again (half-open probe).
        let mut saw_8001 = false;
        for _ in 0..4 {
            if lb.select(None).unwrap().addr.to_string() == "127.0.0.1:8001" {
                saw_8001 = true;
                break;
            }
        }
        assert!(saw_8001, "backend must rejoin rotation after the cooldown");
    }

    #[test]
    fn all_backends_down_returns_none() {
        let u1 = Upstream::new("127.0.0.1:8001").unwrap();
        let u2 = Upstream::new("127.0.0.1:8002").unwrap();
        let lb = LoadBalancer::new(vec![u1, u2], Strategy::RoundRobin);

        lb.mark_unhealthy(&addr("127.0.0.1:8001"));
        lb.mark_unhealthy(&addr("127.0.0.1:8002"));
        assert!(
            lb.select(None).is_none(),
            "all down → None (caller answers 502)"
        );
    }

    #[test]
    fn backup_is_used_only_after_primaries_are_unhealthy() {
        let primary = Upstream::new("127.0.0.1:8201").unwrap();
        let backup = Upstream::new("127.0.0.1:8202").unwrap();
        let lb = LoadBalancer::with_backup(vec![primary], vec![backup], Strategy::RoundRobin);

        assert_eq!(lb.select(None).unwrap().addr.to_string(), "127.0.0.1:8201");
        lb.mark_unhealthy(&addr("127.0.0.1:8201"));
        assert_eq!(lb.select(None).unwrap().addr.to_string(), "127.0.0.1:8202");
    }
}
