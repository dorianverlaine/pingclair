// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Load Balancing for Pingclair
//!
//! Wraps Pingora's native `LoadBalancer` to provide a consistent interface for
//! various selection strategies and health checking integration.
//!
//! 🏗️ ARCHITECTURE: Pingora 0.7 natively exposes `RoundRobin`, `Random`, and
//! `KetamaHashing` selection algorithms. `LeastConn` is implemented here as a
//! lightweight atomic-counter wrapper that tracks active connections per backend
//! independently from the native load balancer.
//!
//! 🔄 DNS: the selector set lives behind an `ArcSwap` because upstream
//! hostnames are re-resolved while the server runs (see [`LoadBalancer::refresh_dns`]).
//! Readers on the request path take a wait-free snapshot; the refresher
//! publishes a whole new pool at once, so a request never observes a
//! half-updated backend list.

use crate::dynamic_upstream::DynamicUpstreamSource;
use crate::health_check::{HealthCheckConfig, HealthChecker, RecoveryState};
use crate::upstream::{Resolve, SystemResolver, Upstream, UpstreamSpec};
use arc_swap::ArcSwap;
use futures::FutureExt;
use parking_lot::Mutex;
use pingora_load_balancing::Backends;
use pingora_load_balancing::LoadBalancer as NativeLoadBalancer;
use pingora_load_balancing::discovery::Static;
use pingora_load_balancing::prelude::RoundRobin;
use pingora_load_balancing::selection::consistent::KetamaHashing;
use pingora_load_balancing::selection::{BackendIter, BackendSelection};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// MARK: - Types

/// How long a backend that failed to connect stays out of rotation before
/// it becomes selectable again (nginx `fail_timeout` semantics). The first
/// selection after the cooldown acts as the half-open probe: if it fails
/// too, the backend is marked down for another cooldown.
pub const FAIL_COOLDOWN: Duration = Duration::from_secs(10);

/// ⏱️ Monotonic origin shared by dynamic DNS deadlines and grace windows.
static DNS_CLOCK_START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// ⏱️ Returns monotonic process-relative milliseconds for DNS bookkeeping.
pub(crate) fn dns_now_millis() -> u64 {
    u64::try_from(DNS_CLOCK_START.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// The inet address of a backend, or `None` for a unix-socket backend.
fn inet_address(backend: &Upstream) -> Option<SocketAddr> {
    match &backend.addr {
        pingora_core::protocols::l4::socket::SocketAddr::Inet(inet) => Some(*inet),
        _ => None,
    }
}

/// 🩺 Reads Pingora's active verdict without coupling it to one selection strategy.
fn active_ready(active: Option<&Arc<NativeLoadBalancer<RoundRobin>>>, backend: &Upstream) -> bool {
    active.is_none_or(|health| health.backends().ready(backend))
}

/// 🌤️ Gradually admits a recovered backend while keeping the request path lock-free.
fn slow_start_ready(
    address: &SocketAddr,
    slots: &HashMap<SocketAddr, Arc<AtomicU64>>,
    duration: Duration,
) -> bool {
    if duration.is_zero() {
        return true;
    }
    let Some(started) = slots.get(address).map(|slot| slot.load(Ordering::Acquire)) else {
        return true;
    };
    if started == 0 {
        return true;
    }
    let elapsed = now_millis().saturating_sub(started);
    let total = duration.as_millis() as u64;
    if elapsed >= total {
        return true;
    }
    let allowance = elapsed.saturating_mul(1_000) / total.max(1);
    let phase = now_millis() / 100;
    let address_hash = match address.ip() {
        std::net::IpAddr::V4(ip) => u32::from(ip) as u64,
        std::net::IpAddr::V6(ip) => {
            let octets = ip.octets();
            u64::from_be_bytes(octets[..8].try_into().unwrap_or_default())
                ^ u64::from_be_bytes(octets[8..].try_into().unwrap_or_default())
        }
    } ^ u64::from(address.port());
    address_hash.wrapping_add(phase.wrapping_mul(1_103_515_245)) % 1_000 < allowance
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
///
/// The map is immutable once built, which keeps the request path lock-free.
/// A DNS refresh builds a fresh map via [`BackendHealth::rebuilt`], carrying
/// over the marks of addresses that survived so a re-resolution cannot
/// silently un-fail a backend that is still refusing connections.
struct BackendHealth {
    down_until: HashMap<SocketAddr, Arc<AtomicU64>>,
}

impl BackendHealth {
    /// Builds the map for a new backend set, reusing the slots of addresses
    /// that are still present. Addresses that went away are dropped, so the
    /// map cannot grow without bound across refreshes.
    fn rebuilt(
        previous: Option<&BackendHealth>,
        addrs: impl IntoIterator<Item = SocketAddr>,
    ) -> Self {
        let down_until = addrs
            .into_iter()
            .map(|addr| {
                let slot = previous
                    .and_then(|health| health.down_until.get(&addr).cloned())
                    .unwrap_or_else(|| Arc::new(AtomicU64::new(0)));
                (addr, slot)
            })
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
        match inet_address(backend) {
            Some(inet) => self.is_up(&inet),
            // Unix-socket backends: no passive marking, always selectable.
            None => true,
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
    /// Ordered list of (addr, counter) pairs mirroring the upstream list
    /// order; `None` marks a Unix-socket backend, which has no inet address.
    counters: Vec<(Option<SocketAddr>, Arc<AtomicUsize>)>,
    /// The raw upstream list for returning the selected `Upstream` value.
    upstreams: Vec<Upstream>,
    /// Passive health marks — down backends are skipped by `select`.
    health: Arc<BackendHealth>,
}

impl LeastConnTracker {
    fn new(upstreams: Vec<Upstream>, health: Arc<BackendHealth>) -> Self {
        let counters = upstreams
            .iter()
            .map(|u| (inet_address(u), Arc::new(AtomicUsize::new(0))))
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
    fn select(
        &self,
        excluded: &HashSet<SocketAddr>,
        active: Option<&Arc<NativeLoadBalancer<RoundRobin>>>,
        recovery_slots: &HashMap<SocketAddr, Arc<AtomicU64>>,
        slow_start: Duration,
    ) -> Option<(Upstream, Arc<AtomicUsize>)> {
        if crate::metrics::enabled() {
            // 🩺 Publish the passive health state for every backend so
            // /metrics can answer `is this upstream healthy?` (MT-5).
            for (index, backend) in self.upstreams.iter().enumerate() {
                let Some((addr, _)) = self.counters.get(index) else {
                    continue;
                };
                let healthy = addr.is_none_or(|inet| self.health.is_up(&inet));
                crate::metrics::UPSTREAM_HEALTHY
                    .with_label_values(&[&backend.addr.to_string()])
                    .set(if healthy { 1 } else { 0 });
            }
        }

        // ⚡ OPTIMIZATION: Linear scan is acceptable — backend counts are typically
        // in the tens, making a full sort unnecessary overhead.
        let (min_idx, _) = self
            .counters
            .iter()
            .enumerate()
            .filter(|(index, (addr, _))| {
                let inet = addr.as_ref();
                inet.is_none_or(|address| self.health.is_up(address))
                    && inet.is_none_or(|address| !excluded.contains(address))
                    && self
                        .upstreams
                        .get(*index)
                        .is_some_and(|backend| active_ready(active, backend))
                    && inet
                        .is_none_or(|address| slow_start_ready(address, recovery_slots, slow_start))
            })
            .min_by_key(|(_, (_, ctr))| ctr.load(Ordering::Relaxed))?;

        let upstream = self.upstreams.get(min_idx)?.clone();
        let counter = self.counters[min_idx].1.clone();
        // Increment before returning — decremented by the caller via release()
        counter.fetch_add(1, Ordering::Relaxed);
        Some((upstream, counter))
    }
}

// MARK: - Backend Pool

/// One immutable snapshot of the selectable backends.
///
/// Everything that depends on the concrete address list lives here, so a DNS
/// refresh is a single `ArcSwap` store rather than a series of mutations that
/// a concurrent request could catch mid-flight.
struct Pool {
    native_rr: Option<Arc<NativeLoadBalancer<RoundRobin>>>,
    native_ketama: Option<Arc<NativeLoadBalancer<KetamaHashing>>>,
    least_conn: Option<LeastConnTracker>,
    active_health: Option<Arc<NativeLoadBalancer<RoundRobin>>>,
    recovery_slots: HashMap<SocketAddr, Arc<AtomicU64>>,
    slow_start: Duration,
    health: Arc<BackendHealth>,
}

/// Active health-check settings, kept so they can be re-applied every time a
/// DNS refresh rebuilds the native load balancer.
#[derive(Clone)]
struct HealthCheckSettings {
    config: HealthCheckConfig,
    peer_template: pingora_core::upstreams::peer::HttpPeer,
    frequency: Option<Duration>,
}

// MARK: - Tracked Upstreams

/// One configured upstream and the address it is currently using.
///
/// `spec` is `None` for backends handed in already resolved (the plain
/// [`LoadBalancer::new`] path used by tests and examples); those are never
/// re-resolved. `backend` is `None` while a hostname has never resolved
/// successfully — the entry stays in the list so a later refresh can adopt
/// it, which is what lets the proxy start before its app container does.
#[derive(Clone)]
struct TrackedUpstream {
    spec: Option<UpstreamSpec>,
    weight: usize,
    backend: Option<Upstream>,
}

/// One configured upstream before resolution.
#[derive(Debug, Clone)]
pub struct UpstreamEntry {
    pub spec: UpstreamSpec,
    pub weight: usize,
}

/// What a [`LoadBalancer::refresh_dns`] pass did. Summed across pools by the
/// refresher so a tick can be logged (and asserted on) as one line.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DnsRefresh {
    /// Backends whose address moved to a new one.
    pub changed: usize,
    /// Hostnames that resolved for the first time and joined the pool.
    pub adopted: usize,
    /// Lookups that failed while a last-known-good address was kept in place.
    pub kept_stale: usize,
    /// Lookups that failed with no address to fall back to.
    pub unresolved: usize,
}

impl DnsRefresh {
    /// Folds another pass's counters into this one.
    pub fn merge(&mut self, other: DnsRefresh) {
        self.changed += other.changed;
        self.adopted += other.adopted;
        self.kept_stale += other.kept_stale;
        self.unresolved += other.unresolved;
    }

    /// Whether the pass actually altered any backend list.
    pub fn is_noop(&self) -> bool {
        self.changed == 0 && self.adopted == 0
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
    /// The current backend snapshot, replaced wholesale by a DNS refresh.
    pool: ArcSwap<Pool>,
    /// Configured upstreams plus their last-known-good addresses. Only the
    /// refresher touches this, so a plain mutex is enough and never appears
    /// on the request path.
    tracked: Mutex<Vec<TrackedUpstream>>,
    /// Resolver used by [`Self::refresh_dns`]; injectable for tests.
    resolver: Arc<dyn Resolve>,
    /// Health-check settings re-applied to every rebuilt pool.
    health_check: Mutex<Option<HealthCheckSettings>>,
    /// 🌤️ Recovery slots are pruned whenever DNS publishes a new backend set.
    recovery: Arc<RecoveryState>,
    /// ⏲️ Next probe round and all-dead backoff are maintained off request paths.
    next_health_check_ms: AtomicU64,
    health_backoff: AtomicU64,
    /// Backup pool consulted only when no primary backend is selectable.
    backup: Option<Arc<LoadBalancer>>,
    /// Bumped every time a new pool is published. Lets a collaborator that
    /// caches per-address state notice a backend set change with one atomic
    /// load, instead of walking the pool on every request to find out nothing
    /// moved.
    generation: AtomicU64,
    /// 🧭 DNS-driven source whose whole peer set is republished on refresh;
    /// absent for pools built from a fixed upstream list.
    dynamic: Option<Box<dyn DynamicUpstreamSource>>,
    /// 🧱 Static peers that remain present when a dynamic generation changes.
    dynamic_static: Mutex<Vec<TrackedUpstream>>,
    /// 🌤️ First failure of the current dynamic outage, which bounds grace.
    dynamic_stale_since_ms: AtomicU64,
    /// ⏱️ Next DNS deadline for the dynamic source, if one exists.
    next_dynamic_dns_refresh_ms: AtomicU64,
    /// ⏱️ Next DNS deadline for fixed hostname entries in this pool.
    next_static_dns_refresh_ms: AtomicU64,
    /// 🧭 Whether fixed configuration contains names that follow global refresh.
    static_dns_refresh: bool,
    /// 🔒 Serializes background publications when both DNS schedules become due.
    dns_refresh_lock: Mutex<()>,
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
    /// The addresses are taken as given and never re-resolved; use
    /// [`Self::from_entries`] when the upstreams come from configuration and
    /// may be hostnames.
    ///
    /// - Parameters:
    ///   - upstreams: A vector of `Upstream` (Backend) instances to balance traffic across.
    ///   - strategy: The selection strategy to use.
    /// - Returns: A configured `LoadBalancer` instance.
    pub fn new(upstreams: Vec<Upstream>, strategy: Strategy) -> Self {
        let tracked = upstreams
            .into_iter()
            .map(|backend| TrackedUpstream {
                spec: None,
                weight: backend.weight,
                backend: Some(backend),
            })
            .collect();
        Self::from_tracked(tracked, strategy, Arc::new(SystemResolver), None)
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

    /// Builds a load balancer from *unresolved* configuration entries.
    ///
    /// Hostnames are resolved once here so boot behaves exactly as before,
    /// but the specs are retained: an entry that fails to resolve now stays
    /// in the list and joins the pool as soon as [`Self::refresh_dns`]
    /// succeeds, instead of being dropped for the lifetime of the process.
    pub fn from_entries(
        primary: Vec<UpstreamEntry>,
        backup: Vec<UpstreamEntry>,
        strategy: Strategy,
    ) -> Self {
        Self::from_entries_with_resolver(primary, backup, strategy, Arc::new(SystemResolver))
    }

    /// 🧭 Builds a pool from a DNS-driven source plus optional static peers.
    ///
    /// The source is resolved once here so the pool is usable at boot, and
    /// every later `refresh_dns` pass re-queries it and republishes the whole
    /// set — the request path never touches the resolver. A lookup failure at
    /// startup leaves the pool empty and is retried, exactly like a hostname
    /// that has not resolved yet.
    pub fn from_dynamic(
        source: Box<dyn DynamicUpstreamSource>,
        primary: Vec<UpstreamEntry>,
        backup: Vec<UpstreamEntry>,
        strategy: Strategy,
    ) -> Self {
        let resolver: Arc<dyn Resolve> = Arc::new(SystemResolver);
        Self::from_dynamic_with_resolver(source, primary, backup, strategy, resolver)
    }

    /// 🧪 Builds a dynamic pool with an injectable resolver for deterministic tests.
    fn from_dynamic_with_resolver(
        source: Box<dyn DynamicUpstreamSource>,
        primary: Vec<UpstreamEntry>,
        backup: Vec<UpstreamEntry>,
        strategy: Strategy,
        resolver: Arc<dyn Resolve>,
    ) -> Self {
        let static_tracked = resolve_entries(primary, resolver.as_ref());
        let mut tracked = static_tracked.clone();
        match source.resolve_specs() {
            Ok(specs) => {
                tracked.extend(specs.into_iter().map(|spec| {
                    let backend = spec
                        .resolve(&*resolver)
                        .ok()
                        .and_then(|address| spec.backend(address, 1));
                    TrackedUpstream {
                        spec: Some(spec),
                        weight: 1,
                        backend,
                    }
                }));
            }
            Err(error) => {
                tracing::warn!(
                    source = %source.describe(),
                    %error,
                    "⚠️ Dynamic upstream lookup failed at startup; it will be retried"
                );
            }
        }
        let backup_pool = (!backup.is_empty()).then(|| {
            Arc::new(Self::from_tracked(
                resolve_entries(backup, resolver.as_ref()),
                strategy,
                resolver.clone(),
                None,
            ))
        });
        let mut load_balancer = Self::from_tracked(tracked, strategy, resolver, backup_pool);
        *load_balancer.dynamic_static.get_mut() = static_tracked;
        load_balancer.dynamic = Some(source);
        load_balancer
    }

    /// [`Self::from_entries`] with an injected resolver (tests).
    pub fn from_entries_with_resolver(
        primary: Vec<UpstreamEntry>,
        backup: Vec<UpstreamEntry>,
        strategy: Strategy,
        resolver: Arc<dyn Resolve>,
    ) -> Self {
        let backup_pool = (!backup.is_empty()).then(|| {
            Arc::new(Self::from_tracked(
                resolve_entries(backup, resolver.as_ref()),
                strategy,
                resolver.clone(),
                None,
            ))
        });

        Self::from_tracked(
            resolve_entries(primary, resolver.as_ref()),
            strategy,
            resolver,
            backup_pool,
        )
    }

    fn from_tracked(
        tracked: Vec<TrackedUpstream>,
        strategy: Strategy,
        resolver: Arc<dyn Resolve>,
        backup: Option<Arc<LoadBalancer>>,
    ) -> Self {
        let static_dns_refresh = tracked
            .iter()
            .any(|entry| entry.spec.as_ref().is_some_and(UpstreamSpec::needs_dns));
        let backends: Vec<Upstream> = tracked.iter().filter_map(|t| t.backend.clone()).collect();
        let recovery = Arc::new(RecoveryState::default());
        let pool = build_pool(strategy, backends, None, None, &recovery);
        Self {
            strategy,
            pool: ArcSwap::from_pointee(pool),
            tracked: Mutex::new(tracked),
            resolver,
            health_check: Mutex::new(None),
            recovery,
            next_health_check_ms: AtomicU64::new(0),
            health_backoff: AtomicU64::new(0),
            backup,
            generation: AtomicU64::new(0),
            dynamic: None,
            dynamic_static: Mutex::new(Vec::new()),
            dynamic_stale_since_ms: AtomicU64::new(0),
            next_dynamic_dns_refresh_ms: AtomicU64::new(0),
            next_static_dns_refresh_ms: AtomicU64::new(0),
            static_dns_refresh,
            dns_refresh_lock: Mutex::new(()),
        }
    }

    /// Whether this pool (or its backup) has any hostname worth re-resolving.
    /// Pools built purely from IP literals are never registered with the
    /// refresher, so a config without hostnames generates no DNS traffic.
    pub fn needs_dns_refresh(&self) -> bool {
        if self.dynamic.is_some() {
            return true;
        }
        self.static_dns_refresh || self.backup.as_ref().is_some_and(|b| b.needs_dns_refresh())
    }

    /// ⏱️ Refreshes only DNS work whose per-pool deadline has arrived.
    pub(crate) fn refresh_dns_due(
        &self,
        default_interval: Option<Duration>,
        now_ms: u64,
    ) -> DnsRefresh {
        let mut report = DnsRefresh::default();
        if let Some(backup) = &self.backup {
            report.merge(backup.refresh_dns_due(default_interval, now_ms));
        }

        if let Some(interval) = self.static_dns_refresh_interval(default_interval)
            && Self::claim_dns_refresh(&self.next_static_dns_refresh_ms, now_ms, interval)
        {
            report.merge(self.refresh_static_dns());
        }
        if let Some(interval) = self.dynamic_dns_refresh_interval(default_interval)
            && Self::claim_dns_refresh(&self.next_dynamic_dns_refresh_ms, now_ms, interval)
            && let Some(source) = &self.dynamic
        {
            report.merge(self.refresh_dynamic_at(source.as_ref(), now_ms));
        }
        report
    }

    /// 🧱 Resolves the fixed-hostname interval without consulting request state.
    fn static_dns_refresh_interval(&self, default_interval: Option<Duration>) -> Option<Duration> {
        self.static_dns_refresh
            .then_some(default_interval)
            .flatten()
    }

    /// 🧭 Resolves the dynamic-source interval without consulting request state.
    fn dynamic_dns_refresh_interval(&self, default_interval: Option<Duration>) -> Option<Duration> {
        self.dynamic
            .as_ref()
            .and_then(|source| source.refresh_interval().or(default_interval))
    }

    /// ⏱️ Reports whether this pool or its backup has an active DNS schedule.
    pub(crate) fn has_dns_schedule(&self, default_interval: Option<Duration>) -> bool {
        self.static_dns_refresh_interval(default_interval).is_some()
            || self
                .dynamic_dns_refresh_interval(default_interval)
                .is_some()
            || self
                .backup
                .as_ref()
                .is_some_and(|backup| backup.has_dns_schedule(default_interval))
    }

    /// ⏱️ Advances one deadline atomically so overlapping scheduler passes do not duplicate DNS.
    fn claim_dns_refresh(deadline: &AtomicU64, now_ms: u64, interval: Duration) -> bool {
        let interval_ms = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);
        let next = deadline.load(Ordering::Acquire);
        if next == 0 {
            let next_deadline = now_ms.saturating_add(interval_ms).max(1);
            let _ =
                deadline.compare_exchange(0, next_deadline, Ordering::AcqRel, Ordering::Acquire);
            return false;
        }
        if now_ms < next {
            return false;
        }
        deadline
            .compare_exchange(
                next,
                now_ms.saturating_add(interval_ms).max(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// 🔄 Re-resolves every hostname upstream and republishes moved addresses.
    ///
    /// 🧭 Fixed hostname failures keep their last-known-good addresses because
    /// they have no source-level grace policy. Dynamic sources retain the
    /// previous generation only for their configured grace period.
    pub fn refresh_dns(&self) -> DnsRefresh {
        let mut report = DnsRefresh::default();
        if let Some(backup) = &self.backup {
            report.merge(backup.refresh_dns());
        }
        report.merge(self.refresh_own_dns_at(dns_now_millis().max(1)));
        report
    }

    /// 🔄 Refreshes this pool without recursively touching its backup.
    fn refresh_own_dns_at(&self, now_ms: u64) -> DnsRefresh {
        let mut report = DnsRefresh::default();
        if self.static_dns_refresh {
            report.merge(self.refresh_static_dns());
        }
        if let Some(source) = &self.dynamic {
            report.merge(self.refresh_dynamic_at(source.as_ref(), now_ms));
        }
        report
    }

    /// 🧱 Re-resolves only the fixed hostname entries and preserves dynamic peers.
    fn refresh_static_dns(&self) -> DnsRefresh {
        let _refresh_guard = self.dns_refresh_lock.lock();
        if self.dynamic.is_some() {
            let mut static_entries = self.dynamic_static.lock();
            let (report, changed) =
                Self::resolve_tracked_entries(&mut static_entries, self.resolver.as_ref());
            if changed {
                let mut tracked = self.tracked.lock();
                let static_count = static_entries.len();
                let mut combined = static_entries.clone();
                combined.extend(tracked.iter().skip(static_count).cloned());
                self.publish(&combined);
                *tracked = combined;
            }
            return report;
        }

        let mut tracked = self.tracked.lock();
        let (report, changed) = Self::resolve_tracked_entries(&mut tracked, self.resolver.as_ref());
        if changed {
            self.publish(&tracked);
        }
        report
    }

    /// 🔄 Updates fixed hostname entries while retaining their last-known-good address.
    fn resolve_tracked_entries(
        tracked: &mut [TrackedUpstream],
        resolver: &dyn Resolve,
    ) -> (DnsRefresh, bool) {
        let mut report = DnsRefresh::default();
        let mut changed = false;
        for entry in tracked.iter_mut() {
            let Some(spec) = entry.spec.as_ref() else {
                continue;
            };
            if !spec.needs_dns() {
                continue;
            }

            match spec.resolve(resolver) {
                Ok(address) => {
                    let current = entry.backend.as_ref().and_then(inet_address);
                    if current == Some(address) {
                        continue;
                    }
                    let Some(backend) = spec.backend(address, entry.weight) else {
                        report.unresolved += 1;
                        continue;
                    };
                    match current {
                        Some(previous) => {
                            report.changed += 1;
                            tracing::info!(
                                upstream = %spec.authority(),
                                from = %previous,
                                to = %address,
                                "🔄 Upstream address changed"
                            );
                        }
                        None => {
                            report.adopted += 1;
                            tracing::info!(
                                upstream = %spec.authority(),
                                %address,
                                "🔄 Upstream resolved and joined the pool"
                            );
                        }
                    }
                    entry.backend = Some(backend);
                    changed = true;
                }
                Err(error) => {
                    if entry.backend.is_some() {
                        report.kept_stale += 1;
                        tracing::warn!(
                            upstream = %spec.authority(),
                            %error,
                            "⚠️ Upstream lookup failed; keeping the last known address"
                        );
                    } else {
                        report.unresolved += 1;
                        tracing::warn!(
                            upstream = %spec.authority(),
                            %error,
                            "⚠️ Upstream has never resolved; it stays out of the pool"
                        );
                    }
                }
            }
        }
        (report, changed)
    }

    /// 🧭 Re-queries one DNS-driven source and republishes its peer set.
    ///
    /// 🌤️ A source-level failure retains the previous generation only inside
    /// its configured grace period. Individual peers whose address lookup
    /// fails are dropped from the new set and rejoin when the source answers.
    fn refresh_dynamic_at(&self, source: &dyn DynamicUpstreamSource, now_ms: u64) -> DnsRefresh {
        let _refresh_guard = self.dns_refresh_lock.lock();
        let mut report = DnsRefresh::default();
        let static_entries = self.dynamic_static.lock().clone();
        let new_specs = match source.resolve_specs() {
            Ok(specs) => {
                self.dynamic_stale_since_ms.store(0, Ordering::Release);
                specs
            }
            Err(error) => {
                let has_stale_generation = self.tracked.lock().len() > static_entries.len();
                let within_grace = has_stale_generation
                    && source.grace_period().is_some_and(|grace| {
                        let grace_ms = u64::try_from(grace.as_millis()).unwrap_or(u64::MAX);
                        let proposed_start = now_ms.max(1);
                        let _ = self.dynamic_stale_since_ms.compare_exchange(
                            0,
                            proposed_start,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        );
                        let stale_since = self.dynamic_stale_since_ms.load(Ordering::Acquire);
                        now_ms < stale_since.saturating_add(grace_ms)
                    });
                if within_grace {
                    report.kept_stale += 1;
                    tracing::warn!(
                        source = %source.describe(),
                        %error,
                        "⚠️ Dynamic upstream lookup failed; keeping peers within the grace period"
                    );
                    return report;
                }

                report.unresolved += 1;
                let replacement = static_entries;
                if self.replace_dynamic_generation(replacement) {
                    report.changed += 1;
                }
                tracing::warn!(
                    source = %source.describe(),
                    %error,
                    "⚠️ Dynamic upstream lookup failed; the stale peer set expired"
                );
                return report;
            }
        };

        let mut new_tracked = static_entries;
        new_tracked.reserve(new_specs.len());
        for spec in new_specs {
            match spec.resolve(self.resolver.as_ref()) {
                Ok(address) => {
                    if let Some(backend) = spec.backend(address, 1) {
                        new_tracked.push(TrackedUpstream {
                            spec: Some(spec),
                            weight: 1,
                            backend: Some(backend),
                        });
                    }
                }
                Err(error) => {
                    report.unresolved += 1;
                    tracing::warn!(
                        source = %source.describe(),
                        upstream = %spec.authority(),
                        %error,
                        "⚠️ A dynamic peer did not resolve; it stays out of this generation"
                    );
                }
            }
        }

        if !self.replace_dynamic_generation(new_tracked) {
            return report;
        }
        report.changed += 1;
        tracing::info!(
            source = %source.describe(),
            "🔄 Dynamic upstream peer set refreshed"
        );
        report
    }

    /// 🔄 Publishes one dynamic generation only when its concrete peers changed.
    fn replace_dynamic_generation(&self, new_tracked: Vec<TrackedUpstream>) -> bool {
        let mut previous = self.tracked.lock();
        let previous_keys: Vec<String> = previous
            .iter()
            .filter_map(|entry| {
                entry
                    .backend
                    .as_ref()
                    .map(|backend| backend.addr.to_string())
            })
            .collect();
        let next_keys: Vec<String> = new_tracked
            .iter()
            .filter_map(|entry| {
                entry
                    .backend
                    .as_ref()
                    .map(|backend| backend.addr.to_string())
            })
            .collect();
        if previous_keys == next_keys {
            return false;
        }

        self.publish(&new_tracked);
        *previous = new_tracked;
        true
    }

    /// Rebuilds and atomically installs the selector set for `tracked`.
    fn publish(&self, tracked: &[TrackedUpstream]) {
        let backends: Vec<Upstream> = tracked.iter().filter_map(|t| t.backend.clone()).collect();
        let previous = self.pool.load();
        let settings = self.health_check.lock().clone();
        let pool = build_pool(
            self.strategy,
            backends,
            Some(previous.health.as_ref()),
            settings.as_ref(),
            &self.recovery,
        );
        self.pool.store(Arc::new(pool));
        self.generation.fetch_add(1, Ordering::Release);
        // 🩺 A DNS generation starts with Pingora's default-ready health table,
        // so schedule its first real probe immediately instead of waiting a full interval.
        self.next_health_check_ms.store(0, Ordering::Release);
    }

    /// Mark a backend as down (passive health check). Called from
    /// `ProxyHttp::fail_to_connect` when a connection attempt to the
    /// backend fails; `select` then skips it for [`FAIL_COOLDOWN`].
    pub fn mark_unhealthy(&self, addr: &SocketAddr) {
        self.pool.load().health.mark_down(addr);
        if let Some(backup) = &self.backup {
            backup.mark_unhealthy(addr);
        }
    }

    /// Configures the health checker for this load balancer.
    ///
    /// The configuration is stored rather than applied once, so a DNS refresh
    /// that rebuilds the native load balancer keeps checking the new backends.
    ///
    /// - Parameter config: The health check configuration to use for monitoring upstream health.
    pub fn set_health_check(
        &self,
        config: HealthCheckConfig,
        peer_template: pingora_core::upstreams::peer::HttpPeer,
    ) {
        if let Some(backup) = &self.backup {
            backup.set_health_check(config.clone(), peer_template.clone());
            crate::health_check::register(backup);
        }
        let mut settings = self.health_check.lock();
        match settings.as_mut() {
            Some(existing) => {
                existing.config = config;
                existing.peer_template = peer_template;
            }
            None => {
                *settings = Some(HealthCheckSettings {
                    config,
                    peer_template,
                    frequency: None,
                })
            }
        }
        drop(settings);
        self.reapply_health_check();
    }

    /// Sets the frequency of health checks.
    ///
    /// - Parameter frequency: The duration interval between health checks.
    pub fn set_health_check_frequency(&self, frequency: Duration) {
        if let Some(backup) = &self.backup {
            backup.set_health_check_frequency(frequency);
        }
        let mut settings = self.health_check.lock();
        match settings.as_mut() {
            Some(existing) => existing.frequency = Some(frequency),
            None => {
                tracing::error!(
                    "🚫 Health-check frequency was set before its validated probe policy"
                );
                return;
            }
        }
        drop(settings);
        self.reapply_health_check();
    }

    /// Rebuilds the current pool so newly-set health-check settings take hold.
    fn reapply_health_check(&self) {
        let tracked = self.tracked.lock();
        self.publish(&tracked);
    }

    /// 🩺 Runs the current DNS generation's active checker when its jittered deadline arrives.
    pub(crate) async fn run_health_check_if_due(&self) {
        let Some(frequency) = self
            .health_check
            .lock()
            .as_ref()
            .and_then(|settings| settings.frequency)
        else {
            return;
        };
        let now = now_millis();
        if self.next_health_check_ms.load(Ordering::Acquire) > now {
            return;
        }
        self.next_health_check_ms.store(
            now.saturating_add(frequency.as_millis() as u64),
            Ordering::Release,
        );

        let Some(active) = self.pool.load().active_health.clone() else {
            return;
        };
        active.backends().run_health_check(true).await;
        let backends = active.backends().get_backend();
        let any_ready = backends
            .iter()
            .any(|backend| active.backends().ready(backend));
        let exponent = if any_ready {
            self.health_backoff.store(0, Ordering::Release);
            0
        } else {
            self.health_backoff
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                    Some((value + 1).min(3))
                })
                .unwrap_or(0)
                .saturating_add(1)
                .min(3)
        };
        let base = frequency.as_millis() as u64;
        let backed_off = base.saturating_mul(1u64 << exponent);
        let generation = self.generation();
        let jitter_span = (backed_off / 5).max(1);
        let jitter = generation.wrapping_mul(1_103_515_245).wrapping_add(now) % jitter_span;
        self.next_health_check_ms.store(
            now.saturating_add(backed_off.saturating_sub(jitter_span / 2))
                .saturating_add(jitter),
            Ordering::Release,
        );
    }

    /// Selects an upstream backend for a request.
    ///
    /// - Parameter key: Client IP bytes for hash-based selection (`IpHash`).
    ///   Ignored for other strategies.
    /// - Returns: An optional `Upstream` if a healthy backend is available.
    pub fn select(&self, key: Option<&[u8]>) -> Option<Upstream> {
        self.select_excluding(key, &HashSet::new())
    }

    /// 🔁 Selects a healthy backend that this request has not already attempted.
    pub fn select_excluding(
        &self,
        key: Option<&[u8]>,
        excluded: &HashSet<SocketAddr>,
    ) -> Option<Upstream> {
        let pool = self.pool.load();
        let primary = match self.strategy {
            Strategy::LeastConn => {
                // ⚡ LeastConn: pick minimum active-connection upstream.
                // The counter slot is released immediately — for the simple
                // select() API we count a "selection" as one request unit.
                pool.least_conn.as_ref().and_then(|tracker| {
                    tracker
                        .select(
                            excluded,
                            pool.active_health.as_ref(),
                            &pool.recovery_slots,
                            pool.slow_start,
                        )
                        .or_else(|| {
                            // 🌤️ Never turn a recovering singleton into a total outage.
                            tracker.select(
                                excluded,
                                pool.active_health.as_ref(),
                                &pool.recovery_slots,
                                Duration::ZERO,
                            )
                        })
                        .map(|(upstream, _guard)| upstream)
                })
            }
            // 🔑 No key means there is nothing to be consistent about.
            //
            // Hashing an absent key as `b""` looks harmless and is not: every
            // request without the field hashes identically, so they all land on
            // one backend. With `lb_policy header X-Session` that is every
            // client which has not logged in yet — a hot spot that reads like a
            // load-balancer defect and is really a configuration one. Falling
            // through to round-robin spreads them, and costs nothing for the
            // requests that *do* carry a key.
            //
            // 🤡 Found on 2026-08-04 in the Day 22 run, after unit tests had
            // already confirmed the extractor returns `None` here. The tests
            // checked the right thing one layer too high: nobody had asked what
            // the balancer does when handed that `None`.
            Strategy::IpHash if key.is_none_or(<[u8]>::is_empty) => {
                Self::select_round_robin(&pool, excluded)
            }
            Strategy::IpHash => {
                let hash_key = key.unwrap_or(b"");
                // select_with keeps Pingora's own health verdict (`ready`,
                // used by active health checks) and adds our passive marks.
                pool.native_ketama.as_ref().and_then(|native| {
                    native
                        .select_with(hash_key, 256, |b, ready| {
                            ready
                                && active_ready(pool.active_health.as_ref(), b)
                                && pool.health.is_up_backend(b)
                                && inet_address(b).is_none_or(|address| {
                                    slow_start_ready(
                                        &address,
                                        &pool.recovery_slots,
                                        pool.slow_start,
                                    )
                                })
                                && inet_address(b)
                                    .is_none_or(|address| !excluded.contains(&address))
                        })
                        .or_else(|| {
                            native.select_with(hash_key, 256, |b, ready| {
                                ready
                                    && active_ready(pool.active_health.as_ref(), b)
                                    && pool.health.is_up_backend(b)
                                    && inet_address(b)
                                        .is_none_or(|address| !excluded.contains(&address))
                            })
                        })
                })
            }
            Strategy::RoundRobin | Strategy::Random => Self::select_round_robin(&pool, excluded),
        };
        primary.or_else(|| {
            self.backup
                .as_ref()
                .and_then(|backup| backup.select_excluding(key, excluded))
        })
    }

    /// 🔁 Plain round-robin selection over the healthy, non-excluded backends.
    ///
    /// Extracted because it is now two callers: the round-robin and random
    /// strategies, and a hashing strategy whose key is missing for this
    /// request. The second caller is the reason the first fallback pass
    /// (which also honours slow-start) is followed by a second that does not:
    /// a pool entirely inside its slow-start window must still serve someone.
    fn select_round_robin(pool: &Pool, excluded: &HashSet<SocketAddr>) -> Option<Upstream> {
        pool.native_rr.as_ref().and_then(|native| {
            native
                .select_with(b"", 256, |b, ready| {
                    ready
                        && active_ready(pool.active_health.as_ref(), b)
                        && pool.health.is_up_backend(b)
                        && inet_address(b).is_none_or(|address| {
                            slow_start_ready(&address, &pool.recovery_slots, pool.slow_start)
                        })
                        && inet_address(b).is_none_or(|address| !excluded.contains(&address))
                })
                .or_else(|| {
                    native.select_with(b"", 256, |b, ready| {
                        ready
                            && active_ready(pool.active_health.as_ref(), b)
                            && pool.health.is_up_backend(b)
                            && inet_address(b).is_none_or(|address| !excluded.contains(&address))
                    })
                })
        })
    }

    /// 🔢 Counts how many times a new backend set has been published.
    ///
    /// Only ever compared for equality — a caller caches the value it last
    /// reconciled against and re-reads it per request, so the check has to stay
    /// a single atomic load.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// 📍 Every address currently selectable, primary and backup.
    ///
    /// Walks the pool, so it belongs on a reconciliation path and not on the
    /// request path. Pair it with [`Self::generation`] to know when to call it.
    pub fn backend_addresses(&self) -> HashSet<SocketAddr> {
        let mut addresses = self.live_addresses();
        if let Some(backup) = &self.backup {
            addresses.extend(backup.backend_addresses());
        }
        addresses
    }

    /// 🧩 Returns one resolved backend for constructing an address-substituted probe template.
    pub fn first_backend(&self) -> Option<Upstream> {
        self.tracked
            .lock()
            .iter()
            .find_map(|entry| entry.backend.clone())
            .or_else(|| {
                self.backup
                    .as_ref()
                    .and_then(|backup| backup.first_backend())
            })
    }

    fn live_addresses(&self) -> HashSet<SocketAddr> {
        self.tracked
            .lock()
            .iter()
            .filter_map(|entry| entry.backend.as_ref().and_then(inet_address))
            .collect()
    }

    /// Provides access to the underlying native Pingora load balancer (RoundRobin variant).
    ///
    /// Useful for integrating with Pingora's background health-check services.
    /// Note the handle belongs to the *current* pool: a DNS refresh publishes a
    /// new one, so callers that hold on to it will keep checking the old
    /// backend set.
    pub fn native(&self) -> Option<Arc<NativeLoadBalancer<RoundRobin>>> {
        self.pool.load().active_health.clone()
    }
}

/// Resolves configuration entries once, keeping the ones that fail so a later
/// refresh can adopt them.
fn resolve_entries(entries: Vec<UpstreamEntry>, resolver: &dyn Resolve) -> Vec<TrackedUpstream> {
    entries
        .into_iter()
        .map(|entry| {
            let backend = if entry.spec.is_unix() {
                match entry.spec.unix_backend(entry.weight) {
                    Some(backend) => Some(backend),
                    None => {
                        tracing::warn!(
                            upstream = %entry.spec.authority(),
                            "⚠️ Unix-socket upstream path is invalid; it stays out of the pool"
                        );
                        None
                    }
                }
            } else {
                match entry.spec.resolve(resolver) {
                    Ok(address) => entry.spec.backend(address, entry.weight),
                    Err(error) => {
                        tracing::warn!(
                            upstream = %entry.spec.authority(),
                            %error,
                            "⚠️ Upstream did not resolve at startup; it will be retried"
                        );
                        None
                    }
                }
            };
            TrackedUpstream {
                spec: Some(entry.spec),
                weight: entry.weight,
                backend,
            }
        })
        .collect()
}

/// Builds the selector set for one concrete backend list.
fn build_pool(
    strategy: Strategy,
    backends: Vec<Upstream>,
    previous_health: Option<&BackendHealth>,
    health_check: Option<&HealthCheckSettings>,
    recovery: &Arc<RecoveryState>,
) -> Pool {
    let health = Arc::new(BackendHealth::rebuilt(
        previous_health,
        backends.iter().filter_map(inet_address),
    ));

    let recovery_slots = recovery.rebuild(backends.iter().filter_map(inet_address));
    let slow_start = health_check.map_or(Duration::ZERO, |settings| settings.config.slow_start);
    let active_health = health_check.map(|settings| {
        let mut native: NativeLoadBalancer<RoundRobin> =
            build_native_load_balancer(backends.clone());
        let checker = HealthChecker::new(
            settings.config.clone(),
            settings.peer_template.clone(),
            recovery.clone(),
        )
        .expect("validated active health-check configuration must build");
        native.set_health_check(Box::new(checker));
        native.parallel_health_check = true;
        Arc::new(native)
    });

    match strategy {
        Strategy::LeastConn => Pool {
            native_rr: None,
            native_ketama: None,
            least_conn: Some(LeastConnTracker::new(backends, health.clone())),
            active_health,
            recovery_slots,
            slow_start,
            health,
        },
        Strategy::IpHash => Pool {
            // 🔁 A hashing pool still needs a round-robin selector, for the
            // requests that arrive without the field it hashes on. Building it
            // here costs one selector at configuration time and keeps the
            // fallback off the request path's critical section; leaving it
            // `None` meant a keyless request selected nothing at all.
            native_rr: Some(Arc::new(build_native_load_balancer(backends.clone()))),
            native_ketama: Some(Arc::new(build_native_load_balancer(backends))),
            least_conn: None,
            active_health,
            recovery_slots,
            slow_start,
            health,
        },
        // RoundRobin and Random share the same Pingora RoundRobin backend;
        // Pingora's `Random` algorithm is separate but our wrapper uses the
        // RR native LB for both — the strategy enum drives the key.
        Strategy::RoundRobin | Strategy::Random => {
            let native: NativeLoadBalancer<RoundRobin> = build_native_load_balancer(backends);
            Pool {
                native_rr: Some(Arc::new(native)),
                native_ketama: None,
                least_conn: None,
                active_health,
                recovery_slots,
                slow_start,
                health,
            }
        }
    }
}

// MARK: - Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::Scheme;
    use std::collections::BTreeMap;
    use std::collections::HashMap as StdHashMap;

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

        let pool = lb.pool.load();
        let tracker = pool
            .least_conn
            .as_ref()
            .expect("Expected LeastConn tracker");
        // Manually inflate u1's counter to simulate a busy upstream
        tracker.counters[0].1.store(5, Ordering::Relaxed);
        // LeastConn should now return u2 (counter = 0)
        let (selected, _guard) = tracker
            .select(&HashSet::new(), None, &HashMap::new(), Duration::ZERO)
            .unwrap();
        assert_eq!(selected.addr.to_string(), "127.0.0.1:9002");
    }

    /// 🏗️ A Unix-socket pool must be selectable without a resolver, and it
    /// must not register itself for DNS refreshes it can never use.
    #[test]
    fn unix_socket_backends_are_selectable_without_a_resolver() {
        let resolver = ScriptedResolver::with("app", "172.20.0.3:8080");
        let lb = LoadBalancer::from_entries_with_resolver(
            vec![entry("unix//run/app.sock")],
            vec![],
            Strategy::RoundRobin,
            resolver,
        );

        assert!(
            !lb.needs_dns_refresh(),
            "a Unix pool must skip the refresher"
        );
        let backend = lb
            .select(None)
            .expect("the socket backend must be selectable");
        match backend.addr {
            pingora_core::protocols::l4::socket::SocketAddr::Unix(addr) => {
                assert_eq!(
                    addr.as_pathname()
                        .map(|path| path.to_string_lossy().to_string()),
                    Some("/run/app.sock".to_string())
                );
            }
            other => panic!("expected a Unix socket backend, got {other:?}"),
        }
    }

    /// 🏗️ Least-conn must see Unix-socket backends too; filtering them out
    /// would make a single-socket route permanently unselectable.
    #[test]
    fn least_conn_counts_unix_socket_backends() {
        let lb = LoadBalancer::from_entries(
            vec![entry("unix//run/app.sock")],
            vec![],
            Strategy::LeastConn,
        );
        let pool = lb.pool.load();
        let tracker = pool.least_conn.as_ref().expect("least-conn tracker");
        assert_eq!(tracker.counters.len(), 1, "the socket must have a counter");

        let (selected, _guard) = tracker
            .select(&HashSet::new(), None, &HashMap::new(), Duration::ZERO)
            .expect("the socket backend must be selectable");
        assert!(matches!(
            selected.addr,
            pingora_core::protocols::l4::socket::SocketAddr::Unix(_)
        ));
    }

    /// 🧭 A scripted DNS source drives a pool whose whole peer set is
    /// republished on refresh, and a failed lookup keeps the old set serving.
    struct ScriptedSource {
        shared: Arc<ScriptedSourceState>,
    }

    struct ScriptedSourceState {
        addresses: Mutex<Vec<String>>,
        failing: std::sync::atomic::AtomicBool,
        refresh_interval: Option<Duration>,
        grace_period: Option<Duration>,
    }

    impl ScriptedSource {
        fn new(addresses: Vec<String>) -> (Arc<ScriptedSourceState>, Self) {
            Self::with_policy(
                addresses,
                Some(Duration::from_secs(5)),
                Some(Duration::from_secs(60)),
            )
        }

        fn with_policy(
            addresses: Vec<String>,
            refresh_interval: Option<Duration>,
            grace_period: Option<Duration>,
        ) -> (Arc<ScriptedSourceState>, Self) {
            let shared = Arc::new(ScriptedSourceState {
                addresses: Mutex::new(addresses),
                failing: std::sync::atomic::AtomicBool::new(false),
                refresh_interval,
                grace_period,
            });
            let source = Self {
                shared: shared.clone(),
            };
            (shared, source)
        }
    }

    impl ScriptedSourceState {
        fn set(&self, addresses: Vec<String>) {
            *self.addresses.lock() = addresses;
        }

        fn fail_next(&self) {
            self.failing
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    impl crate::dynamic_upstream::DynamicUpstreamSource for ScriptedSource {
        fn describe(&self) -> String {
            "scripted".to_string()
        }

        fn resolve_specs(&self) -> std::io::Result<Vec<UpstreamSpec>> {
            if self
                .shared
                .failing
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return Err(std::io::Error::other("scripted resolver unavailable"));
            }
            Ok(self
                .shared
                .addresses
                .lock()
                .iter()
                .filter_map(|address| UpstreamSpec::parse(address))
                .collect())
        }

        fn refresh_interval(&self) -> Option<Duration> {
            self.shared.refresh_interval
        }

        fn grace_period(&self) -> Option<Duration> {
            self.shared.grace_period
        }
    }

    #[test]
    fn dynamic_sources_publish_their_peer_set_and_keep_it_on_failure() {
        let (shared, source) = ScriptedSource::new(vec![
            "127.0.0.1:8401".to_string(),
            "127.0.0.1:8402".to_string(),
        ]);
        let lb = LoadBalancer::from_dynamic(Box::new(source), vec![], vec![], Strategy::RoundRobin);
        assert!(
            lb.needs_dns_refresh(),
            "a dynamic pool must register with the refresher"
        );

        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for _ in 0..8 {
            seen.insert(lb.select(None).expect("a dynamic peer").addr.to_string());
        }
        assert_eq!(seen.len(), 2, "both scripted peers must rotate: {seen:?}");

        // 🧭 The source moved: the next refresh must publish the new set.
        shared.set(vec!["127.0.0.1:8403".to_string()]);
        lb.refresh_dns();
        let after: std::collections::HashSet<String> = (0..4)
            .filter_map(|_| lb.select(None).map(|backend| backend.addr.to_string()))
            .collect();
        assert_eq!(
            after,
            std::collections::HashSet::from(["127.0.0.1:8403".to_string()])
        );

        // 🧯 A source failure keeps the last published generation.
        shared.fail_next();
        lb.refresh_dns();
        let kept = lb.select(None).expect("a stale peer must still serve");
        assert_eq!(kept.addr.to_string(), "127.0.0.1:8403");
    }

    #[test]
    fn dynamic_sources_refresh_only_when_their_own_deadline_arrives() {
        let (shared, source) = ScriptedSource::new(vec!["127.0.0.1:8411".to_string()]);
        let lb = LoadBalancer::from_dynamic(Box::new(source), vec![], vec![], Strategy::RoundRobin);
        shared.set(vec!["127.0.0.1:8412".to_string()]);

        assert_eq!(
            lb.refresh_dns_due(Some(Duration::from_secs(30)), 1_000),
            DnsRefresh::default(),
            "the first scheduler visit only establishes the deadline"
        );
        assert_eq!(selected(&lb), "127.0.0.1:8411");
        assert_eq!(
            lb.refresh_dns_due(Some(Duration::from_secs(30)), 5_999),
            DnsRefresh::default()
        );
        assert_eq!(selected(&lb), "127.0.0.1:8411");

        assert_eq!(
            lb.refresh_dns_due(Some(Duration::from_secs(30)), 6_000)
                .changed,
            1
        );
        assert_eq!(selected(&lb), "127.0.0.1:8412");

        let (off_shared, off_source) = ScriptedSource::new(vec!["127.0.0.1:8413".to_string()]);
        let off_lb =
            LoadBalancer::from_dynamic(Box::new(off_source), vec![], vec![], Strategy::RoundRobin);
        assert!(off_lb.has_dns_schedule(None));
        off_shared.set(vec!["127.0.0.1:8414".to_string()]);
        assert_eq!(
            off_lb.refresh_dns_due(None, 10_000),
            DnsRefresh::default(),
            "an explicit source interval schedules even when global refresh is off"
        );
        assert_eq!(off_lb.refresh_dns_due(None, 15_000).changed, 1);
        assert_eq!(selected(&off_lb), "127.0.0.1:8414");
    }

    #[test]
    fn dynamic_source_grace_expires_from_the_first_failed_refresh() {
        let (shared, source) = ScriptedSource::with_policy(
            vec!["127.0.0.1:8421".to_string()],
            Some(Duration::from_secs(5)),
            Some(Duration::from_secs(2)),
        );
        let lb = LoadBalancer::from_dynamic(Box::new(source), vec![], vec![], Strategy::RoundRobin);
        shared.fail_next();

        let first_failure = lb.refresh_own_dns_at(1_000);
        assert_eq!(first_failure.kept_stale, 1);
        let within = lb.refresh_own_dns_at(2_999);
        assert_eq!(within.kept_stale, 1);
        assert_eq!(selected(&lb), "127.0.0.1:8421");

        let expired = lb.refresh_own_dns_at(3_000);
        assert_eq!(expired.changed, 1);
        assert_eq!(expired.unresolved, 1);
        assert!(lb.select(None).is_none());
    }

    #[test]
    fn dynamic_source_without_grace_drops_stale_peers_immediately() {
        let (shared, source) = ScriptedSource::with_policy(
            vec!["127.0.0.1:8431".to_string()],
            Some(Duration::from_secs(5)),
            None,
        );
        let lb = LoadBalancer::from_dynamic(Box::new(source), vec![], vec![], Strategy::RoundRobin);
        shared.fail_next();

        let report = lb.refresh_dns();
        assert_eq!(report.changed, 1);
        assert_eq!(report.unresolved, 1);
        assert_eq!(report.kept_stale, 0);
        assert!(lb.select(None).is_none());
    }

    #[test]
    fn dynamic_refresh_preserves_static_peers() {
        let (shared, source) = ScriptedSource::new(vec!["127.0.0.1:8441".to_string()]);
        let lb = LoadBalancer::from_dynamic(
            Box::new(source),
            vec![entry("127.0.0.1:8440")],
            vec![],
            Strategy::RoundRobin,
        );
        shared.set(vec!["127.0.0.1:8442".to_string()]);
        assert_eq!(lb.refresh_dns().changed, 1);

        let seen: HashSet<String> = (0..8).map(|_| selected(&lb)).collect();
        assert_eq!(
            seen,
            HashSet::from(["127.0.0.1:8440".to_string(), "127.0.0.1:8442".to_string(),])
        );
    }

    /// ⏱️ A dynamic source and a fixed hostname retain independent schedules.
    #[test]
    fn dynamic_pool_refreshes_static_hostnames_on_the_global_deadline() {
        let resolver = ScriptedResolver::with("app", "172.20.0.3:8080");
        let (shared, source) = ScriptedSource::new(vec!["127.0.0.1:8451".to_string()]);
        let lb = LoadBalancer::from_dynamic_with_resolver(
            Box::new(source),
            vec![entry("http://app:8080")],
            vec![],
            Strategy::RoundRobin,
            resolver.clone(),
        );

        resolver.set("app", "172.20.0.9:8080");
        shared.set(vec!["127.0.0.1:8452".to_string()]);
        assert_eq!(
            lb.refresh_dns_due(Some(Duration::from_secs(30)), 1_000),
            DnsRefresh::default(),
            "the first visit establishes both deadlines"
        );

        assert_eq!(
            lb.refresh_dns_due(Some(Duration::from_secs(30)), 6_000)
                .changed,
            1,
            "only the five-second dynamic deadline is due"
        );
        let before_static_deadline: HashSet<String> = (0..8).map(|_| selected(&lb)).collect();
        assert_eq!(
            before_static_deadline,
            HashSet::from(["172.20.0.3:8080".to_string(), "127.0.0.1:8452".to_string(),])
        );

        assert_eq!(
            lb.refresh_dns_due(Some(Duration::from_secs(30)), 31_000)
                .changed,
            1,
            "the fixed hostname follows the global deadline"
        );
        let after_static_deadline: HashSet<String> = (0..8).map(|_| selected(&lb)).collect();
        assert_eq!(
            after_static_deadline,
            HashSet::from(["172.20.0.9:8080".to_string(), "127.0.0.1:8452".to_string(),])
        );
    }

    #[test]
    fn request_local_exclusions_cover_every_selection_strategy() {
        for strategy in [
            Strategy::RoundRobin,
            Strategy::Random,
            Strategy::LeastConn,
            Strategy::IpHash,
        ] {
            let first_address = addr("127.0.0.1:8201");
            let second_address = addr("127.0.0.1:8202");
            let load_balancer = LoadBalancer::new(
                vec![
                    Upstream::new("127.0.0.1:8201").unwrap(),
                    Upstream::new("127.0.0.1:8202").unwrap(),
                ],
                strategy,
            );
            let key = Some(b"stable-client".as_slice());
            let first = load_balancer.select(key).unwrap();
            let pingora_core::protocols::l4::socket::SocketAddr::Inet(first) = first.addr else {
                panic!("expected an internet upstream");
            };
            let mut excluded = HashSet::from([first]);

            let alternative = load_balancer.select_excluding(key, &excluded).unwrap();
            assert_ne!(alternative.addr.to_string(), first.to_string());

            // 🚫 Excluding the complete pool must fail instead of reusing an attempted peer.
            excluded.insert(if first == first_address {
                second_address
            } else {
                first_address
            });
            assert!(load_balancer.select_excluding(key, &excluded).is_none());
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
        lb.pool
            .load()
            .health
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

    // ---- DNS re-resolution ----

    /// A resolver whose answers the test rewrites between refreshes, so a
    /// container moving to a new IP — and a resolver going away entirely —
    /// can both be reproduced deterministically.
    #[derive(Default)]
    struct ScriptedResolver {
        answers: Mutex<StdHashMap<String, std::io::Result<Vec<SocketAddr>>>>,
        lookups: AtomicUsize,
    }

    impl ScriptedResolver {
        fn with(host: &str, address: &str) -> Arc<Self> {
            let resolver = Arc::new(Self::default());
            resolver.set(host, address);
            resolver
        }

        fn set(&self, host: &str, address: &str) {
            self.answers
                .lock()
                .insert(host.to_string(), Ok(vec![address.parse().unwrap()]));
        }

        fn fail(&self, host: &str) {
            self.answers.lock().insert(
                host.to_string(),
                Err(std::io::Error::other("resolver unavailable")),
            );
        }

        fn lookups(&self) -> usize {
            self.lookups.load(Ordering::Relaxed)
        }
    }

    impl Resolve for ScriptedResolver {
        fn resolve(&self, host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
            self.lookups.fetch_add(1, Ordering::Relaxed);
            match self.answers.lock().get(host) {
                Some(Ok(addrs)) => Ok(addrs.clone()),
                Some(Err(error)) => Err(std::io::Error::new(error.kind(), error.to_string())),
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no such host",
                )),
            }
        }
    }

    fn entry(address: &str) -> UpstreamEntry {
        UpstreamEntry {
            spec: UpstreamSpec::parse(address).unwrap(),
            weight: 1,
        }
    }

    fn selected(lb: &LoadBalancer) -> String {
        lb.select(None).unwrap().addr.to_string()
    }

    #[test]
    fn backend_follows_the_container_to_its_new_address() {
        let resolver = ScriptedResolver::with("app", "172.20.0.3:8080");
        let lb = LoadBalancer::from_entries_with_resolver(
            vec![entry("http://app:8080")],
            vec![],
            Strategy::RoundRobin,
            resolver.clone(),
        );
        assert_eq!(selected(&lb), "172.20.0.3:8080");

        // The container restarts on a different address.
        resolver.set("app", "172.20.0.9:8080");
        let report = lb.refresh_dns();

        assert_eq!(report.changed, 1);
        assert_eq!(report.kept_stale, 0);
        assert_eq!(selected(&lb), "172.20.0.9:8080");
    }

    #[test]
    fn dns_publish_reapplies_health_settings_to_the_new_pool() {
        let resolver = ScriptedResolver::with("app", "172.20.0.3:8080");
        let lb = LoadBalancer::from_entries_with_resolver(
            vec![entry("http://app:8080")],
            vec![],
            Strategy::RoundRobin,
            resolver.clone(),
        );
        let peer = pingora_core::upstreams::peer::HttpPeer::new(
            "172.20.0.3:8080",
            false,
            "app".to_string(),
        );
        lb.set_health_check(
            HealthCheckConfig {
                path: "/health".to_string(),
                timeout: Duration::from_secs(1),
                expected_statuses: vec![200],
                expected_body: None,
                positive_threshold: 1,
                negative_threshold: 1,
                method: "GET".to_string(),
                host: "app".to_string(),
                host_override: None,
                sni_override: None,
                headers: BTreeMap::new(),
                port_override: None,
                reuse_connection: false,
                max_response_body_bytes: 1_024,
                slow_start: Duration::ZERO,
            },
            peer,
        );
        lb.set_health_check_frequency(Duration::from_secs(5));
        let before = lb.native().expect("initial health pool");

        resolver.set("app", "172.20.0.9:8080");
        assert_eq!(lb.refresh_dns().changed, 1);
        let after = lb.native().expect("refreshed health pool");

        assert!(!Arc::ptr_eq(&before, &after));
        assert!(
            after
                .backends()
                .get_backend()
                .iter()
                .any(|backend| { backend.addr.to_string() == "172.20.0.9:8080" })
        );
    }

    #[test]
    fn the_upstream_hostname_survives_a_re_resolution() {
        let resolver = ScriptedResolver::with("app.internal", "172.20.0.3:8443");
        let lb = LoadBalancer::from_entries_with_resolver(
            vec![entry("https://app.internal:8443")],
            vec![],
            Strategy::RoundRobin,
            resolver.clone(),
        );

        resolver.set("app.internal", "172.20.0.9:8443");
        lb.refresh_dns();

        // SNI and the upstream Host header both read these back, so losing
        // them on a refresh would break TLS to the new address.
        let backend = lb.select(None).unwrap();
        assert_eq!(
            backend.ext.get::<crate::upstream::HostName>().unwrap().0,
            "app.internal"
        );
        assert_eq!(*backend.ext.get::<Scheme>().unwrap(), Scheme::Https);
    }

    #[test]
    fn a_failing_resolver_keeps_the_last_known_backend() {
        let resolver = ScriptedResolver::with("app", "172.20.0.3:8080");
        let lb = LoadBalancer::from_entries_with_resolver(
            vec![entry("http://app:8080")],
            vec![],
            Strategy::RoundRobin,
            resolver.clone(),
        );

        resolver.fail("app");
        let report = lb.refresh_dns();

        assert_eq!(report.kept_stale, 1);
        assert_eq!(report.changed, 0);
        assert_eq!(
            selected(&lb),
            "172.20.0.3:8080",
            "a resolver outage must not empty the pool"
        );

        // And it recovers once the resolver answers again.
        resolver.set("app", "172.20.0.4:8080");
        assert_eq!(lb.refresh_dns().changed, 1);
        assert_eq!(selected(&lb), "172.20.0.4:8080");
    }

    #[test]
    fn one_failing_name_does_not_evict_its_healthy_neighbours() {
        let resolver = ScriptedResolver::with("app-a", "172.20.0.3:8080");
        resolver.set("app-b", "172.20.0.4:8080");
        let lb = LoadBalancer::from_entries_with_resolver(
            vec![entry("http://app-a:8080"), entry("http://app-b:8080")],
            vec![],
            Strategy::RoundRobin,
            resolver.clone(),
        );

        resolver.fail("app-a");
        resolver.set("app-b", "172.20.0.5:8080");
        let report = lb.refresh_dns();

        assert_eq!(report.kept_stale, 1);
        assert_eq!(report.changed, 1);

        let mut seen: Vec<String> = (0..2).map(|_| selected(&lb)).collect();
        seen.sort();
        assert_eq!(seen, vec!["172.20.0.3:8080", "172.20.0.5:8080"]);
    }

    #[test]
    fn an_upstream_that_is_not_up_yet_joins_on_a_later_refresh() {
        let resolver = Arc::new(ScriptedResolver::default());
        let lb = LoadBalancer::from_entries_with_resolver(
            vec![entry("http://app:8080")],
            vec![],
            Strategy::RoundRobin,
            resolver.clone(),
        );
        // Boot happened before the app container existed.
        assert!(lb.select(None).is_none());
        assert_eq!(lb.refresh_dns().unresolved, 1);

        resolver.set("app", "172.20.0.7:8080");
        let report = lb.refresh_dns();

        assert_eq!(report.adopted, 1);
        assert_eq!(selected(&lb), "172.20.0.7:8080");
    }

    #[test]
    fn a_backend_that_did_not_move_keeps_its_failure_mark() {
        let resolver = ScriptedResolver::with("app-a", "172.20.0.3:8080");
        resolver.set("app-b", "172.20.0.4:8080");
        let lb = LoadBalancer::from_entries_with_resolver(
            vec![entry("http://app-a:8080"), entry("http://app-b:8080")],
            vec![],
            Strategy::RoundRobin,
            resolver.clone(),
        );

        // app-a is refusing connections, so it is out of rotation.
        lb.mark_unhealthy(&addr("172.20.0.3:8080"));
        // Only app-b moves.
        resolver.set("app-b", "172.20.0.5:8080");
        lb.refresh_dns();

        for _ in 0..4 {
            assert_eq!(
                selected(&lb),
                "172.20.0.5:8080",
                "a refresh elsewhere must not silently revive a failed backend"
            );
        }
    }

    #[test]
    fn ip_literals_are_never_looked_up() {
        let resolver = Arc::new(ScriptedResolver::default());
        let lb = LoadBalancer::from_entries_with_resolver(
            vec![entry("http://127.0.0.1:8001")],
            vec![],
            Strategy::RoundRobin,
            resolver.clone(),
        );

        assert!(!lb.needs_dns_refresh());
        assert_eq!(lb.refresh_dns(), DnsRefresh::default());
        assert_eq!(resolver.lookups(), 0);
        assert_eq!(selected(&lb), "127.0.0.1:8001");
    }

    #[test]
    fn a_refresh_that_changes_nothing_does_not_republish() {
        let resolver = ScriptedResolver::with("app", "172.20.0.3:8080");
        let lb = LoadBalancer::from_entries_with_resolver(
            vec![entry("http://app:8080")],
            vec![],
            Strategy::RoundRobin,
            resolver.clone(),
        );

        let before = Arc::as_ptr(&lb.pool.load_full());
        let report = lb.refresh_dns();
        let after = Arc::as_ptr(&lb.pool.load_full());

        assert!(report.is_noop());
        assert_eq!(before, after, "a steady name must not churn the pool");
    }

    #[test]
    fn backup_pools_are_refreshed_too() {
        let resolver = ScriptedResolver::with("primary", "172.20.0.3:8080");
        resolver.set("standby", "172.20.0.4:8080");
        let lb = LoadBalancer::from_entries_with_resolver(
            vec![entry("http://primary:8080")],
            vec![entry("http://standby:8080")],
            Strategy::RoundRobin,
            resolver.clone(),
        );
        assert!(lb.needs_dns_refresh());

        resolver.set("standby", "172.20.0.8:8080");
        assert_eq!(lb.refresh_dns().changed, 1);

        lb.mark_unhealthy(&addr("172.20.0.3:8080"));
        assert_eq!(selected(&lb), "172.20.0.8:8080");
    }

    #[test]
    fn a_moved_backend_keeps_its_weight_and_strategy() {
        let resolver = ScriptedResolver::with("heavy", "172.20.0.3:8080");
        resolver.set("light", "172.20.0.4:8080");
        let lb = LoadBalancer::from_entries_with_resolver(
            vec![
                UpstreamEntry {
                    spec: UpstreamSpec::parse("http://heavy:8080").unwrap(),
                    weight: 3,
                },
                entry("http://light:8080"),
            ],
            vec![],
            Strategy::RoundRobin,
            resolver.clone(),
        );

        resolver.set("heavy", "172.20.0.9:8080");
        lb.refresh_dns();

        let mut heavy = 0;
        let mut light = 0;
        for _ in 0..40 {
            match selected(&lb).as_str() {
                "172.20.0.9:8080" => heavy += 1,
                "172.20.0.4:8080" => light += 1,
                other => panic!("unexpected backend {other}"),
            }
        }
        assert_eq!(heavy, 30);
        assert_eq!(light, 10);
    }
}

#[cfg(test)]
mod consistent_hash_tests {
    use super::*;

    fn pool_of(count: usize) -> LoadBalancer {
        let upstreams = (0..count)
            .map(|i| Upstream::new(&format!("127.0.0.1:{}", 9000 + i)).unwrap())
            .collect();
        LoadBalancer::new(upstreams, Strategy::IpHash)
    }

    /// 📐 The property that makes consistent hashing worth having.
    ///
    /// Adding a backend to a pool of N must move roughly 1/(N+1) of the keys —
    /// only the share the newcomer takes over. A plain `hash % n` would move
    /// almost all of them, which for a session-affinity policy means logging
    /// nearly every user out at once. Asserting "the same key maps to the same
    /// backend" would pass just as happily for `hash % n`, so it proves nothing
    /// about the choice actually made here.
    ///
    /// The bound is loose (25 %) because ketama distributes by weight over a
    /// ring of virtual nodes rather than exactly; the point is the order of
    /// magnitude. `hash % n` would land near 100 % and fail this by a mile.
    #[test]
    fn growing_the_pool_remaps_only_a_small_share_of_keys() {
        let keys: Vec<String> = (0..2_000).map(|i| format!("session-{i}")).collect();

        let before = pool_of(4);
        let after = pool_of(5);

        let mut placed = 0usize;
        let mut moved = 0usize;
        for key in &keys {
            let (Some(a), Some(b)) = (
                before.select(Some(key.as_bytes())),
                after.select(Some(key.as_bytes())),
            ) else {
                continue;
            };
            placed += 1;
            if a.addr != b.addr {
                moved += 1;
            }
        }

        assert!(placed > 1_000, "the pools placed too few keys to judge");
        let share = moved as f64 / placed as f64;
        assert!(
            share < 0.25,
            "adding one backend to a pool of four moved {:.1}% of keys; consistent hashing \
             should move roughly 1/5, and a modulo scheme would move nearly all of them",
            share * 100.0
        );
    }

    /// 🚫 A hashing pool handed no key must still spread the load.
    ///
    /// This is the defect the Day 22 run found on 2026-08-04. The extractor
    /// correctly returned `None` for a request missing its header — and a unit
    /// test confirmed exactly that — but the balancer turned `None` into `b""`
    /// and hashed it, so every keyless request landed on one backend. With
    /// `lb_policy header X-Session` that is every client not yet logged in.
    ///
    /// **The earlier test checked the right thing one layer too high.** Nobody
    /// had asked what the balancer does with the `None` it was handed, so this
    /// one asks the balancer directly.
    #[test]
    fn a_hashing_pool_without_a_key_falls_back_to_spreading() {
        let pool = pool_of(4);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..80 {
            if let Some(upstream) = pool.select(None) {
                seen.insert(upstream.addr);
            }
        }
        assert!(
            seen.len() >= 3,
            "80 keyless requests reached only {} of 4 backends — hashing an absent \
             key pins every such client to one upstream",
            seen.len()
        );
    }

    /// 🚫 An empty key is the same hot spot as an absent one.
    #[test]
    fn a_hashing_pool_with_an_empty_key_also_spreads() {
        let pool = pool_of(4);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..80 {
            if let Some(upstream) = pool.select(Some(b"")) {
                seen.insert(upstream.addr);
            }
        }
        assert!(
            seen.len() >= 3,
            "an empty key reached only {} backends",
            seen.len()
        );
    }

    /// 🎯 The mirror property: the same key must reach the same backend while
    /// the pool is unchanged, or "consistent" means nothing.
    #[test]
    fn the_same_key_reaches_the_same_backend() {
        let pool = pool_of(4);
        let first = pool.select(Some(b"session-abc")).map(|u| u.addr);
        for _ in 0..50 {
            assert_eq!(
                pool.select(Some(b"session-abc")).map(|u| u.addr),
                first,
                "an unchanged pool must place a key identically every time"
            );
        }
    }

    /// 🌊 Different keys must actually spread. A ring that sent everything to
    /// one backend would pass both tests above.
    #[test]
    fn different_keys_spread_across_the_pool() {
        let pool = pool_of(4);
        let mut seen = std::collections::HashSet::new();
        for i in 0..500 {
            if let Some(upstream) = pool.select(Some(format!("session-{i}").as_bytes())) {
                seen.insert(upstream.addr);
            }
        }
        assert!(
            seen.len() >= 3,
            "500 distinct keys reached only {} of 4 backends",
            seen.len()
        );
    }
}
