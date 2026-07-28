// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Upstream DNS Re-resolution
//!
//! A hostname upstream is resolved once when its route is built, which is
//! enough for a fixed IP but wrong for anything orchestrated: a container
//! that restarts comes back on a different address under the same name, and
//! a proxy holding the old address serves 502s until it is restarted.
//!
//! 🏗️ ARCHITECTURE: every load-balancer pool that has at least one hostname
//! registers itself here as a `Weak`, and a single background task re-resolves
//! all of them on a fixed interval. One task for the whole process rather than
//! one per pool keeps the DNS traffic proportional to the number of distinct
//! upstreams, not to the number of routes that mention them. `Weak` is what
//! makes reload safe: a pool retired by `update_config` simply stops being
//! visited, with no deregistration step to forget.
//!
//! ⏱️ INTERVAL, NOT TTL: the standard-library resolver reports addresses and
//! not their TTL, and reading TTLs would mean carrying a full DNS client and
//! its transport dependencies. It would also buy little where it matters —
//! Docker's embedded resolver answers with a 600 s TTL, far longer than the
//! window in which a restarted container needs to be picked up. A fixed,
//! configurable interval is both the smaller dependency and the tighter
//! bound. `dns_refresh` in the global block controls it.

use crate::load_balancer::{DnsRefresh, LoadBalancer};
use parking_lot::Mutex;
use std::sync::{Arc, LazyLock, Weak};
use std::time::Duration;

/// How often hostname upstreams are re-resolved when the config says nothing.
///
/// Short enough that a container restart is picked up before an operator
/// would notice, long enough that a hundred upstreams are a rounding error
/// of DNS traffic.
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

static POOLS: LazyLock<Mutex<Vec<Weak<LoadBalancer>>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Registers a pool for periodic re-resolution.
///
/// Pools built entirely from IP literals are ignored, so a configuration
/// without hostnames never causes a single lookup.
pub fn register(pool: &Arc<LoadBalancer>) {
    if !pool.needs_dns_refresh() {
        return;
    }
    let mut pools = POOLS.lock();
    pools.retain(|weak| weak.strong_count() > 0);
    pools.push(Arc::downgrade(pool));
}

/// Number of live registered pools. Retiring dead entries here as well keeps
/// the count honest for tests and for the startup log line.
pub fn registered_pools() -> usize {
    let mut pools = POOLS.lock();
    pools.retain(|weak| weak.strong_count() > 0);
    pools.len()
}

/// Re-resolves every registered pool once. Blocking: the standard-library
/// resolver is synchronous, so callers on an async runtime must hand this to
/// a blocking thread.
pub fn refresh_all() -> DnsRefresh {
    // Collect the strong references under the lock but resolve outside it —
    // a slow or hung resolver must not block `register` during a reload.
    let live: Vec<Arc<LoadBalancer>> = {
        let mut pools = POOLS.lock();
        pools.retain(|weak| weak.strong_count() > 0);
        pools.iter().filter_map(Weak::upgrade).collect()
    };

    let mut report = DnsRefresh::default();
    for pool in live {
        report.merge(pool.refresh_dns());
    }
    report
}

/// Runs the refresh loop until the process ends.
pub async fn run(interval: Duration) {
    tracing::info!(
        interval_secs = interval.as_secs(),
        pools = registered_pools(),
        "🔄 Upstream DNS re-resolution enabled"
    );

    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick fires immediately; the pools were just resolved at boot,
    // so skip it and let the first real pass happen one interval later.
    ticker.tick().await;

    loop {
        ticker.tick().await;
        let report = match tokio::task::spawn_blocking(refresh_all).await {
            Ok(report) => report,
            Err(error) => {
                tracing::error!(%error, "❌ DNS refresh task failed");
                continue;
            }
        };

        if !report.is_noop() || report.kept_stale > 0 || report.unresolved > 0 {
            tracing::info!(
                changed = report.changed,
                adopted = report.adopted,
                kept_stale = report.kept_stale,
                unresolved = report.unresolved,
                "🔄 Upstream DNS refresh"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load_balancer::{Strategy, UpstreamEntry};
    use crate::upstream::{Resolve, UpstreamSpec};
    use std::net::SocketAddr;

    /// The registry is process-global, so every assertion about it lives in
    /// one test — two of them running in parallel would race on the count.
    struct Offline;

    impl Resolve for Offline {
        fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no resolver in tests",
            ))
        }
    }

    fn pool(address: &str) -> Arc<LoadBalancer> {
        Arc::new(LoadBalancer::from_entries_with_resolver(
            vec![UpstreamEntry {
                spec: UpstreamSpec::parse(address).unwrap(),
                weight: 1,
            }],
            vec![],
            Strategy::RoundRobin,
            Arc::new(Offline),
        ))
    }

    #[test]
    fn the_registry_holds_hostname_pools_and_forgets_dropped_ones() {
        let literal = pool("http://127.0.0.1:8001");
        register(&literal);
        assert_eq!(
            registered_pools(),
            0,
            "a pool of IP literals must never cause a lookup"
        );

        let hostname = pool("http://app:8080");
        register(&hostname);
        assert_eq!(registered_pools(), 1);

        // A reload drops the old ProxyState, and with it the pool.
        drop(hostname);
        assert_eq!(registered_pools(), 0);
    }
}
