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
//! registers itself here as a `Weak`, and a single background scheduler asks
//! each pool whether its own deadline has arrived. One task for the whole
//! process rather than one per pool keeps the scheduler bounded while honoring
//! dynamic-source intervals independently. `Weak` is what makes reload safe: a
//! pool retired by `update_config` simply stops being visited, with no
//! deregistration step to forget.
//!
//! ⏱️ INTERVAL, NOT TTL: static hostname pools follow the global `dns_refresh`;
//! dynamic sources may override it with their own `refresh`. The one-second
//! scheduler only compares precompiled deadlines and performs no lookup until
//! a pool is due.

use crate::load_balancer::{DnsRefresh, LoadBalancer, dns_now_millis};
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
static REGISTRATION: LazyLock<tokio::sync::Notify> = LazyLock::new(tokio::sync::Notify::new);

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
    REGISTRATION.notify_one();
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

/// ⏱️ Refreshes only pools whose independently compiled deadline is due.
fn refresh_due(default_interval: Option<Duration>) -> DnsRefresh {
    let live: Vec<Arc<LoadBalancer>> = {
        let mut pools = POOLS.lock();
        pools.retain(|weak| weak.strong_count() > 0);
        pools.iter().filter_map(Weak::upgrade).collect()
    };
    let now_ms = dns_now_millis().max(1);

    let mut report = DnsRefresh::default();
    for pool in live {
        report.merge(pool.refresh_dns_due(default_interval, now_ms));
    }
    report
}

/// ⏱️ Checks precompiled pool policy without performing a DNS lookup.
fn has_scheduled_pools(default_interval: Option<Duration>) -> bool {
    let mut pools = POOLS.lock();
    pools.retain(|weak| weak.strong_count() > 0);
    pools
        .iter()
        .filter_map(Weak::upgrade)
        .any(|pool| pool.has_dns_schedule(default_interval))
}

/// Runs the refresh loop until the process ends.
pub async fn run(default_interval: Option<Duration>) {
    match default_interval {
        Some(interval) => tracing::info!(
            interval_secs = interval.as_secs(),
            pools = registered_pools(),
            "🔄 Upstream DNS scheduler enabled"
        ),
        None => tracing::info!(
            pools = registered_pools(),
            "🔄 Upstream DNS scheduler enabled for explicit dynamic intervals"
        ),
    }

    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let registered = REGISTRATION.notified();
        if !has_scheduled_pools(default_interval) {
            registered.await;
            continue;
        }
        ticker.tick().await;
        let report = match tokio::task::spawn_blocking(move || refresh_due(default_interval)).await
        {
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
        assert!(!hostname.has_dns_schedule(None));
        assert!(hostname.has_dns_schedule(Some(Duration::from_secs(30))));

        // A reload drops the old ProxyState, and with it the pool.
        drop(hostname);
        assert_eq!(registered_pools(), 0);
    }
}
