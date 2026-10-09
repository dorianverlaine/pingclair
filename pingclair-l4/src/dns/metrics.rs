// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📊 DNS jobs report configured routes; snapshots and names never become labels.

use super::{DnsRuntime, Failure, Pool};
use pingclair_runtime::metrics::REGISTRY;
use prometheus::{IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts};
use std::sync::{Arc, LazyLock};
use tokio::time::Instant;

const REASONS: [&str; 7] = [
    "available",
    "empty",
    "nxdomain",
    "transient",
    "timeout",
    "invalid",
    "cancelled",
];

fn index(result: Result<(), Failure>) -> usize {
    match result {
        Ok(()) => 0,
        Err(Failure::Empty) => 1,
        Err(Failure::NxDomain) => 2,
        Err(Failure::Transient) => 3,
        Err(Failure::Timeout) => 4,
        Err(Failure::Invalid) => 5,
        Err(Failure::Cancelled) => 6,
    }
}

pub(super) fn reason(result: Result<(), Failure>) -> &'static str {
    REASONS[index(result)]
}

struct Collectors {
    refresh: IntCounterVec,
    available: IntGaugeVec,
}

static COLLECTORS: LazyLock<Collectors> = LazyLock::new(|| {
    let refresh = IntCounterVec::new(
        Opts::new(
            "l4_dns_refreshes_total",
            "Completed or retired DNS jobs observed by each configured TCP route.",
        ),
        &["listener", "route", "reason"],
    )
    .unwrap();
    let available = IntGaugeVec::new(
        Opts::new(
            "l4_dns_pool_available",
            "Whether the configured TCP route has a DNS snapshot before its hard deadline.",
        ),
        &["listener", "route"],
    )
    .unwrap();
    REGISTRY.register(Box::new(refresh.clone())).unwrap();
    REGISTRY.register(Box::new(available.clone())).unwrap();
    Collectors { refresh, available }
});

pub(super) struct Binding {
    pool: Arc<Pool>,
    refresh: [IntCounter; REASONS.len()],
    available: IntGauge,
}

impl Binding {
    pub fn prepare(pool: Arc<Pool>, listener: &str, route: usize) -> Self {
        let route = (route + 1).to_string();
        let c = &*COLLECTORS;
        Self {
            pool,
            refresh: REASONS.map(|reason| c.refresh.with_label_values(&[listener, &route, reason])),
            available: c.available.with_label_values(&[listener, &route]),
        }
    }

    pub fn clear(&self) {
        self.available.set(0);
    }

    fn update(&self, now: Instant) -> Option<Instant> {
        let snapshot = self.pool.snapshot.load();
        let hard = snapshot.as_ref().map(|snapshot| snapshot.hard);
        let hard = hard.filter(|hard| *hard > now);
        self.available.set(i64::from(hard.is_some()));
        hard
    }
}

impl DnsRuntime {
    // 🔒 Callers serialize job completion, retirement and publication with the publication lock.
    pub(super) fn record_refresh(&self, pool: &Arc<Pool>, result: Result<(), Failure>) {
        if pingclair_runtime::metrics::enabled() {
            for binding in self.observers.load().iter() {
                if Arc::ptr_eq(&binding.pool, pool) {
                    binding.refresh[index(result)].inc();
                }
            }
        }
    }

    // ⏱️ The coordinator wakes at hard expiry even while a slow DNS job or backoff is pending.
    pub(super) fn metrics_deadline(&self) -> Option<Instant> {
        let _publication = self.publication.lock().expect("DNS publication");
        let now = Instant::now();
        self.observers
            .load()
            .iter()
            .filter_map(|binding| binding.update(now))
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Answer;
    use pingclair_core::config::{Layer4Dns, Layer4IpVersions};
    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn failed_drafts_preserve_gauges_and_retirement_clears_live_snapshots() {
        let runtime = DnsRuntime::default();
        let config = Layer4Dns {
            name: "pool.test".into(),
            port: 443,
            resolvers: Some(vec!["127.0.0.1:53".into()]),
            versions: Layer4IpVersions::Ipv4,
            valid_ms: None,
            stale_ms: 1000,
            allow_ip: Some(vec!["203.0.113.0/24".into()]),
        };
        let mut draft = runtime.prepare(vec![]);
        let source = draft.source(&config).unwrap();
        draft.observe(&source, "metrics-draft", 0);
        runtime.publish(draft);
        let publish = || {
            source
                .0
                .apply(Ok(Answer {
                    addresses: vec!["203.0.113.10:443".parse().unwrap()],
                    fresh: Instant::now() + Duration::from_secs(1),
                }))
                .unwrap()
        };
        publish();
        assert!(runtime.metrics_deadline().is_some());
        let gauge = COLLECTORS
            .available
            .with_label_values(&["metrics-draft", "1"]);
        assert_eq!(gauge.get(), 1);
        let mut failed = runtime.prepare(vec![]);
        let changed = Layer4Dns {
            name: "other.test".into(),
            ..config
        };
        let replacement = failed.source(&changed).unwrap();
        failed.observe(&replacement, "metrics-draft", 0);
        drop(failed);
        assert_eq!(gauge.get(), 1);
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(runtime.metrics_deadline(), None);
        assert_eq!(gauge.get(), 0);
        publish();
        assert!(runtime.metrics_deadline().is_some());
        assert_eq!(gauge.get(), 1);
        runtime.publish(runtime.prepare(vec![]));
        assert_eq!(gauge.get(), 0);
        assert!(source.0.snapshot.load().is_none());
    }
}
