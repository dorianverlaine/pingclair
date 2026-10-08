// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📊 Configuration-bound labels and precomputed handles for TCP sessions.

use crate::observation::Outcome;
use pingclair_runtime::metrics::REGISTRY;
use prometheus::{
    Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
};
use std::sync::LazyLock;

struct Collectors {
    completed: IntCounterVec,
    active: IntGaugeVec,
    preread: IntCounterVec,
    connect: IntCounterVec,
    bytes: IntCounterVec,
    duration: HistogramVec,
}

static COLLECTORS: LazyLock<Collectors> = LazyLock::new(|| {
    let counters =
        |name, help, labels: &[&str]| IntCounterVec::new(Opts::new(name, help), labels).unwrap();
    let collectors = Collectors {
        completed: counters(
            "l4_connections_total",
            "Completed TCP sessions by configured route and outcome.",
            &["listener", "route", "outcome"],
        ),
        active: IntGaugeVec::new(
            Opts::new(
                "l4_active_connections",
                "Accepted TCP sessions still in progress.",
            ),
            &["listener"],
        )
        .unwrap(),
        preread: counters(
            "l4_preread_failures_total",
            "Preread failures and declined TLS-shaped input.",
            &["listener", "reason"],
        ),
        connect: counters(
            "l4_upstream_connect_failures_total",
            "Failed upstream connection attempts per session.",
            &["listener", "reason"],
        ),
        bytes: counters(
            "l4_bytes_total",
            "Bytes successfully written to the destination, including replayed preread bytes.",
            &["listener", "direction"],
        ),
        duration: HistogramVec::new(
            HistogramOpts::new(
                "l4_connection_duration_seconds",
                "TCP session lifetime, including preread and connection time.",
            )
            .buckets(vec![0.01, 0.1, 1.0, 10.0, 60.0, 300.0, 3600.0]),
            &["listener"],
        )
        .unwrap(),
    };
    for collector in [
        Box::new(collectors.completed.clone()) as Box<dyn prometheus::core::Collector>,
        Box::new(collectors.active.clone()),
        Box::new(collectors.preread.clone()),
        Box::new(collectors.connect.clone()),
        Box::new(collectors.bytes.clone()),
        Box::new(collectors.duration.clone()),
    ] {
        REGISTRY
            .register(collector)
            .expect("L4 metric names are unique");
    }
    collectors
});

pub(crate) struct Metrics {
    completed: Vec<[IntCounter; Outcome::ALL.len()]>,
    pub active: IntGauge,
    pub duration: Histogram,
    pub to_client: IntCounter,
    pub to_upstream: IntCounter,
    pub declined: IntCounter,
    preread: [IntCounter; 3],
    connect: [IntCounter; 2],
}

impl Metrics {
    pub fn prepare(listener: &str, routes: usize) -> Self {
        let c = &*COLLECTORS;
        Self {
            // 🏷️ Slot zero means no selected route; route labels are one-based ordinals.
            completed: (0..=routes)
                .map(|index| {
                    let route = if index == 0 {
                        "none".into()
                    } else {
                        index.to_string()
                    };
                    Outcome::ALL.map(|outcome| {
                        c.completed
                            .with_label_values(&[listener, &route, outcome.name()])
                    })
                })
                .collect(),
            active: c.active.with_label_values(&[listener]),
            duration: c.duration.with_label_values(&[listener]),
            to_client: c.bytes.with_label_values(&[listener, "upstream_to_client"]),
            to_upstream: c.bytes.with_label_values(&[listener, "client_to_upstream"]),
            declined: c.preread.with_label_values(&[listener, "declined_tls"]),
            preread: ["timeout", "overflow", "io_error"]
                .map(|reason| c.preread.with_label_values(&[listener, reason])),
            connect: ["timeout", "io_error"]
                .map(|reason| c.connect.with_label_values(&[listener, reason])),
        }
    }

    pub fn finish(&self, route: Option<usize>, outcome: Outcome, seconds: f64) {
        self.active.dec();
        self.duration.observe(seconds);
        self.completed[route.map_or(0, |index| index + 1)][outcome as usize].inc();
        match outcome {
            Outcome::PrereadTimeout => self.preread[0].inc(),
            Outcome::PrereadOverflow => self.preread[1].inc(),
            Outcome::PrereadError => self.preread[2].inc(),
            Outcome::ConnectTimeout => self.connect[0].inc(),
            Outcome::ConnectError => self.connect[1].inc(),
            Outcome::Completed
            | Outcome::Blocked
            | Outcome::PrereadEof
            | Outcome::NoRoute
            | Outcome::RelayTimeout
            | Outcome::RelayError
            | Outcome::Cancelled => {}
        }
    }
}
