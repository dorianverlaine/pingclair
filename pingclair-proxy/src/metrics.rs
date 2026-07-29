// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Prometheus Metrics for Pingclair
//!
//! Provides metrics collection for requests, errors, and latency.

use prometheus::{Encoder, HistogramVec, IntCounterVec, IntGaugeVec, Opts, Registry, TextEncoder};
use std::sync::LazyLock;

// MARK: - Global Registry

/// Global metrics registry
pub static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

// MARK: - Metrics Definitions

/// Total requests processed
pub static REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new("pingclair_requests_total", "Total number of HTTP requests"),
        &["method", "status", "host"],
    )
    .expect("metric can be created")
});

/// Request latency in seconds
pub static REQUEST_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    HistogramVec::new(
        prometheus::HistogramOpts::new(
            "pingclair_request_duration_seconds",
            "Request duration in seconds",
        ),
        &["method", "status", "host"],
    )
    .expect("metric can be created")
});

/// Active connections
pub static ACTIVE_CONNECTIONS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "pingclair_active_connections",
            "Number of active connections",
        ),
        &["host"],
    )
    .expect("metric can be created")
});

/// 🚦 Requests rejected before upstream dispatch.
pub static OVERLOAD_REJECTIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "pingclair_overload_rejections_total",
            "Requests rejected by overload or circuit-breaker policy",
        ),
        &["host", "route", "reason"],
    )
    .expect("metric can be created")
});

/// 🧱 Requests currently executing inside a protected route.
pub static ROUTE_IN_FLIGHT: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    IntGaugeVec::new(
        Opts::new(
            "pingclair_route_in_flight",
            "Requests currently executing inside a protected route",
        ),
        &["host", "route"],
    )
    .expect("metric can be created")
});

/// 🕰️ Requests currently waiting for a protected route slot.
pub static ROUTE_PENDING: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    IntGaugeVec::new(
        Opts::new(
            "pingclair_route_pending",
            "Requests currently waiting for a protected route slot",
        ),
        &["host", "route"],
    )
    .expect("metric can be created")
});

/// 🔌 Requests currently occupying one upstream capacity slot.
pub static UPSTREAM_IN_FLIGHT: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    IntGaugeVec::new(
        Opts::new(
            "pingclair_upstream_in_flight",
            "Requests currently occupying one upstream capacity slot",
        ),
        &["host", "route", "upstream"],
    )
    .expect("metric can be created")
});

/// 🔄 Circuit-breaker state transitions.
pub static CIRCUIT_TRANSITIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "pingclair_circuit_transitions_total",
            "Per-upstream circuit-breaker state transitions",
        ),
        &["host", "route", "upstream", "state"],
    )
    .expect("metric can be created")
});

/// 🔌 Current circuit-breaker state: closed 0, half-open 1, open 2.
pub static CIRCUIT_STATE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    IntGaugeVec::new(
        Opts::new(
            "pingclair_circuit_state",
            "Current per-upstream circuit state: closed 0, half-open 1, open 2",
        ),
        &["host", "route", "upstream"],
    )
    .expect("metric can be created")
});

// MARK: - Initialization

/// Initialize metrics
///
/// Registers all defined metrics with the global registry.
/// Should be called once at application startup.
pub fn init() {
    // Register metrics
    // We ignore errors in case they are already registered (though typically init is called once)
    let _ = REGISTRY.register(Box::new(REQUESTS_TOTAL.clone()));
    let _ = REGISTRY.register(Box::new(REQUEST_DURATION_SECONDS.clone()));
    let _ = REGISTRY.register(Box::new(ACTIVE_CONNECTIONS.clone()));
    let _ = REGISTRY.register(Box::new(OVERLOAD_REJECTIONS_TOTAL.clone()));
    let _ = REGISTRY.register(Box::new(ROUTE_IN_FLIGHT.clone()));
    let _ = REGISTRY.register(Box::new(ROUTE_PENDING.clone()));
    let _ = REGISTRY.register(Box::new(UPSTREAM_IN_FLIGHT.clone()));
    let _ = REGISTRY.register(Box::new(CIRCUIT_TRANSITIONS_TOTAL.clone()));
    let _ = REGISTRY.register(Box::new(CIRCUIT_STATE.clone()));
}

// MARK: - Export

/// Gather metrics in Prometheus text format
///
/// Use this to expose metrics via an HTTP endpoint.
///
/// - Returns: A string containing the Prometheus-formatted metrics.
pub fn gather() -> String {
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
