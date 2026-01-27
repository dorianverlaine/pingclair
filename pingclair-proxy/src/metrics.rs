//! Prometheus Metrics for Pingclair
//!
//! Provides metrics collection for requests, errors, and latency.

use prometheus::{Encoder, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder};
use std::sync::LazyLock;

/// Global metrics registry
pub static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

/// Total requests processed
pub static REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new("pingclair_requests_total", "Total number of HTTP requests"),
        &["method", "status", "host"]
    ).expect("metric can be created")
});

/// Request latency in seconds
pub static REQUEST_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    HistogramVec::new(
        prometheus::HistogramOpts::new(
            "pingclair_request_duration_seconds",
            "Request duration in seconds"
        ),
        &["method", "status", "host"]
    ).expect("metric can be created")
});

/// Active connections
pub static ACTIVE_CONNECTIONS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new("pingclair_active_connections", "Number of active connections"),
        &["host"]
    ).expect("metric can be created")
});

/// Initialize metrics
pub fn init() {
    // Register metrics
    // We ignore errors in case they are already registered (though typically init is called once)
    let _ = REGISTRY.register(Box::new(REQUESTS_TOTAL.clone()));
    let _ = REGISTRY.register(Box::new(REQUEST_DURATION_SECONDS.clone()));
    let _ = REGISTRY.register(Box::new(ACTIVE_CONNECTIONS.clone()));
}

/// Gather metrics in Prometheus text format
pub fn gather() -> String {
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
