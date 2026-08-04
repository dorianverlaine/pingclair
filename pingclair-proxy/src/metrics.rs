// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Prometheus Metrics for Pingclair
//!
//! Provides metrics collection for requests, errors, and latency.

use prometheus::{
    Encoder, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Once};

// MARK: - Global Registry

/// Global metrics registry
pub static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

/// 📊 Whether the running configuration asked to collect metrics.
static ENABLED: AtomicBool = AtomicBool::new(false);

/// 🧩 Registers collectors only once even when several server paths initialize metrics.
static REGISTER: Once = Once::new();

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

/// 📏 Estimated request body size in bytes (from Content-Length).
pub static REQUEST_SIZE_BYTES: LazyLock<HistogramVec> = LazyLock::new(|| {
    HistogramVec::new(
        prometheus::HistogramOpts::new(
            "pingclair_request_size_bytes",
            "Estimated request body size in bytes",
        )
        .buckets(vec![
            256.0,
            1024.0,
            4096.0,
            16384.0,
            65536.0,
            262144.0,
            1_048_576.0,
            4_194_304.0,
        ]),
        &["method", "status", "host"],
    )
    .expect("metric can be created")
});

/// 📏 Response body size in bytes.
pub static RESPONSE_SIZE_BYTES: LazyLock<HistogramVec> = LazyLock::new(|| {
    HistogramVec::new(
        prometheus::HistogramOpts::new(
            "pingclair_response_size_bytes",
            "Response body size in bytes",
        )
        .buckets(vec![
            256.0,
            1024.0,
            4096.0,
            16384.0,
            65536.0,
            262144.0,
            1_048_576.0,
            4_194_304.0,
        ]),
        &["method", "status", "host"],
    )
    .expect("metric can be created")
});

/// ⏱️ Time-to-first-byte in seconds.
pub static RESPONSE_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    HistogramVec::new(
        prometheus::HistogramOpts::new(
            "pingclair_response_duration_seconds",
            "Time to first response byte in seconds",
        ),
        &["method", "status", "host"],
    )
    .expect("metric can be created")
});

/// 💥 Requests that failed while being handled.
pub static REQUEST_ERRORS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "pingclair_request_errors_total",
            "Requests that ended with an error",
        ),
        &["method", "host"],
    )
    .expect("metric can be created")
});

/// Active connections
pub static ACTIVE_CONNECTIONS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    IntGaugeVec::new(
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

/// 🗄️ How each cacheable request resolved against the response cache.
///
/// One counter with an outcome label rather than four counters, because the
/// question an operator actually asks is a ratio — "what share of these were
/// hits" — and a ratio across separate metric names is easy to get wrong when
/// one of them has never been incremented and so is absent from the scrape.
///
/// Outcomes: `hit` (served from the store), `miss` (went to the origin and was
/// eligible to be stored), `stale` (a stored copy was revalidated), `bypass`
/// (the request or response was refused storage on purpose — see
/// `uncacheable_response_reason`).
pub static CACHE_REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "pingclair_cache_requests_total",
            "Cacheable requests by how they resolved against the response cache",
        ),
        &["host", "route", "outcome"],
    )
    .expect("metric can be created")
});

/// 🗄️ Bytes currently held by the shared response store.
///
/// Paired with [`CACHE_LIMIT_BYTES`] this answers the only question that
/// matters when caching is on: how close is the store to its ceiling. A gauge
/// sitting at the limit means entries are being evicted to make room, which is
/// working as designed but is also the signal that the ceiling is too low for
/// the working set.
pub static CACHE_SIZE_BYTES: LazyLock<IntGauge> = LazyLock::new(|| {
    IntGauge::new(
        "pingclair_cache_size_bytes",
        "Bytes currently stored in the shared response cache",
    )
    .expect("metric can be created")
});

/// 📏 The configured ceiling, exported so a dashboard does not have to be told
/// separately what the limit is.
pub static CACHE_LIMIT_BYTES: LazyLock<IntGauge> = LazyLock::new(|| {
    IntGauge::new(
        "pingclair_cache_limit_bytes",
        "Configured ceiling on shared response cache bytes",
    )
    .expect("metric can be created")
});

/// 🧹 Bytes reclaimed by evicting least-recently-used entries.
///
/// Monotonic. A flat line with a full [`CACHE_SIZE_BYTES`] means the working
/// set fits; a climbing line means entries are being evicted and re-fetched,
/// so the cache is doing work without saving any.
pub static CACHE_EVICTED_BYTES_TOTAL: LazyLock<IntGauge> = LazyLock::new(|| {
    IntGauge::new(
        "pingclair_cache_evicted_bytes_total",
        "Bytes reclaimed from the response cache by eviction",
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

/// 🧑‍💻 Admin API request counter, labelled by endpoint and status.
pub static ADMIN_REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "pingclair_admin_http_requests_total",
            "Requests made to the admin API endpoints",
        ),
        &["method", "path", "status"],
    )
    .expect("metric can be created")
});

/// 🩺 Reverse-proxy upstream healthiness (1 = healthy, 0 = down).
pub static UPSTREAM_HEALTHY: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    IntGaugeVec::new(
        Opts::new(
            "pingclair_reverse_proxy_upstreams_healthy",
            "Healthiness of reverse-proxy upstreams",
        ),
        &["upstream"],
    )
    .expect("metric can be created")
});

// MARK: - Initialization

/// Initialize metrics
///
/// Registers all defined metrics with the global registry.
/// Should be called once at application startup.
pub fn init() {
    ENABLED.store(true, Ordering::Release);
    REGISTER.call_once(|| {
        // 📚 Registering is process-global; duplicate initialization must not
        // rebuild collectors or make a second copy visible at scrape time.
        let _ = REGISTRY.register(Box::new(REQUESTS_TOTAL.clone()));
        let _ = REGISTRY.register(Box::new(REQUEST_DURATION_SECONDS.clone()));
        let _ = REGISTRY.register(Box::new(REQUEST_SIZE_BYTES.clone()));
        let _ = REGISTRY.register(Box::new(RESPONSE_SIZE_BYTES.clone()));
        let _ = REGISTRY.register(Box::new(RESPONSE_DURATION_SECONDS.clone()));
        let _ = REGISTRY.register(Box::new(REQUEST_ERRORS_TOTAL.clone()));
        let _ = REGISTRY.register(Box::new(ACTIVE_CONNECTIONS.clone()));
        let _ = REGISTRY.register(Box::new(OVERLOAD_REJECTIONS_TOTAL.clone()));
        let _ = REGISTRY.register(Box::new(CACHE_REQUESTS_TOTAL.clone()));
        let _ = REGISTRY.register(Box::new(CACHE_SIZE_BYTES.clone()));
        let _ = REGISTRY.register(Box::new(CACHE_LIMIT_BYTES.clone()));
        let _ = REGISTRY.register(Box::new(CACHE_EVICTED_BYTES_TOTAL.clone()));
        let _ = REGISTRY.register(Box::new(ROUTE_IN_FLIGHT.clone()));
        let _ = REGISTRY.register(Box::new(ROUTE_PENDING.clone()));
        let _ = REGISTRY.register(Box::new(UPSTREAM_IN_FLIGHT.clone()));
        let _ = REGISTRY.register(Box::new(CIRCUIT_TRANSITIONS_TOTAL.clone()));
        let _ = REGISTRY.register(Box::new(CIRCUIT_STATE.clone()));
        let _ = REGISTRY.register(Box::new(ADMIN_REQUESTS_TOTAL.clone()));
        let _ = REGISTRY.register(Box::new(UPSTREAM_HEALTHY.clone()));
        // 🧑‍💻 Process metrics (RSS, CPU time) come from a hand-rolled collector
        // built on getrusage, which exists on both Linux and macOS — so the local
        // dev loop actually exercises this code instead of cfg-ing it away.
        let _ = REGISTRY.register(Box::new(ProcessCollector::new()));
    });
}

/// 🍃 Reports whether request paths should perform any metric work.
#[inline]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

/// 📥 Increments and returns the active-request gauge used by this request.
pub fn request_started(host: &str) -> Option<IntGauge> {
    if !enabled() {
        return None;
    }
    let metric = ACTIVE_CONNECTIONS.with_label_values(&[host]);
    metric.inc();
    Some(metric)
}

/// 🧑‍💻 Cross-platform process metrics collected from `getrusage`.
struct ProcessCollector;

impl ProcessCollector {
    fn new() -> Self {
        Self
    }
}

impl prometheus::core::Collector for ProcessCollector {
    fn desc(&self) -> Vec<&prometheus::core::Desc> {
        Vec::new()
    }

    fn collect(&self) -> Vec<prometheus::proto::MetricFamily> {
        let mut families = Vec::new();
        // 🧮 `ru_maxrss` is bytes on macOS and kilobytes on Linux.
        let (user_secs, system_secs, max_rss) = process_usage();
        let rss_bytes = if cfg!(target_os = "macos") {
            max_rss
        } else {
            max_rss.saturating_mul(1024)
        };
        let cpu_seconds = user_secs + system_secs;

        for (name, help, value) in [
            (
                "pingclair_process_resident_memory_bytes",
                "Peak resident set size of the process in bytes",
                rss_bytes as f64,
            ),
            (
                "pingclair_process_cpu_seconds_total",
                "Total user and system CPU time of the process in seconds",
                cpu_seconds,
            ),
        ] {
            let mut family = prometheus::proto::MetricFamily::default();
            family.set_name(name.to_string());
            family.set_help(help.to_string());
            family.set_field_type(prometheus::proto::MetricType::GAUGE);
            let mut metric = prometheus::proto::Metric::default();
            metric.set_gauge(prometheus::proto::Gauge {
                value: Some(value),
                ..Default::default()
            });
            family.set_metric(vec![metric]);
            families.push(family);
        }
        families
    }
}

/// 🧮 Reads process resource usage via `getrusage`, available on both Linux
/// and macOS. Returns (user_seconds, system_seconds, max_rss_in_platform_units).
fn process_usage() -> (f64, f64, i64) {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    if result != 0 {
        return (0.0, 0.0, 0);
    }
    let user_secs = usage.ru_utime.tv_sec as f64 + usage.ru_utime.tv_usec as f64 / 1_000_000.0;
    let system_secs = usage.ru_stime.tv_sec as f64 + usage.ru_stime.tv_usec as f64 / 1_000_000.0;
    (user_secs, system_secs, usage.ru_maxrss)
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
