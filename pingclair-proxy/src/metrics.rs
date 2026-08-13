// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Prometheus Metrics for Pingclair
//!
//! Provides metrics collection for requests, errors, and latency.

use prometheus::{
    Encoder, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder,
};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Once};

// MARK: - Global Registry

/// Global metrics registry
pub static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

/// 📊 Whether the running configuration asked to collect metrics.
static ENABLED: AtomicBool = AtomicBool::new(false);

/// 🧩 Registers collectors only once even when several server paths initialize metrics.
static REGISTER: Once = Once::new();

// MARK: - Label Cardinality

/// 🛡️ Ceiling on distinct values any one label may take.
///
/// Prometheus keeps a separate time series per label combination, each holding
/// a counter and its label strings. A label fed from client input therefore
/// turns a stream of requests into unbounded memory growth — and the `host`
/// label comes straight from the `Host` header, so anyone can drive it.
///
/// 1024 is comfortably more virtual hosts than a single instance serves while
/// still being a fixed, small amount of memory.
const MAX_LABEL_VALUES: usize = 1024;

/// 🏷️ Replacement for values beyond the ceiling.
///
/// Collapsing rather than dropping keeps the totals correct: requests to
/// unrecognised hosts still get counted, just not individually. A dashboard
/// that suddenly shows most traffic under `other` is itself the signal that
/// something is sending junk.
const OVERFLOW_LABEL: &str = "other";

/// 🛡️ Distinct values already admitted, per label name.
static LABEL_VALUES: LazyLock<std::sync::RwLock<HashMap<&'static str, HashSet<String>>>> =
    LazyLock::new(|| std::sync::RwLock::new(HashMap::new()));

/// 🛡️ Caps a client-controlled label value.
///
/// Returns the value itself while the label is under its ceiling, and
/// [`OVERFLOW_LABEL`] once it is not. The set only grows, deliberately: a
/// value that has been admitted keeps its own series, so a host that was busy
/// yesterday does not start folding into `other` because a burst of junk
/// arrived today.
///
/// 🚫 **Never label a metric with a raw path, a user identifier, or anything
/// else per-request without passing it through here.** Configured values —
/// route patterns, upstream addresses — are already bounded by the
/// configuration and do not need it.
pub fn capped_label(label: &'static str, value: &str) -> String {
    {
        let seen = LABEL_VALUES.read().unwrap_or_else(|e| e.into_inner());
        if let Some(values) = seen.get(label) {
            if values.contains(value) {
                return value.to_string();
            }
            if values.len() >= MAX_LABEL_VALUES {
                return OVERFLOW_LABEL.to_string();
            }
        }
    }

    let mut seen = LABEL_VALUES.write().unwrap_or_else(|e| e.into_inner());
    let values = seen.entry(label).or_default();
    if values.contains(value) {
        return value.to_string();
    }
    // 🏁 Re-check under the write lock: two threads can both pass the read
    // check on the last free slot, and without this one of them would push the
    // set one over its ceiling.
    if values.len() >= MAX_LABEL_VALUES {
        return OVERFLOW_LABEL.to_string();
    }
    values.insert(value.to_string());
    value.to_string()
}

// MARK: - Host Label Policy

/// 🏷️ What the `host` label is allowed to say, decided once per configuration.
///
/// All three answers exist because "break the numbers down by host" and "let a
/// stranger decide how many series this process holds" are the same request
/// unless something bounds the host set. The three differ only in what does the
/// bounding.
enum HostLabelPolicy {
    /// No breakdown at all: every request shares one series per method and
    /// status. The default, and the only shape that costs nothing to produce.
    Off,
    /// Only hosts this configuration serves get their own series; everything
    /// else folds into one. The Pingclairfile decides the ceiling, so a
    /// stranger cannot move it.
    Configured(HashSet<Box<str>>),
    /// Every host gets a series until [`MAX_LABEL_VALUES`] of them exist. What
    /// an operator gets by asking for `observe_catchall_hosts`: the sender
    /// chooses the values, and this cap is all that stands behind it.
    Capped,
}

/// 🏷️ The live policy, republished on reload.
///
/// [`ArcSwap`] rather than a lock because this is read on every request and
/// written approximately never — the same reason `ProxyState` is published this
/// way. Readers never block and never wait on a writer.
static HOST_LABEL_POLICY: LazyLock<arc_swap::ArcSwap<HostLabelPolicy>> =
    LazyLock::new(|| arc_swap::ArcSwap::from_pointee(HostLabelPolicy::Off));

/// 📊 Applies a configuration's `metrics` block to the label policy.
///
/// `configured_hosts` is every host name the configuration serves. It is only
/// consulted when the operator asked for per-host numbers without asking for
/// catch-all hosts — which is the default pairing, and the one where the
/// configuration rather than the client decides how many series exist.
pub fn configure_host_labels<'a>(
    options: &pingclair_core::config::MetricsOptions,
    configured_hosts: impl Iterator<Item = &'a str>,
) {
    let policy = match (options.per_host, options.observe_catchall_hosts) {
        (false, _) => HostLabelPolicy::Off,
        (true, true) => HostLabelPolicy::Capped,
        (true, false) => HostLabelPolicy::Configured(
            configured_hosts
                .filter(|host| !host.is_empty())
                .map(Box::from)
                .collect(),
        ),
    };
    HOST_LABEL_POLICY.store(std::sync::Arc::new(policy));
}

/// 🏷️ The `host` label value for one request.
///
/// 🏎️ Borrows in the two common cases. `Off` returns a `'static` empty string
/// and `Configured` returns the caller's own slice, so the default request path
/// does a single hash lookup and no allocation at all — where the previous
/// unconditional [`capped_label`] took a read lock and built a `String` on every
/// request, whether or not anyone had asked to see hosts broken out.
#[inline]
pub fn host_label(host: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    match &**HOST_LABEL_POLICY.load() {
        HostLabelPolicy::Off => Cow::Borrowed(""),
        HostLabelPolicy::Configured(hosts) => {
            if hosts.contains(host) {
                Cow::Borrowed(host)
            } else {
                Cow::Borrowed(OVERFLOW_LABEL)
            }
        }
        HostLabelPolicy::Capped => Cow::Owned(capped_label("host", host)),
    }
}

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

/// 🪵 Access-log lines dropped because the writer could not keep up.
///
/// The only signal that a gap exists. A bounded queue turns "the disk is slow"
/// into "some lines are missing" rather than "the proxy stopped"; this counter
/// is what stops the second outcome from being silent. Any non-zero value means
/// the log is incomplete for that period — alert on the rate, not the total.
pub static ACCESS_LOG_DROPPED_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    IntCounter::new(
        "pingclair_access_log_dropped_total",
        "Access log lines dropped because the writer queue was full",
    )
    .expect("metric can be created")
});

/// ⏱️ Time spent waiting on the upstream, separately from total request time.
///
/// The distinction is what makes it actionable: total latency rising tells you
/// something is slow, this tells you whether it is the origin or this proxy.
/// Labels come from configuration, so they need no cardinality cap.
pub static UPSTREAM_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    HistogramVec::new(
        prometheus::HistogramOpts::new(
            "pingclair_upstream_duration_seconds",
            "Time from dispatching upstream to its response header",
        ),
        &["route", "upstream"],
    )
    .expect("metric can be created")
});

/// 💥 Upstream attempts that failed, by why.
///
/// Split from `pingclair_request_errors_total` because they answer different
/// questions: that one counts requests the client saw fail, this one counts
/// attempts — a request retried twice and then served successfully contributes
/// two failures here and none there, which is precisely the invisible
/// degradation worth alerting on.
pub static UPSTREAM_ERRORS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "pingclair_upstream_errors_total",
            "Failed upstream attempts by route, upstream and reason",
        ),
        &["route", "upstream", "reason"],
    )
    .expect("metric can be created")
});

/// 🔁 Upstream attempts made beyond the first.
///
/// A rising retry rate with a flat error rate is the signature of a backend
/// degrading while the proxy hides it — the users are fine and the origin is
/// not, and nothing else in the metric set says so.
pub static UPSTREAM_RETRIES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "pingclair_upstream_retries_total",
            "Upstream attempts beyond the first, by route and outcome",
        ),
        &["route", "outcome"],
    )
    .expect("metric can be created")
});

/// 🔗 Upstream connections established, versus reused from the keepalive pool.
///
/// The ratio is the point. Every `new` is a TCP handshake and, for TLS
/// upstreams, a full negotiation; a pool that is too small shows up here long
/// before it shows up as latency.
pub static UPSTREAM_CONNECTIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "pingclair_upstream_connections_total",
            "Upstream connections by whether they were newly established or reused",
        ),
        &["disposition"],
    )
    .expect("metric can be created")
});

/// 🔐 Completed downstream TLS handshakes, by negotiated version and ALPN.
///
/// Both labels come from a fixed set the TLS stack can produce, so they are
/// bounded without a cap. Useful for answering "can we drop TLS 1.2 yet"
/// with data rather than a guess.
pub static TLS_HANDSHAKES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "pingclair_tls_handshakes_total",
            "Completed downstream TLS handshakes by version and negotiated protocol",
        ),
        &["version", "alpn"],
    )
    .expect("metric can be created")
});

/// 🚀 HTTP/3 connections currently open.
pub static H3_CONNECTIONS: LazyLock<IntGauge> = LazyLock::new(|| {
    IntGauge::new(
        "pingclair_h3_connections",
        "HTTP/3 connections currently open",
    )
    .expect("metric can be created")
});

/// 🚀 HTTP/3 requests, by how the stream ended.
///
/// `cancelled` is the one to watch: a client abandoning a stream is normal in
/// small numbers and, in large ones, means responses are arriving too slowly
/// to be worth waiting for.
pub static H3_REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "pingclair_h3_requests_total",
            "HTTP/3 requests by how the stream ended",
        ),
        &["outcome"],
    )
    .expect("metric can be created")
});

/// 🚦 Whether this instance is currently accepting traffic (1) or not (0).
///
/// Deliberately a gauge rather than something derived from request counts: an
/// instance that is draining still serves the connections it already has, so
/// "requests are flowing" and "send it more" are different facts.
pub static READY: LazyLock<IntGauge> = LazyLock::new(|| {
    IntGauge::new(
        "pingclair_ready",
        "1 when the instance is accepting new traffic, 0 while starting or draining",
    )
    .expect("metric can be created")
});

/// 🔢 Increments every time a configuration is successfully applied.
///
/// The number itself means nothing; the *change* is the signal. Two instances
/// behind one balancer reporting different versions means a reload reached one
/// and not the other, which is otherwise invisible until they behave
/// differently under traffic.
pub static CONFIG_VERSION: LazyLock<IntGauge> = LazyLock::new(|| {
    IntGauge::new(
        "pingclair_config_version",
        "Increments on every successfully applied configuration",
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
        let _ = REGISTRY.register(Box::new(ACCESS_LOG_DROPPED_TOTAL.clone()));
        let _ = REGISTRY.register(Box::new(UPSTREAM_DURATION_SECONDS.clone()));
        let _ = REGISTRY.register(Box::new(UPSTREAM_ERRORS_TOTAL.clone()));
        let _ = REGISTRY.register(Box::new(UPSTREAM_RETRIES_TOTAL.clone()));
        let _ = REGISTRY.register(Box::new(UPSTREAM_CONNECTIONS_TOTAL.clone()));
        let _ = REGISTRY.register(Box::new(TLS_HANDSHAKES_TOTAL.clone()));
        let _ = REGISTRY.register(Box::new(H3_CONNECTIONS.clone()));
        let _ = REGISTRY.register(Box::new(H3_REQUESTS_TOTAL.clone()));
        let _ = REGISTRY.register(Box::new(READY.clone()));
        let _ = REGISTRY.register(Box::new(CONFIG_VERSION.clone()));
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
///
/// 🛡️ The host is client-controlled, so it goes through [`host_label`] like
/// every other per-request label. It did not, until Day 26 measured it: with
/// 1600 distinct `Host` headers every other host-labelled family stopped at
/// 1025 series while this one grew to 1600, unauthenticated.
///
/// 🔁 The *gauge handle* is returned rather than the label, so the decrement
/// lands on the series that was incremented even if a reload changes the policy
/// in between. Re-deriving the label at the end would leak a count every time a
/// host left the configuration mid-request.
pub fn request_started(host: &str) -> Option<IntGauge> {
    if !enabled() {
        return None;
    }
    let host = host_label(host);
    let metric = ACTIVE_CONNECTIONS.with_label_values(&[host.as_ref()]);
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

/// 📊 The media type every Pingclair scrape response carries.
///
/// The version number is part of the Prometheus text exposition contract, not
/// decoration: a scraper reads it to know how to parse the body. This is the
/// only format written here — no OpenMetrics negotiation happens, which is what
/// [`pingclair_core::config::HandlerConfig::Metrics`] records.
pub const SCRAPE_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

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

#[cfg(test)]
mod host_label_tests {
    use super::*;
    use pingclair_core::config::MetricsOptions;

    /// 🏷️ The three policies, and what each one does with a host nobody
    /// configured.
    ///
    /// One test rather than three because the interesting property is the
    /// *difference* between them: the same unconfigured host has to come back
    /// as three different answers, and a bug that collapses two of them into
    /// one would still pass a test that only looked at one policy.
    ///
    /// ⚠️ Serialized by being a single test — the policy is process-global, so
    /// two tests mutating it in parallel would each see the other's answer.
    #[test]
    fn each_policy_gives_the_configured_and_unconfigured_host_its_own_answer() {
        let configured = ["a.example", "b.example"];

        // 📉 Default: no breakdown at all. This is the behaviour change — the
        // host label used to be emitted unconditionally, and upstream's default
        // is off, so a Pingclairfile that never mentions `per_host` gets one
        // series per method and status.
        configure_host_labels(&MetricsOptions::default(), configured.iter().copied());
        assert_eq!(host_label("a.example"), "");
        assert_eq!(host_label("stranger.example"), "");

        // 🛡️ `per_host` alone: the configuration decides the ceiling. A host
        // nobody set up folds away no matter how many distinct ones arrive, so
        // the series count cannot be moved from outside at all.
        configure_host_labels(
            &MetricsOptions {
                per_host: true,
                ..MetricsOptions::default()
            },
            configured.iter().copied(),
        );
        assert_eq!(host_label("a.example"), "a.example");
        assert_eq!(host_label("b.example"), "b.example");
        assert_eq!(host_label("stranger.example"), OVERFLOW_LABEL);

        // ⚠️ `observe_catchall_hosts`: the sender decides, and only
        // `MAX_LABEL_VALUES` stands behind it. Still bounded, which is why it
        // is offered at all — but bounded far above what the configuration
        // knows about.
        configure_host_labels(
            &MetricsOptions {
                per_host: true,
                observe_catchall_hosts: true,
                ..MetricsOptions::default()
            },
            configured.iter().copied(),
        );
        assert_eq!(
            host_label("stranger.example"),
            "stranger.example",
            "a catch-all host must get its own series once it has been asked for"
        );

        // 🧹 Leave the process in its default state for whatever runs next.
        configure_host_labels(&MetricsOptions::default(), std::iter::empty());
    }
}

#[cfg(test)]
mod cardinality_tests {
    use super::*;

    /// 🛡️ **The property that makes a client-controlled label safe.**
    ///
    /// `host` is the request's `Host` header, so anyone can vary it. Without a
    /// ceiling, Prometheus allocates a fresh time series per distinct value and
    /// the process grows for as long as requests keep arriving — a remote
    /// memory exhaustion that needs no authentication and no unusual traffic
    /// volume, just varied headers.
    #[test]
    fn a_flood_of_distinct_values_collapses_to_one_series() {
        let mut distinct = HashSet::new();
        for i in 0..(MAX_LABEL_VALUES * 4) {
            distinct.insert(capped_label("flood-test", &format!("host-{i}.example")));
        }
        assert!(
            distinct.len() <= MAX_LABEL_VALUES + 1,
            "{} distinct label values survived a ceiling of {}",
            distinct.len(),
            MAX_LABEL_VALUES
        );
        assert!(
            distinct.contains(OVERFLOW_LABEL),
            "values beyond the ceiling must collapse to `{OVERFLOW_LABEL}`, not be dropped"
        );
    }

    /// 🎯 The mirror case. A cap that folded everything into `other` would pass
    /// the test above while making the metric useless — an ordinary deployment
    /// serves a handful of hosts and every one of them must keep its own series.
    #[test]
    fn ordinary_values_keep_their_own_series() {
        for host in ["a.example", "b.example", "c.example"] {
            assert_eq!(capped_label("small-test", host), host);
        }
    }

    /// ♻️ A value already admitted keeps its series forever, so a host that was
    /// busy yesterday does not start folding into `other` because a burst of
    /// junk arrived today.
    #[test]
    fn an_admitted_value_survives_a_later_flood() {
        let kept = capped_label("survive-test", "real.example");
        assert_eq!(kept, "real.example");

        for i in 0..(MAX_LABEL_VALUES * 2) {
            let _ = capped_label("survive-test", &format!("junk-{i}.example"));
        }

        assert_eq!(
            capped_label("survive-test", "real.example"),
            "real.example",
            "a real host lost its series to a flood of junk"
        );
    }

    /// 🏷️ Ceilings are per label name, so a flood on one cannot silence
    /// another.
    #[test]
    fn labels_have_independent_ceilings() {
        for i in 0..(MAX_LABEL_VALUES * 2) {
            let _ = capped_label("noisy-test", &format!("v{i}"));
        }
        assert_eq!(capped_label("quiet-test", "only-value"), "only-value");
    }
}
