// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚦 Provides bounded route admission and per-upstream circuit breakers.

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use pingclair_core::config::{CircuitBreakerConfig, OverloadConfig};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::metrics;

/// 🚫 Explains why admission stopped before upstream dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    QueueFull,
    QueueTimeout,
    UpstreamCapacity,
    CircuitOpen,
}

impl AdmissionError {
    /// 🏷️ Returns the stable Prometheus label for this rejection.
    pub fn metric_reason(self) -> &'static str {
        match self {
            Self::QueueFull => "queue_full",
            Self::QueueTimeout => "queue_timeout",
            Self::UpstreamCapacity => "upstream_capacity",
            Self::CircuitOpen => "circuit_open",
        }
    }
}

/// 🚦 Owns admission state for one configured reverse-proxy route.
pub struct RouteProtection {
    overload: OverloadConfig,
    breaker: CircuitBreakerConfig,
    host: String,
    route: String,
    upstreams: Vec<String>,
    route_slots: Option<Arc<Semaphore>>,
    pending: AtomicUsize,
    backends: ArcSwap<HashMap<SocketAddr, Arc<BackendProtection>>>,
}

impl RouteProtection {
    /// 🧱 Creates one immutable policy with mutable bounded runtime state.
    pub fn new(
        overload: OverloadConfig,
        breaker: CircuitBreakerConfig,
        host: String,
        route: String,
        upstreams: Vec<String>,
    ) -> Self {
        let route_slots = overload
            .max_in_flight
            .map(|limit| Arc::new(Semaphore::new(limit)));
        Self {
            overload,
            breaker,
            host,
            route,
            upstreams,
            route_slots,
            pending: AtomicUsize::new(0),
            backends: ArcSwap::from_pointee(HashMap::new()),
        }
    }

    /// ♻️ Reports whether a hot reload may retain this exact runtime state.
    pub fn compatible(
        &self,
        overload: &OverloadConfig,
        breaker: &CircuitBreakerConfig,
        host: &str,
        route: &str,
        upstreams: &[String],
    ) -> bool {
        self.overload == *overload
            && self.breaker == *breaker
            && self.host == host
            && self.route == route
            && self.upstreams == upstreams
    }

    /// 🚦 Admits immediately or waits inside the explicitly bounded pending queue.
    pub async fn admit_route(&self) -> Result<RouteAdmission, AdmissionError> {
        let Some(slots) = self.route_slots.as_ref() else {
            return Ok(RouteAdmission::unlimited());
        };
        match slots.clone().try_acquire_owned() {
            Ok(permit) => return Ok(RouteAdmission::new(permit, &self.host, &self.route)),
            Err(TryAcquireError::Closed) => return Err(AdmissionError::QueueFull),
            Err(TryAcquireError::NoPermits) => {}
        }

        let pending = self
            .pending
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < self.overload.max_pending).then_some(current + 1)
            })
            .map_err(|_| {
                self.reject(AdmissionError::QueueFull);
                AdmissionError::QueueFull
            })?;
        debug_assert!(pending < self.overload.max_pending);
        let pending_guard = PendingGuard::new(&self.pending, &self.host, &self.route);
        let wait = slots.clone().acquire_owned();
        let result = tokio::time::timeout(
            Duration::from_millis(self.overload.pending_timeout_ms),
            wait,
        )
        .await;
        drop(pending_guard);

        match result {
            Ok(Ok(permit)) => Ok(RouteAdmission::new(permit, &self.host, &self.route)),
            Ok(Err(_)) => {
                self.reject(AdmissionError::QueueFull);
                Err(AdmissionError::QueueFull)
            }
            Err(_) => {
                self.reject(AdmissionError::QueueTimeout);
                Err(AdmissionError::QueueTimeout)
            }
        }
    }

    /// 🔌 Admits one selected backend against capacity and circuit state.
    pub fn admit_upstream(&self, address: SocketAddr) -> Result<UpstreamAdmission, AdmissionError> {
        self.backend(address).admit()
    }

    /// 📊 Records one rejection without creating unbounded metric labels.
    pub fn reject(&self, error: AdmissionError) {
        metrics::OVERLOAD_REJECTIONS_TOTAL
            .with_label_values(&[&self.host, &self.route, error.metric_reason()])
            .inc();
    }

    /// 🧩 Returns the stable backend state, adding only newly resolved addresses.
    fn backend(&self, address: SocketAddr) -> Arc<BackendProtection> {
        if let Some(existing) = self.backends.load().get(&address) {
            return existing.clone();
        }
        let created = Arc::new(BackendProtection::new(
            self.overload.upstream_max_connections,
            self.breaker.clone(),
            self.host.clone(),
            self.route.clone(),
            address,
        ));
        self.backends.rcu(|current| {
            if current.contains_key(&address) {
                return current.clone();
            }
            let mut next = (**current).clone();
            next.insert(address, created.clone());
            Arc::new(next)
        });
        self.backends
            .load()
            .get(&address)
            .cloned()
            .unwrap_or(created)
    }

    #[cfg(test)]
    /// 🧪 Returns one backend's phase for deterministic transition tests.
    fn phase(&self, address: SocketAddr) -> Option<CircuitPhase> {
        self.backends
            .load()
            .get(&address)
            .and_then(|backend| backend.breaker.as_ref())
            .map(|breaker| breaker.phase())
    }
}

/// 🧱 Releases one route execution slot when its request context ends.
pub struct RouteAdmission {
    _permit: Option<OwnedSemaphorePermit>,
    labels: Option<(String, String)>,
}

impl RouteAdmission {
    fn unlimited() -> Self {
        Self {
            _permit: None,
            labels: None,
        }
    }

    fn new(permit: OwnedSemaphorePermit, host: &str, route: &str) -> Self {
        metrics::ROUTE_IN_FLIGHT
            .with_label_values(&[host, route])
            .inc();
        Self {
            _permit: Some(permit),
            labels: Some((host.to_string(), route.to_string())),
        }
    }
}

impl Drop for RouteAdmission {
    fn drop(&mut self) {
        if let Some((host, route)) = &self.labels {
            metrics::ROUTE_IN_FLIGHT
                .with_label_values(&[host, route])
                .dec();
        }
    }
}

/// 🕰️ Keeps pending accounting correct across timeout and cancellation.
struct PendingGuard<'a> {
    pending: &'a AtomicUsize,
    host: &'a str,
    route: &'a str,
}

impl<'a> PendingGuard<'a> {
    fn new(pending: &'a AtomicUsize, host: &'a str, route: &'a str) -> Self {
        metrics::ROUTE_PENDING
            .with_label_values(&[host, route])
            .inc();
        Self {
            pending,
            host,
            route,
        }
    }
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.pending.fetch_sub(1, Ordering::AcqRel);
        metrics::ROUTE_PENDING
            .with_label_values(&[self.host, self.route])
            .dec();
    }
}

/// 🔌 Owns capacity and circuit state for one concrete backend address.
struct BackendProtection {
    slots: Option<Arc<Semaphore>>,
    breaker: Option<Arc<CircuitBreaker>>,
    host: String,
    route: String,
    upstream: String,
}

impl BackendProtection {
    fn new(
        max_connections: Option<usize>,
        breaker: CircuitBreakerConfig,
        host: String,
        route: String,
        address: SocketAddr,
    ) -> Self {
        let upstream = address.to_string();
        let breaker = breaker.enabled().then(|| {
            Arc::new(CircuitBreaker::new(
                breaker,
                host.clone(),
                route.clone(),
                upstream.clone(),
            ))
        });
        Self {
            slots: max_connections.map(|limit| Arc::new(Semaphore::new(limit))),
            breaker,
            host,
            route,
            upstream,
        }
    }

    fn admit(&self) -> Result<UpstreamAdmission, AdmissionError> {
        let circuit = self
            .breaker
            .as_ref()
            .map(|breaker| breaker.admit())
            .transpose()?;
        let permit = match &self.slots {
            Some(slots) => Some(
                slots
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| AdmissionError::UpstreamCapacity)?,
            ),
            None => None,
        };
        if permit.is_some() {
            metrics::UPSTREAM_IN_FLIGHT
                .with_label_values(&[&self.host, &self.route, &self.upstream])
                .inc();
        }
        Ok(UpstreamAdmission {
            _permit: permit,
            circuit,
            labels: (self.host.clone(), self.route.clone(), self.upstream.clone()),
        })
    }
}

/// 🔌 Holds one upstream slot and reports exactly one breaker outcome.
pub struct UpstreamAdmission {
    _permit: Option<OwnedSemaphorePermit>,
    circuit: Option<CircuitAdmission>,
    labels: (String, String, String),
}

impl UpstreamAdmission {
    /// ✅ Records a response status using the configured failure classification.
    pub fn report_status(&mut self, status: u16) {
        if let Some(circuit) = &mut self.circuit {
            circuit.report_status(status);
        }
    }

    /// 🔻 Records a transport failure before a usable response arrives.
    pub fn report_failure(&mut self) {
        if let Some(circuit) = &mut self.circuit {
            circuit.report(false);
        }
    }
}

impl Drop for UpstreamAdmission {
    fn drop(&mut self) {
        if self._permit.is_some() {
            metrics::UPSTREAM_IN_FLIGHT
                .with_label_values(&[&self.labels.0, &self.labels.1, &self.labels.2])
                .dec();
        }
    }
}

/// 🔌 Observable circuit phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitPhase {
    Closed,
    HalfOpen,
    Open,
}

/// 🧠 Mutable evidence retained for one backend circuit.
struct CircuitInner {
    phase: CircuitPhase,
    open_until: Option<Instant>,
    consecutive_failures: u32,
    outcomes: VecDeque<bool>,
    half_open_in_flight: usize,
    half_open_successes: usize,
}

/// 🔌 Evaluates bounded failure evidence without request-body buffering.
struct CircuitBreaker {
    config: CircuitBreakerConfig,
    inner: Mutex<CircuitInner>,
    host: String,
    route: String,
    upstream: String,
}

impl CircuitBreaker {
    fn new(config: CircuitBreakerConfig, host: String, route: String, upstream: String) -> Self {
        metrics::CIRCUIT_STATE
            .with_label_values(&[&host, &route, &upstream])
            .set(0);
        Self {
            config,
            inner: Mutex::new(CircuitInner {
                phase: CircuitPhase::Closed,
                open_until: None,
                consecutive_failures: 0,
                outcomes: VecDeque::new(),
                half_open_in_flight: 0,
                half_open_successes: 0,
            }),
            host,
            route,
            upstream,
        }
    }

    fn admit(self: &Arc<Self>) -> Result<CircuitAdmission, AdmissionError> {
        let mut inner = self.inner.lock();
        let probe = match inner.phase {
            CircuitPhase::Closed => false,
            CircuitPhase::Open => {
                if inner.open_until.is_some_and(|until| Instant::now() < until) {
                    return Err(AdmissionError::CircuitOpen);
                }
                inner.phase = CircuitPhase::HalfOpen;
                inner.half_open_in_flight = 1;
                inner.half_open_successes = 0;
                self.transition(CircuitPhase::HalfOpen);
                true
            }
            CircuitPhase::HalfOpen => {
                if inner.half_open_in_flight >= self.config.half_open_requests {
                    return Err(AdmissionError::CircuitOpen);
                }
                inner.half_open_in_flight += 1;
                true
            }
        };
        drop(inner);
        Ok(CircuitAdmission {
            breaker: self.clone(),
            probe,
            reported: false,
        })
    }

    fn complete(&self, probe: bool, success: bool) {
        let mut inner = self.inner.lock();
        if probe {
            inner.half_open_in_flight = inner.half_open_in_flight.saturating_sub(1);
            if inner.phase != CircuitPhase::HalfOpen {
                return;
            }
            if !success {
                self.open(&mut inner);
                return;
            }
            inner.half_open_successes += 1;
            if inner.half_open_successes >= self.config.half_open_requests {
                inner.phase = CircuitPhase::Closed;
                inner.open_until = None;
                inner.consecutive_failures = 0;
                inner.outcomes.clear();
                self.transition(CircuitPhase::Closed);
            }
            return;
        }
        if inner.phase != CircuitPhase::Closed {
            return;
        }

        inner.outcomes.push_back(success);
        if inner.outcomes.len() > self.config.window_requests {
            inner.outcomes.pop_front();
        }
        if success {
            inner.consecutive_failures = 0;
        } else {
            inner.consecutive_failures = inner.consecutive_failures.saturating_add(1);
        }

        let consecutive_open = self
            .config
            .consecutive_failures
            .is_some_and(|threshold| inner.consecutive_failures >= threshold);
        let ratio_open = self.config.error_rate_percent.is_some_and(|threshold| {
            inner.outcomes.len() >= self.config.minimum_requests
                && inner.outcomes.iter().filter(|success| !**success).count() * 100
                    >= usize::from(threshold) * inner.outcomes.len()
        });
        if consecutive_open || ratio_open {
            self.open(&mut inner);
        }
    }

    fn abandon_probe(&self) {
        let mut inner = self.inner.lock();
        if inner.phase == CircuitPhase::HalfOpen {
            inner.half_open_in_flight = inner.half_open_in_flight.saturating_sub(1);
        }
    }

    fn open(&self, inner: &mut CircuitInner) {
        inner.phase = CircuitPhase::Open;
        inner.open_until =
            Some(Instant::now() + Duration::from_millis(self.config.open_duration_ms));
        inner.half_open_in_flight = 0;
        inner.half_open_successes = 0;
        self.transition(CircuitPhase::Open);
    }

    fn transition(&self, phase: CircuitPhase) {
        let (label, value) = match phase {
            CircuitPhase::Closed => ("closed", 0),
            CircuitPhase::HalfOpen => ("half_open", 1),
            CircuitPhase::Open => ("open", 2),
        };
        match phase {
            CircuitPhase::Open => tracing::warn!(
                host = %self.host,
                route = %self.route,
                upstream = %self.upstream,
                "🔌 Upstream circuit opened"
            ),
            CircuitPhase::HalfOpen => tracing::info!(
                host = %self.host,
                route = %self.route,
                upstream = %self.upstream,
                "🧪 Upstream circuit entered half-open recovery"
            ),
            CircuitPhase::Closed => tracing::info!(
                host = %self.host,
                route = %self.route,
                upstream = %self.upstream,
                "✅ Upstream circuit closed after recovery"
            ),
        }
        metrics::CIRCUIT_TRANSITIONS_TOTAL
            .with_label_values(&[&self.host, &self.route, &self.upstream, label])
            .inc();
        metrics::CIRCUIT_STATE
            .with_label_values(&[&self.host, &self.route, &self.upstream])
            .set(value);
    }

    #[cfg(test)]
    fn phase(&self) -> CircuitPhase {
        self.inner.lock().phase
    }
}

/// 🧪 Represents one closed or half-open circuit admission.
struct CircuitAdmission {
    breaker: Arc<CircuitBreaker>,
    probe: bool,
    reported: bool,
}

impl CircuitAdmission {
    fn report_status(&mut self, status: u16) {
        let failed = if self.breaker.config.failure_statuses.is_empty() {
            (500..=599).contains(&status)
        } else {
            self.breaker.config.failure_statuses.contains(&status)
        };
        self.report(!failed);
    }

    fn report(&mut self, success: bool) {
        if self.reported {
            return;
        }
        self.reported = true;
        self.breaker.complete(self.probe, success);
    }
}

impl Drop for CircuitAdmission {
    fn drop(&mut self) {
        if self.probe && !self.reported {
            self.breaker.abandon_probe();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn breaker_config() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            consecutive_failures: Some(2),
            error_rate_percent: None,
            minimum_requests: 2,
            window_requests: 4,
            open_duration_ms: 20,
            half_open_requests: 1,
            failure_statuses: vec![503],
        }
    }

    fn protection(overload: OverloadConfig) -> RouteProtection {
        RouteProtection::new(
            overload,
            breaker_config(),
            "example.test".to_string(),
            "/api".to_string(),
            vec!["127.0.0.1:9000".to_string()],
        )
    }

    #[tokio::test]
    async fn queue_is_bounded_and_times_out() {
        let protection = Arc::new(protection(OverloadConfig {
            max_in_flight: Some(1),
            max_pending: 1,
            pending_timeout_ms: 10,
            upstream_max_connections: None,
        }));
        let held = protection.admit_route().await.unwrap();
        let waiting = {
            let protection = protection.clone();
            tokio::spawn(async move { protection.admit_route().await })
        };
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(matches!(
            protection.admit_route().await,
            Err(AdmissionError::QueueFull)
        ));
        assert!(matches!(
            waiting.await.unwrap(),
            Err(AdmissionError::QueueTimeout)
        ));
        drop(held);
        assert!(protection.admit_route().await.is_ok());
    }

    #[tokio::test]
    async fn circuit_opens_probes_and_recovers() {
        let protection = protection(OverloadConfig::default());
        let address = "127.0.0.1:9000".parse().unwrap();
        for _ in 0..2 {
            let mut admission = protection.admit_upstream(address).unwrap();
            admission.report_status(503);
        }
        assert_eq!(protection.phase(address), Some(CircuitPhase::Open));
        assert!(matches!(
            protection.admit_upstream(address),
            Err(AdmissionError::CircuitOpen)
        ));
        tokio::time::sleep(Duration::from_millis(25)).await;
        let mut probe = protection.admit_upstream(address).unwrap();
        assert_eq!(protection.phase(address), Some(CircuitPhase::HalfOpen));
        assert!(matches!(
            protection.admit_upstream(address),
            Err(AdmissionError::CircuitOpen)
        ));
        probe.report_status(200);
        drop(probe);
        assert_eq!(protection.phase(address), Some(CircuitPhase::Closed));
    }

    #[test]
    fn rolling_error_rate_opens_after_minimum_sample() {
        let config = CircuitBreakerConfig {
            consecutive_failures: None,
            error_rate_percent: Some(50),
            minimum_requests: 4,
            window_requests: 4,
            ..breaker_config()
        };
        let protection = RouteProtection::new(
            OverloadConfig::default(),
            config,
            "example.test".to_string(),
            "/api".to_string(),
            vec!["127.0.0.1:9000".to_string()],
        );
        let address = "127.0.0.1:9000".parse().unwrap();
        for status in [200, 503, 200] {
            let mut admission = protection.admit_upstream(address).unwrap();
            admission.report_status(status);
        }
        assert_eq!(protection.phase(address), Some(CircuitPhase::Closed));
        let mut admission = protection.admit_upstream(address).unwrap();
        admission.report_status(503);
        assert_eq!(protection.phase(address), Some(CircuitPhase::Open));
    }

    #[test]
    fn upstream_capacity_is_released_on_drop() {
        let protection = protection(OverloadConfig {
            upstream_max_connections: Some(1),
            ..OverloadConfig::default()
        });
        let address = "127.0.0.1:9000".parse().unwrap();
        let held = protection.admit_upstream(address).unwrap();
        assert!(matches!(
            protection.admit_upstream(address),
            Err(AdmissionError::UpstreamCapacity)
        ));
        drop(held);
        assert!(protection.admit_upstream(address).is_ok());
    }
}
