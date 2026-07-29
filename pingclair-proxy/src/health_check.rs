// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🩺 Bounded active health checking for Pingclair upstream pools.

use async_trait::async_trait;
use parking_lot::Mutex;
use pingora_core::connectors::ConnectorOptions;
use pingora_core::connectors::http::Connector as HttpConnector;
use pingora_core::custom_session;
use pingora_core::protocols::http::custom::client::Session;
use pingora_core::upstreams::peer::{HttpPeer, Peer};
use pingora_core::{Error, ErrorType};
use pingora_http::RequestHeader;
use pingora_load_balancing::Backend;
use pingora_load_balancing::health_check::HealthCheck;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 🧹 Weak registrations let hot reload remove obsolete pools without a leak.
static POOLS: LazyLock<Mutex<Vec<Weak<crate::load_balancer::LoadBalancer>>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

/// 🧩 Registers a configured pool for the single Pingora background driver.
pub fn register(pool: &Arc<crate::load_balancer::LoadBalancer>) {
    let mut pools = POOLS.lock();
    pools.retain(|existing| existing.strong_count() > 0);
    if !pools
        .iter()
        .filter_map(Weak::upgrade)
        .any(|existing| Arc::ptr_eq(&existing, pool))
    {
        pools.push(Arc::downgrade(pool));
    }
}

/// 🩺 Pingora background service that drives every current DNS pool generation.
pub struct HealthCheckDriver;

#[async_trait]
impl pingora_core::services::background::BackgroundService for HealthCheckDriver {
    async fn start(&self, shutdown: pingora_core::server::ShutdownWatch) {
        loop {
            if *shutdown.borrow() {
                return;
            }
            let live = {
                let mut pools = POOLS.lock();
                let live = pools.iter().filter_map(Weak::upgrade).collect::<Vec<_>>();
                pools.retain(|pool| pool.strong_count() > 0);
                live
            };
            futures::future::join_all(live.iter().map(|pool| pool.run_health_check_if_due())).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// 🧱 Default maximum response body consumed by one health probe.
pub const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024;

/// 🧭 Returns a monotonic-enough wall-clock marker shared with selection state.
fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// 🌤️ Recovery timestamps retained only for addresses in the current DNS pool.
#[derive(Default)]
pub(crate) struct RecoveryState {
    slots: Mutex<HashMap<SocketAddr, Arc<AtomicU64>>>,
}

impl RecoveryState {
    /// 🧹 Rebuilds and prunes the address map when DNS publishes a new pool.
    pub(crate) fn rebuild(
        &self,
        addresses: impl IntoIterator<Item = SocketAddr>,
    ) -> HashMap<SocketAddr, Arc<AtomicU64>> {
        let mut slots = self.slots.lock();
        let rebuilt = addresses
            .into_iter()
            .map(|address| {
                let slot = slots
                    .get(&address)
                    .cloned()
                    .unwrap_or_else(|| Arc::new(AtomicU64::new(0)));
                (address, slot)
            })
            .collect::<HashMap<_, _>>();
        *slots = rebuilt.clone();
        rebuilt
    }

    /// 🌱 Starts slow-start only after an unhealthy backend is observed healthy again.
    fn observe(&self, target: &Backend, healthy: bool) {
        let pingora_core::protocols::l4::socket::SocketAddr::Inet(address) = target.addr else {
            return;
        };
        if let Some(slot) = self.slots.lock().get(&address) {
            slot.store(if healthy { now_millis() } else { 0 }, Ordering::Release);
        }
    }
}

/// 🩺 Runtime probe configuration already validated by the config compiler.
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    pub path: String,
    pub timeout: Duration,
    pub expected_statuses: Vec<u16>,
    pub expected_body: Option<String>,
    pub positive_threshold: usize,
    pub negative_threshold: usize,
    pub method: String,
    pub host: String,
    pub headers: HashMap<String, String>,
    pub port_override: Option<u16>,
    pub reuse_connection: bool,
    pub max_response_body_bytes: usize,
    pub slow_start: Duration,
}

/// 🩺 Pingora HTTP connector with bounded body validation and TLS peer parity.
pub struct HealthChecker {
    config: HealthCheckConfig,
    peer_template: HttpPeer,
    request: RequestHeader,
    connector: HttpConnector,
    recovery: Arc<RecoveryState>,
}

impl HealthChecker {
    /// 🧩 Builds the request once so probe rounds perform no header parsing.
    pub(crate) fn new(
        config: HealthCheckConfig,
        peer_template: HttpPeer,
        recovery: Arc<RecoveryState>,
    ) -> pingora_core::Result<Self> {
        let mut request = RequestHeader::build(
            config.method.as_str(),
            config.path.as_bytes(),
            Some(config.headers.len() + 2),
        )?;
        request.append_header("Host", &config.host)?;
        request.append_header("User-Agent", "Pingclair-HealthCheck/0.2")?;
        for (name, value) in &config.headers {
            request.insert_header(name.clone(), value.clone())?;
        }
        if !config.reuse_connection {
            request.insert_header("Connection", "close")?;
        }
        Ok(Self {
            config,
            peer_template,
            request,
            // 🔐 Passing explicit connector options loads the system trust store;
            // Pingora's `None` constructor leaves it empty even though peer
            // verification remains enabled.
            connector: HttpConnector::new(Some(ConnectorOptions::from_server_conf(
                &pingora_core::server::configuration::ServerConf::default(),
            ))),
            recovery,
        })
    }

    /// 🌊 Runs one probe while retaining at most the configured body prefix.
    async fn check_inner(&self, target: &Backend) -> pingora_core::Result<()> {
        let mut peer = self.peer_template.clone();
        peer._address = target.addr.clone();
        if let Some(port) = self.config.port_override {
            peer._address.set_port(port);
        }
        let (mut session, _) = self.connector.get_http_session(&peer).await?;
        session
            .write_request_header(Box::new(self.request.clone()))
            .await?;
        session.finish_request_body().await?;
        if let Some(read_timeout) = peer.options.read_timeout {
            session.set_read_timeout(Some(read_timeout));
        }
        session.read_response_header().await?;
        let response = session
            .response_header()
            .ok_or_else(|| Error::explain(ErrorType::ReadError, "health response has no header"))?
            .clone();
        let status = response.status.as_u16();
        if !self.config.expected_statuses.contains(&status) {
            return Err(Error::explain(
                ErrorType::HTTPStatus(status),
                "health response status was not accepted",
            ));
        }
        if response
            .headers
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length > self.config.max_response_body_bytes)
        {
            return Err(Error::explain(
                ErrorType::ReadError,
                "health response body exceeded its configured byte limit",
            ));
        }

        let mut body = self
            .config
            .expected_body
            .as_ref()
            .map(|_| Vec::with_capacity(self.config.max_response_body_bytes.min(4_096)));
        let mut body_bytes = 0usize;
        while let Some(chunk) = session.read_response_body().await? {
            body_bytes = body_bytes.saturating_add(chunk.len());
            if body_bytes > self.config.max_response_body_bytes {
                return Err(Error::explain(
                    ErrorType::ReadError,
                    "health response body exceeded its configured byte limit",
                ));
            }
            if let Some(buffer) = body.as_mut() {
                buffer.extend_from_slice(&chunk);
            }
        }
        custom_session!(session.finish_custom().await?);

        if let (Some(expected), Some(body)) = (&self.config.expected_body, body)
            && !body
                .windows(expected.len())
                .any(|window| window == expected.as_bytes())
        {
            return Err(Error::explain(
                ErrorType::ReadError,
                "health response body did not contain the configured fragment",
            ));
        }

        if self.config.reuse_connection {
            let idle_timeout = peer.idle_timeout();
            self.connector
                .release_http_session(session, &peer, idle_timeout)
                .await;
        }
        Ok(())
    }
}

#[async_trait]
impl HealthCheck for HealthChecker {
    async fn check(&self, target: &Backend) -> pingora_core::Result<()> {
        match tokio::time::timeout(self.config.timeout, self.check_inner(target)).await {
            Ok(result) => result,
            Err(_) => Err(Error::explain(
                ErrorType::ReadTimedout,
                "health probe exceeded its total timeout",
            )),
        }
    }

    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.config.positive_threshold
        } else {
            self.config.negative_threshold
        }
    }

    async fn health_status_change(&self, target: &Backend, healthy: bool) {
        self.recovery.observe(target, healthy);
        tracing::info!(
            backend = ?target.addr,
            healthy,
            "🩺 Active upstream health changed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn config(host: String) -> HealthCheckConfig {
        HealthCheckConfig {
            path: "/health".to_string(),
            timeout: Duration::from_secs(1),
            expected_statuses: vec![200],
            expected_body: None,
            positive_threshold: 1,
            negative_threshold: 1,
            method: "GET".to_string(),
            host,
            headers: HashMap::new(),
            port_override: None,
            reuse_connection: false,
            max_response_body_bytes: 4,
            slow_start: Duration::ZERO,
        }
    }

    #[tokio::test]
    async fn response_body_read_stops_at_the_configured_byte_bound() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789",
                )
                .await
                .unwrap();
        });
        let target = Backend::new(&address.to_string()).unwrap();
        let recovery = Arc::new(RecoveryState::default());
        recovery.rebuild([address]);
        let checker = HealthChecker::new(
            config(address.ip().to_string()),
            HttpPeer::new(address, false, address.ip().to_string()),
            recovery,
        )
        .unwrap();

        let error = checker.check(&target).await.unwrap_err().to_string();
        assert!(error.contains("configured byte limit"), "{error}");
        origin.await.unwrap();
    }

    #[test]
    fn dns_rebuild_prunes_recovery_slots_that_left_the_pool() {
        let state = RecoveryState::default();
        let first: SocketAddr = "127.0.0.1:8001".parse().unwrap();
        let second: SocketAddr = "127.0.0.1:8002".parse().unwrap();
        state.rebuild([first, second]);
        let rebuilt = state.rebuild([second]);
        assert_eq!(rebuilt.len(), 1);
        assert!(rebuilt.contains_key(&second));
        assert!(!state.slots.lock().contains_key(&first));
    }
}
