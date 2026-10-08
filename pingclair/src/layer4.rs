// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔌 Raw TCP services, immutable route generations, and process lifecycle integration.

use arc_swap::ArcSwap;
use pingclair_core::config::{PingclairConfig, covering_wildcard, normalize_listen_addr};
use pingclair_l4::PreparedListener;
use pingclair_proxy::server::ConfigApplyError;
use pingora_core::apps::ServerApp;
use pingora_core::protocols::Stream;
use pingora_core::server::{ListenFds, ShutdownWatch};
use pingora_core::services::{Service, listening};
use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener};
use std::os::fd::IntoRawFd;
use std::sync::Arc;

pub(crate) type Generation = HashMap<String, Arc<PreparedListener>>;

/// 📦 New connections load one generation; established tunnels retain their own state.
#[derive(Default)]
pub(crate) struct Runtime(ArcSwap<Generation>);

impl Runtime {
    pub(crate) fn publish(&self, next: Generation) {
        self.0.store(Arc::new(next));
    }
}

/// 🛡️ Checks effective HTTP companions and Admin before resolving any upstream.
pub(crate) fn prepare(
    config: &PingclairConfig,
    current: &Runtime,
    http_addresses: impl Iterator<Item = String>,
) -> Result<Generation, ConfigApplyError> {
    let mut occupied: Vec<SocketAddr> = http_addresses
        .filter_map(|address| address.parse().ok())
        .collect();
    if let Some(admin) = &config.admin
        && admin.enabled
        && let Some(address) = pingclair_core::config::parse_listen_addr(&admin.listen)
    {
        occupied.push(address);
    }
    let previous = current.0.load();
    let mut next = HashMap::new();
    for listener in &config.layer4 {
        let address = normalize_listen_addr(&listener.listen);
        let socket: SocketAddr = address
            .parse()
            .map_err(|error| ConfigApplyError::invalid(format!("invalid L4 address: {error}")))?;
        for other in &occupied {
            if socket == *other
                || (socket.ip().is_unspecified()
                    && covering_wildcard(&other.to_string(), &[socket]).is_some())
                || (other.ip().is_unspecified() && covering_wildcard(&address, &[*other]).is_some())
            {
                return Err(ConfigApplyError::invalid(format!(
                    "L4 listener {address} overlaps TCP listener {other}"
                )));
            }
        }
        let prepared = PreparedListener::prepare_with_previous(
            listener,
            &config.global.blocked_ips,
            previous.get(&address).map(Arc::as_ref),
        )
        .map_err(|error| {
            ConfigApplyError::invalid(format!("cannot prepare L4 listener {address}: {error}"))
        })?;
        occupied.push(socket);
        next.insert(address, Arc::new(prepared));
    }
    Ok(next)
}

/// ♻️ Routes may change live; socket topology and listener limits require a restart.
pub(crate) fn ensure_hot_compatible(
    current: &PingclairConfig,
    next: &PingclairConfig,
) -> Result<(), ConfigApplyError> {
    let captured = |config: &PingclairConfig| {
        config
            .layer4
            .iter()
            .map(|listener| {
                let mut listener = listener.clone();
                listener.routes.clear();
                listener.log = None;
                listener.listen = normalize_listen_addr(&listener.listen);
                (listener.listen.clone(), listener)
            })
            .collect::<HashMap<_, _>>()
    };
    if captured(current) != captured(next) {
        return Err(ConfigApplyError::restart_required(
            "L4 listener topology or limits changed; restart Pingclair",
        ));
    }
    Ok(())
}

/// 🔌 Reserves sockets before readiness and transfers ownership without a rebind gap.
pub(crate) fn register(
    server: &mut pingora_core::server::Server,
    runtime: &Arc<Runtime>,
) -> std::io::Result<()> {
    for address in runtime.0.load().keys() {
        let socket = TcpListener::bind(address)?;
        socket.set_nonblocking(true)?;
        let app = App {
            address: address.clone(),
            runtime: runtime.clone(),
        };
        let mut inner = listening::Service::new(format!("L4 {address}"), app);
        inner.add_tcp(address);
        server.add_service(BoundService {
            inner,
            address: address.clone(),
            socket: Some(socket),
        });
        tracing::info!(listener = %address, "🔌 Reserved L4 TCP listener");
    }
    Ok(())
}

struct App {
    address: String,
    runtime: Arc<Runtime>,
}

// 🔌 Pingora 0.9.0 defines `ServerApp` with async-trait, which its implementors must match.
#[async_trait::async_trait]
impl ServerApp for App {
    async fn process_new(
        self: &Arc<Self>,
        stream: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let _in_flight = pingclair_proxy::drain::InFlight::enter();
        if *shutdown.borrow() || pingclair_proxy::drain::is_stopping() {
            return None;
        }
        let peer = stream
            .get_socket_digest()?
            .peer_addr()?
            .as_inet()?
            .to_owned();
        let prepared = self.runtime.0.load().get(&self.address)?.clone();
        if let Err(error) = prepared.serve(stream, peer).await {
            tracing::debug!(listener = %self.address, %error, "🔌 L4 connection ended");
        }
        None
    }
}

struct BoundService {
    inner: listening::Service<App>,
    address: String,
    socket: Option<TcpListener>,
}

// 🔌 Pingora 0.9.0 also requires async-trait for its external `Service` interface.
#[async_trait::async_trait]
impl Service for BoundService {
    async fn start_service(
        &mut self,
        _fds: Option<ListenFds>,
        shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
    ) {
        let Some(socket) = self.socket.take() else {
            return;
        };
        let mut fds = pingora_core::server::Fds::new();
        // 🔌 Pingora's `listeners::l4::from_raw_fd` takes ownership of the reserved descriptor.
        fds.add(self.address.clone(), socket.into_raw_fd());
        self.inner
            .start_service(Some(Arc::new(parking_lot::Mutex::new(fds))), shutdown, 1)
            .await;
    }

    fn name(&self) -> &str {
        self.inner.name()
    }
}
