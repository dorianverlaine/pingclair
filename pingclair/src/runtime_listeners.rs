// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 Listeners that appear and disappear after the process has started.
//!
//! Pingora's `Server` accepts services only before `run_forever`, so a `/load`
//! that names a port nobody is listening on cannot go through the normal path.
//! Each such listener instead runs its own accept loop as a task on the shared
//! background runtime, which is the entire reason this type exists.
//!
//! The ordering inside `start_listener` is the part worth preserving: bind
//! first, as a probe, so a privileged port or a permission error comes back to
//! the `/load` caller as an error instead of panicking an accept task seconds
//! later with nobody to tell.

use crate::certs::DynamicCertResolver;
use crate::listen::server_requires_tls;
use parking_lot::RwLock;
use pingclair_tls::manager::TlsManager;
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::services::Service as PingoraService;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// 🧭 Runtime listener manager: `/load` can create and tear down listeners
/// after startup, like Caddy.
///
/// Pingora's `Server` cannot add services once `run_forever` has started, so
/// every dynamically added listener runs its own `Service` accept loop on the
/// shared background runtime. The proxy map is updated first so `/load`
/// resolution and traffic both see the listener immediately.
pub(crate) struct RuntimeListeners {
    pub(crate) port_proxies: Arc<RwLock<HashMap<String, pingclair_proxy::server::PingclairProxy>>>,
    pub(crate) server_conf: Arc<pingora::server::configuration::ServerConf>,
    pub(crate) tls_manager: Arc<TlsManager>,
    pub(crate) trusted_proxies: Vec<String>,
    pub(crate) blocked_ips: Vec<String>,
    pub(crate) proxy_protocol_addresses: HashSet<String>,
    pub(crate) http_port: u16,
    pub(crate) https_port: u16,
    pub(crate) running: RwLock<HashMap<String, tokio::task::JoinHandle<()>>>,
    pub(crate) shutdowns: RwLock<HashMap<String, tokio::sync::watch::Sender<bool>>>,
    pub(crate) dynamic_addrs: RwLock<HashSet<String>>,
}

impl pingclair_proxy::server::DynamicListeners for RuntimeListeners {
    fn start_listener(
        &self,
        addr: &str,
        server: &pingclair_core::config::ServerConfig,
    ) -> Result<(), String> {
        if self.running.read().contains_key(addr) {
            return Ok(());
        }

        let is_https = server_requires_tls(server, addr, self.http_port, self.https_port);
        // 🚫 Bind first so permission and privileged-port failures surface
        // synchronously to `/load` instead of panicking the accept task later
        // (the accept loop re-binds immediately after this probe).
        std::net::TcpListener::bind(addr)
            .map_err(|error| format!("cannot bind {addr}: {error}"))?;
        let proxy = {
            let mut guard = self.port_proxies.write();
            guard
                .entry(addr.to_string())
                .or_insert_with(|| {
                    pingclair_proxy::server::PingclairProxy::with_tls_and_trusted_proxies(
                        self.tls_manager.clone(),
                        &self.trusted_proxies,
                        self.proxy_protocol_addresses.contains(addr),
                    )
                })
                .clone()
        };
        proxy.add_server(server.clone());

        let listener_limits = proxy.listener_limits();
        let http_proxy = pingora_proxy::HttpProxy::new(proxy, self.server_conf.clone());
        let mut server_options = pingora_core::apps::HttpServerOptions::default();
        server_options.h2c = !is_https;
        let app = crate::resource_guard::ResourceGuardedProxy::new(
            http_proxy,
            listener_limits,
            server_options,
        );
        let mut service = pingora_core::services::listening::Service::new(
            "Pingclair Dynamic HTTP Service".to_string(),
            app,
        );
        if !self.blocked_ips.is_empty() {
            let filter = std::sync::Arc::new(pingclair_proxy::PingclairConnectionFilter::new(
                &self.blocked_ips,
            ));
            service.set_connection_filter(filter);
        }
        if is_https {
            // 🏷️ Read straight off the server being added, so a listener
            // created by a reload gets the same no-SNI answer as one created
            // at startup.
            let acceptor = DynamicCertResolver::new(self.tls_manager.clone()).with_default_sni(
                server
                    .tls
                    .as_ref()
                    .and_then(|tls| tls.default_sni.as_deref()),
            );
            let mut tls_settings =
                TlsSettings::with_callbacks(Box::new(acceptor)).map_err(|e| e.to_string())?;
            tls_settings.enable_h2();
            service.add_tls_with_settings(addr, None, tls_settings);
        } else {
            service.add_tcp(addr);
        }

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = tokio::runtime::Handle::current().spawn(async move {
            #[cfg(unix)]
            PingoraService::start_service(&mut service, None, shutdown_rx, 1).await;
            #[cfg(not(unix))]
            PingoraService::start_service(&mut service, shutdown_rx, 1).await;
        });
        self.running.write().insert(addr.to_string(), handle);
        self.shutdowns.write().insert(addr.to_string(), shutdown_tx);
        self.dynamic_addrs.write().insert(addr.to_string());
        tracing::info!("🧭 Dynamically listening on {} (TLS: {})", addr, is_https);
        Ok(())
    }

    fn stop_listener(&self, addr: &str) {
        if let Some(tx) = self.shutdowns.write().remove(addr) {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.running.write().remove(addr) {
            handle.abort();
        }
        self.port_proxies.write().remove(addr);
        self.dynamic_addrs.write().remove(addr);
        tracing::info!("🛑 Dynamically stopped listener {}", addr);
    }

    fn is_dynamic(&self, addr: &str) -> bool {
        self.dynamic_addrs.read().contains(addr)
    }

    fn probe_listener(&self, addr: &str) -> Result<(), String> {
        // 🔎 Bind and drop. There is an unavoidable gap between this check and
        // the real bind, so another process could still take the port in
        // between — but the failure this prevents is the common one: a reload
        // whose own configuration names a port something else already holds.
        std::net::TcpListener::bind(addr)
            .map(|_| ())
            .map_err(|error| format!("cannot bind {addr}: {error}"))
    }
}
