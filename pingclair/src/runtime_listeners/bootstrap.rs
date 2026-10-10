// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🏗️ The first plaintext listener generation for an admin-only process.

use super::PreparedListenerPolicy;
use crate::resource_guard::ResourceGuardedProxy;
use pingclair_core::config::PingclairConfig;
use pingclair_proxy::client_auth::PublishedListenerPolicy;
use pingclair_proxy::server::{ConfigApplyError, PingclairProxy};
use pingclair_tls::manager::TlsManager;
use pingora_core::services::{Service as _, listening::Service};
use std::collections::HashMap;
use std::os::fd::IntoRawFd;
use std::sync::Arc;

/// 🧵 Uses startup's worker runtime, proxy settings, and graceful-stop broadcast.
pub(crate) struct BootstrapRuntime {
    pub(crate) handle: tokio::runtime::Handle,
    pub(crate) configuration: Arc<pingora_core::server::configuration::ServerConf>,
    pub(crate) shutdown: pingora_core::server::ShutdownWatch,
}

/// 🛡️ Owns bound sockets until the whole document is ready to publish.
pub(super) struct BootstrapListener {
    pub(super) address: String,
    pub(super) proxy: PingclairProxy,
    pub(super) policy: Arc<PublishedListenerPolicy>,
    socket: std::net::TcpListener,
    service: Service<ResourceGuardedProxy>,
}

impl BootstrapRuntime {
    /// 🏗️ Prepares routes and reserves every socket before any service starts.
    pub(super) fn prepare(
        &self,
        config: &PingclairConfig,
        policies: &HashMap<String, PreparedListenerPolicy>,
        tls_manager: &Arc<TlsManager>,
    ) -> Result<Vec<BootstrapListener>, ConfigApplyError> {
        let mut listeners = Vec::with_capacity(policies.len());
        for (address, prepared) in policies {
            let policy = Arc::new(PublishedListenerPolicy::new(prepared.client_auth.clone()));
            let trusted = pingclair_core::config::listener_options_for(
                &config.global.listener_options,
                address,
            )
            .and_then(|options| options.trusted_proxies.as_deref())
            .unwrap_or(&config.global.trusted_proxies);
            let proxy = PingclairProxy::with_listener_policy(
                tls_manager.clone(),
                trusted,
                false,
                policy.clone(),
            )
            .expecting_underscore_headers(
                pingclair_core::config::listener_options_for(
                    &config.global.listener_options,
                    address,
                )
                .and_then(|options| options.expected_underscore_headers.as_deref())
                .unwrap_or(&config.global.expected_underscore_headers),
            );
            for server in &prepared.servers {
                proxy.add_server(server.clone());
            }
            let mut options = pingora_core::apps::HttpServerOptions::default();
            options.h2c = true;
            options.allow_connect_method_proxying = true;
            // 🔌 Same ceiling resolution as the ordinary listener path; the
            // bootstrap service is a listener too.
            let mut listener_limits = proxy.listener_limits();
            let ceiling = pingclair_proxy::connection_limit::resolve(
                &listener_limits,
                self.configuration.threads,
            );
            listener_limits.max_connections = Some(ceiling);
            options.keepalive_request_limit =
                pingclair_proxy::keepalive_requests::resolve(&listener_limits);
            let app = ResourceGuardedProxy::new(
                pingora_proxy::HttpProxy::new(proxy.clone(), self.configuration.clone()),
                listener_limits,
                options,
            );
            let mut service = Service::new("Pingclair bootstrap HTTP service".to_string(), app);
            service.add_tcp(address);
            let blocked = &config.global.blocked_ips;
            if !blocked.is_empty() {
                let networks = pingclair_proxy::proxy_protocol::parse_networks(blocked)
                    .map_err(|error| ConfigApplyError::invalid(error.to_string()))?;
                service.set_connection_filter(Arc::new(
                    pingclair_proxy::PingclairConnectionFilter::new(networks),
                ));
            }
            let socket = std::net::TcpListener::bind(address)
                .and_then(|socket| {
                    socket.set_nonblocking(true)?;
                    Ok(socket)
                })
                .map_err(|error| {
                    ConfigApplyError::invalid(format!("failed to bind {address}: {error}"))
                })?;
            listeners.push(BootstrapListener {
                address: address.clone(),
                proxy,
                policy,
                socket,
                service,
            });
        }
        Ok(listeners)
    }

    /// 🚦 Transfers already-bound sockets to Pingora without a second bind race.
    pub(super) fn start(&self, listener: BootstrapListener) {
        let shutdown = self.shutdown.clone();
        self.handle.spawn(async move {
            let mut fds = pingora_core::server::Fds::new();
            // 🔌 Pingora 0.9.0 takes ownership of these descriptors in `listeners::l4::from_raw_fd`.
            fds.add(listener.address, listener.socket.into_raw_fd());
            let mut service = listener.service;
            service
                .start_service(Some(Arc::new(parking_lot::Mutex::new(fds))), shutdown, 1)
                .await;
        });
    }
}
