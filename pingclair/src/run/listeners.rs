// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ Turning each address's proxy into a bound, registered Pingora service.
//!
//! Every address is bound here once, synchronously, before Pingora binds it
//! for real, so a port another process holds stops startup with the address
//! in the message instead of leaving a process that listens on nothing. The
//! same pass attaches TLS (with mutual TLS when a site demands it), binds the
//! HTTP/3 UDP socket next to its TCP twin, and starts the PROXY-protocol
//! ingress for addresses that require the header.

use super::http3::BoundH3Port;
use crate::certs::DynamicCertResolver;
use crate::listen::reserve_private_listener_address;
use crate::runtime_listeners::PreparedListenerPolicy;
use parking_lot::RwLock;
use pingclair_proxy::server::PingclairProxy;
use pingora_core::listeners::tls::TlsSettings;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// 🛡️ What the listener phase reads, all of it decided by earlier phases.
pub(super) struct ListenerInputs<'a> {
    pub(super) port_proxies: &'a RwLock<HashMap<String, PingclairProxy>>,
    pub(super) tls_listeners: &'a HashSet<String>,
    pub(super) proxy_protocol_addresses: &'a HashSet<String>,
    pub(super) prepared_listener_policies: &'a HashMap<String, PreparedListenerPolicy>,
    pub(super) tls_manager: &'a Arc<pingclair_tls::manager::TlsManager>,
    pub(super) proxy_protocol_networks: &'a [ipnet::IpNet],
    pub(super) blocked_client_networks: &'a [ipnet::IpNet],
    pub(super) http3_globally_enabled: bool,
    pub(super) h3_excluded_domains: &'a [String],
    pub(super) bg_handle: &'a tokio::runtime::Handle,
}

/// 🛡️ What the listener phase leaves for the rest of startup.
pub(super) struct BoundListeners {
    /// 🌐 The UDP sockets bound for HTTP/3, one per HTTPS address.
    pub(super) https_ports: Vec<BoundH3Port>,
    /// 🔓 Private loopback addresses held for PROXY-protocol listeners until
    /// immediately before Pingora binds them.
    pub(super) private_listener_reservations: Vec<std::net::TcpListener>,
}

/// 🛡️ Probes, configures and registers one Pingora service per address.
pub(super) fn register(
    server: &mut pingora::server::Server,
    inputs: ListenerInputs<'_>,
) -> anyhow::Result<BoundListeners> {
    let ListenerInputs {
        port_proxies,
        tls_listeners,
        proxy_protocol_addresses,
        prepared_listener_policies,
        tls_manager,
        proxy_protocol_networks,
        blocked_client_networks,
        http3_globally_enabled,
        h3_excluded_domains,
        bg_handle,
    } = inputs;
    // 🛡️ One filter for every listener, built from networks parsed once.
    let connection_filter = (!blocked_client_networks.is_empty()).then(|| {
        std::sync::Arc::new(pingclair_proxy::PingclairConnectionFilter::new(
            blocked_client_networks.to_vec(),
        ))
    });
    let mut https_ports: Vec<BoundH3Port> = Vec::new();
    let mut private_listener_reservations = Vec::new();
    {
        let proxies_guard = port_proxies.read();
        for (addr, proxy_logic) in proxies_guard.iter() {
            let is_https = tls_listeners.contains(addr);
            let requires_proxy_protocol = proxy_protocol_addresses.contains(addr);
            let internal_reservation = requires_proxy_protocol
                .then(reserve_private_listener_address)
                .transpose()?;
            let internal_address = internal_reservation.as_ref().map(|(_, address)| *address);
            let service_address = internal_address
                .map(|address| address.to_string())
                .unwrap_or_else(|| addr.clone());
            // 🌐 Enables prior-knowledge h2c only on plaintext listeners while TLS uses ALPN.
            let mut server_options = pingora_core::apps::HttpServerOptions::default();
            server_options.h2c = !is_https;
            let listener_limits = proxy_logic.listener_limits();
            // 🧱 Captured before the guard consumes the limits, so the public
            // PROXY ingress can carry the same ceiling as the private hop.
            let ingress_max_connections = listener_limits.max_connections;
            let proxy =
                pingora_proxy::HttpProxy::new(proxy_logic.clone(), server.configuration.clone());
            let app = crate::resource_guard::ResourceGuardedProxy::new(
                proxy,
                listener_limits,
                server_options,
            );
            let mut service = pingora_core::services::listening::Service::new(
                "Pingclair HTTP Proxy Service".to_string(),
                app,
            );

            // 🛡️ The global block list, shared by every listener. A PROXY
            // listener filters at its public ingress instead, where the real
            // client address is known.
            if let Some(filter) = connection_filter.as_ref()
                && !requires_proxy_protocol
            {
                service.set_connection_filter(filter.clone());
            }

            // 🛡️ The address is bound here first, and the probe listener is
            // dropped immediately so Pingora can bind it for real.
            //
            // 🤡 Without this, a second instance on an address the first one
            // holds panicked inside Pingora's service runtime — `Failed to
            // build listeners: … Address already in use` — and the process then
            // stayed up, listening on nothing. Under systemd that is the worst
            // of both: a liveness check can pass while no traffic is served,
            // and the supervisor never learns the port was the problem. The
            // PROXY-protocol ingress a few lines below already binds directly
            // and reports the failure; this gives the ordinary listener the
            // same answer, naming the address.
            //
            // 📌 The window between dropping the probe and Pingora's own bind is
            // the one thing this cannot close, and it is the same window the
            // kernel would have had anyway.
            let probe = std::net::TcpListener::bind(addr)
                .map_err(|error| anyhow::anyhow!("failed to bind {addr}: {error}"))?;
            drop(probe);

            // 🔐 Explicit TLS configuration supports HTTPS and H3 on non-standard ports.
            let mut tls_enabled = false;
            let mut http3_enabled = false;

            if is_https {
                // 🔐 Enable dynamic certificates and advertise HTTP/2 plus HTTP/1.1 over ALPN.
                // 🪪 Derived from the table having something in it, not merely
                // existing, so this flag can never disagree with what the
                // acceptor installs. They gate different things — one turns on
                // the SNI-against-Host check, the other records the name that
                // check reads — and a listener where only the first fires would
                // answer 421 to every request.
                let listener_policy = proxy_logic.listener_policy();
                let requires_client_auth = listener_policy.client_auth_reload_capable();
                let acceptor = DynamicCertResolver::new(tls_manager.clone())
                    .with_default_sni(
                        prepared_listener_policies
                            .get(addr)
                            .and_then(|policy| policy.default_sni.as_deref()),
                    )
                    .with_listener_policy(listener_policy);
                let install_name_alert = acceptor.name_alert_installer();
                match TlsSettings::with_callbacks(Box::new(acceptor)) {
                    Ok(mut tls_settings) => {
                        install_name_alert(&mut tls_settings);
                        tls_settings.enable_h2();
                        if requires_client_auth {
                            // 🚫 Session resumption is turned off for the whole
                            // listener, and this is a deliberate trade rather
                            // than caution. A resumed handshake carries no
                            // `CertificateRequest` — BoringSSL restores the
                            // peer's chain from the ticket and never asks
                            // again — so a ticket issued before a certificate
                            // expired, was revoked, or before the trust pool
                            // changed would keep letting its holder in. The
                            // cost is a full handshake per connection on this
                            // listener; the alternative is a site that reports
                            // mutual TLS and, for the lifetime of a ticket,
                            // does not enforce it.
                            tls_settings.set_options(boring::ssl::SslOptions::NO_TICKET);
                            tls_settings
                                .set_session_cache_mode(boring::ssl::SslSessionCacheMode::OFF);
                            tracing::info!(
                                "🪪 Mutual TLS is enforced on {} (session resumption off, \
                                 SNI must match Host)",
                                addr
                            );
                        }
                        service.add_tls_with_settings(&service_address, None, tls_settings);
                        tls_enabled = true;
                    }
                    Err(e) => {
                        tracing::error!("❌ Failed to create TlsSettings for {}: {}", addr, e);
                    }
                }

                // Enable HTTP/3 for HTTPS ports when the global switch is on:
                // advertise Alt-Svc on this listener and queue the port for
                // a QUIC socket.
                //
                // 🪪 A listener demanding a client certificate starts HTTP/3
                // like any other: `quic.rs` installs the same compiled policy
                // through its own BoringSSL context, and enforces the same
                // SNI-against-`:authority` rule. Suppressing HTTP/3 here was
                // the fail-closed answer while that was not true.
                //
                // 🚫 The UDP socket is bound here, synchronously and next to
                // the TCP listener, and a failed bind stops startup. `Alt-Svc`
                // is set only once the socket exists: it tells clients to
                // come back over QUIC for a day, so publishing it for a port
                // this process does not hold would send them to nothing.
                //
                // 📌 An address that is not a literal socket address never
                // had HTTP/3 (the QUIC task refused it before, too); it stays
                // a log line rather than a new reason to refuse startup.
                let h3_address = http3_globally_enabled
                    .then(|| addr.parse::<std::net::SocketAddr>())
                    .and_then(|parsed| {
                        parsed
                            .inspect_err(|error| {
                                tracing::error!(
                                    "❌ Invalid HTTP/3 listen address {}: {}",
                                    addr,
                                    error
                                );
                            })
                            .ok()
                    });
                if let Some(socket_addr) = h3_address {
                    let socket = pingclair_proxy::quic::bind_udp(socket_addr).map_err(|error| {
                        anyhow::anyhow!("failed to bind HTTP/3 (UDP) on {addr}: {error}")
                    })?;
                    https_ports.push((addr.clone(), socket_addr, socket));
                    http3_enabled = true;
                    proxy_logic.set_alt_svc(socket_addr.port(), h3_excluded_domains);
                }
            } else {
                service.add_tcp(&service_address);
            }

            if let Some(internal_address) = internal_address {
                let public_listener = std::net::TcpListener::bind(addr).map_err(|error| {
                    anyhow::anyhow!("failed to bind PROXY protocol ingress on {addr}: {error}")
                })?;
                let registry = proxy_logic.proxy_protocol_registry();
                let trusted = proxy_protocol_networks.to_vec();
                let blocked = blocked_client_networks.to_vec();
                bg_handle.spawn(async move {
                    if let Err(error) = pingclair_proxy::proxy_protocol::run_ingress(
                        public_listener,
                        internal_address,
                        registry,
                        trusted,
                        blocked,
                        ingress_max_connections,
                    )
                    .await
                    {
                        tracing::error!(
                            %error,
                            "❌ PROXY protocol ingress stopped unexpectedly"
                        );
                    }
                });
            }
            if let Some((reservation, _)) = internal_reservation {
                private_listener_reservations.push(reservation);
            }

            // Enhanced diagnostic logging for each binding
            tracing::info!(
                "   🌐 Server listening on {} (TLS: {}, HTTP/3: {})",
                addr,
                if tls_enabled { "enabled" } else { "disabled" },
                if http3_enabled { "enabled" } else { "disabled" }
            );

            server.add_service(service);
        }
    }

    Ok(BoundListeners {
        https_ports,
        private_listener_reservations,
    })
}
