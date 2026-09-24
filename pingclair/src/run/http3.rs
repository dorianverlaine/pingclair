// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌐 HTTP/3 servers for the UDP sockets the listener phase already bound.
//!
//! The sockets exist before this runs — a port that cannot be bound stops
//! startup where its TCP twin is bound — so this module only turns them into
//! QUIC servers, seeds the certificate table they share, and keeps that table
//! fresh as certificates renew. A QUIC server that stops withdraws `Alt-Svc`
//! from its listener, so clients are never told to come back to a port that
//! no longer answers.

use crate::certs::refresh_h3_cert_table;
use parking_lot::RwLock;
use pingclair_proxy::server::PingclairProxy;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

/// 🌐 One bound HTTP/3 port: the listen address as configured, the parsed
/// socket address, and the UDP socket bound for it.
pub(super) type BoundH3Port = (String, std::net::SocketAddr, std::net::UdpSocket);

/// 🌐 The UDP side of startup: the sockets to serve and the block list that
/// applies to every one of them.
pub(super) struct H3Sockets<'a> {
    pub(super) ports: Vec<BoundH3Port>,
    /// 🛡️ Parsed once at startup and shared in meaning with the TCP
    /// listeners' connection filter.
    pub(super) blocked_networks: &'a [ipnet::IpNet],
}

/// 🌐 Starts a QUIC server for every bound port and returns the certificate
/// table they share, or `None` when no port asked for HTTP/3.
///
/// 🔐 The table is seeded synchronously on `tls_runtime` before this returns,
/// so the Admin API, which starts next, can never have a manual rotation
/// overwritten by a late startup read.
pub(super) fn start(
    config: &pingclair_core::config::PingclairConfig,
    sockets: H3Sockets<'_>,
    h3_excluded_domains: &[String],
    tls_runtime: &tokio::runtime::Runtime,
    tls_manager: &Arc<pingclair_tls::manager::TlsManager>,
    port_proxies: &Arc<RwLock<HashMap<String, PingclairProxy>>>,
    bg_handle: &tokio::runtime::Handle,
) -> Option<Arc<pingclair_proxy::quic::CertTable>> {
    let H3Sockets {
        ports: https_ports,
        blocked_networks,
    } = sockets;
    // 📜 The domains whose certificates seed the SNI cert table, and the
    // upstream pool size and L4 blocklist kept consistent with H1/H2.
    let h3_domains: Vec<String> = config
        .servers
        .iter()
        .filter_map(|s| s.name.clone())
        .filter(|n| !n.is_empty() && n != "_" && n != "*" && !n.starts_with(':'))
        .collect();
    let manual_h3_domains: HashSet<&str> = config
        .servers
        .iter()
        .filter(|server| {
            server
                .tls
                .as_ref()
                .is_some_and(|tls| tls.cert.is_some() && tls.key.is_some())
        })
        .filter_map(|server| server.name.as_deref())
        .collect();
    let h3_periodic_domains: Vec<String> = h3_domains
        .iter()
        .filter(|name| !manual_h3_domains.contains(name.as_str()))
        .cloned()
        .collect();
    let h3_pool_size = config.global.upstream_keepalive_pool_size.unwrap_or(512);

    // 📜 One certificate table is retained by the runtime publisher so a
    // manual rotation reaches QUIC in the same transaction as TCP TLS.
    let h3_cert_table =
        (!https_ports.is_empty()).then(|| Arc::new(pingclair_proxy::quic::CertTable::new()));

    // Start HTTP/3 (QUIC) servers for HTTPS ports
    if let Some(cert_table) = h3_cert_table.clone() {
        cert_table.set_excluded_names(h3_excluded_domains.to_vec());
        tracing::info!(
            "🚀 Starting HTTP/3 servers for {} port(s)",
            https_ports.len()
        );

        // Shared SNI certificate table: populated from the TLS manager
        // (manual certs + already-issued ACME certs), then refreshed
        // periodically so renewals reach new handshakes without a restart.
        // 🔐 Seed synchronously before Admin can publish a rotation; an
        // asynchronous startup read could otherwise overwrite the first new
        // manual generation after `/load` had already reported success.
        tls_runtime.block_on(refresh_h3_cert_table(&cert_table, tls_manager, &h3_domains));
        let table_for_task = cert_table.clone();
        let tls_for_task = tls_manager.clone();
        let proxies_for_task = port_proxies.clone();
        let periodic_domains_for_task = h3_periodic_domains.clone();
        let blocked_for_task = blocked_networks.to_vec();
        bg_handle.spawn(async move {
            for (addr_str, socket_addr, socket) in https_ports {
                let proxy = {
                    let guard = proxies_for_task.read();
                    guard.get(&addr_str).map(|p| std::sync::Arc::new(p.clone()))
                };
                let Some(proxy) = proxy else {
                    tracing::error!("❌ No proxy found for HTTP/3 address {}", addr_str);
                    continue;
                };

                let advertiser = Arc::clone(&proxy);
                let server = pingclair_proxy::quic::QuicServer::new(
                    socket_addr,
                    proxy,
                    table_for_task.clone(),
                    h3_pool_size,
                    blocked_for_task.clone(),
                )
                .with_socket(socket);

                tokio::spawn(async move {
                    let outcome = server.run().await;
                    // 🚫 Whatever ended the QUIC server, the port no longer
                    // answers it, so this listener stops saying it does.
                    advertiser.clear_alt_svc();
                    match outcome {
                        Ok(()) => tracing::warn!(
                            "🌐 HTTP/3 server on {} stopped; Alt-Svc withdrawn",
                            socket_addr
                        ),
                        Err(e) => tracing::error!(
                            "🌐 HTTP/3 server on {} failed; Alt-Svc withdrawn: {}",
                            socket_addr,
                            e
                        ),
                    }
                });
            }

            // 🔁 Periodic refresh picks up ACME and internal renewals. Manual
            // pairs are excluded because the synchronous config publisher
            // installs them under its generation gate; an older periodic read
            // must never overwrite a completed rotation.
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                refresh_h3_cert_table(&table_for_task, &tls_for_task, &periodic_domains_for_task)
                    .await;
            }
        });
    }

    h3_cert_table
}
