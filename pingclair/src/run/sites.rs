// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📍 Which site answers on which address.
//!
//! Every site is placed on its listen addresses — 443 by default when it
//! configures TLS, 80 otherwise — and, under automatic HTTPS, on a plaintext
//! companion that answers ACME validation and redirects to HTTPS. The result is
//! one proxy per address holding every site that shares it, plus the set of
//! addresses that must speak TLS. Nothing is bound here; that is the next
//! phase, and it needs this whole picture first.

use crate::listen::{automatic_http_companion, explicit_http_names, server_requires_tls};
use pingclair_proxy::client_auth::PublishedListenerPolicy;
use pingclair_proxy::server::PingclairProxy;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

/// 📍 Sites grouped by listen address.
pub(super) struct SiteGroups {
    /// 📍 One proxy per listen address, holding every site bound there.
    pub(super) port_proxies: HashMap<String, PingclairProxy>,
    /// 🔐 The addresses whose listener must terminate TLS.
    pub(super) tls_listeners: HashSet<String>,
}

/// 📍 Places every configured site on its addresses and logs the result.
pub(super) fn group_by_address(
    config: &pingclair_core::config::PingclairConfig,
    listener_security_by_address: &HashMap<String, Arc<PublishedListenerPolicy>>,
    automatic_http_available: bool,
    tls_manager: &Arc<pingclair_tls::manager::TlsManager>,
    trusted_proxies: &[String],
    listener_options: &BTreeMap<String, pingclair_core::config::ListenerOptions>,
    proxy_protocol_addresses: &HashSet<String>,
) -> anyhow::Result<SiteGroups> {
    let mut port_proxies: HashMap<String, PingclairProxy> = HashMap::new();
    // Track binding information for diagnostic logging
    let mut binding_info: HashMap<String, Vec<String>> = HashMap::new();
    let mut tls_listeners = HashSet::new();

    // 🔎 Probed once, before any listener is registered: whether an automatic
    // port-80 companion is even possible here. Doing it per site would probe a
    // privileged port repeatedly for one unchanging answer.
    let auto_https_mode = config.global.auto_https.clone();
    let http_port = config.global.http_port;
    let https_port = config.global.https_port;
    let explicit_http_names = explicit_http_names(config);

    for server_config in &config.servers {
        tracing::debug!(
            "🚀 Processing ServerConfig: name={:?}, listens={:?}",
            server_config.name,
            server_config.listen
        );

        // 🔐 The derivation is in `pingclair_core::config`, next to the
        // validator that has to agree with it: a site that configures TLS but
        // no port means HTTPS, and defaulting it to 80 would quietly serve a
        // site the operator asked to encrypt on the plaintext port instead.
        let listen_addrs: Vec<String> = server_config.listen_addresses(http_port, https_port);

        // 🔁 Automatic HTTPS: give an HTTPS site its plaintext port-80 companion
        // so ACME validation and the HTTP→HTTPS redirect both work unattended.
        let companion = automatic_http_companion(
            server_config,
            auto_https_mode.clone(),
            &listen_addrs,
            &explicit_http_names,
            http_port,
            https_port,
        )
        .filter(|_| {
            if automatic_http_available {
                true
            } else {
                tracing::warn!(
                    "🚫 Automatic HTTPS could not take {} for {:?}: HTTP→HTTPS \
                     redirects and ACME HTTP-01 validation are unavailable. \
                     Free the port, run with CAP_NET_BIND_SERVICE, or add an \
                     explicit `listen` for the plaintext port.",
                    format!("[::]:{http_port}"),
                    server_config.name
                );
                false
            }
        });

        for addr in listen_addrs {
            if server_requires_tls(server_config, &addr, http_port, https_port) {
                tls_listeners.insert(addr.clone());
            }
            let listener_policy = listener_security_by_address
                .get(&addr)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no prepared listener policy for {addr}"))?;
            // 🛡️ An addressed `servers <address> { trusted_proxies … }` block
            // replaces the global list for that one listener: believing a
            // forwarded address is a decision about who is in front of *this*
            // socket, and two deployments behind different load balancers is
            // the case the address exists to separate.
            let trusted = pingclair_core::config::listener_options_for(listener_options, &addr)
                .and_then(|options| options.trusted_proxies.as_deref())
                .unwrap_or(trusted_proxies);
            let proxy = port_proxies.entry(addr.clone()).or_insert_with(|| {
                pingclair_proxy::server::PingclairProxy::with_listener_policy(
                    tls_manager.clone(),
                    trusted,
                    proxy_protocol_addresses.contains(&addr),
                    listener_policy,
                )
            });

            // Track what sites are bound to what addresses
            let site_name = server_config
                .name
                .clone()
                .unwrap_or_else(|| "default".to_string());
            binding_info
                .entry(addr.clone())
                .or_default()
                .push(site_name);

            proxy.add_server(server_config.clone());
        }

        if let Some(companion) = companion {
            let addr = format!("[::]:{http_port}");
            let listener_policy = listener_security_by_address
                .get(&addr)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no prepared listener policy for {addr}"))?;
            let proxy = port_proxies.entry(addr.clone()).or_insert_with(|| {
                pingclair_proxy::server::PingclairProxy::with_listener_policy(
                    tls_manager.clone(),
                    trusted_proxies,
                    proxy_protocol_addresses.contains(&addr),
                    listener_policy,
                )
            });
            binding_info.entry(addr).or_default().push(format!(
                "{} (automatic HTTP)",
                companion.name.as_deref().unwrap_or("default")
            ));
            // 🔄 The redirect a request gets when its `Host` matches no site.
            //
            // 📌 Gated on the companion actually carrying routes. Under
            // `auto_https disable_redirects` the listener is provisioned for
            // ACME validation only, with no routes at all — and telling the
            // proxy to redirect there would quietly undo the mode the operator
            // asked for.
            if !companion.routes.is_empty() {
                proxy.automatic_https.store(std::sync::Arc::new(Some(
                    pingclair_proxy::server::AutomaticHttpsRedirect {
                        http_port,
                        https_port,
                    },
                )));
            }
            proxy.add_server(companion);
        }
    }

    // Log binding information for diagnostics
    tracing::info!("🌐 Server binding information:");
    for (addr, sites) in &binding_info {
        tracing::info!("   📍 {} -> [{}]", addr, sites.join(", "));
    }

    Ok(SiteGroups {
        port_proxies,
        tls_listeners,
    })
}
