// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚀 Everything between a compiled configuration and a serving process.
//!
//! One function, because it is one sequence with an order that matters: build
//! the Pingora server, prove the certificate store is writable, load manual
//! certificates as a set, derive and bind listeners, start HTTP/3, start the
//! Admin API, install signal handlers, and only then announce readiness.
//! Several of those steps are ordering constraints rather than steps —
//! announcing readiness before the listeners exist is what makes a rolling
//! deploy drop requests, and it is a one-line mistake to make.
//!
//! 🚧 This module is over the size the rest of the binary aims for, and that is
//! recorded rather than hidden: the split that moved it here was a move, and
//! carving `run_server` into phases means inventing signatures for six or seven
//! captured values. That is a change worth reviewing on its own terms, so it
//! has a TRIAGE row instead of being smuggled in here.

use crate::certs::{DynamicCertResolver, eager_issuance_domains, h3_excluded_domains};
use crate::listen::{
    automatic_http_companion, can_bind_automatic_http_port, explicit_http_names,
    normalize_listen_addr, reserve_private_listener_address, server_requires_tls,
};
use crate::paths::tls_store_dir_with;
use crate::runtime_listeners::{
    RuntimeListeners, RuntimePublisherInputs, prepare_listener_policies,
};
use crate::systemd::notify_systemd_ready;
use parking_lot::RwLock;
use pingclair_proxy::client_auth::PublishedListenerPolicy;
use pingora_core::listeners::tls::TlsSettings;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

mod certificates;
mod http3;
#[cfg(unix)]
mod reload;
mod server_conf;

pub(crate) fn run_server(
    config_path: String,
    config: pingclair_core::config::PingclairConfig,
) -> anyhow::Result<()> {
    // Create a background Tokio runtime for async tasks (HTTP/3, SIGHUP, etc.)
    // We do this in a separate thread to avoid conflicts with Pingora's runtime.
    let bg_runtime = tokio::runtime::Runtime::new().expect("Failed to create background runtime");
    let bg_handle = bg_runtime.handle().clone();

    std::thread::spawn(move || {
        bg_runtime.block_on(async {
            // Keep the runtime alive
            std::future::pending::<()>().await;
        });
    });

    // Enhanced diagnostic logging
    tracing::info!("🚀 Starting Pingclair v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("📄 Loaded configuration from: {}", config_path);
    tracing::info!("🔧 Configured {} server(s)", config.servers.len());

    // 📊 Register Prometheus metrics with the global registry so the admin
    // /metrics endpoint has data to expose. `{ metrics }` can turn collection
    // on explicitly; it stays on by default for existing deployments.
    if config.global.metrics {
        pingclair_proxy::metrics::init();
    }

    // 📡 OTLP push is parsed so a configuration written elsewhere still loads
    // and still says what it meant, but nothing here exports it. Refusing beats
    // starting: an operator who asked for push and got a silent scrape-only
    // server finds out when an incident needs the dashboard that was never
    // receiving anything.
    if config.global.metrics_options.otlp {
        anyhow::bail!(
            "🚫 `metrics {{ otlp }}` is configured, but Pingclair has no OTLP exporter — \
             metrics are exposed by scraping only. Remove `otlp` to start."
        );
    }

    // 📊 Publish the label policy before any request path reads it, and give it
    // every host this configuration serves so `per_host` can tell a host it was
    // set up for from one a stranger typed into the `Host` header.
    pingclair_proxy::metrics::configure_host_labels(
        &config.global.metrics_options,
        config
            .servers
            .iter()
            .flat_map(|s| s.names.iter().map(String::as_str)),
    );

    // 🪵 Named log channels must exist before any ProxyState resolves a
    // reference to one. Registration is idempotent, so a reload that keeps a
    // channel keeps its writer thread and its queue rather than spawning a
    // second writer onto the same file.
    pingclair_proxy::access_log::register_channels(&config.logging.channels);

    // 🔢 The startup configuration is version 1. The number itself is
    // meaningless; two instances behind one balancer reporting *different*
    // versions is the signal — it means a reload reached one and not the other,
    // which is otherwise invisible until they start behaving differently.
    pingclair_proxy::metrics::CONFIG_VERSION.set(1);

    if config.global.auto_https != pingclair_core::config::AutoHttpsMode::Off {
        tracing::info!("🔐 Auto HTTPS: enabled");
        if let Some(email) = &config.global.email {
            tracing::info!("📧 ACME email: {}", email);
        }
    } else {
        tracing::info!("🔐 Auto HTTPS: disabled");
    }

    if config.servers.is_empty() {
        tracing::warn!("⚠️ No servers configured!");
        return Ok(());
    }

    // 🧮 Every Pingora knob is chosen deliberately; see `server_conf`.
    let (server_conf, grace_period_secs) = server_conf::build(&config);

    let mut server = pingora::server::Server::new_with_opt_and_conf(
        Some(pingora::server::configuration::Opt {
            upgrade: false,
            daemon: false,
            nocapture: false,
            test: false,
            conf: None, // We build ServerConf ourselves above; no file to load.
        }),
        server_conf,
    );
    server.bootstrap();
    // 🩺 One Pingora-owned driver follows weak pool registrations across hot reloads.
    server.add_service(pingora::services::background::background_service(
        "Pingclair active health checks",
        pingclair_proxy::health_check::HealthCheckDriver,
    ));

    // 🔐 Certificate sources are ready before any listener exists; see
    // `certificates`.
    let certificates::PreparedCertificates {
        runtime: tls_runtime,
        manager: tls_manager,
        manual: manual_certs,
    } = certificates::prepare(&config)?;

    // 🏗️ Startup and every later reload compile listener policy through this
    // same path. Trust files are read now; handshakes only load one published
    // generation and never parse configuration or PEM material.
    let automatic_http_available = config.global.auto_https
        != pingclair_core::config::AutoHttpsMode::Off
        && config.servers.iter().any(|server| server.tls.is_some())
        && can_bind_automatic_http_port(config.global.http_port);
    let prepared_listener_policies = prepare_listener_policies(&config, automatic_http_available)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let listener_security_by_address: HashMap<String, Arc<PublishedListenerPolicy>> =
        prepared_listener_policies
            .iter()
            .map(|(address, policy)| {
                (
                    address.clone(),
                    Arc::new(
                        PublishedListenerPolicy::new(Arc::clone(&policy.client_auth))
                            .with_default_sni(policy.default_sni.as_deref()),
                    ),
                )
            })
            .collect();

    match tls_manager.refresh_manual_certs(&manual_certs) {
        Ok(count) if count > 0 => {
            tracing::info!("🔐 Loaded {count} manual TLS certificate(s)");
        }
        Ok(_) => {}
        Err(problems) => {
            for problem in &problems {
                tracing::error!("❌ Manual TLS certificate rejected: {problem}");
            }
            anyhow::bail!(
                "{} manual TLS certificate(s) could not be loaded; refusing to start with \
                 certificates the operator asked for but that cannot serve",
                problems.len()
            );
        }
    }

    // 🚀 Kick off the background certificate machinery: renewals plus eager
    // issuance for every `tls auto` hostname. Domains already covered by
    // internal or manual certificates are excluded — those paths are eager
    // already, and ACME must never race a local authority.
    let eager_domains = eager_issuance_domains(&config);
    // 🚀 The background tasks need a Tokio reactor; the dedicated background
    // runtime already exists for H3 and SIGHUP work.
    let tls_manager_for_tasks = tls_manager.clone();
    bg_handle.spawn(async move {
        tls_manager_for_tasks.start_background_issuance(eager_domains);
    });

    // Group servers by listen address
    let port_proxies = std::collections::HashMap::new();
    let port_proxies = std::sync::Arc::new(parking_lot::RwLock::new(port_proxies));

    // 🚫 Sites that asked to stay off HTTP/3; see `h3_excluded_domains`.
    let h3_excluded_domains = h3_excluded_domains(&config);
    let http3_globally_enabled = config.global.http3;
    let trusted_proxies = config.global.trusted_proxies.clone();
    // 🧭 Which listen addresses require a PROXY header, resolved once. The
    // compiler has already rejected any address two servers disagree about, so
    // membership here is the whole answer for a given socket.
    let proxy_protocol_addresses: std::collections::HashSet<String> = config
        .servers
        .iter()
        .flat_map(|server| server.proxy_protocol_listen.iter().cloned())
        .collect();
    let proxy_protocol_networks =
        pingclair_proxy::proxy_protocol::parse_networks(&trusted_proxies)?;
    let blocked_client_networks =
        pingclair_proxy::proxy_protocol::parse_networks(&config.global.blocked_ips)?;

    // Track binding information for diagnostic logging
    let mut binding_info: HashMap<String, Vec<String>> = HashMap::new();
    let mut tls_listeners = HashSet::new();

    // 🔎 Probed once, before any listener is registered: whether an automatic
    // port-80 companion is even possible here. Doing it per site would probe a
    // privileged port repeatedly for one unchanging answer.
    let auto_https_mode = config.global.auto_https.clone();
    let http_port = config.global.http_port;
    let https_port = config.global.https_port;
    let explicit_http_names = explicit_http_names(&config);

    for server_config in &config.servers {
        tracing::debug!(
            "🚀 Processing ServerConfig: name={:?}, listens={:?}",
            server_config.name,
            server_config.listen
        );

        let listen_addrs: Vec<String> = if server_config.listen.is_empty() {
            // 🔐 A site that configures TLS but no port means HTTPS, so it
            // belongs on 443. Defaulting it to 80 would quietly serve a site
            // the operator asked to encrypt on the plaintext port instead.
            let host = server_config
                .bind
                .as_deref()
                .filter(|h| !h.is_empty())
                .unwrap_or("[::]");
            if server_config.tls.is_some() {
                vec![format!("{host}:{https_port}")]
            } else {
                vec![format!("{host}:{http_port}")]
            }
        } else {
            server_config
                .listen
                .iter()
                .map(|a| normalize_listen_addr(a))
                .collect()
        };

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
            let mut proxies_guard = port_proxies.write();
            let proxy = proxies_guard.entry(addr.clone()).or_insert_with(|| {
                pingclair_proxy::server::PingclairProxy::with_listener_policy(
                    tls_manager.clone(),
                    &trusted_proxies,
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
            let mut proxies_guard = port_proxies.write();
            let proxy = proxies_guard.entry(addr.clone()).or_insert_with(|| {
                pingclair_proxy::server::PingclairProxy::with_listener_policy(
                    tls_manager.clone(),
                    &trusted_proxies,
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

    // Create services for each proxy
    let mut https_ports = Vec::new();
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

            // Add L4 Connection Filter (Global Blocked IPs)
            let blocked_ips = &config.global.blocked_ips;
            if !requires_proxy_protocol && !blocked_ips.is_empty() {
                let filter = std::sync::Arc::new(pingclair_proxy::PingclairConnectionFilter::new(
                    blocked_ips,
                ));
                service.set_connection_filter(filter);
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
                    proxy_logic.set_alt_svc(socket_addr.port(), &h3_excluded_domains);
                }
            } else {
                service.add_tcp(&service_address);
            }

            if let Some(internal_address) = internal_address {
                let public_listener = std::net::TcpListener::bind(addr).map_err(|error| {
                    anyhow::anyhow!("failed to bind PROXY protocol ingress on {addr}: {error}")
                })?;
                let registry = proxy_logic.proxy_protocol_registry();
                let trusted = proxy_protocol_networks.clone();
                let blocked = blocked_client_networks.clone();
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

    // ⚠️ Every listener is known now, so this is the first point where the
    // descriptors the keepalive pools may hold can be compared with the limit.
    crate::fd_budget::warn_if_over_limit(crate::fd_budget::DescriptorReservation {
        pool_size: server.configuration.upstream_keepalive_pool_size,
        worker_threads: server.configuration.threads,
        tcp_listeners: port_proxies.read().len(),
        h3_ports: https_ports.len(),
        admin_listener: config.admin.as_ref().is_some_and(|admin| admin.enabled),
    });

    // 🌐 Turn the bound UDP sockets into QUIC servers; see `http3`.
    let h3_cert_table = http3::start(
        &config,
        https_ports,
        &h3_excluded_domains,
        &tls_runtime,
        &tls_manager,
        &port_proxies,
        &bg_handle,
    );

    // 🛑 `POST /stop` notifies this; the shutdown task treats it like SIGTERM.
    let admin_shutdown = Arc::new(tokio::sync::Notify::new());
    // 🚫 Caddy disables SIGUSR1 reloads once the Admin API has changed the
    // config; this flag records that transition.
    let api_changed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // 🔐 Admin access and every data-plane listener share one transaction
    // publisher. A reload therefore either publishes all prepared policy or
    // leaves the startup generation untouched.
    let admin_listen = config
        .admin
        .as_ref()
        .map(|admin| admin.listen.clone())
        .unwrap_or_else(|| "localhost:2019".to_string());
    let admin_listener_available = config.admin.as_ref().is_some_and(|admin| admin.enabled);
    // 🧭 Signal reload and Admin mutations publish the same active document;
    // `/config` can therefore never describe a generation older than runtime.
    let active_document = Arc::new(RwLock::new(
        serde_json::to_value(config.clone())
            .unwrap_or_else(|_| serde_json::Value::Object(Default::default())),
    ));
    let admin_policy = Arc::new(pingclair_api::AdminPolicy::new(
        admin_listen,
        config.admin.as_ref(),
        admin_listener_available,
    ));
    let config_publisher: Arc<dyn pingclair_proxy::server::ConfigPublisher> =
        Arc::new(RuntimeListeners::new(
            RuntimePublisherInputs {
                port_proxies: port_proxies.clone(),
                tls_manager: tls_manager.clone(),
                h3_cert_table,
                admin_policy: admin_policy.clone(),
                document: active_document.clone(),
                listener_policies: listener_security_by_address,
                automatic_http_available,
                api_changed: api_changed.clone(),
            },
            config.clone(),
            prepared_listener_policies,
        ));

    // Start Admin API if enabled
    if let Some(admin_config) = &config.admin
        && admin_config.enabled
    {
        let listen = admin_config.listen.clone();
        let shutdown_for_admin = admin_shutdown.clone();
        let autosave =
            tls_store_dir_with(config.global.storage_path.as_deref()).join("autosave.json");
        // 🧭 The admin traversal endpoints read and write one shared config
        // document; it starts as the exact configuration that was loaded.
        let document = active_document.clone();
        let publisher_for_admin = config_publisher.clone();
        let policy_for_admin = admin_policy.clone();

        // 🚫 Bound here, synchronously, like the TCP and UDP listeners above: a
        // taken admin port stops startup and names the address. Binding inside
        // the admin thread used to log the failure to stdout and carry on, so
        // the server looked healthy while refusing every `/load` and `/config`.
        // `validate_config` already refuses an address that does not parse;
        // this re-checks rather than panicking if one ever reaches here.
        let addr = pingclair_core::config::parse_listen_addr(&listen)
            .ok_or_else(|| anyhow::anyhow!("admin API address `{listen}` is not bindable"))?;
        let admin_listener = std::net::TcpListener::bind(addr)
            .map_err(|error| anyhow::anyhow!("failed to bind admin API on {listen}: {error}"))?;

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create admin runtime");
            rt.block_on(async {
                let options = pingclair_api::AdminServerOptions {
                    document,
                    shutdown: shutdown_for_admin,
                    autosave: Some(autosave),
                    publisher: Some(publisher_for_admin),
                    policy: policy_for_admin,
                };
                if let Err(e) = pingclair_api::run_admin_server(admin_listener, options).await {
                    tracing::error!("🔧 Admin server error: {}", e);
                }
            });
        });
    }

    // 🔔 SIGUSR1 reloads the configuration file; see `reload`.
    #[cfg(unix)]
    if !config_path.is_empty() {
        bg_handle.spawn(reload::listen_for_reload(
            config_path.clone(),
            config_publisher.clone(),
            api_changed.clone(),
        ));
    }

    // 🔄 ========================================
    // 🔄 Upstream DNS re-resolution.
    // 🔄 ========================================
    // 🔄 Every route was resolved once while its ProxyState was built. One
    // shared scheduler honors each dynamic source's interval while ordinary
    // hostname pools follow the global interval.
    //
    // ♻️ The task runs even when no pool has registered yet because a hot
    // reload can introduce the first hostname or explicitly scheduled source.
    let dns_refresh_secs = config.global.dns_refresh_secs;
    let default_dns_interval = if dns_refresh_secs == 0 {
        tracing::info!("🔄 Global upstream DNS re-resolution disabled (dns_refresh off)");
        None
    } else {
        Some(std::time::Duration::from_secs(dns_refresh_secs))
    };
    bg_handle.spawn(pingclair_proxy::dns::run(default_dns_interval));

    // ========================================
    // 🛑 Graceful shutdown (SIGINT, SIGTERM, admin `POST /stop`)
    // ========================================
    // 🧭 The order lives in `crate::shutdown`. The listener records a stop
    // request from now on, Pingora reads it through `SignalWatch` and closes
    // the listeners, and the drain task then waits for running requests,
    // flushes the logs, and exits.
    #[cfg(unix)]
    let (stop_requested, stop_watch) = tokio::sync::watch::channel(false);
    #[cfg(unix)]
    bg_handle.spawn(crate::shutdown::listen_for_stop(
        admin_shutdown.clone(),
        stop_requested,
    ));
    bg_handle.spawn(crate::shutdown::drain_then_exit(
        server.watch_execution_phase(),
        Duration::from_secs(grace_period_secs),
    ));

    println!("🚀 Pingclair running...");
    // 🔓 Releases every unique private address immediately before Pingora binds it.
    drop(private_listener_reservations);

    // 🚦 Ready only now. Every listener has been added to the server and the
    // reservations are released, so the next thing that happens is Pingora
    // binding them. Announcing readiness any earlier — right after parsing the
    // config, say — is what makes a rolling deploy drop requests: the
    // orchestrator believes the instance is serving and sends it traffic while
    // the sockets are still being created.
    //
    // 📣 systemd learns the same fact at the same moment. With `Type=notify`
    // the unit is not considered started until this arrives, so `systemctl
    // start` blocks until the process can actually answer, and anything
    // ordered `After=` it starts against a working proxy rather than a
    // half-open one.
    pingclair_proxy::readiness::mark_ready();
    notify_systemd_ready();

    #[cfg(unix)]
    server.run(pingora::server::RunArgs {
        shutdown_signal: Box::new(crate::shutdown::SignalWatch {
            requested: stop_watch,
        }),
    });
    #[cfg(not(unix))]
    server.run(pingora::server::RunArgs::default());
    // 🧯 Pingora returns only if the drain task above never ran; leave through
    // the same log drains rather than its own bare `exit`.
    crate::shutdown::shutdown_and_exit();
}
