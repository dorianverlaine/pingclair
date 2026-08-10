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

use crate::certs::{DynamicCertResolver, eager_issuance_domains, refresh_h3_cert_table};
use crate::listen::{
    automatic_http_companion, can_bind_automatic_http_port, explicit_http_names,
    normalize_listen_addr, reserve_private_listener_address, server_requires_tls,
    servers_by_bind_address,
};
use crate::paths::tls_store_dir;
use crate::runtime_listeners::RuntimeListeners;
use crate::systemd::{notify_systemd_ready, notify_systemd_stopping};
use parking_lot::RwLock;
use pingora_core::listeners::tls::TlsSettings;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

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

    // Create Pingora Server.
    //
    // We build `ServerConf` explicitly (rather than passing `conf: None`
    // and letting Pingora fall back to its own implicit default) so the
    // upstream keepalive connection pool size is always a deliberate,
    // known value — not an invisible one an operator only discovers when
    // a slow upstream under load starts exhausting connections.
    let mut server_conf = pingora::server::configuration::ServerConf::default();
    server_conf.upstream_keepalive_pool_size = config
        .global
        .upstream_keepalive_pool_size
        // ⚡ 512, not Pingora's 128: an interleaved t4g.small scan of the
        // reverse-proxy path (2026-08-03) measured 128 → 8.1k req/s, 256 →
        // 8.5k, 512 → 8.9k on 100×20 HTTP/2 streams, then a small decline at
        // 768/1024. The idle pool only caps reusable upstream connections, so
        // the cost is bounded by the FD limit; operators can still override
        // the knob per deployment.
        .unwrap_or_else(|| server_conf.upstream_keepalive_pool_size.max(512));
    // Pingora defaults to ONE thread per service — on a multi-core box that
    // leaves the machine idle while nginx runs one worker per core. Scale
    // with available parallelism instead (still overridable via config).
    server_conf.threads = config.global.worker_threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    });
    // 🚰 What happens to a request that is still running when SIGTERM arrives.
    //
    // Pingora's own default gives the runtime five seconds and then stops it,
    // which truncates anything slower than that: measured on 2026-08-05, a
    // 20 MiB download over a rate-limited link arrived as 4.1 MiB, status 200,
    // no error the client could distinguish from a network fault. Every
    // rolling restart did that to every transfer in progress.
    //
    // Caddy waits for them however long they take — its log literally says
    // "eternal grace period" — so that is the default here too, expressed as
    // the largest span Pingora will accept. `grace_period` is how an operator
    // trades that for a bounded restart.
    // ⏱️ 30 seconds, not "forever". The window is an unconditional sleep, so
    // "forever" would mean a process that never exits — and Pingora's own
    // 300-second default means every restart waits five minutes with nothing
    // to drain. 30s is long enough for ordinary requests to land and short
    // enough that a rolling restart still moves.
    const DEFAULT_GRACE_SECS: u64 = 30;
    let grace_period_secs = config
        .global
        .grace_period_secs
        .unwrap_or(DEFAULT_GRACE_SECS);
    // 🕐 Which knob does what, read off pingora-core 0.8.1 `server/mod.rs:771`
    // rather than guessed — the first attempt at this guessed wrong in both
    // directions and shipped a shutdown that hung:
    //
    //   grace_period_seconds          → `thread::sleep(...)` before teardown.
    //                                   The window during which the runtimes
    //                                   are still alive. Unconditional: every
    //                                   shutdown costs exactly this.
    //   graceful_shutdown_timeout_secs → `rt.shutdown_timeout(t)` *and then*
    //                                   `thread::sleep(t)` again. A large value
    //                                   here does not extend the drain; it just
    //                                   makes the process refuse to exit.
    //
    // So the configured grace belongs in the sleep, and the teardown budget
    // stays at Pingora's own small default.
    //
    // 🚧 A bounded window is a deliberate choice, not the finished behaviour, and
    // must not be described as "graceful shutdown works". The alternative —
    // exiting as soon as the last in-flight request finishes, bounded by work
    // remaining rather than by a clock — is not expressible with the knobs the
    // transport exposes. Day 26 also measured that the sleep window does not by
    // itself keep a large download alive, so something in the service layer ends
    // the connection first. Until that is found, this bounds the damage rather
    // than fixing it.
    server_conf.grace_period_seconds = Some(grace_period_secs);
    tracing::info!(
        "🚰 Shutdown grace period: {}s{}",
        grace_period_secs,
        if config.global.grace_period_secs.is_some() {
            ""
        } else {
            " (default; set `grace_period` to change it)"
        }
    );
    tracing::info!(
        "🔗 Upstream keepalive pool size: {} connections/thread",
        server_conf.upstream_keepalive_pool_size
    );
    tracing::info!("🧵 Worker threads per service: {}", server_conf.threads);
    tracing::info!(
        "🛡️ Trusted proxy networks: {}",
        config.global.trusted_proxies.len()
    );
    {
        let required: Vec<&str> = config
            .servers
            .iter()
            .flat_map(|server| server.proxy_protocol_listen.iter())
            .map(String::as_str)
            .collect();
        tracing::info!(
            "🧭 PROXY protocol listeners: {}",
            if required.is_empty() {
                "none".to_string()
            } else {
                required.join(", ")
            }
        );
    }

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
    let server_conf_arc = server.configuration.clone();

    server.bootstrap();
    // 🩺 One Pingora-owned driver follows weak pool registrations across hot reloads.
    server.add_service(pingora::services::background::background_service(
        "Pingclair active health checks",
        pingclair_proxy::health_check::HealthCheckDriver,
    ));

    // 🔐 Initialize every certificate source below one configurable persistent store.
    let tls_store_path_str = tls_store_dir().to_string_lossy().to_string();
    let tls_store_path = std::path::Path::new(&tls_store_path_str);
    if !tls_store_path.exists() {
        std::fs::create_dir_all(tls_store_path).map_err(|error| {
            anyhow::anyhow!(
                "🔐 TLS store {tls_store_path_str} cannot be created: {error} \
                 (set PINGCLAIR_TLS_STORE to a writable, persistent directory)"
            )
        })?;
    }
    // 💾 Probe writeability before any ACME or internal-CA work: a store that
    // cannot persist certificates must fail startup with a clear message, not
    // a confusing mid-flight error later.
    let probe = tls_store_path.join(format!(".write-probe-{}", std::process::id()));
    std::fs::write(&probe, b"ok").map_err(|error| {
        anyhow::anyhow!(
            "🔐 TLS store {tls_store_path_str} is not writable: {error} \
             (set PINGCLAIR_TLS_STORE to a writable, persistent directory)"
        )
    })?;
    let _ = std::fs::remove_file(&probe);

    let mut auto_https_config = pingclair_tls::auto_https::AutoHttpsConfig::default();
    if let Some(email) = &config.global.email {
        auto_https_config.email = Some(email.clone());
    }
    if config.global.auto_https == pingclair_core::config::AutoHttpsMode::Off {
        auto_https_config.enabled = false;
    }

    // 🧰 Reuse one temporary runtime for manager initialization and eager local issuance.
    let tls_runtime = tokio::runtime::Runtime::new()
        .expect("Failed to create runtime for TLS manager initialization");
    let tls_manager = std::sync::Arc::new(tls_runtime.block_on(async {
        pingclair_tls::manager::TlsManager::new(Some(auto_https_config), tls_store_path)
            .await
            .expect("Failed to create TLS manager with persistent challenge handler")
    }));

    // 🔐 Prepare configured certificate sources before any listener can accept a handshake.
    let mut manual_certs: Vec<(String, String, String)> = Vec::new();
    for server_config in &config.servers {
        let Some(tls) = &server_config.tls else {
            continue;
        };

        if tls.internal {
            let name = server_config.name.as_deref().unwrap_or_default();
            match tls_runtime.block_on(tls_manager.enable_internal_domain(name)) {
                Ok(_) => {
                    tracing::info!("🏛️ Prepared an internal TLS certificate for {}", name);
                }
                Err(error) => {
                    anyhow::bail!(
                        "failed to prepare the internal TLS certificate for {name}: {error}"
                    );
                }
            }
        }

        let (Some(cert_path), Some(key_path)) = (&tls.cert, &tls.key) else {
            continue;
        };

        let Some(name) = server_config.name.as_deref() else {
            tracing::warn!(
                "⚠️ TLS cert/key configured on an unnamed server, skipping manual certificate load"
            );
            continue;
        };
        if name.is_empty() || name == "_" {
            tracing::warn!(
                "⚠️ Skipping manual TLS certificate for wildcard/unnamed server '{}'",
                name
            );
            continue;
        }

        // 🔐 Collected rather than loaded here. Reading them one at a time
        // meant a half-written pair could be installed on its own, and the
        // failure would surface at handshake time to a real client rather than
        // at load time to the operator. `refresh_manual_certs` reads and
        // validates the whole set, then publishes it or nothing.
        manual_certs.push((name.to_string(), cert_path.clone(), key_path.clone()));
    }

    // 🪪 `client_auth` parses and compiles, and nothing in the acceptor checks a
    // client certificate yet. Starting anyway would give an operator a site that
    // reports mutual TLS in its configuration and admits everyone — the exact
    // shape of silent failure this project treats as worse than not starting.
    //
    // The refusal is here rather than in `validate_config` on purpose: `adapt`
    // converts a Caddyfile to JSON without running anything, and upstream
    // converts these configurations happily. Refusing to *serve* is the honest
    // line, not refusing to translate.
    let mtls_sites: Vec<&str> = config
        .servers
        .iter()
        .filter(|server| {
            server
                .tls
                .as_ref()
                .is_some_and(|tls| tls.client_auth.is_some())
        })
        .map(|server| server.name.as_deref().unwrap_or("_"))
        .collect();
    if !mtls_sites.is_empty() {
        anyhow::bail!(
            "site(s) {} ask for `tls client_auth`, and no client certificate is verified yet; \
             refusing to start rather than serve a site that reports mutual TLS and admits \
             everyone",
            mtls_sites.join(", ")
        );
    }

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

    // HTTP/3 startup inputs, captured before `config.servers` is consumed:
    // - the global on/off switch (HTTPS ports only ever start H3),
    // - the domains whose certificates seed the SNI cert table,
    // - the upstream pool size + L4 blocklist kept consistent with H1/H2.
    let http3_globally_enabled = config.global.http3;
    let h3_domains: Vec<String> = config
        .servers
        .iter()
        .filter_map(|s| s.name.clone())
        .filter(|n| !n.is_empty() && n != "_" && n != "*" && !n.starts_with(':'))
        .collect();
    let h3_pool_size = config.global.upstream_keepalive_pool_size.unwrap_or(512);
    let h3_blocked_ips = config.global.blocked_ips.clone();
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
    let automatic_http_available = auto_https_mode != pingclair_core::config::AutoHttpsMode::Off
        && config.servers.iter().any(|server| server.tls.is_some())
        && can_bind_automatic_http_port(http_port);

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
            let mut proxies_guard = port_proxies.write();
            let proxy = proxies_guard.entry(addr.clone()).or_insert_with(|| {
                pingclair_proxy::server::PingclairProxy::with_tls_and_trusted_proxies(
                    tls_manager.clone(),
                    &trusted_proxies,
                    proxy_protocol_addresses.contains(&addr),
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
            let mut proxies_guard = port_proxies.write();
            let proxy = proxies_guard.entry(addr.clone()).or_insert_with(|| {
                pingclair_proxy::server::PingclairProxy::with_tls_and_trusted_proxies(
                    tls_manager.clone(),
                    &trusted_proxies,
                    proxy_protocol_addresses.contains(&addr),
                )
            });
            binding_info.entry(addr).or_default().push(format!(
                "{} (automatic HTTP)",
                companion.name.as_deref().unwrap_or("default")
            ));
            proxy.add_server(companion);
        }
    }

    // Log binding information for diagnostics
    tracing::info!("🌐 Server binding information:");
    for (addr, sites) in &binding_info {
        tracing::info!("   📍 {} -> [{}]", addr, sites.join(", "));
    }

    // 🏷️ Listen address → the name to serve when a client sends no SNI, built
    // once here. The alternative is a lookup inside BoringSSL's SNI callback,
    // which runs on every handshake and cannot get a different answer than it
    // would have got at startup.
    let default_sni_by_address: std::collections::HashMap<&str, &str> = config
        .servers
        .iter()
        .filter_map(|server| {
            let sni = server.tls.as_ref()?.default_sni.as_deref()?;
            Some((server, sni))
        })
        .flat_map(|(server, sni)| server.listen.iter().map(move |addr| (addr.as_str(), sni)))
        .collect();

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

            // 🔐 Explicit TLS configuration supports HTTPS and H3 on non-standard ports.
            let mut tls_enabled = false;
            let mut http3_enabled = false;

            if is_https {
                // 🔐 Enable dynamic certificates and advertise HTTP/2 plus HTTP/1.1 over ALPN.
                let acceptor = DynamicCertResolver::new(tls_manager.clone())
                    .with_default_sni(default_sni_by_address.get(addr.as_str()).copied());
                match TlsSettings::with_callbacks(Box::new(acceptor)) {
                    Ok(mut tls_settings) => {
                        tls_settings.enable_h2();
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
                if http3_globally_enabled {
                    https_ports.push(addr.clone());
                    http3_enabled = true;

                    if let Some(port) = addr.rsplit(':').next().and_then(|p| p.parse::<u16>().ok())
                    {
                        proxy_logic.set_alt_svc(port);
                    }
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

    // Start HTTP/3 (QUIC) servers for HTTPS ports
    if !https_ports.is_empty() {
        tracing::info!(
            "🚀 Starting HTTP/3 (quiche) servers for {} port(s)",
            https_ports.len()
        );

        // Shared SNI certificate table: populated from the TLS manager
        // (manual certs + already-issued ACME certs), then refreshed
        // periodically so renewals reach new handshakes without a restart.
        let cert_table = std::sync::Arc::new(pingclair_proxy::quic::CertTable::new());
        let table_for_task = cert_table.clone();
        let tls_for_task = tls_manager.clone();
        let proxies_for_task = port_proxies.clone();
        let domains_for_task = h3_domains.clone();
        let blocked_for_task = h3_blocked_ips.clone();

        bg_handle.spawn(async move {
            // Populate the table before serving so the first handshake can
            // already find its certificate.
            refresh_h3_cert_table(&table_for_task, &tls_for_task, &domains_for_task).await;

            for addr_str in &https_ports {
                let Ok(socket_addr) = addr_str.parse::<std::net::SocketAddr>() else {
                    tracing::error!("❌ Invalid HTTP/3 listen address: {}", addr_str);
                    continue;
                };

                let proxy = {
                    let guard = proxies_for_task.read();
                    guard.get(addr_str).map(|p| std::sync::Arc::new(p.clone()))
                };
                let Some(proxy) = proxy else {
                    tracing::error!("❌ No proxy found for HTTP/3 address {}", addr_str);
                    continue;
                };

                let server = pingclair_proxy::quic::QuicServer::new(
                    socket_addr,
                    proxy,
                    table_for_task.clone(),
                    h3_pool_size,
                    blocked_for_task.clone(),
                );

                tokio::spawn(async move {
                    if let Err(e) = server.run().await {
                        tracing::error!("HTTP/3 server on {} failed: {}", socket_addr, e);
                    }
                });
            }

            // Periodic refresh: picks up ACME issuances and renewals.
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                refresh_h3_cert_table(&table_for_task, &tls_for_task, &domains_for_task).await;
            }
        });
    }

    // 🛑 `POST /stop` notifies this; the shutdown task treats it like SIGTERM.
    let admin_shutdown = Arc::new(tokio::sync::Notify::new());
    // 🚫 Caddy disables SIGUSR1 reloads once the Admin API has changed the
    // config; this flag records that transition.
    let api_changed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // 🧭 `/load` can create listeners at runtime; the manager is handed to
    // the admin server so a document naming a new address is honored.
    let dynamic_listeners: Arc<dyn pingclair_proxy::server::DynamicListeners> =
        Arc::new(RuntimeListeners {
            port_proxies: port_proxies.clone(),
            server_conf: server_conf_arc,
            tls_manager: tls_manager.clone(),
            trusted_proxies: trusted_proxies.clone(),
            blocked_ips: h3_blocked_ips.clone(),
            proxy_protocol_addresses: proxy_protocol_addresses.clone(),
            http_port,
            https_port,
            running: RwLock::new(HashMap::new()),
            shutdowns: RwLock::new(HashMap::new()),
            dynamic_addrs: RwLock::new(HashSet::new()),
        });

    // Start Admin API if enabled
    if let Some(admin_config) = &config.admin
        && admin_config.enabled
    {
        let listen = admin_config.listen.clone();
        let admin_origins = admin_config.origins.clone();
        let admin_enforce_origin = admin_config.enforce_origin;
        let api_key = admin_config.api_key.clone();
        let proxies = port_proxies.clone();
        let shutdown_for_admin = admin_shutdown.clone();
        let autosave = tls_store_dir().join("autosave.json");
        // 🧭 The admin traversal endpoints read and write one shared config
        // document; it starts as the exact configuration that was loaded.
        let document = Arc::new(RwLock::new(
            serde_json::to_value(config.clone())
                .unwrap_or_else(|_| serde_json::Value::Object(Default::default())),
        ));
        let dynamic_listeners_for_admin = dynamic_listeners.clone();
        let api_changed_for_admin = api_changed.clone();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create admin runtime");
            rt.block_on(async {
                let addr = listen.parse().expect("Invalid admin listen address");
                let options = pingclair_api::AdminServerOptions {
                    proxies,
                    document,
                    shutdown: shutdown_for_admin,
                    autosave: Some(autosave),
                    listeners: Some(dynamic_listeners_for_admin),
                    api_changed: api_changed_for_admin,
                    api_key,
                    origins: admin_origins,
                    enforce_origin: admin_enforce_origin,
                };
                if let Err(e) = pingclair_api::run_admin_server(addr, options).await {
                    tracing::error!("Admin server error: {}", e);
                }
            });
        });
    }

    // ========================================
    // 🔔 Signal Handling for SIGUSR1 (Reload)
    // ========================================
    #[cfg(unix)]
    if !config_path.is_empty() {
        let config_path = config_path.clone();
        let port_proxies = port_proxies.clone();
        let dynamic_listeners_for_reload = dynamic_listeners.clone();
        let api_changed_for_reload = api_changed.clone();
        // 🧭 Snapshot the global settings the process started with, so a
        // reload that changes them can say so instead of silently ignoring
        // the difference.
        let original_global = config.global.clone();

        bg_handle.spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};

            // 🚦 SIGUSR1 is Caddy's reload signal; SIGHUP is deliberately
            // ignored, matching Caddy's signal table.
            // 🙈 Claiming the stream registers the handler, so the default
            // terminate-on-SIGHUP action never fires; the signal is dropped.
            let mut _hup_ignored = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("❌ Failed to create SIGHUP listener: {}", e);
                    return;
                }
            };
            let mut usr1_stream = match signal(SignalKind::user_defined1()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("❌ Failed to create SIGUSR1 listener: {}", e);
                    return;
                }
            };

            tracing::info!("📡 Reload listener active (SIGUSR1, Config: {})", config_path);

            loop {
                let signal_name = tokio::select! {
                    _ = usr1_stream.recv() => "SIGUSR1",
                };
                if api_changed_for_reload.load(std::sync::atomic::Ordering::SeqCst) {
                    tracing::warn!(
                        "🚫 SIGUSR1 reload disabled: the configuration was changed through \
                         the Admin API after startup (Caddy semantics)"
                    );
                    continue;
                }
                let reload_start = std::time::Instant::now();
                tracing::info!("🔔 Received {signal_name}, reloading configuration from: {}", config_path);
                // 🛑 Let the new configuration start its own ACME transactions
                // immediately instead of waiting on the old config's in-flight
                // issuance markers.
                tls_manager.cancel_pending_issuance().await;

                // Step 1: Validate and load new configuration
                tracing::info!("📋 Step 1/3: Validating configuration...");
                let result = if std::path::Path::new(&config_path).is_dir() {
                    pingclair_config::compile_directory(&config_path)
                } else {
                    pingclair_config::compile_file(&config_path)
                };

                match result {
                    Ok(new_config) => {
                        // 🚩 Global options (email, auto_https, trusted
                        // proxies, ports, ...) only take effect at startup.
                        // Detecting the difference here keeps a reload from
                        // looking successful while the operator's global
                        // change silently never happened.
                        if new_config.global != original_global {
                            tracing::warn!(
                                "🚫 Reloaded configuration changes global options; \
                                 global settings only take effect after a restart \
                                 (old={:?}, new={:?})",
                                original_global,
                                new_config.global
                            );
                        }
                        tracing::info!("✅ Step 1/3: Configuration validation successful");
                        tracing::info!("📋 Step 2/3: Preparing configuration update...");

                        // 🪵 Register any channel the reload introduced before
                        // the servers that reference it are published, or the
                        // first requests after a reload would resolve to no
                        // channel and their lines would go nowhere.
                        pingclair_proxy::access_log::register_channels(
                            &new_config.logging.channels,
                        );
                        pingclair_proxy::metrics::CONFIG_VERSION.inc();

                        // 🧭 Derive every bind address the same way startup
                        // does (including the automatic HTTP companion), so a
                        // hostname site updates its TLS listener and not just
                        // a phantom `:80` entry.
                        let new_config_by_port = servers_by_bind_address(&new_config);

                        // 🧭 Phase 1 — prepare. Work out what each bind
                        // address needs and prove every fallible step can
                        // succeed, touching nothing.
                        //
                        // The old loop published each port as it went, so a
                        // port that could not be bound left the earlier ones
                        // already serving the new configuration and the
                        // reload reported "partially reloaded" — a state no
                        // operator asked for and none can reason about. Now
                        // the only fallible step (binding) happens for all
                        // new addresses first, and a single failure means
                        // nothing changed at all.
                        let existing: std::collections::HashSet<String> =
                            port_proxies.read().keys().cloned().collect();
                        let mut to_update: Vec<(String, Vec<pingclair_core::config::ServerConfig>)> =
                            Vec::new();
                        let mut to_start: Vec<(String, Vec<pingclair_core::config::ServerConfig>)> =
                            Vec::new();
                        let mut rejected: Vec<String> = Vec::new();

                        for (addr, servers) in new_config_by_port {
                            if existing.contains(&addr) {
                                to_update.push((addr, servers));
                            } else {
                                match dynamic_listeners_for_reload.probe_listener(&addr) {
                                    Ok(()) => to_start.push((addr, servers)),
                                    Err(error) => rejected.push(format!("{addr}: {error}")),
                                }
                            }
                        }

                        // 🔐 Certificates are part of the configuration, so a
                        // reload must pick up a rotation on disk — before this
                        // they were read once at startup and swapping a cert
                        // needed a restart that nothing told the operator
                        // about. Collected here so a bad pair joins the same
                        // rejection set as an unbindable listener: either the
                        // whole reload lands or none of it does.
                        let mut reloaded_certs: Vec<(String, String, String)> = Vec::new();
                        for server in &new_config.servers {
                            let (Some(tls), Some(name)) =
                                (server.tls.as_ref(), server.name.as_deref())
                            else {
                                continue;
                            };
                            if let (Some(cert), Some(key)) = (&tls.cert, &tls.key)
                                && !name.is_empty()
                                && name != "_"
                            {
                                reloaded_certs.push((
                                    name.to_string(),
                                    cert.clone(),
                                    key.clone(),
                                ));
                            }
                        }
                        if let Err(problems) = tls_manager.refresh_manual_certs(&reloaded_certs) {
                            // 🛡️ The previous certificates keep serving. An
                            // operator halfway through copying a new pair sees
                            // exactly which file is wrong instead of a site
                            // that starts failing handshakes.
                            rejected.extend(
                                problems
                                    .into_iter()
                                    .map(|problem| format!("certificate: {problem}")),
                            );
                        }

                        if !rejected.is_empty() {
                            let reload_duration = reload_start.elapsed();
                            for reason in &rejected {
                                tracing::error!("❌ Reload rejected: {reason}");
                            }
                            tracing::error!(
                                "❌ Configuration reload rejected after {:?}: {} problem(s)",
                                reload_duration,
                                rejected.len()
                            );
                            tracing::error!("   💡 Previous configuration remains active, unchanged");
                            eprintln!(
                                "❌ Configuration reload rejected: {}",
                                rejected.join("; ")
                            );
                            eprintln!("   💡 Previous configuration remains active, unchanged");
                            continue;
                        }

                        // 🧭 Phase 2 — publish. Nothing below can fail, so the
                        // configuration lands whole.
                        tracing::info!(
                            "📋 Step 3/3: Applying configuration to {} port(s)...",
                            to_update.len() + to_start.len()
                        );
                        let mut success_count = 0;
                        let mut warnings: Vec<String> = Vec::new();

                        // 🔄 Updates are an ArcSwap store each, so an in-flight
                        // request sees either the old snapshot or the new one
                        // and never a mixture.
                        let mut published: std::collections::HashSet<String> =
                            std::collections::HashSet::new();
                        for (addr, servers) in to_update {
                            if let Some(proxy) = port_proxies.read().get(&addr).cloned() {
                                proxy.update_config(servers);
                                success_count += 1;
                                published.insert(addr.clone());
                                tracing::debug!("   ✓ Updated configuration for {}", addr);
                            }
                        }

                        for (addr, servers) in to_start {
                            match dynamic_listeners_for_reload.start_listener(&addr, &servers[0]) {
                                Ok(()) => {
                                    for extra in &servers[1..] {
                                        if let Some(proxy) = port_proxies.read().get(&addr) {
                                            proxy.add_server(extra.clone());
                                        }
                                    }
                                    success_count += 1;
                                    published.insert(addr.clone());
                                }
                                // 🚩 The probe passed and the real bind still
                                // failed: something else took the port in the
                                // gap. Rare, and reported rather than hidden.
                                Err(error) => warnings.push(format!("{addr}: {error}")),
                            }
                        }

                        // 🧹 Addresses the new configuration no longer names.
                        // Without this the old configuration kept serving on
                        // them forever — a site deleted from the Pingclairfile
                        // stayed reachable until the next restart, which is the
                        // most dangerous direction for this bug to fail in.
                        for stale in existing.difference(&published) {
                            if dynamic_listeners_for_reload.is_dynamic(stale) {
                                tracing::info!("🧹 Stopping listener {stale}: no longer configured");
                                dynamic_listeners_for_reload.stop_listener(stale);
                            } else {
                                // 📌 A listener created at startup cannot be
                                // unbound without a restart, so say so rather
                                // than leaving the operator to discover that
                                // the deleted site still answers.
                                warnings.push(format!(
                                    "{stale}: no longer in the configuration, but it was bound at \
                                     startup and needs a restart to release"
                                ));
                            }
                        }

                        let reload_duration = reload_start.elapsed();

                        if warnings.is_empty() {
                            tracing::info!("✅ Configuration reload completed successfully in {:?}", reload_duration);
                            tracing::info!("   📊 {} server(s) updated", success_count);
                            println!("✅ Configuration reloaded successfully ({success_count} servers updated in {reload_duration:?})");
                        } else {
                            for warning in &warnings {
                                tracing::warn!("⚠️ Reload listener warning: {warning}");
                            }
                            tracing::warn!("⚠️ Configuration reload completed with warnings in {:?}", reload_duration);
                            tracing::warn!("   📊 {} server(s) updated, {} warning(s)", success_count, warnings.len());
                            println!("⚠️ Configuration partially reloaded ({success_count} servers updated, {} warnings in {reload_duration:?})", warnings.len());
                        }
                    }
                    Err(e) => {
                        let reload_duration = reload_start.elapsed();
                        tracing::error!("❌ Configuration reload failed after {:?}: {}", reload_duration, e);
                        tracing::error!("   💡 Previous configuration remains active");
                        eprintln!("❌ Configuration reload failed: {e}");
                        eprintln!("   💡 Previous configuration remains active");
                    }
                }
            }
        });
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
    // 🛑 Signal Handling for Shutdown (SIGINT/SIGTERM)
    // ========================================
    // Pingora's `run_forever()` blocks indefinitely, so without explicit
    // handlers the process only dies on SIGKILL. Install shutdown handlers
    // on the background runtime before entering it.
    let shutdown_for_task = admin_shutdown.clone();
    bg_handle.spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};

            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("❌ Failed to create SIGTERM listener: {}", e);
                    // Fall back to SIGINT-only handling.
                    let _ = tokio::signal::ctrl_c().await;
                    tracing::info!("🛑 Received SIGINT, shutting down");
                    std::process::exit(0);
                }
            };
            let mut sigquit = match signal(SignalKind::quit()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("❌ Failed to create SIGQUIT listener: {}", e);
                    return;
                }
            };

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("🛑 Received SIGINT, shutting down");
                    // 🚰 Stop being sent new traffic before the process starts
                    // going away. A load balancer polling /ready gets a 503 on
                    // its next check and routes around, so the connections
                    // still in flight are the last ones this instance has to
                    // finish rather than the first of a fresh wave.
                    pingclair_proxy::readiness::mark_draining();
                    notify_systemd_stopping();
                }
                _ = sigterm.recv() => {
                    tracing::info!("🛑 Received SIGTERM, shutting down");
                    pingclair_proxy::readiness::mark_draining();
                    notify_systemd_stopping();
                }
                _ = sigquit.recv() => {
                    // 🏃 Caddy exits immediately on SIGQUIT (code 2) after
                    // cleaning storage locks; Pingora has no equivalent lock
                    // step, so a prompt exit is the faithful behavior.
                    tracing::info!("🏃 Received SIGQUIT, forced exit");
                    std::process::exit(2);
                }
                _ = shutdown_for_task.notified() => {
                    tracing::info!("🛑 Admin API requested shutdown");
                }
            }
        }

        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("🛑 Received Ctrl-C, shutting down");
        }

        std::process::exit(0);
    });

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

    server.run_forever();
}
