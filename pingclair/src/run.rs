// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚀 Everything between a compiled configuration and a serving process.
//!
//! `run_server` is one sequence with an order that matters: build the Pingora
//! server, prepare every certificate source, place sites on addresses, bind
//! and register listeners, start HTTP/3, start the Admin API, install signal
//! handlers, and only then announce readiness. Several of those steps are
//! ordering constraints rather than steps — announcing readiness before the
//! listeners exist is what makes a rolling deploy drop requests, and it is a
//! one-line mistake to make.
//!
//! 🧭 So the order stays here, readable top to bottom, and each phase's body
//! lives in the submodule that owns it:
//!
//! - `server_conf` — the Pingora knobs this process runs with.
//! - `certificates` — the TLS store, the manager, internal and manual
//!   certificates, and which ACME challenge proves which name.
//! - `sites` — which site answers on which address.
//! - `listeners` — bind-probing, TLS, the HTTP/3 UDP socket and the
//!   PROXY-protocol ingress for each address.
//! - `http3` — QUIC servers over the sockets `listeners` bound.
//! - `admin` — the Admin API.
//! - `reload` — the SIGUSR1 reload listener.
//!
//! 🛑 Shutdown lives in `crate::shutdown` and the descriptor check in
//! `crate::fd_budget`, because neither is only a startup concern.

use crate::certs::{eager_issuance_domains, h3_excluded_domains};
use crate::listen::can_bind_automatic_http_port;
use crate::runtime_listeners::{
    RuntimeListeners, RuntimePublisherInputs, prepare_listener_policies,
};
use crate::systemd::notify_systemd_ready;
use parking_lot::RwLock;
use pingclair_proxy::client_auth::PublishedListenerPolicy;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

mod admin;
mod certificates;
mod http3;
mod listeners;
#[cfg(unix)]
mod reload;
mod server_conf;
mod sites;

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
        // 🔐 The mode is named, not just "enabled": `ignore_loaded_certs`
        // changes which sites reach a certificate authority, so an operator
        // reading the startup log has to be able to tell it apart from the
        // default without diffing the config they just loaded.
        match config.global.auto_https {
            pingclair_core::config::AutoHttpsMode::IgnoreLoadedCerts => {
                tracing::info!("🔐 Auto HTTPS: enabled (ignore_loaded_certs)");
            }
            pingclair_core::config::AutoHttpsMode::DisableRedirects => {
                tracing::info!("🔐 Auto HTTPS: enabled (disable_redirects)");
            }
            _ => tracing::info!("🔐 Auto HTTPS: enabled"),
        }
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

    // 📍 Place every site on its addresses before anything is bound; see
    // `sites`.
    let sites::SiteGroups {
        port_proxies,
        tls_listeners,
    } = sites::group_by_address(
        &config,
        &listener_security_by_address,
        automatic_http_available,
        &tls_manager,
        &trusted_proxies,
        &proxy_protocol_addresses,
    )?;
    let port_proxies = Arc::new(RwLock::new(port_proxies));

    // 🛡️ Bind-probe and register every listener; see `listeners`.
    let listeners::BoundListeners {
        https_ports,
        private_listener_reservations,
    } = listeners::register(
        &mut server,
        listeners::ListenerInputs {
            port_proxies: &port_proxies,
            tls_listeners: &tls_listeners,
            proxy_protocol_addresses: &proxy_protocol_addresses,
            prepared_listener_policies: &prepared_listener_policies,
            tls_manager: &tls_manager,
            proxy_protocol_networks: &proxy_protocol_networks,
            blocked_client_networks: &blocked_client_networks,
            http3_globally_enabled,
            h3_excluded_domains: &h3_excluded_domains,
            bg_handle: &bg_handle,
        },
    )?;

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
        http3::H3Sockets {
            ports: https_ports,
            blocked_networks: &blocked_client_networks,
        },
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

    // 🔧 Admin API, bound now so a taken port stops startup; see `admin`.
    admin::start(
        &config,
        admin::AdminShared {
            document: active_document.clone(),
            shutdown: admin_shutdown.clone(),
            publisher: config_publisher.clone(),
            policy: admin_policy.clone(),
        },
    )?;

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
