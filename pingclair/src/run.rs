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

use crate::certs::{
    DynamicCertResolver, eager_issuance_domains, public_issuance_domains, refresh_h3_cert_table,
};
use crate::listen::{
    automatic_http_companion, can_bind_automatic_http_port, explicit_http_names,
    normalize_listen_addr, reserve_private_listener_address, server_requires_tls,
};
use crate::paths::tls_store_dir;
use crate::runtime_listeners::{
    RuntimeListeners, RuntimePublisherInputs, prepare_listener_policies,
};
use crate::systemd::{notify_systemd_ready, notify_systemd_stopping};
use parking_lot::RwLock;
use pingclair_proxy::client_auth::PublishedListenerPolicy;
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
    // 🔄 How early to renew, as a fraction of each certificate's own lifetime.
    if let Some(ratio) = config.global.renewal_window_ratio {
        auto_https_config.renewal_window_ratio = ratio;
    }
    // 🔗 Said once, at startup, rather than silently: the ACME client this
    // build uses downloads whichever chain the authority offers first and has
    // no way to ask for another (`instant-acme` 0.8.5, verified 2026-08-12).
    // The certificate still works; the chain simply is not the one requested.
    if config.global.preferred_chains.is_some() {
        tracing::warn!(
            "🔗 `preferred_chains` is recorded but not applied: this build's ACME \
             client cannot request an alternate issuer chain"
        );
    }

    // 🧰 Reuse one temporary runtime for manager initialization and eager local issuance.
    let tls_runtime = tokio::runtime::Runtime::new()
        .expect("Failed to create runtime for TLS manager initialization");
    let tls_manager = std::sync::Arc::new(tls_runtime.block_on(async {
        pingclair_tls::manager::TlsManager::new(Some(auto_https_config), tls_store_path)
            .await
            .expect("Failed to create TLS manager with persistent challenge handler")
    }));

    // 🌐 Publish the names a public CA may be asked about, before anything can
    // accept a handshake.
    //
    // The server name in a ClientHello is chosen by whoever dialled the
    // socket, and the resolver used to hand an unrecognised one straight to a
    // public CA. Setting this first means the window where that is possible is
    // not "until the configuration is read" but "never".
    let authorised_issuance = public_issuance_domains(&config);
    tls_manager.set_public_issuance_domains(&authorised_issuance);
    tracing::info!(
        "🌐 Automatic public certificates authorised for {} hostname(s)",
        authorised_issuance.len()
    );

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

    // 🏛️ `pki` and `acme_server` parse, validate and serialise; this build
    // never acts as a certificate authority. A site carrying an ACME server
    // would answer other clients' RFC 8555 requests and issue nothing, which
    // is a worse answer than saying so — those clients would retry against a
    // server that looks alive.
    //
    // 🚫 Refused here rather than in `validate_config` for the same reason as
    // `client_auth` and DNS-01: `adapt` translating a configuration is honest,
    // serving one it cannot honour is not.
    let acme_server_sites: Vec<&str> = config
        .servers
        .iter()
        .filter(|server| {
            server.routes.iter().any(|route| {
                matches!(
                    route.handler,
                    pingclair_core::config::HandlerConfig::AcmeServer(_)
                )
            })
        })
        .map(|server| server.name.as_deref().unwrap_or("_"))
        .collect();
    if !acme_server_sites.is_empty() {
        anyhow::bail!(
            "site(s) {} configure `acme_server`, and Pingclair does not act as a certificate \
             authority issuing to other clients; refusing to start rather than answer ACME \
             requests that can never produce a certificate. The `pki` block itself is accepted \
             and unused",
            acme_server_sites.join(", ")
        );
    }

    // 📡 DNS-01: build one provider per site that asked for it, and publish
    // which challenge proves which name. Everything expensive — the API client,
    // the token, the propagation policy — is resolved here so an issuance or a
    // renewal never has to read the configuration again.
    //
    // 🚫 A provider name we do not implement is refused by name rather than
    // ignored. Ignoring it would leave the site on HTTP-01, which cannot prove
    // control of a wildcard, and the operator would find out at renewal from
    // an error that never mentions the option they set.
    {
        let mut policy = pingclair_tls::acme::ChallengePolicy::uniform(
            pingclair_tls::acme::ChallengeSolver::http01(tls_manager.challenge_handler()),
        );
        for server_config in &config.servers {
            let Some(challenge) = server_config
                .tls
                .as_ref()
                .and_then(|tls| tls.dns_challenge.as_ref())
            else {
                continue;
            };
            let provider_config = challenge
                .provider
                .as_ref()
                .expect("validate_config refuses a DNS challenge with no provider");

            let names: Vec<&str> = if server_config.names.is_empty() {
                server_config.name.as_deref().into_iter().collect()
            } else {
                server_config.names.iter().map(String::as_str).collect()
            };

            let provider = build_dns_provider(provider_config).map_err(|problem| {
                anyhow::anyhow!(
                    "site {} asks for the DNS-01 challenge, and its provider cannot be used: \
                     {problem}",
                    names.first().copied().unwrap_or("_")
                )
            })?;

            let propagation = pingclair_tls::dns01::PropagationPolicy {
                delay: std::time::Duration::from_secs(
                    challenge.propagation_delay_secs.unwrap_or(0),
                ),
                timeout: std::time::Duration::from_secs(
                    challenge.propagation_timeout_secs.unwrap_or(120),
                ),
                resolvers: challenge.resolvers.clone(),
                ttl_secs: challenge.ttl_secs.unwrap_or(60),
            };
            let handler: Arc<dyn pingclair_tls::acme::ChallengeHandler> = Arc::new(
                pingclair_tls::dns01::Dns01Handler::new(provider, propagation),
            );
            for name in names {
                policy = policy.with_override(
                    name,
                    pingclair_tls::acme::ChallengeSolver::dns01(handler.clone()),
                );
                tracing::info!(
                    "📡 {} will be proved with DNS-01 through `{}`",
                    name,
                    provider_config.name
                );
            }
        }
        tls_manager.set_challenge_policy(policy);
    }

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
                    Arc::new(PublishedListenerPolicy::new(Arc::clone(
                        &policy.client_auth,
                    ))),
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
                match TlsSettings::with_callbacks(Box::new(acceptor)) {
                    Ok(mut tls_settings) => {
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

    // 📜 One certificate table is retained by the runtime publisher so a
    // manual rotation reaches QUIC in the same transaction as TCP TLS.
    let h3_cert_table =
        (!https_ports.is_empty()).then(|| Arc::new(pingclair_proxy::quic::CertTable::new()));

    // Start HTTP/3 (QUIC) servers for HTTPS ports
    if let Some(cert_table) = h3_cert_table.clone() {
        tracing::info!(
            "🚀 Starting HTTP/3 (quiche) servers for {} port(s)",
            https_ports.len()
        );

        // Shared SNI certificate table: populated from the TLS manager
        // (manual certs + already-issued ACME certs), then refreshed
        // periodically so renewals reach new handshakes without a restart.
        // 🔐 Seed synchronously before Admin can publish a rotation; an
        // asynchronous startup read could otherwise overwrite the first new
        // manual generation after `/load` had already reported success.
        tls_runtime.block_on(refresh_h3_cert_table(
            &cert_table,
            &tls_manager,
            &h3_domains,
        ));
        let table_for_task = cert_table.clone();
        let tls_for_task = tls_manager.clone();
        let proxies_for_task = port_proxies.clone();
        let periodic_domains_for_task = h3_periodic_domains.clone();
        let blocked_for_task = h3_blocked_ips.clone();
        bg_handle.spawn(async move {
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
        let autosave = tls_store_dir().join("autosave.json");
        // 🧭 The admin traversal endpoints read and write one shared config
        // document; it starts as the exact configuration that was loaded.
        let document = active_document.clone();
        let publisher_for_admin = config_publisher.clone();
        let policy_for_admin = admin_policy.clone();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create admin runtime");
            rt.block_on(async {
                let addr = listen.parse().expect("Invalid admin listen address");
                let options = pingclair_api::AdminServerOptions {
                    document,
                    shutdown: shutdown_for_admin,
                    autosave: Some(autosave),
                    publisher: Some(publisher_for_admin),
                    policy: policy_for_admin,
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
        let publisher_for_reload = config_publisher.clone();
        let api_changed_for_reload = api_changed.clone();

        bg_handle.spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};

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

            tracing::info!(
                "📡 Reload listener active (SIGUSR1, Config: {})",
                config_path
            );

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
                tracing::info!(
                    "🔔 Received {signal_name}, reloading configuration from: {}",
                    config_path
                );
                // Step 1: Validate and load new configuration
                tracing::info!("📋 Step 1/3: Validating configuration...");
                let result = if std::path::Path::new(&config_path).is_dir() {
                    pingclair_config::compile_directory(&config_path)
                } else {
                    pingclair_config::compile_file(&config_path)
                };

                match result {
                    Ok(new_config) => {
                        tracing::info!("✅ Step 1/3: Configuration validation successful");
                        tracing::info!("📋 Step 2/3: Preparing configuration update...");
                        tracing::info!("📋 Step 3/3: Publishing prepared configuration...");
                        match publisher_for_reload.publish_config(&new_config, None) {
                            Ok(success_count) => {
                                let reload_duration = reload_start.elapsed();
                                tracing::info!(
                                    "✅ Configuration reload completed successfully in {:?}",
                                    reload_duration
                                );
                                tracing::info!("   📊 {} listener(s) updated", success_count);
                                println!(
                                    "✅ Configuration reloaded successfully ({success_count} \
                                     listeners updated in {reload_duration:?})"
                                );
                            }
                            Err(error) => {
                                let reload_duration = reload_start.elapsed();
                                tracing::error!(
                                    kind = ?error.kind,
                                    "❌ Configuration reload rejected after {:?}: {}",
                                    reload_duration,
                                    error
                                );
                                tracing::error!(
                                    "   💡 Previous configuration remains active, unchanged"
                                );
                                eprintln!("❌ Configuration reload rejected: {error}");
                                eprintln!("   💡 Previous configuration remains active, unchanged");
                            }
                        }
                    }
                    Err(e) => {
                        let reload_duration = reload_start.elapsed();
                        tracing::error!(
                            "❌ Configuration reload failed after {:?}: {}",
                            reload_duration,
                            e
                        );
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

/// 📡 Builds the DNS provider a site named, or says why it cannot be used.
///
/// 🚫 One provider is implemented. Every other name upstream defines is a real
/// module there and nothing here, so the refusal names what is available rather
/// than calling the word unknown — an operator told `route53` is unrecognised
/// would go looking for the right spelling of something that does not exist.
fn build_dns_provider(
    config: &pingclair_core::config::DnsProviderConfig,
) -> anyhow::Result<Arc<dyn pingclair_tls::dns01::DnsProvider>> {
    match config.name.as_str() {
        "cloudflare" => {
            let token = config.arguments.first().ok_or_else(|| {
                anyhow::anyhow!(
                    "the cloudflare provider needs an API token: `dns cloudflare <token>`"
                )
            })?;
            let provider =
                pingclair_tls::dns01::cloudflare::CloudflareProvider::new(token.clone())?;
            Ok(Arc::new(provider))
        }
        other => anyhow::bail!(
            "DNS provider `{other}` is not implemented; this build ships `cloudflare` only"
        ),
    }
}
