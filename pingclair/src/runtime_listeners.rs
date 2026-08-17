// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔐 Prepared listener policy and the runtime configuration publisher.
//!
//! Startup, Admin `/load`, and signal reload used to derive different pieces
//! of listener policy. That made a successful reload weaker than startup: the
//! route changed while client authentication, H3, resumption, or Admin access
//! stayed behind. This module owns the common preparation step and the only
//! post-start publication path.
//!
//! Listener topology is deliberately restart-required for now. Pingora cannot
//! add a service after `run_forever`, and the old side accept loop created only
//! TCP/H1/H2. Reporting success for that listener meant H3 was absent and TLS
//! lacked the startup mTLS safeguards. Refusing is the safe, honest answer
//! until all transports can be constructed and rolled back as one unit.

use crate::listen::{normalize_listen_addr, server_requires_tls, servers_by_bind_address};
use parking_lot::{Mutex, RwLock};
use pingclair_api::{AdminPolicy, PreparedAdminPolicy};
use pingclair_core::config::{DnsChallengeConfig, PingclairConfig, ResourceLimitsConfig};
use pingclair_proxy::client_auth::{ClientAuthTable, CompiledClientAuth, PublishedListenerPolicy};
use pingclair_proxy::server::{ConfigApplyError, ConfigPublisher, PingclairProxy};
use pingclair_tls::manager::{PreparedManualCerts, TlsManager};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// 🧱 Listener limits captured by Pingora or the H3 transport at construction.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CapturedListenerLimits {
    header_timeout_ms: Option<u64>,
    idle_timeout_ms: Option<u64>,
    long_idle_timeout_ms: Option<u64>,
    max_header_count: Option<usize>,
    max_header_bytes: Option<usize>,
    max_connections: Option<usize>,
}

impl From<&ResourceLimitsConfig> for CapturedListenerLimits {
    fn from(limits: &ResourceLimitsConfig) -> Self {
        Self {
            header_timeout_ms: limits.header_timeout_ms,
            idle_timeout_ms: limits.idle_timeout_ms,
            long_idle_timeout_ms: limits.long_connections.idle_timeout_ms,
            max_header_count: limits.max_header_count,
            max_header_bytes: limits.max_header_bytes,
            max_connections: limits.max_connections,
        }
    }
}

/// 🔐 TLS choices whose machinery is created only during process startup.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StartupTlsPolicy {
    automatic: bool,
    internal: bool,
    manual_cert: Option<String>,
    manual_key: Option<String>,
    acme_email: Option<String>,
    http3: bool,
    dns_challenge: Option<DnsChallengeConfig>,
}

/// 🏗️ Everything one concrete listen address needs, prepared without publishing.
pub(crate) struct PreparedListenerPolicy {
    /// 🧭 Complete whole-document host set for this listener.
    pub(crate) servers: Vec<pingclair_core::config::ServerConfig>,
    /// 🔐 Whether this socket was constructed as TLS rather than plaintext.
    pub(crate) is_https: bool,
    /// 🏷️ Certificate name used when ClientHello carries no SNI.
    pub(crate) default_sni: Option<String>,
    /// 🪪 Parsed trust stores and SNI policy shared by TCP and QUIC.
    pub(crate) client_auth: Arc<ClientAuthTable>,
    proxy_protocol: bool,
    tls_names: HashSet<String>,
    startup_tls: HashMap<String, StartupTlsPolicy>,
    captured_limits: CapturedListenerLimits,
}

impl PreparedListenerPolicy {
    /// 🧪 Compiles one listener's trust material and immutable socket policy.
    fn prepare(
        address: &str,
        servers: Vec<pingclair_core::config::ServerConfig>,
        http_port: u16,
        https_port: u16,
    ) -> Result<Self, ConfigApplyError> {
        let tls_answers: HashSet<bool> = servers
            .iter()
            .map(|server| server_requires_tls(server, address, http_port, https_port))
            .collect();
        if tls_answers.len() > 1 {
            return Err(ConfigApplyError::invalid(format!(
                "listener {address} mixes plaintext and TLS sites"
            )));
        }
        let is_https = tls_answers.into_iter().next().unwrap_or(false);

        let default_sni_values: HashSet<String> = servers
            .iter()
            .filter_map(|server| server.tls.as_ref()?.default_sni.clone())
            .collect();
        if default_sni_values.len() > 1 {
            return Err(ConfigApplyError::invalid(format!(
                "listener {address} declares conflicting default_sni values"
            )));
        }
        let default_sni = default_sni_values.into_iter().next();

        let mut client_auth = ClientAuthTable::default();
        let mut tls_names = HashSet::new();
        let mut startup_tls = HashMap::new();
        for server in &servers {
            let names: Vec<&str> = if server.names.is_empty() {
                server.name.as_deref().into_iter().collect()
            } else {
                server.names.iter().map(String::as_str).collect()
            };
            if is_https {
                for name in &names {
                    if !name.is_empty() && *name != "_" && *name != "*" && !name.starts_with(':') {
                        tls_names.insert((*name).to_ascii_lowercase());
                    }
                }
                let tls = server.tls.as_ref();
                let startup = StartupTlsPolicy {
                    automatic: tls.is_some_and(|tls| tls.auto),
                    internal: tls.is_some_and(|tls| tls.internal),
                    manual_cert: tls.and_then(|tls| tls.cert.clone()),
                    manual_key: tls.and_then(|tls| tls.key.clone()),
                    acme_email: tls.and_then(|tls| tls.acme_email.clone()),
                    http3: tls.is_some_and(|tls| tls.http3),
                    dns_challenge: tls.and_then(|tls| tls.dns_challenge.clone()),
                };
                for name in &names {
                    if !name.is_empty() {
                        startup_tls.insert((*name).to_ascii_lowercase(), startup.clone());
                    }
                }
            }

            let Some(config) = server.tls.as_ref().and_then(|tls| tls.client_auth.as_ref()) else {
                continue;
            };
            let compiled = Arc::new(CompiledClientAuth::compile(config).map_err(|problem| {
                ConfigApplyError::invalid(format!(
                    "site {} asks for `tls client_auth` that cannot be honoured: {problem}",
                    names.first().copied().unwrap_or("_")
                ))
            })?);
            client_auth.insert(&names, compiled);
        }

        let proxy_protocol = servers.iter().any(|server| {
            server
                .proxy_protocol_listen
                .iter()
                .any(|declared| normalize_listen_addr(declared) == address)
        });
        let limits = PingclairProxy::listener_limits_for_servers(&servers);
        Ok(Self {
            servers,
            is_https,
            default_sni,
            client_auth: Arc::new(client_auth),
            proxy_protocol,
            tls_names,
            startup_tls,
            captured_limits: CapturedListenerLimits::from(&limits),
        })
    }
}

/// 🏗️ Prepares every concrete listener exactly as startup derives it.
pub(crate) fn prepare_listener_policies(
    config: &PingclairConfig,
    automatic_http_available: bool,
) -> Result<HashMap<String, PreparedListenerPolicy>, ConfigApplyError> {
    servers_by_bind_address(config, automatic_http_available)
        .into_iter()
        .map(|(address, servers)| {
            PreparedListenerPolicy::prepare(
                &address,
                servers,
                config.global.http_port,
                config.global.https_port,
            )
            .map(|policy| (address, policy))
        })
        .collect()
}

struct ActiveRuntimeConfig {
    config: PingclairConfig,
    listeners: HashMap<String, PreparedListenerPolicy>,
}

/// 📣 Serialises and publishes every post-start configuration transaction.
pub(crate) struct RuntimeListeners {
    pub(crate) port_proxies: Arc<RwLock<HashMap<String, PingclairProxy>>>,
    pub(crate) tls_manager: Arc<TlsManager>,
    pub(crate) h3_cert_table: Option<Arc<pingclair_proxy::quic::CertTable>>,
    pub(crate) admin_policy: Arc<AdminPolicy>,
    pub(crate) document: Arc<RwLock<Value>>,
    pub(crate) listener_policies: HashMap<String, Arc<PublishedListenerPolicy>>,
    pub(crate) automatic_http_available: bool,
    pub(crate) api_changed: Arc<AtomicBool>,
    current: RwLock<ActiveRuntimeConfig>,
    publication: Mutex<()>,
}

/// 🧩 Shared runtime handles captured by the configuration publisher.
pub(crate) struct RuntimePublisherInputs {
    pub(crate) port_proxies: Arc<RwLock<HashMap<String, PingclairProxy>>>,
    pub(crate) tls_manager: Arc<TlsManager>,
    pub(crate) h3_cert_table: Option<Arc<pingclair_proxy::quic::CertTable>>,
    pub(crate) admin_policy: Arc<AdminPolicy>,
    pub(crate) document: Arc<RwLock<Value>>,
    pub(crate) listener_policies: HashMap<String, Arc<PublishedListenerPolicy>>,
    pub(crate) automatic_http_available: bool,
    pub(crate) api_changed: Arc<AtomicBool>,
}

impl RuntimeListeners {
    /// 🏗️ Captures the startup generation that later reloads must be compatible with.
    pub(crate) fn new(
        inputs: RuntimePublisherInputs,
        config: PingclairConfig,
        prepared: HashMap<String, PreparedListenerPolicy>,
    ) -> Self {
        Self {
            port_proxies: inputs.port_proxies,
            tls_manager: inputs.tls_manager,
            h3_cert_table: inputs.h3_cert_table,
            admin_policy: inputs.admin_policy,
            document: inputs.document,
            listener_policies: inputs.listener_policies,
            automatic_http_available: inputs.automatic_http_available,
            api_changed: inputs.api_changed,
            current: RwLock::new(ActiveRuntimeConfig {
                config,
                listeners: prepared,
            }),
            publication: Mutex::new(()),
        }
    }

    fn prepare_admin(
        &self,
        config: &PingclairConfig,
        expected_admin_revision: Option<u64>,
    ) -> Result<PreparedAdminPolicy, ConfigApplyError> {
        if let Some(expected) = expected_admin_revision
            && self.admin_policy.revision() != expected
        {
            return Err(ConfigApplyError::stale_authorization(
                "the Admin access policy changed; authenticate again before retrying",
            ));
        }
        self.admin_policy.prepare(config.admin.as_ref())
    }

    fn ensure_hot_compatible(
        &self,
        current: &ActiveRuntimeConfig,
        next_config: &PingclairConfig,
        next: &HashMap<String, PreparedListenerPolicy>,
    ) -> Result<(), ConfigApplyError> {
        if next_config.global != current.config.global {
            return Err(ConfigApplyError::restart_required(
                "global options changed; restart Pingclair so every process-wide policy is rebuilt",
            ));
        }

        let current_addresses: HashSet<&str> =
            current.listeners.keys().map(String::as_str).collect();
        let next_addresses: HashSet<&str> = next.keys().map(String::as_str).collect();
        if current_addresses != next_addresses {
            let added: Vec<&str> = next_addresses
                .difference(&current_addresses)
                .copied()
                .collect();
            let removed: Vec<&str> = current_addresses
                .difference(&next_addresses)
                .copied()
                .collect();
            return Err(ConfigApplyError::restart_required(format!(
                "listener topology changed (added: {added:?}, removed: {removed:?}); restart \
                 Pingclair to rebuild H1, H2, H3, and TLS together"
            )));
        }

        for (address, next_policy) in next {
            let current_policy = &current.listeners[address];
            if next_policy.is_https != current_policy.is_https {
                return Err(ConfigApplyError::restart_required(format!(
                    "listener {address} changes between plaintext and TLS"
                )));
            }
            if next_policy.default_sni != current_policy.default_sni {
                return Err(ConfigApplyError::restart_required(format!(
                    "listener {address} changes default_sni"
                )));
            }
            if next_policy.proxy_protocol != current_policy.proxy_protocol {
                return Err(ConfigApplyError::restart_required(format!(
                    "listener {address} changes PROXY protocol policy"
                )));
            }
            if next_policy.captured_limits != current_policy.captured_limits {
                return Err(ConfigApplyError::restart_required(format!(
                    "listener {address} changes limits captured by the transport"
                )));
            }
            if !next_policy.tls_names.is_subset(&current_policy.tls_names) {
                return Err(ConfigApplyError::restart_required(format!(
                    "listener {address} adds a TLS hostname; certificate and H3 domain topology \
                     are created at startup"
                )));
            }
            for (name, next_tls) in &next_policy.startup_tls {
                if let Some(current_tls) = current_policy.startup_tls.get(name)
                    && next_tls != current_tls
                {
                    return Err(ConfigApplyError::restart_required(format!(
                        "site {name} changes TLS automation, manual certificate source, or HTTP/3 policy"
                    )));
                }
            }

            let published = &self.listener_policies[address];
            if !next_policy.client_auth.is_empty() && !published.client_auth_reload_capable() {
                return Err(ConfigApplyError::restart_required(format!(
                    "listener {address} enables client_auth after its TLS context issued \
                     resumable sessions"
                )));
            }
        }
        Ok(())
    }

    fn prepare_manual_certs(
        &self,
        config: &PingclairConfig,
    ) -> Result<PreparedManualCerts, ConfigApplyError> {
        let mut entries = Vec::new();
        for server in &config.servers {
            let (Some(tls), Some(name)) = (server.tls.as_ref(), server.name.as_deref()) else {
                continue;
            };
            if let (Some(cert), Some(key)) = (&tls.cert, &tls.key)
                && !name.is_empty()
                && name != "_"
            {
                entries.push((name.to_string(), cert.clone(), key.clone()));
            }
        }
        self.tls_manager
            .prepare_manual_certs(&entries)
            .map_err(|problems| ConfigApplyError::invalid(problems.join("; ")))
    }
}

/// 🚧 Reopens every listener even if a debug build unwinds during publication.
struct PublicationGate<'a> {
    policies: Vec<&'a PublishedListenerPolicy>,
    admin_policy: &'a AdminPolicy,
}

impl<'a> PublicationGate<'a> {
    fn close(
        policies: impl Iterator<Item = &'a Arc<PublishedListenerPolicy>>,
        admin_policy: &'a AdminPolicy,
    ) -> Self {
        let policies: Vec<&PublishedListenerPolicy> = policies.map(Arc::as_ref).collect();
        admin_policy.begin_publish();
        for policy in &policies {
            policy.begin_publish();
        }
        Self {
            policies,
            admin_policy,
        }
    }
}

impl Drop for PublicationGate<'_> {
    fn drop(&mut self) {
        for policy in &self.policies {
            policy.finish_publish();
        }
        self.admin_policy.finish_publish();
    }
}

impl ConfigPublisher for RuntimeListeners {
    fn publish_config(
        &self,
        config: &PingclairConfig,
        expected_admin_revision: Option<u64>,
    ) -> Result<usize, ConfigApplyError> {
        let _publication = self.publication.lock();
        if expected_admin_revision.is_none() && self.api_changed.load(Ordering::SeqCst) {
            return Err(ConfigApplyError::unavailable(
                "SIGUSR1 reload is disabled because the Admin API changed the active configuration",
            ));
        }
        pingclair_config::compiler::validate_config(config)
            .map_err(|error| ConfigApplyError::invalid(error.to_string()))?;

        let prepared_admin = self.prepare_admin(config, expected_admin_revision)?;
        let next = prepare_listener_policies(config, self.automatic_http_available)?;
        let current = self.current.read();
        self.ensure_hot_compatible(&current, config, &next)?;
        let prepared_manual_certs = self.prepare_manual_certs(config)?;
        let previous_manual_names: Vec<String> = current
            .config
            .servers
            .iter()
            .filter_map(|server| {
                let tls = server.tls.as_ref()?;
                (tls.cert.is_some() && tls.key.is_some())
                    .then(|| server.name.clone())
                    .flatten()
            })
            .filter(|name| !name.is_empty() && name != "_")
            .collect();
        let prepared_h3_certs = self
            .h3_cert_table
            .as_ref()
            .map(|table| {
                table.prepare_manual_update(
                    previous_manual_names.iter().map(String::as_str),
                    prepared_manual_certs.entries(),
                )
            })
            .transpose()
            .map_err(|error| ConfigApplyError::invalid(error.to_string()))?;
        let prepared_document = serde_json::to_value(config)
            .map_err(|error| ConfigApplyError::invalid(error.to_string()))?;

        let targets = {
            let proxies = self.port_proxies.read();
            let mut targets = Vec::with_capacity(next.len());
            for (address, policy) in &next {
                let Some(proxy) = proxies.get(address).cloned() else {
                    return Err(ConfigApplyError {
                        kind: pingclair_proxy::server::ConfigApplyErrorKind::Unavailable,
                        message: format!(
                            "listener {address} disappeared before the prepared transaction could publish"
                        ),
                    });
                };
                targets.push((address.clone(), policy.servers.clone(), proxy));
            }
            targets
        };
        drop(current);

        // 🚧 No fallible work remains below this gate. Requests and new
        // handshakes are refused until routes, TLS, and Admin access all name
        // the same generation.
        let gate = PublicationGate::close(self.listener_policies.values(), &self.admin_policy);
        if let (Some(table), Some(prepared)) = (&self.h3_cert_table, prepared_h3_certs) {
            table.publish_manual_update(prepared);
        }
        self.tls_manager.publish_manual_certs(prepared_manual_certs);
        // 🌐 Republish the names a public CA may be asked about. Without this a
        // reload that adds a `tls auto` site would fail closed forever — the
        // site would serve, the resolver would decline to ask for its
        // certificate, and nothing would say why.
        self.tls_manager
            .set_public_issuance_domains(crate::certs::public_issuance_domains(config));
        for (address, policy) in &next {
            self.listener_policies[address].publish_client_auth(Arc::clone(&policy.client_auth));
        }
        for (address, servers, proxy) in targets {
            proxy.update_config(servers);
            tracing::info!(listener = %address, "♻️ Published listener configuration");
        }
        self.admin_policy.publish(prepared_admin);
        pingclair_proxy::access_log::register_channels(&config.logging.channels);
        pingclair_proxy::metrics::configure_host_labels(
            &config.global.metrics_options,
            config
                .servers
                .iter()
                .flat_map(|server| server.names.iter().map(String::as_str)),
        );
        pingclair_proxy::metrics::CONFIG_VERSION.inc();
        *self.current.write() = ActiveRuntimeConfig {
            config: config.clone(),
            listeners: next,
        };
        *self.document.write() = prepared_document;
        drop(gate);

        // 🚫 Claim the Admin-owned generation before releasing the same
        // publication mutex that a signal reload must acquire. Setting this in
        // the HTTP handler after return left a window where SIGUSR1 could queue
        // and overwrite a successful API key rotation.
        if expected_admin_revision.is_some() {
            self.api_changed.store(true, Ordering::SeqCst);
        }

        Ok(self.listener_policies.len())
    }
}
