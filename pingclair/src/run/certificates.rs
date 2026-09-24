// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔐 Certificate sources, prepared before any listener can accept a handshake.
//!
//! Everything a TLS handshake may need is decided here, once, at startup: the
//! persistent store (proved writable before anything is issued into it), the
//! TLS manager, the names a public CA may be asked about, internal
//! certificates, the manual pairs to load as one set, and which ACME challenge
//! proves which name. Configurations this build cannot honour as a certificate
//! source — an `acme_server` site, a DNS provider it does not ship — are
//! refused here rather than discovered at the first renewal.

use crate::certs::public_issuance_domains;
use crate::paths::tls_store_dir_with;
use std::sync::Arc;

/// 🔐 What certificate preparation hands back to the rest of startup.
pub(super) struct PreparedCertificates {
    /// 🧰 The temporary runtime the manager was built on, reused for the
    /// synchronous HTTP/3 certificate-table seed.
    pub(super) runtime: tokio::runtime::Runtime,
    pub(super) manager: Arc<pingclair_tls::manager::TlsManager>,
    /// 🔐 `(name, cert path, key path)` for every manual pair, loaded later as
    /// one set by `refresh_manual_certs`.
    pub(super) manual: Vec<(String, String, String)>,
}

/// 🔐 Prepares every certificate source the configuration names, or refuses
/// the configuration with a message naming what cannot be served.
pub(super) fn prepare(
    config: &pingclair_core::config::PingclairConfig,
) -> anyhow::Result<PreparedCertificates> {
    // 🔐 Initialize every certificate source below one configurable persistent store.
    // 🗄️ The global `storage file_system <path>` option, when the config has
    // one, decides where every certificate source below lives. It is resolved
    // once here rather than at each reader, so the whole process agrees about
    // which store it is using.
    let tls_store_path_str = tls_store_dir_with(config.global.storage_path.as_deref())
        .to_string_lossy()
        .to_string();
    let tls_store_path = std::path::Path::new(&tls_store_path_str);
    // 🗄️ Said out loud because it is the one setting whose effect is invisible
    // from the outside: two deployments that name the same store share a trust
    // root, and two that do not mint their own with no visible difference
    // until a client refuses one of them.
    tracing::info!("🗄️ TLS store: {tls_store_path_str}");
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
    // 📴 `ocsp_stapling off` is the one spelling this build accepts, and it
    // names the behaviour already in force rather than changing it: no OCSP
    // response is stapled onto a handshake here. That is worth one startup line
    // because it is otherwise only discoverable by inspecting a handshake with
    // an external tool, and because the operator asked for something — silence
    // would leave them thinking the setting had taken effect on a stapler that
    // exists.
    if config.global.ocsp_stapling_off {
        tracing::info!(
            "📴 OCSP stapling: off — this build staples no OCSP response onto a handshake, \
             so the option describes what the server already does"
        );
    }
    // 🔗 `preferred_chains` is refused by `validate_config` — the ACME client
    // this build uses downloads whichever chain the authority offers first and
    // cannot ask for another (`instant-acme` 0.8.5, verified 2026-08-12), so a
    // preference here is a setting that silently does nothing. A warning used to
    // live at this point instead; it went into a log an operator reads once, and
    // the certificate they got was not the one they asked for.

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
    let authorised_issuance = public_issuance_domains(config);
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

    Ok(PreparedCertificates {
        runtime: tls_runtime,
        manager: tls_manager,
        manual: manual_certs,
    })
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
            let provider = pingclair_tls::dns01::cloudflare::CloudflareProvider::new(
                token.expose().to_string(),
            )?;
            Ok(Arc::new(provider))
        }
        other => anyhow::bail!(
            "DNS provider `{other}` is not implemented; this build ships `cloudflare` only"
        ),
    }
}
