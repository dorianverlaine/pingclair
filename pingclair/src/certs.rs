// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔐 Everything the binary itself knows about certificates.
//!
//! Three jobs that look unrelated until you notice they answer the same
//! question — *which certificate does this name get, and when* — for the three
//! moments the process has to answer it:
//!
//! - **At an H1/H2 handshake.** [`DynamicCertResolver`] is BoringSSL's SNI
//!   callback. It runs inside the handshake, so it caches the parsed
//!   `X509`/`PKey` objects rather than re-parsing PEM for every connection.
//! - **At an H3 handshake.** QUIC does not go through that callback at all, so
//!   [`refresh_h3_cert_table`] pushes certificates into the table `quiche`
//!   reads instead. It uses `peek_pem`, which never triggers issuance.
//! - **Before any handshake.** [`eager_issuance_domains`] picks the names worth
//!   asking a CA about at startup, so the first visitor is not the one who pays
//!   for the ACME round trip.
//!
//! The recurring bug this module guards against is handing out a leaf with no
//! intermediates. It completes a handshake against any client that already
//! holds the intermediate — browsers cache them, and will even fetch a missing
//! one over AIA — so it looks fine in a browser and fails hard in `curl`, Go,
//! and Java. Hence a whole chain everywhere, never a single certificate.

use boring::pkey::{PKey, Private};
use boring::ssl::NameType;
use boring::x509::X509;
use parking_lot::RwLock;
use pingclair_proxy::client_auth::ClientAuthTable;
use pingclair_proxy::tls_identity::DownstreamTlsIdentity;
use pingclair_tls::manager::TlsManager;
use pingora_core::listeners::TlsAccept;
use pingora_core::protocols::tls::TlsRef;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Cached BoringSSL certificate with expiration tracking
struct CachedSslCert {
    /// 🔗 The leaf first, then every intermediate the CA issued alongside it.
    ///
    /// This is a whole chain rather than a single certificate because a TLS
    /// server has to hand the client everything between its leaf and a trusted
    /// root. Keeping only the leaf here is exactly the bug this field replaced.
    chain: Vec<X509>,
    pkey: PKey<Private>,
    /// Unix timestamp when this cache entry expires
    expires_at: u64,
}

/// Cache TTL for parsed certificates (1 hour)
const CERT_CACHE_TTL_SECS: u64 = 3600;

/// Resolves certificates dynamically using TlsManager with BoringSSL caching
pub(crate) struct DynamicCertResolver {
    tls_manager: Arc<TlsManager>,
    /// Cache for parsed BoringSSL objects to avoid PEM parsing on every TLS handshake
    ssl_cache: Arc<RwLock<HashMap<String, CachedSslCert>>>,
    /// 🏷️ The name to resolve when a client sends no SNI.
    ///
    /// Resolved once when the listener is built, because this callback runs on
    /// every single handshake and the answer cannot change between them. An
    /// `Arc<str>` rather than a `String` so the no-SNI path borrows instead of
    /// allocating — the branch that reaches it is already the slow one for the
    /// client, and there is no reason to make it slower for the server.
    default_sni: Option<Arc<str>>,
    /// 🪪 What this listener's sites ask of a client's own certificate.
    ///
    /// `None` on the overwhelming majority of listeners, which is what keeps
    /// the ordinary handshake free of any mutual-TLS cost: the branch below is
    /// a null check, not a lookup.
    client_auth: Option<Arc<ClientAuthTable>>,
}

// Manual Debug because TlsManager might not implement it
impl std::fmt::Debug for DynamicCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicCertResolver")
            .field("cache_size", &self.ssl_cache.read().len())
            .finish()
    }
}

impl DynamicCertResolver {
    /// Create a new resolver with caching
    pub(crate) fn new(tls_manager: Arc<TlsManager>) -> Self {
        Self {
            tls_manager,
            ssl_cache: Arc::new(RwLock::new(HashMap::new())),
            default_sni: None,
            client_auth: None,
        }
    }

    /// 🏷️ Names the certificate to serve when a client sends no SNI.
    ///
    /// Without one, such a client gets no certificate and the handshake fails —
    /// which is correct, because there is nothing to choose by, but it is also
    /// why the option exists: TLS 1.2 made SNI optional and health checkers,
    /// older tooling and anything dialling a bare IP still omit it.
    pub(crate) fn with_default_sni(mut self, default_sni: Option<&str>) -> Self {
        self.default_sni = default_sni.filter(|name| !name.is_empty()).map(Arc::from);
        self
    }

    /// 🪪 Installs what this listener's sites ask of a client certificate.
    ///
    /// The table is built once at startup — trust stores parsed, files read —
    /// so a handshake only looks a name up and hands BoringSSL a pointer.
    pub(crate) fn with_client_auth(mut self, client_auth: Option<Arc<ClientAuthTable>>) -> Self {
        self.client_auth = client_auth.filter(|table| !table.is_empty());
        self
    }

    /// Get current unix timestamp
    fn current_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs()
    }

    /// Clean expired cache entries
    #[allow(dead_code)]
    fn cleanup_expired(&self) {
        let current = Self::current_time();
        let mut cache = self.ssl_cache.write();
        let before = cache.len();
        cache.retain(|_, entry| entry.expires_at > current);
        let removed = before - cache.len();
        if removed > 0 {
            tracing::debug!("🧹 Cleaned {} expired certificate cache entries", removed);
        }
    }
}

/// 🔗 Parses a PEM bundle into the leaf plus every intermediate that follows it.
///
/// The distinction that matters: `X509::from_pem` stops at the first
/// `-----END CERTIFICATE-----` and silently discards the rest, while
/// `stack_from_pem` returns all of them. A CA-issued bundle is leaf-then-
/// intermediates, so the first parser quietly produces a certificate that no
/// strict client can build a trust path from.
fn parse_certificate_chain(cert_pem: &str) -> Result<Vec<X509>, String> {
    let chain = X509::stack_from_pem(cert_pem.as_bytes()).map_err(|e| e.to_string())?;
    if chain.is_empty() {
        // 🚫 An empty bundle must fail closed: handing BoringSSL no leaf at all
        // would otherwise surface as a confusing handshake error much later.
        return Err("the PEM bundle contained no certificate".to_string());
    }
    Ok(chain)
}

/// 🔗 Installs one leaf, its intermediates, and the matching key on a handshake.
///
/// Sending only the leaf still completes a handshake against any client that
/// already happens to hold the intermediate — browsers cache them and will even
/// fetch a missing one over AIA. That is precisely why a missing chain hides so
/// well: it looks fine in a browser and fails hard in `curl`, Go, and Java.
fn install_certificate_chain(
    ssl: &mut TlsRef,
    chain: &[X509],
    pkey: &PKey<Private>,
) -> Result<(), boring::error::ErrorStack> {
    let (leaf, intermediates) = chain.split_first().expect("chain is never empty");
    ssl.set_certificate(leaf)?;
    for intermediate in intermediates {
        ssl.add_chain_cert(intermediate)?;
    }
    ssl.set_private_key(pkey)?;
    Ok(())
}

#[async_trait::async_trait]
impl TlsAccept for DynamicCertResolver {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        // 🏷️ The borrow of `ssl` has to end before the chain is installed
        // through `&mut ssl`, which is why the name is copied out. Only the
        // path that has an SNI allocates; the no-SNI path borrows the
        // configured default, so the fix below costs nothing on the hot path.
        let offered = {
            let sni = ssl.servername(NameType::HOST_NAME).unwrap_or("");
            (!sni.is_empty()).then(|| sni.to_string())
        };
        // 🪪 Mutual TLS is decided from the name the client actually sent, not
        // from `default_sni`. A client that named nothing has authorised
        // nothing, so it falls to the catch-all policy — and the SNI-against-
        // Host check at the HTTP layer refuses it any named site afterwards.
        if let Some(table) = &self.client_auth
            && let Some(policy) = table.policy_for(offered.as_deref().unwrap_or(""))
        {
            policy.install(ssl);
        }

        let sni: &str = match (&offered, self.default_sni.as_deref()) {
            (Some(sni), _) => sni,
            // 🔐 A client that sent no SNI used to get no certificate at all,
            // so the handshake failed with nothing to explain it. With a
            // configured name there is something to select by.
            (None, Some(default)) => default,
            (None, None) => {
                tracing::debug!(
                    "🔐 No SNI and no default_sni configured; no certificate can be selected"
                );
                return;
            }
        };

        tracing::debug!("🔐 Resolving cert for SNI: {}", sni);

        // Step 1: Check cache first (fast path)
        let current_time = Self::current_time();
        {
            let cache = self.ssl_cache.read();
            if let Some(cached) = cache.get(sni)
                && cached.expires_at > current_time
            {
                // Cache hit - use cached BoringSSL objects
                tracing::debug!("🚀 Using cached cert for {}", sni);
                if let Err(e) = install_certificate_chain(ssl, &cached.chain, &cached.pkey) {
                    tracing::error!("Failed to install cached certificate chain: {}", e);
                }
                return;
            }
        }

        // Step 2: Cache miss or expired - fetch and parse PEM
        if let Some((cert_pem, key_pem)) = self.tls_manager.resolve_pem(sni).await {
            let chain = match parse_certificate_chain(&cert_pem) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("Failed to parse cert PEM: {}", e);
                    return;
                }
            };

            let pkey = match PKey::private_key_from_pem(key_pem.as_bytes()) {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!("Failed to parse key PEM: {}", e);
                    return;
                }
            };

            // Step 3: Set the leaf, its intermediates, and the key
            if let Err(e) = install_certificate_chain(ssl, &chain, &pkey) {
                tracing::error!("Failed to install certificate chain: {}", e);
                return;
            }

            // Step 4: Cache the parsed BoringSSL objects for future handshakes
            let expires_at = current_time + CERT_CACHE_TTL_SECS;
            let cached_entry = CachedSslCert {
                chain,
                pkey,
                expires_at,
            };

            self.ssl_cache.write().insert(sni.to_string(), cached_entry);
            tracing::info!(
                "🔐 Cached cert for {} (expires in {}s)",
                sni,
                CERT_CACHE_TTL_SECS
            );
        }
    }

    /// 🪪 Carries the handshake's server name into the request lifecycle.
    ///
    /// Only listeners that ask something of a client certificate pay for this.
    /// Everywhere else the answer is `None` and no allocation happens, because
    /// the only consumer is the SNI-against-Host check, and that check only
    /// runs where being admitted is not the same as being authorised.
    async fn handshake_complete_callback(
        &self,
        ssl: &TlsRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        self.client_auth.as_ref()?;
        let server_name = ssl.servername(NameType::HOST_NAME).unwrap_or("");
        Some(Arc::new(DownstreamTlsIdentity::new(server_name)))
    }
}

/// 🚀 Collects the hostnames that need eager ACME issuance: `tls auto` sites
/// that are not covered by the internal authority or manual certificates, are
/// concretely named, and are not wildcards (which would need DNS-01).
pub(crate) fn eager_issuance_domains(
    config: &pingclair_core::config::PingclairConfig,
) -> Vec<String> {
    config
        .servers
        .iter()
        .filter(|server| {
            server
                .tls
                .as_ref()
                .is_some_and(|tls| tls.auto && !tls.internal && tls.cert.is_none())
        })
        .flat_map(|server| {
            // 🧭 JSON documents may carry hostnames in `names` while `name`
            // stays the listener label; issuance must honor both shapes.
            if server.names.is_empty() {
                server.name.clone().into_iter().collect::<Vec<_>>()
            } else {
                server.names.clone()
            }
        })
        .filter(|name| !name.is_empty() && name != "_" && !name.contains('*'))
        .collect()
}

/// Populate the HTTP/3 SNI certificate table from the TLS manager.
///
/// Uses `peek_pem`, which only returns certificates that already exist
/// (manual certs and previously issued ACME certs) and never triggers an
/// ACME issuance — issuance stays on the lazy HTTP/1.1 handshake path.
/// Called once at startup and then periodically, so renewed certificates
/// reach new QUIC handshakes without a restart.
pub(crate) async fn refresh_h3_cert_table(
    table: &pingclair_proxy::quic::CertTable,
    tls_manager: &TlsManager,
    domains: &[String],
) {
    for domain in domains {
        if let Some((cert_pem, key_pem)) = tls_manager.peek_pem(domain).await
            && let Err(e) = table.upsert_pem(domain, &cert_pem, &key_pem)
        {
            tracing::warn!("⚠️ H3: skipping certificate for {}: {}", domain, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🚀 Only `tls auto` hostnames qualify for eager issuance; internal,
    /// manual and wildcard sites are excluded.
    #[test]
    fn eager_issuance_domains_excludes_internal_manual_and_wildcards() {
        use pingclair_core::config::{ServerConfig, TlsConfig};

        let auto = ServerConfig {
            name: Some("auto.example".to_string()),
            tls: Some(TlsConfig {
                auto: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let internal = ServerConfig {
            name: Some("internal.example".to_string()),
            tls: Some(TlsConfig {
                auto: true,
                internal: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let manual = ServerConfig {
            name: Some("manual.example".to_string()),
            tls: Some(TlsConfig {
                auto: true,
                cert: Some("/certs/fullchain.pem".to_string()),
                key: Some("/certs/key.pem".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let wildcard = ServerConfig {
            name: Some("*.example.com".to_string()),
            tls: Some(TlsConfig {
                auto: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let plain = ServerConfig {
            name: Some("plain.example".to_string()),
            tls: None,
            ..Default::default()
        };
        let json_shape = ServerConfig {
            name: Some("default".to_string()),
            names: vec!["json.example".to_string()],
            tls: Some(TlsConfig {
                auto: true,
                ..Default::default()
            }),
            ..Default::default()
        };

        let config = pingclair_core::config::PingclairConfig {
            servers: vec![auto, internal, manual, wildcard, plain, json_shape],
            ..Default::default()
        };
        assert_eq!(
            eager_issuance_domains(&config),
            vec!["auto.example", "json.example"]
        );
    }

    /// 🔗 A CA bundle carries the leaf and its intermediates; keep all of them.
    #[test]
    fn parsing_a_bundle_keeps_every_certificate_after_the_leaf() {
        let leaf = certificate_pem("leaf.test");
        let intermediate = certificate_pem("intermediate.test");

        let single = parse_certificate_chain(&leaf).expect("a lone leaf parses");
        assert_eq!(single.len(), 1);

        let bundle = format!("{leaf}{intermediate}");
        let chain = parse_certificate_chain(&bundle).expect("a bundle parses");
        assert_eq!(
            chain.len(),
            2,
            "the intermediate was dropped; clients cannot build a trust path without it"
        );

        // 🚫 An empty bundle fails closed rather than reaching BoringSSL with
        // no leaf and surfacing as a confusing handshake error much later.
        assert!(parse_certificate_chain("").is_err());
    }

    /// 🎫 Generates one throwaway self-signed certificate in PEM form.
    #[cfg(test)]
    fn certificate_pem(common_name: &str) -> String {
        let mut params =
            rcgen::CertificateParams::new(vec![common_name.to_string()]).expect("parameters");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        let key = rcgen::KeyPair::generate().expect("key pair");
        params.self_signed(&key).expect("certificate").pem()
    }
}
