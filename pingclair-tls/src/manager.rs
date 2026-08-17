// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! TLS Manager
//!
//! 🛡️ Coordinates certificate management, ACME challenges, and TLS handshakes.

use crate::acme::{ChallengeHandler, ChallengePolicy, ChallengeSolver, MemoryChallengeHandler};
use crate::auto_https::{AutoHttps, AutoHttpsConfig};
use crate::cert_store::CertStore;
use crate::internal_ca::{InternalCa, InternalCaError};
use crate::persistent_challenge_handler::PersistentChallengeHandler;
use arc_swap::ArcSwap;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_rustls::rustls;

/// 🗃️ Tracks a parsed certificate and its cache expiration.
#[derive(Clone)]
struct CachedCert {
    certified_key: Arc<rustls::sign::CertifiedKey>,
    /// ⏰ Records the Unix timestamp when this cache entry expires.
    expires_at: u64,
    /// 🕰️ Records the Unix timestamp when this certificate was cached.
    #[allow(dead_code)]
    cached_at: u64,
}

/// 📜 A complete manual-certificate table validated but not yet published.
pub struct PreparedManualCerts {
    entries: HashMap<String, (String, String)>,
}

impl PreparedManualCerts {
    /// 📜 Borrows the validated PEM set for another transport's preparation.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str, &str)> {
        self.entries
            .iter()
            .map(|(name, (cert, key))| (name.as_str(), cert.as_str(), key.as_str()))
    }
}

/// 🛡️ TLS Manager for Pingclair
pub struct TlsManager {
    /// 🌐 Manages automatic public certificates.
    auto_https: Option<Arc<AutoHttps>>,
    /// 🚦 Publishes HTTP-01 challenges through memory or persistent storage.
    challenge_handler: Arc<dyn ChallengeHandler>,
    /// 📜 Stores explicitly configured PEM pairs with the highest precedence.
    manual_pem_certs: RwLock<HashMap<String, (String, String)>>,
    /// 🏛️ Issues and persists certificates for explicitly enabled internal domains.
    internal_ca: Arc<InternalCa>,
    /// 🧭 Limits local issuance to domains selected by configuration.
    internal_domains: RwLock<HashSet<String>>,
    /// 🌐 Limits *public* issuance to domains selected by configuration.
    ///
    /// The exact counterpart of [`Self::internal_domains`], and it exists for
    /// a sharper reason. A TLS handshake carries a server name chosen by
    /// whoever dialled the socket, and this resolver used to hand any
    /// unrecognised name straight to a public CA — so a stranger could pick
    /// the name and the process would go and do outbound ACME work about it.
    /// Names get here from the configuration only, normalized once at
    /// publication, and a name that is not covered never reaches a CA.
    ///
    /// 🚫 Empty means "issue for nothing", which is the right answer for a
    /// process that was never told what it serves. This is not the same as
    /// automatic HTTPS being off — that is a separate switch, checked further
    /// in — and both have to say yes.
    public_issuance_domains: RwLock<HashSet<String>>,
    /// ⚡ Avoids repeated PEM parsing for generated certificates.
    cached_certs: RwLock<HashMap<String, CachedCert>>,
    /// ⏳ Limits parsed certificate lifetime so rotations become visible.
    cache_ttl: Duration,
    /// 🗺️ Which challenge proves which name.
    ///
    /// Published through `ArcSwap` rather than held directly because the
    /// DNS-01 half is built after the manager exists — `run.rs` has to read the
    /// configuration to know which names need a provider — and a second
    /// constructor taking a policy would leave the first one silently meaning
    /// "HTTP-01 for everything".
    challenge_policy: ArcSwap<ChallengePolicy>,
}

impl TlsManager {
    /// 🏗️ Creates a TLS manager with a persistent challenge handler.
    pub async fn new(
        config: Option<AutoHttpsConfig>,
        store_path: &std::path::Path,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // 💾 Persistent challenges survive process restarts during validation.
        let challenge_storage_path = store_path.join("acme-challenges.json");
        let challenge_handler =
            Arc::new(PersistentChallengeHandler::new(challenge_storage_path).await?);

        let auto_https = if let Some(config) = config {
            let store = Arc::new(CertStore::with_renewal_window(
                store_path,
                config.renewal_window_ratio,
            ));
            // 📁 A fresh process must see certificates persisted by earlier
            // runs; without this the in-memory cache stays empty, eager
            // issuance re-requests every domain, and the first TLS handshakes
            // fail with NO_CERTIFICATE_SET until a new issuance completes.
            store.init().await?;
            Some(Arc::new(AutoHttps::new(config, store)))
        } else {
            None
        };

        Ok(Self {
            auto_https,
            challenge_handler: challenge_handler.clone() as Arc<dyn ChallengeHandler>,
            manual_pem_certs: RwLock::new(HashMap::new()),
            internal_ca: Arc::new(InternalCa::new(store_path)),
            internal_domains: RwLock::new(HashSet::new()),
            public_issuance_domains: RwLock::new(HashSet::new()),
            cached_certs: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(3600),
            challenge_policy: ArcSwap::from_pointee(ChallengePolicy::uniform(
                ChallengeSolver::http01(challenge_handler as Arc<dyn ChallengeHandler>),
            )),
        })
    }

    /// 🧪 Creates a TLS manager with an in-memory challenge handler.
    pub fn new_with_memory_challenges(
        config: Option<AutoHttpsConfig>,
        store_path: &std::path::Path,
    ) -> Self {
        let challenge_handler = Arc::new(MemoryChallengeHandler::new());

        let auto_https = if let Some(config) = config {
            let store = Arc::new(CertStore::with_renewal_window(
                store_path,
                config.renewal_window_ratio,
            ));
            Some(Arc::new(AutoHttps::new(config, store)))
        } else {
            None
        };

        Self {
            auto_https,
            challenge_handler: challenge_handler.clone() as Arc<dyn ChallengeHandler>,
            manual_pem_certs: RwLock::new(HashMap::new()),
            internal_ca: Arc::new(InternalCa::new(store_path)),
            internal_domains: RwLock::new(HashSet::new()),
            public_issuance_domains: RwLock::new(HashSet::new()),
            cached_certs: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(3600),
            challenge_policy: ArcSwap::from_pointee(ChallengePolicy::uniform(
                ChallengeSolver::http01(challenge_handler as Arc<dyn ChallengeHandler>),
            )),
        }
    }

    /// 🧪 Creates a TLS manager whose public issuance goes to a given issuer.
    ///
    /// The same shape as [`Self::new_with_memory_challenges`] and for the same
    /// reason: it lets a test drive the real resolver — allowlist, precedence
    /// between manual, internal and public certificates, the lot — without a
    /// single packet leaving the machine.
    pub fn new_with_issuer(
        config: AutoHttpsConfig,
        store_path: &std::path::Path,
        issuer: Arc<dyn crate::acme::CertificateIssuer>,
    ) -> Self {
        let store = Arc::new(CertStore::with_renewal_window(
            store_path,
            config.renewal_window_ratio,
        ));
        let mut manager = Self::new_with_memory_challenges(None, store_path);
        manager.auto_https = Some(Arc::new(AutoHttps::with_issuer(config, store, issuer)));
        manager
    }

    /// 🧰 Creates a TLS manager with a custom persistent challenge path.
    pub async fn new_with_custom_challenge_path(
        config: Option<AutoHttpsConfig>,
        store_path: &std::path::Path,
        challenge_storage_path: &std::path::Path,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let challenge_handler =
            Arc::new(PersistentChallengeHandler::new(challenge_storage_path.to_path_buf()).await?);

        let auto_https = if let Some(config) = config {
            let store = Arc::new(CertStore::with_renewal_window(
                store_path,
                config.renewal_window_ratio,
            ));
            // 📁 Hydrate the persisted certificate cache like the main
            // constructor does; a custom challenge path must not change
            // certificate discovery semantics.
            store.init().await?;
            Some(Arc::new(AutoHttps::new(config, store)))
        } else {
            None
        };

        Ok(Self {
            auto_https,
            challenge_handler: challenge_handler.clone() as Arc<dyn ChallengeHandler>,
            manual_pem_certs: RwLock::new(HashMap::new()),
            internal_ca: Arc::new(InternalCa::new(store_path)),
            internal_domains: RwLock::new(HashSet::new()),
            public_issuance_domains: RwLock::new(HashSet::new()),
            cached_certs: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(3600),
            challenge_policy: ArcSwap::from_pointee(ChallengePolicy::uniform(
                ChallengeSolver::http01(challenge_handler as Arc<dyn ChallengeHandler>),
            )),
        })
    }

    /// Initializes the manager (async steps)
    pub async fn init(&self) -> Result<(), crate::AutoHttpsError> {
        if let Some(auto) = &self.auto_https {
            // 📁 The constructors already hydrate the store; this entry point
            // keeps the manager usable when it is built step by step.
            auto.init_store().await?;
        }
        Ok(())
    }

    /// 📜 Adds an explicitly configured PEM pair with the highest precedence.
    pub fn add_manual_cert(&self, domain: &str, cert_pem: String, key_pem: String) {
        self.manual_pem_certs
            .write()
            .insert(domain.to_string(), (cert_pem, key_pem));
    }

    /// 📜 Replaces the whole manual certificate table, or leaves it untouched.
    ///
    /// **Why the whole table and not one domain at a time.** Certificates are
    /// rotated by writing files, and writing is not atomic: a cert can land
    /// before its key, or a copy can be interrupted halfway. Loading them
    /// one at a time means a partial rotation gets partially applied — some
    /// domains on the new certificate, some on the old, and one domain on a
    /// cert whose key has not arrived yet. That last one is the bad case,
    /// because it does not fail here; it fails at handshake time, to a real
    /// client, on a site that was working a second ago.
    ///
    /// So every pair is read and parsed first. If any of them is unusable the
    /// table is not touched at all and the errors are returned together, naming
    /// each file — an operator mid-rotation gets told what is wrong while the
    /// previous certificates keep serving.
    ///
    /// 🔐 Validation is deliberately more than "the file exists": the PEM has
    /// to contain at least one certificate, the key has to parse, and the key
    /// has to be one the TLS provider can actually sign with. A half-written
    /// file usually fails exactly one of those.
    pub fn refresh_manual_certs(
        &self,
        entries: &[(String, String, String)],
    ) -> Result<usize, Vec<String>> {
        let prepared = self.prepare_manual_certs(entries)?;
        Ok(self.publish_manual_certs(prepared))
    }

    /// 🧪 Reads and validates every manual pair without changing active TLS.
    pub fn prepare_manual_certs(
        &self,
        entries: &[(String, String, String)],
    ) -> Result<PreparedManualCerts, Vec<String>> {
        let mut prepared: HashMap<String, (String, String)> = HashMap::new();
        let mut problems = Vec::new();

        for (domain, cert_path, key_path) in entries {
            let cert_pem = match std::fs::read_to_string(cert_path) {
                Ok(pem) => pem,
                Err(error) => {
                    problems.push(format!("{domain}: cannot read {cert_path}: {error}"));
                    continue;
                }
            };
            let key_pem = match std::fs::read_to_string(key_path) {
                Ok(pem) => pem,
                Err(error) => {
                    problems.push(format!("{domain}: cannot read {key_path}: {error}"));
                    continue;
                }
            };
            if let Err(reason) = validate_pem_pair(&cert_pem, &key_pem) {
                problems.push(format!("{domain}: {reason} ({cert_path}, {key_path})"));
                continue;
            }
            prepared.insert(domain.clone(), (cert_pem, key_pem));
        }

        if !problems.is_empty() {
            return Err(problems);
        }

        Ok(PreparedManualCerts { entries: prepared })
    }

    /// 📣 Publishes a table whose files and key pairs already passed validation.
    pub fn publish_manual_certs(&self, prepared: PreparedManualCerts) -> usize {
        let count = prepared.entries.len();
        *self.manual_pem_certs.write() = prepared.entries;
        count
    }

    /// 📜 Whether a manual certificate is installed for `domain`.
    pub fn has_manual_cert(&self, domain: &str) -> bool {
        self.manual_pem_certs.read().contains_key(domain)
    }

    /// 🏛️ Enables local issuance for one configured domain and eagerly prepares its leaf.
    pub async fn enable_internal_domain(
        &self,
        domain: &str,
    ) -> Result<(String, String), InternalCaError> {
        let domain = normalize_internal_domain(domain);
        let certificate = self.internal_ca.get_or_issue(&domain).await?;
        self.internal_domains.write().insert(domain);
        Ok((certificate.cert_pem, certificate.key_pem))
    }

    /// 🏗️ Picks the configured internal pattern that issues for `domain`: an
    /// exact name first, then a wildcard (`*.example.com`) whose suffix covers
    /// the concrete SNI. `None` means the name has no local issuer.
    fn internal_issuance_domain(&self, domain: &str) -> Option<String> {
        let normalized = normalize_internal_domain(domain);
        matching_pattern(&self.internal_domains.read(), &normalized)
    }

    /// 🌐 Names this process may ask a public CA about.
    ///
    /// Published once from the configuration, before any listener accepts a
    /// handshake. Wildcards are kept as written (`*.example.com`) so a DNS-01
    /// site still covers the names underneath it; the catch-all spellings are
    /// the caller's job to exclude, because "this site answers to anything" is
    /// not a statement about which names are worth a certificate.
    pub fn set_public_issuance_domains<I, S>(&self, domains: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        // 🔤 Normalized here rather than per handshake: the comparison happens
        // inside a TLS handshake and the answer cannot change between them.
        *self.public_issuance_domains.write() = domains
            .into_iter()
            .map(|domain| normalize_internal_domain(domain.as_ref()))
            .filter(|domain| !domain.is_empty())
            .collect();
    }

    /// 🚦 Reports whether the configuration authorised public issuance for
    /// this server name.
    fn public_issuance_allowed(&self, domain: &str) -> bool {
        let normalized = normalize_internal_domain(domain);
        matching_pattern(&self.public_issuance_domains.read(), &normalized).is_some()
    }

    /// 🌐 The single door to a public certificate authority.
    ///
    /// Both resolvers go through here so the allowlist cannot hold on one and
    /// not the other — the two used to call `get_certificate` directly, side
    /// by side, and a check added to one of them would have looked complete.
    async fn issue_public_certificate(&self, domain: &str) -> Option<crate::Certificate> {
        let auto = self.auto_https.as_ref()?;
        // 🔤 Normalized before anything downstream sees it, not just for the
        // allowlist comparison. The certificate store, the in-flight claim and
        // the renewal daemon all key on this string, so `Example.com`,
        // `example.com.` and `EXAMPLE.COM` reaching them as three different
        // names means three cache misses, three claims and three ACME orders
        // for one site — and the spelling is the client's to choose. DNS is
        // case-insensitive and the CA normalizes anyway, so the only thing
        // varied capitalisation could ever buy is repeated work here.
        let domain = normalize_internal_domain(domain);
        if !self.public_issuance_allowed(&domain) {
            // 📉 `debug`, not `warn`: on a public listener this fires once per
            // stranger scanning the address, and a log line an unauthenticated
            // client can emit at will is its own denial of service.
            tracing::debug!(
                "🚫 {} is not a name this configuration serves; no certificate was requested",
                domain
            );
            return None;
        }
        match auto
            .get_certificate(&domain, self.challenge_policy.load().solver_for(&domain))
            .await
        {
            Ok(cert) => Some(cert),
            Err(error) => {
                tracing::warn!("❌ Failed to obtain cert for {}: {}", domain, error);
                None
            }
        }
    }

    /// 🌳 Returns the public root certificate for trust-store installation.
    pub async fn internal_root_certificate_pem(&self) -> Result<String, InternalCaError> {
        self.internal_ca.root_certificate_pem().await
    }

    /// 🔍 Resolves existing or locally renewable PEM without starting public ACME issuance.
    ///
    /// 🧭 This path may renew a configured internal leaf, but it never starts
    /// public ACME issuance. HTTP/3 uses it to refresh the SNI certificate table.
    pub async fn peek_pem(&self, domain: &str) -> Option<(String, String)> {
        // 📜 Explicit PEM pairs always take precedence.
        let manual = self.manual_pem_certs.read().get(domain).cloned();
        if let Some(pems) = manual {
            return Some(pems);
        }

        // 🏛️ Configured internal leaves can renew without contacting a public issuer.
        if let Some(internal_domain) = self.internal_issuance_domain(domain) {
            return match self.internal_ca.get_or_issue(&internal_domain).await {
                Ok(cert) => Some((cert.cert_pem, cert.key_pem)),
                Err(error) => {
                    tracing::error!(
                        "❌ Failed to resolve internal certificate for {}: {}",
                        domain,
                        error
                    );
                    None
                }
            };
        }

        // 🗃️ Public certificates are read only from the existing ACME cache.
        if let Some(auto) = &self.auto_https
            && let Some(cert) = auto.cached_certificate(domain).await
        {
            return Some((cert.cert_pem, cert.key_pem));
        }
        None
    }

    /// 🔍 Resolves a PEM pair for a client hello.
    pub async fn resolve_pem(&self, domain: &str) -> Option<(String, String)> {
        // 📜 Explicit PEM pairs always take precedence.
        let manual = self.manual_pem_certs.read().get(domain).cloned();
        if let Some(pems) = manual {
            return Some(pems);
        }

        // 🏛️ Internal domains must never fall through to public ACME issuance.
        if let Some(internal_domain) = self.internal_issuance_domain(domain) {
            return match self.internal_ca.get_or_issue(&internal_domain).await {
                Ok(cert) => Some((cert.cert_pem, cert.key_pem)),
                Err(error) => {
                    tracing::error!(
                        "❌ Failed to resolve internal certificate for {}: {}",
                        domain,
                        error
                    );
                    None
                }
            };
        }

        // 🌐 Remaining names may use automatic public HTTPS — if the
        // configuration named them.
        let cert = self.issue_public_certificate(domain).await?;
        Some((cert.cert_pem, cert.key_pem))
    }

    /// 🔍 Resolves a parsed rustls certificate for a client hello.
    pub async fn resolve_cert(&self, domain: &str) -> Option<Arc<rustls::sign::CertifiedKey>> {
        // 📜 Explicit PEM pairs always take precedence.
        let manual = self.manual_pem_certs.read().get(domain).cloned();
        if let Some((cert_pem, key_pem)) = manual {
            let cert = crate::Certificate {
                cert_pem,
                key_pem,
                domains: vec![domain.to_string()],
                expires_at: 0,
            };
            match self.convert_to_rustls(&cert) {
                Ok(key) => return Some(Arc::new(key)),
                Err(e) => {
                    tracing::error!(
                        "❌ Failed to parse manual certificate for {}: {}",
                        domain,
                        e
                    );
                    return None;
                }
            }
        }

        // ⚡ Parsed certificates avoid repeated PEM work until the bounded TTL expires.
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        {
            let cache_guard = self.cached_certs.read();
            if let Some(cached) = cache_guard.get(domain) {
                if current_time < cached.expires_at {
                    tracing::debug!("🔐 Using cached CertifiedKey for {}", domain);
                    return Some(cached.certified_key.clone());
                } else {
                    tracing::debug!(
                        "⏰ Cached certificate expired for {}, removing from cache",
                        domain
                    );
                }
            }
        }

        // 🏛️ Internal domains must never fall through to public ACME issuance.
        if let Some(internal_domain) = self.internal_issuance_domain(domain) {
            return match self.internal_ca.get_or_issue(&internal_domain).await {
                Ok(cert) => self.cache_rustls_certificate(domain, &cert),
                Err(error) => {
                    tracing::error!(
                        "❌ Failed to resolve internal certificate for {}: {}",
                        domain,
                        error
                    );
                    None
                }
            };
        }

        // 🌐 Remaining names may use automatic public HTTPS — if the
        // configuration named them.
        let cert = self.issue_public_certificate(domain).await?;
        self.cache_rustls_certificate(domain, &cert)
    }

    /// ⚡ Parses and caches one generated certificate for rustls consumers.
    fn cache_rustls_certificate(
        &self,
        domain: &str,
        cert: &crate::Certificate,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let key = match self.convert_to_rustls(cert) {
            Ok(key) => key,
            Err(error) => {
                tracing::error!("❌ Failed to parse certificate for {}: {}", domain, error);
                return None;
            }
        };
        let key = Arc::new(key);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        self.cached_certs.write().insert(
            domain.to_string(),
            CachedCert {
                certified_key: key.clone(),
                expires_at: current_time + self.cache_ttl.as_secs(),
                cached_at: current_time,
            },
        );
        tracing::info!(
            "🔐 Cached a parsed certificate for {} for {}s",
            domain,
            self.cache_ttl.as_secs()
        );
        Some(key)
    }

    /// 🔧 Converts one PEM certificate bundle into a rustls signing key.
    fn convert_to_rustls(
        &self,
        cert: &crate::Certificate,
    ) -> Result<rustls::sign::CertifiedKey, String> {
        use rustls::pki_types::CertificateDer;

        // 🔗 Parse the complete certificate chain in leaf-first order.
        let mut reader = std::io::Cursor::new(&cert.cert_pem);
        let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut reader)
            .filter_map(|r| r.ok())
            .collect();

        if certs.is_empty() {
            return Err("No certificates found".to_string());
        }

        // 🔑 Parse the private key corresponding to the leaf certificate.
        let mut reader = std::io::Cursor::new(&cert.key_pem);
        let key = rustls_pemfile::private_key(&mut reader)
            .map_err(|e| e.to_string())?
            .ok_or("No private key found")?;

        // 🛡️ Reject key types that the configured rustls provider cannot sign with.
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
            .map_err(|_| "Unsupported key type".to_string())?;

        Ok(rustls::sign::CertifiedKey::new(certs, signing_key))
    }

    /// 🔐 Checks that a PEM pair is usable before it is allowed to serve.
    ///
    /// Kept next to the code that later builds a `CertifiedKey` from the same
    /// bytes, so the two cannot drift into accepting different things.
    fn validate_pem_pair_impl(cert_pem: &str, key_pem: &str) -> Result<(), String> {
        let mut reader = std::io::Cursor::new(cert_pem.as_bytes());
        let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("certificate PEM is malformed: {error}"))?;
        if certs.is_empty() {
            return Err("certificate PEM contains no certificate".to_string());
        }

        let mut reader = std::io::Cursor::new(key_pem.as_bytes());
        let key = rustls_pemfile::private_key(&mut reader)
            .map_err(|error| format!("private key PEM is malformed: {error}"))?
            .ok_or_else(|| "private key PEM contains no key".to_string())?;

        rustls::crypto::ring::sign::any_supported_type(&key)
            .map_err(|_| "private key type is not supported".to_string())?;
        Ok(())
    }

    /// 🚦 Returns the configured HTTP-01 challenge handler.
    pub fn challenge_handler(&self) -> Arc<dyn ChallengeHandler> {
        self.challenge_handler.clone()
    }

    /// 🗺️ Publishes which challenge proves which name.
    ///
    /// Called once at startup, after the configuration has said which sites
    /// need DNS-01 and a provider has been built for them. Anything not named
    /// keeps the HTTP-01 default.
    pub fn set_challenge_policy(&self, policy: ChallengePolicy) {
        self.challenge_policy.store(Arc::new(policy));
    }

    /// 🚀 Starts the background certificate machinery: the renewal daemon
    /// (once) plus eager issuance for every `tls auto` hostname, so the first
    /// handshake never blocks on ACME.
    pub fn start_background_issuance(&self, domains: Vec<String>) {
        use std::sync::OnceLock;

        // 🔁 The renewal daemon is process-wide; guard against duplicate
        // spawns if a future reload path calls this again.
        static RENEWAL_STARTED: OnceLock<()> = OnceLock::new();
        let Some(auto) = &self.auto_https else {
            return;
        };
        let policy = self.challenge_policy.load_full();
        if RENEWAL_STARTED.set(()).is_ok() {
            let renewal = auto.clone();
            renewal.start_renewal_task(policy.clone());
        }
        auto.clone().start_eager_issuance(domains, policy);
    }

    /// 🛑 Clears in-flight ACME markers so a reloaded configuration can begin
    /// issuing immediately.
    pub async fn cancel_pending_issuance(&self) {
        if let Some(auto) = &self.auto_https {
            auto.cancel_pending_issuance().await;
        }
    }

    /// 🧹 Removes expired parsed certificate cache entries.
    pub fn cleanup_expired_cache(&self) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        let mut cache_guard = self.cached_certs.write();
        cache_guard.retain(|_domain, cached| current_time < cached.expires_at);

        tracing::debug!("🧹 Cleaned expired certificate cache entries");
    }

    /// ⏳ Updates the parsed certificate cache lifetime.
    pub fn set_cache_ttl(&mut self, ttl: Duration) {
        self.cache_ttl = ttl;
    }
}

/// 🔤 Normalizes DNS case and a trailing absolute-name dot for SNI comparison.
fn normalize_internal_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

/// 🧭 Finds the configured pattern that covers `normalized`: an exact name
/// first, then a wildcard whose one label it fills.
///
/// `*.example.com` answers for `a.example.com` and not for `a.b.example.com`
/// or for `example.com` itself, which is how a TLS wildcard has always worked
/// and how upstream matches an SNI. The remainder is checked for a dot rather
/// than the suffix being rebuilt with `format!`, because this runs inside a
/// handshake — including the handshakes that turn out not to match, which is
/// exactly the traffic a stranger can generate.
fn matching_pattern(patterns: &HashSet<String>, normalized: &str) -> Option<String> {
    if patterns.contains(normalized) {
        return Some(normalized.to_string());
    }
    // 🃏 The one-label rule lives in `acme::pattern_covers`, shared with the
    // challenge policy — the two used to answer this question separately, and the
    // other copy got it wrong.
    patterns.iter().find_map(|pattern| {
        crate::acme::pattern_covers(pattern, normalized).then(|| pattern.clone())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::acme::{AcmeError, Certificate, CertificateIssuer, ChallengeSolver};
    use parking_lot::Mutex;

    fn test_manager() -> TlsManager {
        let dir =
            std::env::temp_dir().join(format!("pingclair-tls-manager-test-{}", std::process::id()));
        TlsManager::new_with_memory_challenges(None, &dir)
    }

    // MARK: - Public issuance allowlist

    /// 🧪 An issuer that never contacts anyone and remembers who asked.
    #[derive(Default)]
    struct RecordingIssuer {
        calls: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl CertificateIssuer for RecordingIssuer {
        async fn obtain_certificate(
            &self,
            domains: &[String],
            _solver: &ChallengeSolver,
        ) -> Result<Certificate, AcmeError> {
            let domain = domains.first().cloned().unwrap_or_default();
            self.calls.lock().push(domain.clone());
            Ok(Certificate {
                cert_pem: format!("CERT for {domain}"),
                key_pem: format!("KEY for {domain}"),
                domains: domains.to_vec(),
                // ⏳ Far enough out that the store never calls it renewable.
                expires_at: 4_102_444_800,
            })
        }
    }

    fn issuing_manager(directory: &std::path::Path) -> (TlsManager, Arc<RecordingIssuer>) {
        let issuer = Arc::new(RecordingIssuer::default());
        let manager = TlsManager::new_with_issuer(
            AutoHttpsConfig::default(),
            directory,
            issuer.clone() as Arc<dyn CertificateIssuer>,
        );
        (manager, issuer)
    }

    /// 🚫 A name the configuration never mentioned must not reach a CA.
    ///
    /// This is the finding in one test. The server name in a ClientHello is
    /// chosen by whoever dialled the socket, and this resolver used to hand an
    /// unrecognised one straight to a public certificate authority — outbound
    /// work, account quota, and rate-limit pressure, all triggered by a
    /// stranger picking a hostname. The recording issuer below is how "no
    /// certificate was returned" is separated from "nobody was contacted":
    /// only the second one is the fix.
    #[tokio::test]
    async fn an_unconfigured_name_never_reaches_the_certificate_authority() {
        let directory = tempfile::tempdir().unwrap();
        let (manager, issuer) = issuing_manager(directory.path());
        manager.set_public_issuance_domains(["configured.example"]);

        assert!(manager.resolve_pem("stranger.example").await.is_none());
        assert!(manager.resolve_cert("stranger.example").await.is_none());
        assert!(
            issuer.calls.lock().is_empty(),
            "an unconfigured name reached the issuer: {:?}",
            issuer.calls.lock()
        );

        // 🧭 The configured name still works, so the gate refuses strangers
        // rather than refusing everyone.
        let resolved = manager.resolve_pem("configured.example").await;
        assert_eq!(
            resolved,
            Some((
                "CERT for configured.example".to_string(),
                "KEY for configured.example".to_string()
            ))
        );
        assert_eq!(issuer.calls.lock().as_slice(), ["configured.example"]);
    }

    /// 🕳️ An empty allowlist authorises nothing.
    ///
    /// The state a process is in before it has read its configuration, and the
    /// state it stays in if a future change forgets to publish the list. Both
    /// have to mean "ask nobody", because the alternative — an unset list
    /// meaning "anything" — is the defect this replaced.
    #[tokio::test]
    async fn an_empty_allowlist_authorises_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let (manager, issuer) = issuing_manager(directory.path());

        assert!(manager.resolve_pem("anything.example").await.is_none());
        assert!(issuer.calls.lock().is_empty());
    }

    /// 🃏 A wildcard site covers one label under it, and no more.
    ///
    /// `*.example.com` is a name a DNS-01 site legitimately serves, so it has
    /// to authorise `a.example.com`. It must not authorise `a.b.example.com`
    /// or `example.com` itself — no TLS client accepts a wildcard certificate
    /// for either, so issuing one would spend quota on something unusable.
    #[tokio::test]
    async fn a_wildcard_authorises_exactly_one_label_under_it() {
        let directory = tempfile::tempdir().unwrap();
        let (manager, issuer) = issuing_manager(directory.path());
        manager.set_public_issuance_domains(["*.example.com"]);

        assert!(manager.resolve_pem("a.example.com").await.is_some());
        assert!(manager.resolve_pem("a.b.example.com").await.is_none());
        assert!(manager.resolve_pem("example.com").await.is_none());
        assert!(manager.resolve_pem("notexample.com").await.is_none());
        assert_eq!(issuer.calls.lock().as_slice(), ["a.example.com"]);
    }

    /// 🔤 A name is compared after normalisation, not as it arrived.
    ///
    /// SNI is case-insensitive and may carry the trailing dot of an absolute
    /// name. Comparing raw bytes would let `EXAMPLE.COM.` slip past a list
    /// that says `example.com` — refusing a legitimate client — and, worse,
    /// would make the allowlist depend on how the client spelled it.
    #[tokio::test]
    async fn names_are_compared_after_normalisation() {
        let directory = tempfile::tempdir().unwrap();
        let (manager, issuer) = issuing_manager(directory.path());
        manager.set_public_issuance_domains(["Configured.Example."]);

        assert!(manager.resolve_pem("configured.example").await.is_some());
        assert!(manager.resolve_pem("CONFIGURED.EXAMPLE.").await.is_some());
        assert_eq!(issuer.calls.lock().len(), 1, "the second call was cached");
    }

    #[tokio::test]
    async fn resolve_pem_returns_manual_cert() {
        let manager = test_manager();
        manager.add_manual_cert("example.com", "CERT_PEM".to_string(), "KEY_PEM".to_string());

        let resolved = manager.resolve_pem("example.com").await;
        assert_eq!(
            resolved,
            Some(("CERT_PEM".to_string(), "KEY_PEM".to_string()))
        );

        // Unknown domains fall through to ACME (disabled here) and return None.
        assert!(manager.resolve_pem("other.example.com").await.is_none());
    }

    #[tokio::test]
    async fn startup_hydrates_persisted_certificates_into_the_cache() {
        let directory = tempfile::tempdir().unwrap();
        let data = serde_json::json!({
            "cert_pem": "LEAF_CERT_PEM",
            "key_pem": "LEAF_KEY_PEM",
            "domains": ["example.com"],
            "expires_at": 4_102_444_800_i64,
        });
        std::fs::write(
            directory.path().join("example_com.json"),
            serde_json::to_vec(&data).unwrap(),
        )
        .unwrap();

        let manager = TlsManager::new(Some(AutoHttpsConfig::default()), directory.path())
            .await
            .unwrap();

        // 🗃️ A cold start must see the persisted bundle immediately, so the
        // first handshake does not trigger a pointless ACME re-issuance.
        assert_eq!(
            manager.peek_pem("example.com").await,
            Some(("LEAF_CERT_PEM".to_string(), "LEAF_KEY_PEM".to_string()))
        );
    }

    #[tokio::test]
    async fn resolve_pem_prefers_manual_over_acme() {
        // Even with auto_https disabled the manual lookup must happen first;
        // the key property is that a manual entry is returned verbatim.
        let manager = test_manager();
        manager.add_manual_cert("a.example.com", "A_CERT".to_string(), "A_KEY".to_string());
        manager.add_manual_cert("b.example.com", "B_CERT".to_string(), "B_KEY".to_string());

        assert_eq!(
            manager.resolve_pem("b.example.com").await,
            Some(("B_CERT".to_string(), "B_KEY".to_string()))
        );
    }

    #[tokio::test]
    async fn peek_pem_returns_manual_cert_without_issuance() {
        let manager = test_manager();
        manager.add_manual_cert("example.com", "CERT_PEM".to_string(), "KEY_PEM".to_string());

        assert_eq!(
            manager.peek_pem("example.com").await,
            Some(("CERT_PEM".to_string(), "KEY_PEM".to_string()))
        );

        // Unknown domains return None without triggering any issuance flow.
        assert!(manager.peek_pem("other.example.com").await.is_none());
    }

    #[tokio::test]
    async fn internal_certificate_is_persistent_and_visible_to_h3() {
        let directory = tempfile::tempdir().unwrap();
        let manager = TlsManager::new_with_memory_challenges(None, directory.path());
        let first = manager
            .enable_internal_domain("Origin.Example.Test.")
            .await
            .unwrap();

        assert_eq!(
            manager.peek_pem("origin.example.test").await,
            Some(first.clone())
        );
        assert_eq!(
            manager.resolve_pem("origin.example.test").await,
            Some(first.clone())
        );
        assert!(
            manager
                .resolve_pem("unconfigured.example.test")
                .await
                .is_none()
        );

        let restarted = TlsManager::new_with_memory_challenges(None, directory.path());
        let second = restarted
            .enable_internal_domain("origin.example.test")
            .await
            .unwrap();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn wildcard_internal_domains_cover_concrete_snis() {
        let directory = tempfile::tempdir().unwrap();
        let manager = TlsManager::new_with_memory_challenges(None, directory.path());
        manager
            .enable_internal_domain("*.sandbox.localhost")
            .await
            .unwrap();

        let (cert, key) = manager
            .resolve_pem("123.sandbox.localhost")
            .await
            .expect("a wildcard internal domain must cover a subdomain SNI");
        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("PRIVATE KEY"));
        assert_eq!(
            manager.peek_pem("456.sandbox.localhost").await,
            Some((cert, key)),
            "peek_pem must resolve the same wildcard leaf without ACME"
        );

        // 🧭 A bare suffix is not covered by `*.suffix`, matching DNS
        // wildcard semantics; it must not fall through to public issuance.
        assert!(manager.resolve_pem("sandbox.localhost").await.is_none());
    }

    #[tokio::test]
    async fn manual_certificate_precedes_internal_issuance() {
        let directory = tempfile::tempdir().unwrap();
        let manager = TlsManager::new_with_memory_challenges(None, directory.path());
        manager
            .enable_internal_domain("origin.example.test")
            .await
            .unwrap();
        manager.add_manual_cert(
            "origin.example.test",
            "MANUAL_CERT".to_string(),
            "MANUAL_KEY".to_string(),
        );

        assert_eq!(
            manager.resolve_pem("origin.example.test").await,
            Some(("MANUAL_CERT".to_string(), "MANUAL_KEY".to_string()))
        );
    }
}

/// 🔐 Free-function wrapper so the validator can be unit-tested directly.
fn validate_pem_pair(cert_pem: &str, key_pem: &str) -> Result<(), String> {
    TlsManager::validate_pem_pair_impl(cert_pem, key_pem)
}

#[cfg(test)]
mod manual_cert_refresh_tests {
    use super::*;

    fn real_pair() -> (String, String) {
        let cert =
            rcgen::generate_simple_self_signed(vec!["example.com".to_string()]).expect("generate");
        (cert.cert.pem(), cert.signing_key.serialize_pem())
    }

    /// 🔐 A usable pair passes.
    #[test]
    fn a_well_formed_pair_validates() {
        let (cert, key) = real_pair();
        assert!(validate_pem_pair(&cert, &key).is_ok());
    }

    /// ✂️ **The half-written file.** A copy interrupted partway leaves a cert
    /// whose PEM never closes, and the naive check — "the file exists" — is
    /// perfectly happy with it. The failure then arrives at handshake time, to
    /// a real client, on a site that worked a second ago.
    #[test]
    fn a_truncated_certificate_is_rejected() {
        let (cert, key) = real_pair();
        let truncated = &cert[..cert.len() / 2];
        let error = validate_pem_pair(truncated, &key)
            .expect_err("a truncated certificate must not be accepted");
        assert!(
            error.contains("certificate"),
            "the diagnosis must name the certificate, not the key: {error}"
        );
    }

    /// ✂️ The mirror case: the cert landed and the key is still arriving.
    #[test]
    fn a_missing_key_is_rejected_by_name() {
        let (cert, _) = real_pair();
        let error = validate_pem_pair(&cert, "").expect_err("an empty key must not be accepted");
        assert!(
            error.contains("key"),
            "the diagnosis must name the key: {error}"
        );
    }

    /// 🧱 **The atomicity property.** One bad pair must leave the table
    /// untouched, not install the good ones and skip the bad one — a partial
    /// rotation is how some domains end up on the new certificate and one ends
    /// up on a cert whose key has not arrived.
    #[test]
    fn one_bad_pair_leaves_the_previous_table_intact() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert, key) = real_pair();
        let good_cert = dir.path().join("good.crt");
        let good_key = dir.path().join("good.key");
        std::fs::write(&good_cert, &cert).unwrap();
        std::fs::write(&good_key, &key).unwrap();

        let manager = TlsManager::new_with_memory_challenges(None, dir.path());
        let good = vec![(
            "a.example".to_string(),
            good_cert.to_string_lossy().into_owned(),
            good_key.to_string_lossy().into_owned(),
        )];
        assert_eq!(manager.refresh_manual_certs(&good).unwrap(), 1);

        // 🩹 Now attempt a rotation where one domain's certificate is truncated.
        let bad_cert = dir.path().join("bad.crt");
        std::fs::write(&bad_cert, &cert[..cert.len() / 2]).unwrap();
        let mixed = vec![
            good[0].clone(),
            (
                "b.example".to_string(),
                bad_cert.to_string_lossy().into_owned(),
                good_key.to_string_lossy().into_owned(),
            ),
        ];
        let problems = manager
            .refresh_manual_certs(&mixed)
            .expect_err("a bad pair must reject the whole refresh");
        assert_eq!(problems.len(), 1);
        assert!(
            problems[0].contains("b.example"),
            "the failing domain must be named: {:?}",
            problems
        );

        // 🎯 The domain that was already serving must be untouched — and
        // crucially `b.example` must NOT have been installed.
        assert!(
            manager.has_manual_cert("a.example"),
            "the working certificate was dropped by a failed refresh"
        );
        assert!(
            !manager.has_manual_cert("b.example"),
            "a certificate that failed validation was installed anyway"
        );
    }
}
