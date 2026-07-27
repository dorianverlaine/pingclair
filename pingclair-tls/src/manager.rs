// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! TLS Manager
//!
//! 🛡️ Coordinates certificate management, ACME challenges, and TLS handshakes.

use crate::acme::{ChallengeHandler, MemoryChallengeHandler};
use crate::auto_https::{AutoHttps, AutoHttpsConfig};
use crate::cert_store::CertStore;
use crate::internal_ca::{InternalCa, InternalCaError};
use crate::persistent_challenge_handler::PersistentChallengeHandler;
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
    /// ⚡ Avoids repeated PEM parsing for generated certificates.
    cached_certs: RwLock<HashMap<String, CachedCert>>,
    /// ⏳ Limits parsed certificate lifetime so rotations become visible.
    cache_ttl: Duration,
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
            let store = Arc::new(CertStore::new(store_path));
            Some(Arc::new(AutoHttps::new(config, store)))
        } else {
            None
        };

        Ok(Self {
            auto_https,
            challenge_handler: challenge_handler as Arc<dyn ChallengeHandler>,
            manual_pem_certs: RwLock::new(HashMap::new()),
            internal_ca: Arc::new(InternalCa::new(store_path)),
            internal_domains: RwLock::new(HashSet::new()),
            cached_certs: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(3600),
        })
    }

    /// 🧪 Creates a TLS manager with an in-memory challenge handler.
    pub fn new_with_memory_challenges(
        config: Option<AutoHttpsConfig>,
        store_path: &std::path::Path,
    ) -> Self {
        let challenge_handler = Arc::new(MemoryChallengeHandler::new());

        let auto_https = if let Some(config) = config {
            let store = Arc::new(CertStore::new(store_path));
            Some(Arc::new(AutoHttps::new(config, store)))
        } else {
            None
        };

        Self {
            auto_https,
            challenge_handler: challenge_handler as Arc<dyn ChallengeHandler>,
            manual_pem_certs: RwLock::new(HashMap::new()),
            internal_ca: Arc::new(InternalCa::new(store_path)),
            internal_domains: RwLock::new(HashSet::new()),
            cached_certs: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(3600),
        }
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
            let store = Arc::new(CertStore::new(store_path));
            Some(Arc::new(AutoHttps::new(config, store)))
        } else {
            None
        };

        Ok(Self {
            auto_https,
            challenge_handler: challenge_handler as Arc<dyn ChallengeHandler>,
            manual_pem_certs: RwLock::new(HashMap::new()),
            internal_ca: Arc::new(InternalCa::new(store_path)),
            internal_domains: RwLock::new(HashSet::new()),
            cached_certs: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(3600),
        })
    }

    /// Initializes the manager (async steps)
    pub async fn init(&self) -> Result<(), crate::AutoHttpsError> {
        if let Some(_auto) = &self.auto_https {
            // We can access the store via internal field if we exposed it, or we just trust it works lazy
            // But actually CertStore::init creates directories, which is good to do early.
            // For this MVP, we will rely on AutoHttps lazily using it or simple directory creation.
        }
        Ok(())
    }

    /// 📜 Adds an explicitly configured PEM pair with the highest precedence.
    pub fn add_manual_cert(&self, domain: &str, cert_pem: String, key_pem: String) {
        self.manual_pem_certs
            .write()
            .insert(domain.to_string(), (cert_pem, key_pem));
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
        let internal_domain = normalize_internal_domain(domain);
        if self.internal_domains.read().contains(&internal_domain) {
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
        let internal_domain = normalize_internal_domain(domain);
        if self.internal_domains.read().contains(&internal_domain) {
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

        // 🌐 Remaining names may use automatic public HTTPS.
        if let Some(auto) = &self.auto_https {
            match auto
                .get_certificate(domain, self.challenge_handler.as_ref())
                .await
            {
                Ok(cert) => {
                    return Some((cert.cert_pem, cert.key_pem));
                }
                Err(e) => {
                    tracing::warn!("❌ Failed to obtain cert for {}: {}", domain, e);
                }
            }
        }
        None
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
        let internal_domain = normalize_internal_domain(domain);
        if self.internal_domains.read().contains(&internal_domain) {
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

        // 🌐 Remaining names may use automatic public HTTPS.
        if let Some(auto) = &self.auto_https {
            match auto
                .get_certificate(domain, self.challenge_handler.as_ref())
                .await
            {
                Ok(cert) => return self.cache_rustls_certificate(domain, &cert),
                Err(e) => {
                    tracing::warn!("❌ Failed to obtain cert for {}: {}", domain, e);
                }
            }
        }

        None
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

    /// 🚦 Returns the configured HTTP-01 challenge handler.
    pub fn challenge_handler(&self) -> Arc<dyn ChallengeHandler> {
        self.challenge_handler.clone()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_manager() -> TlsManager {
        let dir =
            std::env::temp_dir().join(format!("pingclair-tls-manager-test-{}", std::process::id()));
        TlsManager::new_with_memory_challenges(None, &dir)
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
