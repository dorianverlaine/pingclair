//! TLS Manager
//!
//! 🛡️ Coordinates certificate management, ACME challenges, and TLS handshakes.

use crate::acme::{ChallengeHandler, MemoryChallengeHandler};
use crate::auto_https::{AutoHttps, AutoHttpsConfig};
use crate::cert_store::CertStore;
use crate::persistent_challenge_handler::PersistentChallengeHandler;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_rustls::rustls;

/// Certificate entry with expiration tracking
#[derive(Clone)]
struct CachedCert {
    certified_key: Arc<rustls::sign::CertifiedKey>,
    /// Unix timestamp when cert expires
    expires_at: u64,
    /// Unix timestamp when cert was cached
    #[allow(dead_code)]
    cached_at: u64,
}

/// 🛡️ TLS Manager for Pingclair
pub struct TlsManager {
    /// Auto HTTPS manager
    auto_https: Option<Arc<AutoHttps>>,
    /// Challenge handler (HTTP-01) - can be either memory or persistent
    challenge_handler: Arc<dyn ChallengeHandler>,
    /// Manually configured certificates in PEM form (domain -> (cert_pem, key_pem)).
    /// Loaded from the config file at startup; takes precedence over ACME certs.
    manual_pem_certs: RwLock<HashMap<String, (String, String)>>,
    /// Cached parsed CertifiedKey from ACME certs (domain -> cached key with metadata)
    /// Avoids expensive PEM parsing on every TLS handshake
    cached_certs: RwLock<HashMap<String, CachedCert>>,
    /// Cache TTL in seconds (default 1 hour to avoid stale entries)
    cache_ttl: Duration,
}

impl TlsManager {
    /// Create a new TLS manager with persistent challenge handler (default)
    pub async fn new(
        config: Option<AutoHttpsConfig>,
        store_path: &std::path::Path,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Use persistent challenge handler by default
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
            cached_certs: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(3600), // 1 hour default TTL
        })
    }

    /// Create a new TLS manager with memory-based challenge handler (legacy)
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
            cached_certs: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(3600), // 1 hour default TTL
        }
    }

    /// Create a new TLS manager with custom persistent challenge storage path
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
            cached_certs: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(3600), // 1 hour default TTL
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

    /// Add a manually configured certificate (PEM form) for a domain.
    /// Manual certificates take precedence over ACME-issued ones.
    pub fn add_manual_cert(&self, domain: &str, cert_pem: String, key_pem: String) {
        self.manual_pem_certs
            .write()
            .insert(domain.to_string(), (cert_pem, key_pem));
    }

    /// 🔍 Resolve a certificate PEM pair WITHOUT triggering ACME issuance.
    ///
    /// Checks manual certificates first, then certificates already present in
    /// the ACME store cache. Unlike [`TlsManager::resolve_pem`] this never
    /// starts an issuance flow — it only surfaces material that already
    /// exists. Used to populate the HTTP/3 SNI certificate table, where new
    /// issuance must stay on the lazy HTTP/1.1 handshake path.
    pub async fn peek_pem(&self, domain: &str) -> Option<(String, String)> {
        // 1. Manual certs (PEM pair configured in the config file)
        let manual = self.manual_pem_certs.read().get(domain).cloned();
        if let Some(pems) = manual {
            return Some(pems);
        }

        // 2. Already-issued ACME certs (store cache only — no issuance)
        if let Some(auto) = &self.auto_https
            && let Some(cert) = auto.cached_certificate(domain).await
        {
            return Some((cert.cert_pem, cert.key_pem));
        }
        None
    }

    /// 🔍 Resolve a certificate for a client hello (SNI) as PEM
    pub async fn resolve_pem(&self, domain: &str) -> Option<(String, String)> {
        // 1. Check manual certs (PEM pair configured in the config file)
        let manual = self.manual_pem_certs.read().get(domain).cloned();
        if let Some(pems) = manual {
            return Some(pems);
        }

        // 2. Auto HTTPS (ACME store)
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

    /// 🔍 Resolve a certificate for a client hello (SNI) as rustls CertifiedKey
    pub async fn resolve_cert(&self, domain: &str) -> Option<Arc<rustls::sign::CertifiedKey>> {
        // 1. Check manual certs (PEM pair configured in the config file)
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

        // 2. Check cached CertifiedKey (fast path - no PEM parsing)
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        {
            let cache_guard = self.cached_certs.read();
            if let Some(cached) = cache_guard.get(domain) {
                // Check if cache entry is still valid (not expired by TTL)
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

        // 3. Auto HTTPS (may need to fetch/renew from ACME)
        if let Some(auto) = &self.auto_https {
            match auto
                .get_certificate(domain, self.challenge_handler.as_ref())
                .await
            {
                Ok(cert) => {
                    // Convert to rustls CertifiedKey and cache it
                    if let Ok(key) = self.convert_to_rustls(&cert) {
                        let key_arc = Arc::new(key);
                        let current_time = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or(Duration::from_secs(0))
                            .as_secs();
                        let expires_at = current_time + self.cache_ttl.as_secs();

                        let cached_entry = CachedCert {
                            certified_key: key_arc.clone(),
                            expires_at,
                            cached_at: current_time,
                        };

                        // Cache the converted key to avoid future PEM parsing
                        self.cached_certs
                            .write()
                            .insert(domain.to_string(), cached_entry);
                        tracing::info!(
                            "🔐 Cached new CertifiedKey for {} (expires in {}s)",
                            domain,
                            self.cache_ttl.as_secs()
                        );
                        return Some(key_arc);
                    }
                }
                Err(e) => {
                    tracing::warn!("❌ Failed to obtain cert for {}: {}", domain, e);
                }
            }
        }

        None
    }

    /// Convert internal Certificate to rustls::sign::CertifiedKey
    fn convert_to_rustls(
        &self,
        cert: &crate::Certificate,
    ) -> Result<rustls::sign::CertifiedKey, String> {
        use rustls::pki_types::CertificateDer;

        // Parse Chain
        let mut reader = std::io::Cursor::new(&cert.cert_pem);
        let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut reader)
            .filter_map(|r| r.ok())
            .collect();

        if certs.is_empty() {
            return Err("No certificates found".to_string());
        }

        // Parse Key
        let mut reader = std::io::Cursor::new(&cert.key_pem);
        let key = rustls_pemfile::private_key(&mut reader)
            .map_err(|e| e.to_string())?
            .ok_or("No private key found")?;

        // Verify key type
        // Verify key type
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
            .map_err(|_| "Unsupported key type".to_string())?;

        Ok(rustls::sign::CertifiedKey::new(certs, signing_key))
    }

    /// Get the challenge handler for HTTP-01
    pub fn challenge_handler(&self) -> Arc<dyn ChallengeHandler> {
        self.challenge_handler.clone()
    }

    /// Clean expired cache entries
    pub fn cleanup_expired_cache(&self) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        let mut cache_guard = self.cached_certs.write();
        cache_guard.retain(|_domain, cached| current_time < cached.expires_at);

        tracing::debug!("🧹 Cleaned expired certificate cache entries");
    }

    /// Update cache TTL
    pub fn set_cache_ttl(&mut self, ttl: Duration) {
        self.cache_ttl = ttl;
    }
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
}
