//! TLS Manager
//!
//! 🛡️ Coordinates certificate management, ACME challenges, and TLS handshakes.

use crate::auto_https::{AutoHttps, AutoHttpsConfig};
use crate::cert_store::CertStore;
use crate::acme::{ChallengeHandler, MemoryChallengeHandler};
use crate::persistent_challenge_handler::PersistentChallengeHandler;
use std::sync::Arc;
use std::collections::HashMap;
use tokio_rustls::rustls;
use parking_lot::RwLock;
use std::time::{SystemTime, UNIX_EPOCH, Duration};

/// Certificate entry with expiration tracking
#[derive(Clone)]
struct CachedCert {
    certified_key: Arc<rustls::sign::CertifiedKey>,
    /// Unix timestamp when cert expires
    expires_at: u64,
    /// Unix timestamp when cert was cached
    cached_at: u64,
}

/// 🛡️ TLS Manager for Pingclair
pub struct TlsManager {
    /// Auto HTTPS manager
    auto_https: Option<Arc<AutoHttps>>,
    /// Challenge handler (HTTP-01) - can be either memory or persistent
    challenge_handler: Arc<dyn ChallengeHandler>,
    /// Fallback/Manual certificates (domain -> cert)
    manual_certs: HashMap<String, Arc<rustls::sign::CertifiedKey>>,
    /// Cached parsed CertifiedKey from ACME certs (domain -> cached key with metadata)
    /// Avoids expensive PEM parsing on every TLS handshake
    cached_certs: RwLock<HashMap<String, CachedCert>>,
    /// Cache TTL in seconds (default 1 hour to avoid stale entries)
    cache_ttl: Duration,
}

impl TlsManager {
    /// Create a new TLS manager with persistent challenge handler (default)
    pub async fn new(config: Option<AutoHttpsConfig>, store_path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Use persistent challenge handler by default
        let challenge_storage_path = store_path.join("acme-challenges.json");
        let challenge_handler = Arc::new(PersistentChallengeHandler::new(challenge_storage_path).await?);

        let auto_https = if let Some(config) = config {
            let store = Arc::new(CertStore::new(store_path));
            Some(Arc::new(AutoHttps::new(config, store)))
        } else {
            None
        };

        Ok(Self {
            auto_https,
            challenge_handler: challenge_handler as Arc<dyn ChallengeHandler>,
            manual_certs: HashMap::new(),
            cached_certs: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(3600), // 1 hour default TTL
        })
    }

    /// Create a new TLS manager with memory-based challenge handler (legacy)
    pub fn new_with_memory_challenges(config: Option<AutoHttpsConfig>, store_path: &std::path::Path) -> Self {
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
            manual_certs: HashMap::new(),
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
        let challenge_handler = Arc::new(PersistentChallengeHandler::new(challenge_storage_path.to_path_buf()).await?);

        let auto_https = if let Some(config) = config {
            let store = Arc::new(CertStore::new(store_path));
            Some(Arc::new(AutoHttps::new(config, store)))
        } else {
            None
        };

        Ok(Self {
            auto_https,
            challenge_handler: challenge_handler as Arc<dyn ChallengeHandler>,
            manual_certs: HashMap::new(),
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

    /// 🔍 Resolve a certificate for a client hello (SNI) as PEM
    pub async fn resolve_pem(&self, domain: &str) -> Option<(String, String)> {
        // 1. Check manual certs? (Manual certs currently store CertifiedKey, need to change to PEM)
        // For now let's focus on Auto HTTPS which has PEMs in Certificate struct
        
        if let Some(auto) = &self.auto_https {
             match auto.get_certificate(domain, self.challenge_handler.as_ref()).await {
                 Ok(cert) => {
                     return Some((cert.cert_pem, cert.key_pem));
                 },
                 Err(e) => {
                     tracing::warn!("❌ Failed to obtain cert for {}: {}", domain, e);
                 }
             }
        }
        None
    }

    /// 🔍 Resolve a certificate for a client hello (SNI) as rustls CertifiedKey
    pub async fn resolve_cert(&self, domain: &str) -> Option<Arc<rustls::sign::CertifiedKey>> {
        // 1. Check manual certs
        if let Some(cert) = self.manual_certs.get(domain) {
            return Some(cert.clone());
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
                    tracing::debug!("⏰ Cached certificate expired for {}, removing from cache", domain);
                }
            }
        }
 
        // 3. Auto HTTPS (may need to fetch/renew from ACME)
        if let Some(auto) = &self.auto_https {
             match auto.get_certificate(domain, self.challenge_handler.as_ref()).await {
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
                         self.cached_certs.write().insert(domain.to_string(), cached_entry);
                         tracing::info!("🔐 Cached new CertifiedKey for {} (expires in {}s)", domain, self.cache_ttl.as_secs());
                         return Some(key_arc);
                     }
                 },
                 Err(e) => {
                     tracing::warn!("❌ Failed to obtain cert for {}: {}", domain, e);
                 }
             }
        }
        
        None
    }
    
    /// Convert internal Certificate to rustls::sign::CertifiedKey
    fn convert_to_rustls(&self, cert: &crate::Certificate) -> Result<rustls::sign::CertifiedKey, String> {
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
        cache_guard.retain(|_domain, cached| {
            current_time < cached.expires_at
        });
        
        tracing::debug!("🧹 Cleaned expired certificate cache entries");
    }

    /// Update cache TTL
    pub fn set_cache_ttl(&mut self, ttl: Duration) {
        self.cache_ttl = ttl;
    }
}
