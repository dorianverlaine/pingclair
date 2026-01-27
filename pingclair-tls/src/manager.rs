//! TLS Manager
//!
//! 🛡️ Coordinates certificate management, ACME challenges, and TLS handshakes.

use crate::auto_https::{AutoHttps, AutoHttpsConfig};
use crate::cert_store::CertStore;
use crate::acme::MemoryChallengeHandler;
use std::sync::Arc;
use std::collections::HashMap;
use tokio_rustls::rustls;
use parking_lot::RwLock;

/// 🛡️ TLS Manager for Pingclair
pub struct TlsManager {
    /// Auto HTTPS manager
    auto_https: Option<Arc<AutoHttps>>,
    /// Challenge handler (HTTP-01)
    challenge_handler: Arc<MemoryChallengeHandler>,
    /// Fallback/Manual certificates (domain -> cert)
    manual_certs: HashMap<String, Arc<rustls::sign::CertifiedKey>>,
    /// Cached parsed CertifiedKey from ACME certs (domain -> cached key)
    /// Avoids expensive PEM parsing on every TLS handshake
    cached_certs: RwLock<HashMap<String, Arc<rustls::sign::CertifiedKey>>>,
}

impl TlsManager {
    /// Create a new TLS manager
    pub fn new(config: Option<AutoHttpsConfig>, store_path: &std::path::Path) -> Self {
        let challenge_handler = Arc::new(MemoryChallengeHandler::new());
        
        let auto_https = if let Some(config) = config {
            let store = Arc::new(CertStore::new(store_path));
            // Initialize store in background? For now assuming initialized by caller or on first use
            // but CertStore::init is async. In a real app we'd await it.
            
            Some(Arc::new(AutoHttps::new(config, store)))
        } else {
            None
        };
        
        Self {
            auto_https,
            challenge_handler,
            manual_certs: HashMap::new(),
            cached_certs: RwLock::new(HashMap::new()),
        }
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
        if let Some(cached) = self.cached_certs.read().get(domain) {
            tracing::debug!("🔐 Using cached CertifiedKey for {}", domain);
            return Some(cached.clone());
        }
 
        // 3. Auto HTTPS (may need to fetch/renew from ACME)
        if let Some(auto) = &self.auto_https {
             match auto.get_certificate(domain, self.challenge_handler.as_ref()).await {
                 Ok(cert) => {
                     // Convert to rustls CertifiedKey and cache it
                     if let Ok(key) = self.convert_to_rustls(&cert) {
                         let key_arc = Arc::new(key);
                         // Cache the converted key to avoid future PEM parsing
                         self.cached_certs.write().insert(domain.to_string(), key_arc.clone());
                         tracing::info!("🔐 Cached new CertifiedKey for {}", domain);
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
    pub fn challenge_handler(&self) -> Arc<MemoryChallengeHandler> {
        self.challenge_handler.clone()
    }
}
