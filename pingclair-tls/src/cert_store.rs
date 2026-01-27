//! Certificate storage and management
//!
//! 💾 Provides persistent storage for certificates with hot-reload support.

use crate::acme::Certificate;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use thiserror::Error;

/// Certificate store errors
#[derive(Debug, Error)]
pub enum CertStoreError {
    #[error("💥 IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("🔍 Certificate not found for domain: {0}")]
    NotFound(String),
    
    #[error("⚠️ Invalid certificate: {0}")]
    Invalid(String),
}

/// 🗄️ Certificate store for managing TLS certificates
pub struct CertStore {
    /// Storage directory
    path: PathBuf,
    /// In-memory cache
    cache: Arc<RwLock<HashMap<String, Certificate>>>,
}

impl CertStore {
    /// Create a new certificate store
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Create a store in the default location
    pub fn default_path() -> PathBuf {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("pingclair")
            .join("certs")
    }
    
    /// 🚀 Initialize the store (create directories)
    pub async fn init(&self) -> Result<(), CertStoreError> {
        tracing::info!("📁 Initializing certificate store at {:?}", self.path);
        tokio::fs::create_dir_all(&self.path).await?;
        self.load_all().await?;
        tracing::info!("✅ Certificate store initialized");
        Ok(())
    }
    
    /// 📂 Load all certificates from disk
    async fn load_all(&self) -> Result<(), CertStoreError> {
        let mut entries = tokio::fs::read_dir(&self.path).await?;
        let mut cache = self.cache.write().await;
        let mut count = 0;
        
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(content) = tokio::fs::read_to_string(&path).await {
                    if let Ok(cert) = serde_json::from_str::<CertificateData>(&content) {
                        for domain in &cert.domains {
                            cache.insert(domain.clone(), Certificate {
                                cert_pem: cert.cert_pem.clone(),
                                key_pem: cert.key_pem.clone(),
                                domains: cert.domains.clone(),
                                expires_at: cert.expires_at,
                            });
                        }
                        count += 1;
                    }
                }
            }
        }
        
        tracing::info!("📜 Loaded {} certificate(s) from disk", count);
        Ok(())
    }
    
    /// 💾 Store a certificate
    pub async fn store(&self, cert: &Certificate) -> Result<(), CertStoreError> {
        let primary_domain = cert.domains.first()
            .ok_or_else(|| CertStoreError::Invalid("No domains in certificate".to_string()))?;
        
        tracing::info!("💾 Storing certificate for {}", primary_domain);
        
        // Save to disk
        let data = CertificateData {
            cert_pem: cert.cert_pem.clone(),
            key_pem: cert.key_pem.clone(),
            domains: cert.domains.clone(),
            expires_at: cert.expires_at,
        };
        
        let json = serde_json::to_string_pretty(&data)
            .map_err(|e| CertStoreError::Invalid(e.to_string()))?;
        
        let file_path = self.path.join(format!("{}.json", primary_domain.replace('.', "_")));
        tokio::fs::write(&file_path, json).await?;
        
        // Update cache
        let mut cache = self.cache.write().await;
        for domain in &cert.domains {
            cache.insert(domain.clone(), cert.clone());
        }
        
        tracing::info!("✅ Certificate stored for {} ({} domain(s))", primary_domain, cert.domains.len());
        Ok(())
    }
    
    /// 🔍 Get a certificate for a domain
    pub async fn get(&self, domain: &str) -> Option<Certificate> {
        let cache = self.cache.read().await;
        cache.get(domain).cloned()
    }
    
    /// ✅ Check if a certificate exists and is valid
    pub async fn has_valid(&self, domain: &str) -> bool {
        if let Some(cert) = self.get(domain).await {
            !cert.needs_renewal()
        } else {
            false
        }
    }
    
    /// ⏰ Get all certificates that need renewal
    pub async fn get_needing_renewal(&self) -> Vec<Certificate> {
        let cache = self.cache.read().await;
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        
        for cert in cache.values() {
            let key = cert.domains.join(",");
            if !seen.contains(&key) && cert.needs_renewal() {
                seen.insert(key);
                result.push(cert.clone());
            }
        }
        
        if !result.is_empty() {
            tracing::info!("⏰ Found {} certificate(s) needing renewal", result.len());
        }
        
        result
    }
    
    /// 🗑️ Remove a certificate
    pub async fn remove(&self, domain: &str) -> Result<(), CertStoreError> {
        tracing::info!("🗑️ Removing certificate for {}", domain);
        
        let mut cache = self.cache.write().await;
        
        if let Some(cert) = cache.remove(domain) {
            // Remove from disk
            if let Some(primary) = cert.domains.first() {
                let file_path = self.path.join(format!("{}.json", primary.replace('.', "_")));
                let _ = tokio::fs::remove_file(&file_path).await;
            }
            
            // Remove other domain mappings
            for d in &cert.domains {
                cache.remove(d);
            }
            
            tracing::info!("✅ Certificate removed for {}", domain);
        }
        
        Ok(())
    }
}

/// Serializable certificate data
#[derive(serde::Serialize, serde::Deserialize)]
struct CertificateData {
    cert_pem: String,
    key_pem: String,
    domains: Vec<String>,
    expires_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_cert_store() {
        let temp_dir = std::env::temp_dir().join("pingclair_test_certs");
        let store = CertStore::new(&temp_dir);
        
        store.init().await.unwrap();
        
        let cert = Certificate {
            cert_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
            key_pem: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----".to_string(),
            domains: vec!["test.example.com".to_string()],
            expires_at: 0,
        };
        
        store.store(&cert).await.unwrap();
        
        let loaded = store.get("test.example.com").await;
        assert!(loaded.is_some());
        
        // Cleanup
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
