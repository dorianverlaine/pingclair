//! Certificate Storage Management
//!
//! 💾 Handles the persistent storage and lifecycle of TLS certificates.
//! Supports disk-based persistence with an in-memory readout cache for high performance.
//!
//! **Structure:**
//! - Metadata + PEMs are stored as JSON files on disk.
//! - Filenames are derived from the primary domain (sanitized).

use crate::acme::Certificate;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use thiserror::Error;

// MARK: - Errors

#[derive(Debug, Error)]
pub enum CertStoreError {
    #[error("💥 IO Error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("🔍 Not Found: Certificate for {0} does not exist")]
    NotFound(String),
    
    #[error("⚠️ Invalid Format: {0}")]
    Invalid(String),
}

// MARK: - Data Structures

/// Internal serializable representation of a certificate on disk.
#[derive(serde::Serialize, serde::Deserialize)]
struct CertificateData {
    cert_pem: String,
    key_pem: String,
    domains: Vec<String>,
    expires_at: i64,
}

// MARK: - Certificate Store

/// A thread-safe, persistent store for TLS certificates.
pub struct CertStore {
    /// Root directory for persistence.
    path: PathBuf,
    
    /// Write-through cache of loaded certificates.
    /// Key: Domain name (each SAN entry points to the cert).
    cache: Arc<RwLock<HashMap<String, Certificate>>>,
}

impl CertStore {
    /// Creates a new `CertStore` backed by the specified directory.
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Resolves the default system path for certificate storage.
    /// Typically `~/.local/share/pingclair/certs` on Linux/macOS.
    pub fn default_path() -> PathBuf {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("pingclair")
            .join("certs")
    }
    
    /// Initializes the store by creating directories and loading existing data.
    pub async fn init(&self) -> Result<(), CertStoreError> {
        tracing::info!("📁 Initializing CertStore at {:?}", self.path);
        
        // Ensure directory exists
        tokio::fs::create_dir_all(&self.path).await?;
        
        // Hydrate cache
        self.load_all().await?;
        
        tracing::info!("✅ CertStore ready");
        Ok(())
    }
    
    /// Loads all JSON certificate files from the storage directory into memory.
    async fn load_all(&self) -> Result<(), CertStoreError> {
        let mut entries = tokio::fs::read_dir(&self.path).await?;
        let mut cache = self.cache.write().await;
        let mut count = 0;
        
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                // Try processing the file
                match tokio::fs::read_to_string(&path).await {
                    Ok(content) => {
                        match serde_json::from_str::<CertificateData>(&content) {
                            Ok(data) => {
                                let cert = Certificate {
                                    cert_pem: data.cert_pem,
                                    key_pem: data.key_pem,
                                    domains: data.domains.clone(),
                                    expires_at: data.expires_at,
                                };
                                
                                // Map all domains in the cert to this entry
                                for domain in &cert.domains {
                                    cache.insert(domain.clone(), cert.clone());
                                }
                                count += 1;
                            },
                            Err(e) => {
                                tracing::warn!("⚠️ Skipping corrupt cert file {:?}: {}", path, e);
                            }
                        }
                    },
                    Err(e) => {
                        tracing::warn!("⚠️ Failed to read cert file {:?}: {}", path, e);
                    }
                }
            }
        }
        
        if count > 0 {
            tracing::info!("📜 Hydrated {} certificate(s) from disk", count);
        }
        Ok(())
    }
    
    /// Persists a certificate to disk and updates the cache.
    ///
    /// The filename is derived from the primary (first) domain in the list.
    pub async fn store(&self, cert: &Certificate) -> Result<(), CertStoreError> {
        let primary_domain = cert.domains.first()
            .ok_or_else(|| CertStoreError::Invalid("Certificate has no domains".to_string()))?;
        
        tracing::debug!("💾 Persisting certificate for {}", primary_domain);
        
        // 1. Prepare Data
        let data = CertificateData {
            cert_pem: cert.cert_pem.clone(),
            key_pem: cert.key_pem.clone(),
            domains: cert.domains.clone(),
            expires_at: cert.expires_at,
        };
        
        let json = serde_json::to_string_pretty(&data)
            .map_err(|e| CertStoreError::Invalid(e.to_string()))?;
        
        // 2. Write to Disk
        let safe_filename = primary_domain.replace('.', "_");
        let file_path = self.path.join(format!("{}.json", safe_filename));
        
        tokio::fs::write(&file_path, json).await?;
        
        // 3. Update Cache
        let mut cache = self.cache.write().await;
        for domain in &cert.domains {
            cache.insert(domain.clone(), cert.clone());
        }
        
        tracing::info!("✅ Certificate stored successfully: {}", primary_domain);
        Ok(())
    }
    
    /// Retrieves a certificate from the in-memory cache.
    pub async fn get(&self, domain: &str) -> Option<Certificate> {
        let cache = self.cache.read().await;
        cache.get(domain).cloned()
    }
    
    /// Checks if a non-expired certificate exists for the domain.
    pub async fn has_valid(&self, domain: &str) -> bool {
        if let Some(cert) = self.get(domain).await {
            !cert.needs_renewal()
        } else {
            false
        }
    }
    
    /// Returns a list of all certificates that require renewal.
    ///
    /// Deduplicates results so each certificate is only listed once.
    pub async fn get_needing_renewal(&self) -> Vec<Certificate> {
        let cache = self.cache.read().await;
        let mut seen_primary_keys = std::collections::HashSet::new();
        let mut candidates = Vec::new();
        
        for cert in cache.values() {
            // Use the primary domain as a unique key for the certificate bundle
            let primary_key = cert.domains.first().cloned().unwrap_or_default();
            
            if !primary_key.is_empty() && !seen_primary_keys.contains(&primary_key) {
                if cert.needs_renewal() {
                    seen_primary_keys.insert(primary_key);
                    candidates.push(cert.clone());
                }
            }
        }
        
        candidates
    }
    
    /// Deletes a certificate (and its mappings) from both disk and cache.
    pub async fn remove(&self, domain: &str) -> Result<(), CertStoreError> {
        tracing::info!("🗑️ Requested removal of certificate for {}", domain);
        
        let mut cache = self.cache.write().await;
        
        if let Some(cert) = cache.get(domain).cloned() {
            // 1. Delete File
            if let Some(primary) = cert.domains.first() {
                let safe_filename = primary.replace('.', "_");
                let file_path = self.path.join(format!("{}.json", safe_filename));
                
                if file_path.exists() {
                    tokio::fs::remove_file(&file_path).await?;
                }
            }
            
            // 2. Clear Cache Entries
            for d in &cert.domains {
                cache.remove(d);
            }
            
            tracing::info!("✅ Certificate deleted for {}", domain);
        } else {
            tracing::warn!("⚠️ Certificate for {} not found during removal", domain);
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_store_lifecycle() {
        let temp_dir = std::env::temp_dir().join("pingclair_test_certs_lifecycle");
        let _ = tokio::fs::remove_dir_all(&temp_dir).await; // clean start
        
        let store = CertStore::new(&temp_dir);
        store.init().await.expect("Init failed");
        
        let cert = Certificate {
            cert_pem: "CERT".into(),
            key_pem: "KEY".into(),
            domains: vec!["a.com".into(), "b.com".into()],
            expires_at: 1234567890,
        };
        
        // Store
        store.store(&cert).await.expect("Store failed");
        
        // Verify Persistence
        let store2 = CertStore::new(&temp_dir);
        store2.init().await.expect("Re-init failed");
        
        assert!(store2.get("a.com").await.is_some());
        assert!(store2.get("b.com").await.is_some());
        
        // Cleanup
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
