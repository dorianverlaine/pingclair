//! Automatic HTTPS Management
//!
//! 🔐 Orchestra component that combines `AcmeClient` and `CertStore` to provide
//! "Zero Configuration" HTTPS. Handles the certificate lifecycle: issuance, storage, and renewal.

use crate::acme::{AcmeClient, Certificate, ChallengeHandler, AcmeError};
use crate::cert_store::{CertStore, CertStoreError};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;

// MARK: - Errors

/// Errors specific to the AutoHTTPS subsystem.
#[derive(Debug, Error)]
pub enum AutoHttpsError {
    #[error("🔐 ACME Protocol Error: {0}")]
    Acme(#[from] AcmeError),
    
    #[error("💾 Certificate Storage Error: {0}")]
    CertStore(#[from] CertStoreError),
    
    #[error("⚙️ Configuration Error: {0}")]
    Config(String),
}

// MARK: - Configuration

/// Configuration for the Automatic HTTPS system.
#[derive(Debug, Clone)]
pub struct AutoHttpsConfig {
    /// If false, AutoHTTPS logic is bypassed entirely.
    pub enabled: bool,
    
    /// If true, uses the Let's Encrypt Staging environment (Unstrusted roots).
    pub staging: bool,
    
    /// Email used for ACME account registration and expiry notices.
    pub email: Option<String>,
    
    /// How often to scan for certificates needing renewal.
    pub renewal_interval: Duration,
    
    /// Whether to enforce HTTP Strict Transport Security (HSTS).
    pub hsts: bool,
    
    /// HSTS `max-age` directive in seconds.
    pub hsts_max_age: u64,
    
    /// HSTS `includeSubDomains` directive.
    pub hsts_include_subdomains: bool,
    
    /// HSTS `preload` directive.
    pub hsts_preload: bool,
}

impl Default for AutoHttpsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            staging: false,
            email: None,
            renewal_interval: Duration::from_secs(12 * 60 * 60), // Check every 12 hours
            hsts: true,
            hsts_max_age: 31536000, // 1 year recommendation
            hsts_include_subdomains: true,
            hsts_preload: false,
        }
    }
}

impl AutoHttpsConfig {
    /// Generates the HSTS header value based on configuration.
    ///
    /// - Returns: The value string for the `Strict-Transport-Security` header, or `None`.
    pub fn hsts_header(&self) -> Option<String> {
        if !self.hsts {
            return None;
        }
        
        let mut value = format!("max-age={}", self.hsts_max_age);
        if self.hsts_include_subdomains {
            value.push_str("; includeSubDomains");
        }
        if self.hsts_preload {
            value.push_str("; preload");
        }
        
        Some(value)
    }
}

// MARK: - Auto HTTPS Manager

/// The high-level manager that automates the acquisition and renewal of TLS certificates.
///
/// It coordinates:
/// 1. Checking the `CertStore` for existing valid certificates.
/// 2. Requesting new certificates via `AcmeClient` if missing or expired.
/// 3. Running a background task to renew certificates automatically.
pub struct AutoHttps {
    config: AutoHttpsConfig,
    acme: AcmeClient,
    store: Arc<CertStore>,
    
    /// Set of domains currently being processed to prevent thundering herds equivalent.
    processing: Arc<RwLock<std::collections::HashSet<String>>>,
}

impl AutoHttps {
    /// Create a new AutoHttps manager.
    ///
    /// - Parameters:
    ///   - config: The configuration struct.
    ///   - store: The backing `CertStore` for persistence.
    pub fn new(config: AutoHttpsConfig, store: Arc<CertStore>) -> Self {
        tracing::info!("🔐 Initializing AutoHTTPS Manager");
        
        // Initialize ACME Client
        let acme = if config.staging {
            tracing::info!("🧪 ACME Environment: Staging");
            AcmeClient::staging()
        } else {
            tracing::info!("🏭 ACME Environment: Production");
            AcmeClient::new()
        };
        
        // Attach Email if provided
        let acme = if let Some(email) = &config.email {
            tracing::info!("📧 ACME Account Email: {}", email);
            acme.with_email(email)
        } else {
            acme
        };
        
        Self {
            config,
            acme,
            store,
            processing: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }
    
    /// Retrieves a valid certificate for the given domain.
    ///
    /// **Logic Flow:**
    /// 1. Check Store (Cache/Disk). Return if valid.
    /// 2. If missing or nearing expiry, verify no other task is processing this domain.
    /// 3. Trigger ACME flow via `obtain_certificate`.
    /// 4. Save result to Store.
    ///
    /// - Parameters:
    ///   - domain: The fully qualified domain name.
    ///   - handler: The challenge handler needed for ACME validation.
    pub async fn get_certificate<H: ChallengeHandler + ?Sized>(
        &self,
        domain: &str,
        handler: &H,
    ) -> Result<Certificate, AutoHttpsError> {
        // 1. Fast Path: Check Store
        if let Some(cert) = self.store.get(domain).await {
            if !cert.needs_renewal() {
                tracing::debug!("✅ Cache Hit: Valid certificate found for {}", domain);
                return Ok(cert);
            }
            tracing::info!("⏰ Expiry Warning: Certificate for {} needs renewal", domain);
        }
        
        // 2. Concurrency Check
        {
            let processing = self.processing.read().await;
            if processing.contains(domain) {
                return Err(AutoHttpsError::Config(
                    format!("🔄 Race Protection: Certificate for {} is already being issued", domain)
                ));
            }
        }
        
        // 3. Mark as Processing
        {
            let mut processing = self.processing.write().await;
            processing.insert(domain.to_string());
        }
        
        tracing::info!("🚀 Starting issuance workflow for {}", domain);
        
        // 4. Perform ACME Operation
        // Note: We use a block here to ensure the processing flag is removed even if panic occurs (though simple await shouldn't panic)
        // Actually simple robust logic:
        let result = self.acme
            .obtain_certificate(&[domain.to_string()], handler)
            .await;
        
        // 5. Cleanup Processing Flag
        {
            let mut processing = self.processing.write().await;
            processing.remove(domain);
        }
        
        let cert = result?;
        
        // 6. Persistence
        self.store.store(&cert).await?;
        
        tracing::info!("🎉 Certificate issuance complete for {}", domain);
        
        Ok(cert)
    }
    
    /// Starts the background renewal task.
    ///
    /// Scans the certificate store periodically and proactively renews certificates
    /// that are approaching expiration.
    pub fn start_renewal_task(self: Arc<Self>, handler: Arc<dyn ChallengeHandler>) {
        let interval = self.config.renewal_interval;
        
        tracing::info!("🔄 Starting Renewal Daemon (Interval: {:?})", interval);
        
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                
                tracing::debug!("🔍 Renewal Daemon: Scanning certificates...");
                
                let renewal_candidates = self.store.get_needing_renewal().await;
                
                if renewal_candidates.is_empty() {
                    tracing::debug!("✅ Renewal Daemon: All certificates healthy");
                    continue;
                }
                
                tracing::info!("⏰ Renewal Daemon: found {} cert(s) needing attention", renewal_candidates.len());
                
                for cert in renewal_candidates {
                    if let Some(domain) = cert.domains.first() {
                        tracing::info!("🔄 Renewing {}...", domain);
                        
                        match self.get_certificate(domain, handler.as_ref()).await {
                            Ok(_) => {
                                tracing::info!("✅ Renewed successfully: {}", domain);
                            }
                            Err(e) => {
                                tracing::error!("❌ Renew failed for {}: {}", domain, e);
                            }
                        }
                    }
                }
            }
        });
    }
    
    /// Checks if a valid certificate currently exists for a domain.
    pub async fn has_certificate(&self, domain: &str) -> bool {
        self.store.has_valid(domain).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hsts_header_generation() {
        let config = AutoHttpsConfig::default();
        let header = config.hsts_header().unwrap();
        assert!(header.contains("max-age=31536000"));
        assert!(header.contains("includeSubDomains"));
        assert!(!header.contains("preload"));
    }
    
    #[test]
    fn test_hsts_disabled() {
        let config = AutoHttpsConfig {
            hsts: false,
            ..Default::default()
        };
        assert!(config.hsts_header().is_none());
    }
    
    #[test]
    fn test_hsts_preload() {
        let config = AutoHttpsConfig {
            hsts_preload: true,
            ..Default::default()
        };
        let header = config.hsts_header().unwrap();
        assert!(header.contains("preload"));
    }
}
