//! Automatic HTTPS management
//!
//! 🔐 Provides automatic certificate issuance and renewal.

use crate::acme::{AcmeClient, Certificate, ChallengeHandler, AcmeError};
use crate::cert_store::{CertStore, CertStoreError};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;

/// Auto HTTPS errors
#[derive(Debug, Error)]
pub enum AutoHttpsError {
    #[error("🔐 ACME error: {0}")]
    Acme(#[from] AcmeError),
    
    #[error("💾 Certificate store error: {0}")]
    CertStore(#[from] CertStoreError),
    
    #[error("⚙️ Configuration error: {0}")]
    Config(String),
}

/// ⚙️ Configuration for automatic HTTPS
#[derive(Debug, Clone)]
pub struct AutoHttpsConfig {
    /// Enable automatic certificate issuance
    pub enabled: bool,
    /// Use Let's Encrypt staging (for testing)
    pub staging: bool,
    /// Account email for Let's Encrypt
    pub email: Option<String>,
    /// Automatic renewal check interval
    pub renewal_interval: Duration,
    /// Add HSTS header
    pub hsts: bool,
    /// HSTS max-age in seconds
    pub hsts_max_age: u64,
    /// Include subdomains in HSTS
    pub hsts_include_subdomains: bool,
    /// Enable HSTS preload
    pub hsts_preload: bool,
}

impl Default for AutoHttpsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            staging: false,
            email: None,
            renewal_interval: Duration::from_secs(12 * 60 * 60), // 12 hours
            hsts: true,
            hsts_max_age: 31536000, // 1 year
            hsts_include_subdomains: true,
            hsts_preload: false,
        }
    }
}

impl AutoHttpsConfig {
    /// 🛡️ Generate HSTS header value
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

/// 🔐 Automatic HTTPS manager
pub struct AutoHttps {
    config: AutoHttpsConfig,
    acme: AcmeClient,
    store: Arc<CertStore>,
    /// Domains being processed
    processing: Arc<RwLock<std::collections::HashSet<String>>>,
}

impl AutoHttps {
    /// 🚀 Create a new AutoHttps manager
    pub fn new(config: AutoHttpsConfig, store: Arc<CertStore>) -> Self {
        tracing::info!("🔐 Initializing AutoHTTPS manager");
        
        let acme = if config.staging {
            tracing::info!("🧪 Using Let's Encrypt STAGING");
            AcmeClient::staging()
        } else {
            tracing::info!("🏭 Using Let's Encrypt PRODUCTION");
            AcmeClient::new()
        };
        
        let acme = if let Some(email) = &config.email {
            tracing::info!("📧 Account email: {}", email);
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
    
    /// 📜 Get or obtain a certificate for a domain
    pub async fn get_certificate<H: ChallengeHandler + ?Sized>(
        &self,
        domain: &str,
        handler: &H,
    ) -> Result<Certificate, AutoHttpsError> {
        // Check cache first
        if let Some(cert) = self.store.get(domain).await {
            if !cert.needs_renewal() {
                tracing::debug!("✅ Using cached certificate for {}", domain);
                return Ok(cert);
            }
            tracing::info!("⏰ Certificate for {} needs renewal", domain);
        }
        
        // Check if already being processed
        {
            let processing = self.processing.read().await;
            if processing.contains(domain) {
                return Err(AutoHttpsError::Config(
                    format!("🔄 Certificate for {} is already being obtained", domain)
                ));
            }
        }
        
        // Mark as processing
        {
            let mut processing = self.processing.write().await;
            processing.insert(domain.to_string());
        }
        
        tracing::info!("🔐 Obtaining certificate for {}", domain);
        
        // Obtain certificate
        let result = self.acme
            .obtain_certificate(&[domain.to_string()], handler)
            .await;
        
        // Remove from processing
        {
            let mut processing = self.processing.write().await;
            processing.remove(domain);
        }
        
        let cert = result?;
        
        // Store certificate
        self.store.store(&cert).await?;
        
        tracing::info!("🎉 Certificate ready for {}", domain);
        
        Ok(cert)
    }
    
    /// 🔄 Start the renewal background task
    pub fn start_renewal_task(self: Arc<Self>, handler: Arc<dyn ChallengeHandler>) {
        let interval = self.config.renewal_interval;
        
        tracing::info!("🔄 Starting certificate renewal task (interval: {:?})", interval);
        
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                
                tracing::info!("🔍 Running certificate renewal check...");
                
                let certs = self.store.get_needing_renewal().await;
                
                if certs.is_empty() {
                    tracing::info!("✅ All certificates up to date");
                    continue;
                }
                
                for cert in certs {
                    if let Some(domain) = cert.domains.first() {
                        tracing::info!("🔄 Renewing certificate for {}", domain);
                        
                        match self.get_certificate(domain, handler.as_ref()).await {
                            Ok(_) => {
                                tracing::info!("🎉 Certificate renewed for {}", domain);
                            }
                            Err(e) => {
                                tracing::error!("❌ Renewal failed for {}: {}", domain, e);
                            }
                        }
                    }
                }
            }
        });
    }
    
    /// ✅ Check if a domain has a valid certificate
    pub async fn has_certificate(&self, domain: &str) -> bool {
        self.store.has_valid(domain).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hsts_header() {
        let config = AutoHttpsConfig::default();
        let header = config.hsts_header().unwrap();
        assert!(header.contains("max-age=31536000"));
        assert!(header.contains("includeSubDomains"));
    }
    
    #[test]
    fn test_hsts_header_disabled() {
        let config = AutoHttpsConfig {
            hsts: false,
            ..Default::default()
        };
        assert!(config.hsts_header().is_none());
    }
    
    #[test]
    fn test_hsts_header_preload() {
        let config = AutoHttpsConfig {
            hsts_preload: true,
            ..Default::default()
        };
        let header = config.hsts_header().unwrap();
        assert!(header.contains("preload"));
    }
}
