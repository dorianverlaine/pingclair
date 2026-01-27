//! ACME protocol client for Let's Encrypt using instant-acme
//!
//! 🔐 Provides automatic certificate issuance and renewal.

use instant_acme::{
    Account, AuthorizationStatus, ChallengeType as AcmeChallengeType,
    Identifier, NewAccount, NewOrder, OrderStatus,
};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

/// ACME directory URLs
pub mod directory {
    /// 🏭 Let's Encrypt Production - for real certificates
    pub const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
    /// 🧪 Let's Encrypt Staging - for testing (not trusted)
    pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
}

/// ACME error types
#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("🔴 ACME protocol error: {0}")]
    Protocol(#[from] instant_acme::Error),
    
    #[error("⚠️ Challenge failed: {0}")]
    ChallengeFailed(String),
    
    #[error("❌ Order failed: {0}")]
    OrderFailed(String),
    
    #[error("🔧 Certificate generation error: {0}")]
    CertGeneration(String),
    
    #[error("👤 Account error: {0}")]
    Account(String),
}

/// ACME challenge types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeType {
    /// 🌐 HTTP-01 challenge (port 80)
    Http01,
    /// 📡 DNS-01 challenge  
    Dns01,
    /// 🔒 TLS-ALPN-01 challenge (port 443)
    TlsAlpn01,
}

/// Challenge response data
#[derive(Debug, Clone)]
pub struct ChallengeResponse {
    /// Domain being validated
    pub domain: String,
    /// Challenge type
    pub challenge_type: ChallengeType,
    /// Token for HTTP-01
    pub token: String,
    /// Key authorization
    pub key_authorization: String,
}

/// 📜 Certificate data
#[derive(Debug, Clone)]
pub struct Certificate {
    /// Certificate chain (PEM)
    pub cert_pem: String,
    /// Private key (PEM)
    pub key_pem: String,
    /// Domains covered
    pub domains: Vec<String>,
    /// Expiry timestamp (Unix seconds)
    pub expires_at: i64,
}

impl Certificate {
    /// ⏰ Check if certificate is about to expire (within 30 days)
    pub fn needs_renewal(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        
        // Renew if less than 30 days remaining
        self.expires_at - now < 30 * 24 * 60 * 60
    }
}

/// Callback for handling ACME challenges
pub trait ChallengeHandler: Send + Sync {
    /// 🚀 Deploy challenge response (make it accessible)
    fn deploy(&self, challenge: &ChallengeResponse) -> Result<(), AcmeError>;
    
    /// 🧹 Cleanup challenge response
    fn cleanup(&self, challenge: &ChallengeResponse) -> Result<(), AcmeError>;
}

/// 💾 HTTP-01 challenge handler that stores tokens in memory
pub struct MemoryChallengeHandler {
    tokens: Arc<RwLock<std::collections::HashMap<String, String>>>,
}

impl MemoryChallengeHandler {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }
    
    /// Get token for a given path
    pub async fn get_token(&self, token: &str) -> Option<String> {
        let tokens = self.tokens.read().await;
        tokens.get(token).cloned()
    }
}

impl Default for MemoryChallengeHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ChallengeHandler for MemoryChallengeHandler {
    fn deploy(&self, challenge: &ChallengeResponse) -> Result<(), AcmeError> {
        let tokens = self.tokens.clone();
        let token = challenge.token.clone();
        let key_auth = challenge.key_authorization.clone();
        
        tokio::spawn(async move {
            let mut tokens = tokens.write().await;
            tokens.insert(token, key_auth);
        });
        
        Ok(())
    }
    
    fn cleanup(&self, challenge: &ChallengeResponse) -> Result<(), AcmeError> {
        let tokens = self.tokens.clone();
        let token = challenge.token.clone();
        
        tokio::spawn(async move {
            let mut tokens = tokens.write().await;
            tokens.remove(&token);
        });
        
        Ok(())
    }
}

/// 🔐 ACME client for certificate issuance
pub struct AcmeClient {
    /// Use staging environment
    staging: bool,
    /// Account email
    email: Option<String>,
    /// Preferred challenge type
    challenge_type: ChallengeType,
}

impl AcmeClient {
    /// 🏭 Create a new production ACME client
    pub fn new() -> Self {
        Self {
            staging: false,
            email: None,
            challenge_type: ChallengeType::Http01,
        }
    }
    
    /// 🧪 Create a staging ACME client (for testing)
    pub fn staging() -> Self {
        Self {
            staging: true,
            email: None,
            challenge_type: ChallengeType::Http01,
        }
    }
    
    /// 📧 Set the account email
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }
    
    /// 🎯 Set the preferred challenge type
    pub fn with_challenge_type(mut self, challenge_type: ChallengeType) -> Self {
        self.challenge_type = challenge_type;
        self
    }
    
    /// 📜 Obtain a certificate for the given domains
    pub async fn obtain_certificate<H: ChallengeHandler + ?Sized>(
        &self,
        domains: &[String],
        handler: &H,
    ) -> Result<Certificate, AcmeError> {
        tracing::info!("🔐 Obtain certificate for domains: {:?}", domains);
        
        // Get ACME directory URL
        let directory_url = if self.staging {
            tracing::info!("🧪 Using Let's Encrypt STAGING environment");
            directory::LETS_ENCRYPT_STAGING.to_string()
        } else {
            tracing::info!("🏭 Using Let's Encrypt PRODUCTION environment");
            directory::LETS_ENCRYPT_PRODUCTION.to_string()
        };
        
        // Create account builder
        let builder = Account::builder()
            .map_err(|e| AcmeError::Account(format!("Failed to create account builder: {}", e)))?;
        
        // Prepare contact info
        let contact: Vec<String> = self.email.as_ref()
            .map(|e| vec![format!("mailto:{}", e)])
            .unwrap_or_default();
        let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();
        
        tracing::info!("👤 Creating ACME account...");
        
        // Create new account
        let new_account = NewAccount {
            contact: &contact_refs,
            terms_of_service_agreed: true,
            only_return_existing: false,
        };
        
        let (account, _credentials) = builder
            .create(&new_account, directory_url, None)
            .await
            .map_err(|e| AcmeError::Account(format!("Failed to create account: {}", e)))?;
        
        tracing::info!("✅ ACME account created successfully!");
        
        // Create order for domains
        let identifiers: Vec<Identifier> = domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();
        
        tracing::info!("📝 Creating certificate order...");
        
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|e| AcmeError::OrderFailed(format!("Failed to create order: {}", e)))?;
        
        tracing::info!("✅ Order created! Processing authorizations...");
        
        // Get authorizations - this returns a stream wrapper
        let mut auths_stream = order.authorizations();
        
        // Process each authorization
        let mut challenge_urls = Vec::new();
        
        while let Some(auth_result) = auths_stream.next().await {
            let mut auth_handle = auth_result
                .map_err(|e| AcmeError::OrderFailed(format!("Failed to get authorization: {}", e)))?;
            
            // Check status directly
            if auth_handle.status == AuthorizationStatus::Valid {
                 tracing::info!("✅ Authorization already valid (via status check)");
                 continue;
            }
            
            let domain = auth_handle.identifier().to_string();
            tracing::info!("🎯 Processing authorization for {}", domain);
            
            // Find appropriate challenge
            let challenge_type = match self.challenge_type {
                ChallengeType::Http01 => AcmeChallengeType::Http01,
                ChallengeType::Dns01 => AcmeChallengeType::Dns01,
                ChallengeType::TlsAlpn01 => AcmeChallengeType::TlsAlpn01,
            };
            
            let mut challenge_handle = auth_handle
                .challenge(challenge_type)
                .ok_or_else(|| AcmeError::ChallengeFailed(
                    format!("No {:?} challenge available for {}", self.challenge_type, domain)
                ))?;
                
            let token = challenge_handle.token.clone();
            let key_auth = challenge_handle.key_authorization();
            let key_auth_str = key_auth.as_str().to_string();
            
            let response = ChallengeResponse {
                domain: domain.clone(),
                challenge_type: self.challenge_type,
                token: token.clone(),
                key_authorization: key_auth_str,
            };
            
             // Deploy challenge
            handler.deploy(&response)?;
            tracing::info!("🚀 Challenge deployed for {}", domain);
            
            // Tell ACME server we're ready
            challenge_handle
                .set_ready()
                .await
                .map_err(|e| AcmeError::ChallengeFailed(format!("Failed to set challenge ready: {}", e)))?;
                
            challenge_urls.push((challenge_handle.url.clone(), response));
            tracing::info!("⏳ Verified challenge for {}", domain);
        }
        
        // Wait for all challenges to be valid (using order poll_ready)
        tracing::info!("⏳ Waiting for order to become ready...");
        
        let retry_policy = instant_acme::RetryPolicy::default();
        let status = order
            .poll_ready(&retry_policy)
            .await
            .map_err(|e| AcmeError::ChallengeFailed(format!("Order validation failed: {}", e)))?;
            
        // Cleanup challenges
        for (_, response) in challenge_urls {
            let _ = handler.cleanup(&response);
        }
        
        if status != OrderStatus::Ready && status != OrderStatus::Valid {
             return Err(AcmeError::OrderFailed(
                format!("Order status is {:?} (not Ready or Valid)", status)
            ));
        }

        tracing::info!("🔧 Finalizing order and generating certificate...");
        
        // Finalize order
        let key_pem = order
            .finalize()
            .await
            .map_err(|e| AcmeError::OrderFailed(format!("Failed to finalize order: {}", e)))?;
        
        tracing::info!("⏳ Waiting for certificate issuance...");
        
        // Get certificate
        let cert_pem = order
            .poll_certificate(&retry_policy)
            .await
            .map_err(|e| AcmeError::OrderFailed(format!("Failed to get certificate: {}", e)))?;

        // Calculate expiry (approximate, 90 days)
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64 + 89 * 24 * 60 * 60;
        
        tracing::info!("🎉 Certificate obtained successfully for {:?}!", domains);
        
        Ok(Certificate {
            cert_pem,
            key_pem,
            domains: domains.to_vec(),
            expires_at,
        })
    }
}

impl Default for AcmeClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_certificate_needs_renewal() {
        let cert = Certificate {
            cert_pem: String::new(),
            key_pem: String::new(),
            domains: vec!["example.com".to_string()],
            expires_at: 0, // Expired
        };
        
        assert!(cert.needs_renewal());
    }
    
    #[test]
    fn test_certificate_no_renewal() {
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64 + 60 * 24 * 60 * 60; // 60 days in future
        
        let cert = Certificate {
            cert_pem: String::new(),
            key_pem: String::new(),
            domains: vec!["example.com".to_string()],
            expires_at: future,
        };
        
        assert!(!cert.needs_renewal());
    }
    
    #[tokio::test]
    async fn test_challenge_handler() {
        let handler = MemoryChallengeHandler::new();
        let challenge = ChallengeResponse {
            domain: "example.com".to_string(),
            challenge_type: ChallengeType::Http01,
            token: "test-token".to_string(),
            key_authorization: "test-auth".to_string(),
        };
        
        handler.deploy(&challenge).unwrap();
        handler.cleanup(&challenge).unwrap();
    }
}
