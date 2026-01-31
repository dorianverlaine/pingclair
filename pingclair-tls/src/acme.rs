//! ACME Protocol Client
//!
//! 🔐 Provides automatic certificate issuance and renewal via Let's Encrypt (or compatible ACME providers).
//! Encapsulates the complexity of the ACME RFC 8555 state machine:
//! - Account registration
//! - Order creation
//! - Challenge solving (HTTP-01)
//! - Certificate finalization and download.

use instant_acme::{
    Account, AuthorizationStatus, ChallengeType as AcmeChallengeType,
    Identifier, NewAccount, NewOrder, OrderStatus,
};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

// MARK: - Constants

/// ACME Directory URLs for Let's Encrypt.
pub mod directory {
    /// 🏭 Let's Encrypt Production - Trusted certificates.
    pub const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
    
    /// 🧪 Let's Encrypt Staging - Testing only (untrusted root).
    pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
}

// MARK: - Errors

/// Errors that can occur during ACME operations.
#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("🔴 Protocol Error: {0}")]
    Protocol(#[from] instant_acme::Error),
    
    #[error("⚠️ Challenge Verification Failed: {0}")]
    ChallengeFailed(String),
    
    #[error("❌ Order Processing Failed: {0}")]
    OrderFailed(String),
    
    #[error("🔧 Certificate Generation Failed: {0}")]
    CertGeneration(String),
    
    #[error("👤 Account Management Error: {0}")]
    Account(String),
}

// MARK: - Types

/// Supported ACME challenge types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeType {
    /// 🌐 HTTP-01: Validates control via file serving on port 80.
    Http01,
    /// 📡 DNS-01: Validates control via DNS TXT records (Wildcards supported).
    Dns01,
    /// 🔒 TLS-ALPN-01: Validates via TLS handshake on port 443.
    TlsAlpn01,
}

/// Data required to solve a challenge.
#[derive(Debug, Clone)]
pub struct ChallengeResponse {
    /// The domain (identifier) being validated.
    pub domain: String,
    
    /// The type of challenge (e.g., HTTP-01).
    pub challenge_type: ChallengeType,
    
    /// The challenge token (The filename/path).
    pub token: String,
    
    /// The key authorization (The content).
    pub key_authorization: String,
}

/// A fully issued certificate bundle.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// Full certificate chain in PEM format.
    pub cert_pem: String,
    
    /// Private key in PEM format.
    pub key_pem: String,
    
    /// List of SANs (Subject Alternative Names) covered.
    pub domains: Vec<String>,
    
    /// Expiration timestamp (Unix epoch seconds).
    pub expires_at: i64,
}

impl Certificate {
    /// Checks if the certificate is nearing expiration.
    ///
    /// - Returns: `true` if expiration is within 30 days.
    pub fn needs_renewal(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        
        // Renew if less than 30 days remaining (standard practice)
        self.expires_at - now < 30 * 24 * 60 * 60
    }
}

// MARK: - Challenge Handler Trait

/// Interface for handling ACME challenges.
/// Implementations must solve the challenge (e.g., Serve file, Set DNS record).
pub trait ChallengeHandler: Send + Sync {
    /// Deploy the solution for a challenge (e.g., Write file).
    fn deploy(&self, challenge: &ChallengeResponse) -> Result<(), AcmeError>;
    
    /// Clean up resources after validation (e.g., Delete file).
    fn cleanup(&self, challenge: &ChallengeResponse) -> Result<(), AcmeError>;
    
    /// Retrieve a deployed token (Used by HTTP server router).
    fn get_token(&self, token: &str) -> Option<String>;
}

// MARK: - Memory Challenge Handler

/// A simple, non-persistent challenge handler for HTTP-01.
/// Stores tokens in an in-memory HashMap.
pub struct MemoryChallengeHandler {
    tokens: Arc<RwLock<std::collections::HashMap<String, String>>>,
}

impl MemoryChallengeHandler {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
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
        
        // Use blocking task or spawn, here we just spawn to avoid blocking caller
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
    
    fn get_token(&self, token: &str) -> Option<String> {
        // Must block since interface is synchronous for the caller (usually server router)
        futures::executor::block_on(async {
            let tokens = self.tokens.read().await;
            tokens.get(token).cloned()
        })
    }
}

// MARK: - ACME Client

/// The high-level client for ACME operations.
pub struct AcmeClient {
    /// If true, uses the Let's Encrypt Staging environment.
    staging: bool,
    
    /// Contact email for account registration and expiration notices.
    email: Option<String>,
    
    /// Preferred challenge type for validation.
    challenge_type: ChallengeType,
}

impl AcmeClient {
    /// Creates a client configured for the Production environment.
    pub fn new() -> Self {
        Self {
            staging: false,
            email: None,
            challenge_type: ChallengeType::Http01,
        }
    }
    
    /// Creates a client configured for the Staging environment.
    pub fn staging() -> Self {
        Self {
            staging: true,
            email: None,
            challenge_type: ChallengeType::Http01,
        }
    }
    
    /// Sets the contact email.
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }
    
    /// Sets the preferred challenge type.
    pub fn with_challenge_type(mut self, challenge_type: ChallengeType) -> Self {
        self.challenge_type = challenge_type;
        self
    }
    
    /// Obtains a certificate for the specified domains.
    ///
    /// This method executes the full ACME workflow:
    /// 1. Account creation/retrieval.
    /// 2. Order placement.
    /// 3. Authorization & Challenge solving.
    /// 4. Polling for validity.
    /// 5. Certificate finalization & download.
    pub async fn obtain_certificate<H: ChallengeHandler + ?Sized>(
        &self,
        domains: &[String],
        handler: &H,
    ) -> Result<Certificate, AcmeError> {
        tracing::info!("🔐 Starting ACME flow for domains: {:?}", domains);
        
        // 1. Select Directory
        let directory_url = if self.staging {
            tracing::info!("🧪 Environment: Staging (Untrusted)");
            directory::LETS_ENCRYPT_STAGING
        } else {
            tracing::info!("🏭 Environment: Production (Trusted)");
            directory::LETS_ENCRYPT_PRODUCTION
        };
        
        // 2. Account Setup
        let account = self.ensure_account(directory_url).await?;
        
        // 3. Create Order
        let identifiers: Vec<Identifier> = domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();
            
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|e| AcmeError::OrderFailed(format!("Failed to create order: {}", e)))?;
            
        tracing::info!("✅ Order created. URL: {}", order.url());

        // 4. Process Authorizations
        let mut auths_stream = order.authorizations();
        let mut active_challenges = Vec::new(); // Keep track for cleanup
        
        while let Some(auth_result) = auths_stream.next().await {
            let mut auth = auth_result
                .map_err(|e| AcmeError::OrderFailed(format!("Failed to fetch authorization: {}", e)))?;
                
            let domain = auth.identifier().to_string();
            
            if auth.status == AuthorizationStatus::Valid {
                tracing::info!("✅ Authorization already valid for {}", domain);
                continue;
            }
            
            tracing::info!("🧩 Solving challenge for {}", domain);
            
            // 4a. Pick Challenge
            let target_type = match self.challenge_type {
                ChallengeType::Http01 => AcmeChallengeType::Http01,
                ChallengeType::Dns01 => AcmeChallengeType::Dns01,
                ChallengeType::TlsAlpn01 => AcmeChallengeType::TlsAlpn01,
            };
            
            let mut challenge = auth.challenge(target_type).ok_or_else(|| {
                AcmeError::ChallengeFailed(format!("Challenge type {:?} not offered for {}", self.challenge_type, domain))
            })?;
            
            // 4b. Deploy Solution
            let response = ChallengeResponse {
                domain: domain.clone(),
                challenge_type: self.challenge_type,
                token: challenge.token.clone(),
                key_authorization: challenge.key_authorization().as_str().to_string(),
            };
            
            handler.deploy(&response)?;
            active_challenges.push(response);
            
            // 4c. Notify Server
            challenge.set_ready().await
                .map_err(|e| AcmeError::ChallengeFailed(format!("Failed to set ready: {}", e)))?;
                
            tracing::info!("🚀 Verification triggered for {}", domain);
        }
        
        // 5. Poll for Status
        tracing::info!("⏳ Polling order status...");
        let retry_policy = instant_acme::RetryPolicy::default(); // reasonable defaults
        let state = order.poll_ready(&retry_policy).await
             .map_err(|e| AcmeError::OrderFailed(format!("Polling failed: {}", e)))?;
             
        // Cleanup challenges regardless of outcome
        for challenge in &active_challenges {
            let _ = handler.cleanup(challenge);
        }
        
        if state != OrderStatus::Ready && state != OrderStatus::Valid {
             return Err(AcmeError::OrderFailed(format!("Order ended in state: {:?}", state)));
        }
        
        // 6. Finalize & Download
        tracing::info!("�️ Finalizing order...");
        let key_pem = order.finalize().await
            .map_err(|e| AcmeError::CertGeneration(format!("Finalization failed: {}", e)))?;
            
        let cert_pem = order.poll_certificate(&retry_policy).await
            .map_err(|e| AcmeError::CertGeneration(format!("Download failed: {}", e)))?;
            
        tracing::info!("🎉 Certificate acquired for {:?}", domains);
        
        // 7. Calculate Expiry (approximate 90 days)
        // Note: Ideally we parse x509 here, but ACME doesn't return that metadata directly in the result struct.
        // We assume 90 days for Let's Encrypt.
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64 + 89 * 24 * 60 * 60;

        Ok(Certificate {
            cert_pem,
            key_pem,
            domains: domains.to_vec(),
            expires_at,
        })
    }

    /// Internal helper to ensure an account exists.
    async fn ensure_account(&self, directory_url: &str) -> Result<Account, AcmeError> {
        let contact: Vec<String> = self.email.as_ref()
            .map(|e| vec![format!("mailto:{}", e)])
            .unwrap_or_default();
            
        let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();
        
        let new_account = NewAccount {
            contact: &contact_refs,
            terms_of_service_agreed: true,
            only_return_existing: false,
        };
        
        let builder = Account::builder()
            .map_err(|e| AcmeError::Account(format!("Builder init failed: {}", e)))?;
            
        let (account, _) = builder.create(&new_account, directory_url.to_string(), None).await
            .map_err(|e| AcmeError::Account(format!("Registration failed: {}", e)))?;
            
        Ok(account)
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
    fn test_certificate_renewal_logic() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
            
        // Case 1: Expired
        let expired = Certificate {
            cert_pem: "".into(), key_pem: "".into(), domains: vec![],
            expires_at: now - 3600,
        };
        assert!(expired.needs_renewal());
        
        // Case 2: Fresh (60 days left)
        let fresh = Certificate {
            cert_pem: "".into(), key_pem: "".into(), domains: vec![],
            expires_at: now + 60 * 86400,
        };
        assert!(!fresh.needs_renewal());
        
         // Case 3: Nearing expiry (29 days left)
        let near = Certificate {
            cert_pem: "".into(), key_pem: "".into(), domains: vec![],
            expires_at: now + 29 * 86400,
        };
        assert!(near.needs_renewal());
    }
}
