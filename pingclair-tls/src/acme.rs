//! ACME Protocol Client
//!
//! 🔐 Provides automatic certificate issuance and renewal via Let's Encrypt (or compatible ACME providers).
//! Encapsulates the complexity of the ACME RFC 8555 state machine:
//! - Account registration
//! - Order creation
//! - Challenge solving (HTTP-01)
//! - Certificate finalization and download.

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType as AcmeChallengeType,
    Identifier, NewAccount, NewOrder, OrderStatus,
};
use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use x509_parser::prelude::*;

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
#[async_trait::async_trait]
pub trait ChallengeHandler: Send + Sync {
    /// 🚦 Deploys and durably publishes the solution before returning.
    async fn deploy(&self, challenge: &ChallengeResponse) -> Result<(), AcmeError>;
    
    /// 🧹 Cleans up resources after validation.
    async fn cleanup(&self, challenge: &ChallengeResponse) -> Result<(), AcmeError>;
    
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

#[async_trait::async_trait]
impl ChallengeHandler for MemoryChallengeHandler {
    async fn deploy(&self, challenge: &ChallengeResponse) -> Result<(), AcmeError> {
        // 🛡️ The token is visible before ACME validation can be triggered.
        self.tokens
            .write()
            .insert(challenge.token.clone(), challenge.key_authorization.clone());
        Ok(())
    }
    
    async fn cleanup(&self, challenge: &ChallengeResponse) -> Result<(), AcmeError> {
        self.tokens.write().remove(&challenge.token);
        Ok(())
    }
    
    fn get_token(&self, token: &str) -> Option<String> {
        self.tokens.read().get(token).cloned()
    }
}

/// 🧹 Removes every deployed challenge and records cleanup failures.
async fn cleanup_challenges<H: ChallengeHandler + ?Sized>(
    handler: &H,
    challenges: &[ChallengeResponse],
) {
    for challenge in challenges {
        if let Err(error) = handler.cleanup(challenge).await {
            tracing::warn!(
                domain = %challenge.domain,
                %error,
                "⚠️ Failed to clean up an ACME challenge"
            );
        }
    }
}

/// 📅 Reads the leaf certificate's authoritative X.509 expiration timestamp.
fn certificate_expiry(cert_pem: &str) -> Result<i64, AcmeError> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|error| AcmeError::CertGeneration(format!("Invalid certificate PEM: {error}")))?;
    let (_, certificate) = parse_x509_certificate(&pem.contents)
        .map_err(|error| AcmeError::CertGeneration(format!("Invalid X.509 certificate: {error}")))?;
    Ok(certificate.validity().not_after.timestamp())
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
    
    /// Root directory of the TLS store where the ACME account credentials
    /// are persisted. When `None`, the account is not persisted.
    account_store_root: Option<PathBuf>,
}

impl AcmeClient {
    /// Creates a client configured for the Production environment.
    pub fn new() -> Self {
        Self {
            staging: false,
            email: None,
            challenge_type: ChallengeType::Http01,
            account_store_root: None,
        }
    }
    
    /// Creates a client configured for the Staging environment.
    pub fn staging() -> Self {
        Self {
            staging: true,
            email: None,
            challenge_type: ChallengeType::Http01,
            account_store_root: None,
        }
    }
    
    /// Sets the contact email.
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }
    
    /// Sets the root directory of the TLS store so the ACME account
    /// credentials are persisted and reused across restarts.
    pub fn with_account_store(mut self, store_root: impl Into<PathBuf>) -> Self {
        self.account_store_root = Some(store_root.into());
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
            
            if let Err(error) = handler.deploy(&response).await {
                cleanup_challenges(handler, &active_challenges).await;
                return Err(error);
            }
            active_challenges.push(response);
            
            // 4c. Notify Server
            if let Err(error) = challenge.set_ready().await {
                cleanup_challenges(handler, &active_challenges).await;
                return Err(AcmeError::ChallengeFailed(format!(
                    "Failed to set ready: {error}"
                )));
            }
                
            tracing::info!("🚀 Verification triggered for {}", domain);
        }
        
        // 5. Poll for Status
        tracing::info!("⏳ Polling order status...");
        let retry_policy = instant_acme::RetryPolicy::default(); // reasonable defaults
        let state = order
            .poll_ready(&retry_policy)
            .await
            .map_err(|error| AcmeError::OrderFailed(format!("Polling failed: {error}")));

        // 🧹 Challenge tokens are removed even when polling fails.
        cleanup_challenges(handler, &active_challenges).await;
        let state = state?;
        
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
        
        // 📅 Renewal decisions use the CA-signed leaf certificate's real expiry.
        let expires_at = certificate_expiry(&cert_pem)?;

        Ok(Certificate {
            cert_pem,
            key_pem,
            domains: domains.to_vec(),
            expires_at,
        })
    }

    /// Internal helper to ensure an account exists.
    ///
    /// Reuses the persisted account credentials when available so the same
    /// ACME account survives restarts. Falls back to registering a new
    /// account when the credentials file is missing, unreadable, or rejected
    /// by the ACME provider, and persists the new credentials afterwards.
    async fn ensure_account(&self, directory_url: &str) -> Result<Account, AcmeError> {
        let credentials_path = self.account_store_root.as_ref()
            .map(|root| crate::account_store::credentials_path(root, self.staging));

        // 1. Try to restore the account from persisted credentials.
        if let Some(path) = &credentials_path {
            match Self::load_account_credentials(path) {
                Ok(Some(credentials)) => {
                    let builder = Account::builder()
                        .map_err(|e| AcmeError::Account(format!("Builder init failed: {}", e)))?;
                    match builder.from_credentials(credentials).await {
                        Ok(account) => {
                            tracing::info!("🔑 Reusing persisted ACME account from {:?}", path);
                            return Ok(account);
                        }
                        Err(e) => {
                            tracing::warn!(
                                "⚠️ Stored ACME account rejected ({}); registering a new account",
                                e
                            );
                        }
                    }
                }
                Ok(None) => {
                    tracing::debug!("No persisted ACME account at {:?}; registering a new one", path);
                }
                Err(e) => {
                    tracing::warn!(
                        "⚠️ Failed to load ACME account credentials from {:?}: {}; registering a new account",
                        path, e
                    );
                }
            }
        }

        // 2. Register a new account.
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
            
        let (account, credentials) = builder.create(&new_account, directory_url.to_string(), None).await
            .map_err(|e| AcmeError::Account(format!("Registration failed: {}", e)))?;

        // 3. Persist the credentials for future restarts. A failure here is
        //    non-fatal: issuance can proceed with the in-memory account.
        if let Some(path) = &credentials_path {
            if let Err(e) = Self::store_account_credentials(path, &credentials) {
                tracing::warn!(
                    "⚠️ Failed to persist ACME account credentials to {:?}: {}",
                    path, e
                );
            } else {
                tracing::info!("💾 Persisted ACME account credentials to {:?}", path);
            }
        }
            
        Ok(account)
    }

    /// Loads and deserializes persisted account credentials.
    ///
    /// - Returns: `Ok(Some(_))` when valid credentials exist, `Ok(None)` when
    ///   the file is missing, or an `Err` when the file is unreadable or
    ///   corrupt.
    fn load_account_credentials(path: &std::path::Path) -> Result<Option<AccountCredentials>, AcmeError> {
        match crate::account_store::load(path)
            .map_err(|e| AcmeError::Account(format!("Read failed: {}", e)))?
        {
            Some(json) => {
                let credentials = serde_json::from_str(&json)
                    .map_err(|e| AcmeError::Account(format!("Corrupt credentials: {}", e)))?;
                Ok(Some(credentials))
            }
            None => Ok(None),
        }
    }

    /// Serializes and persists account credentials to disk.
    fn store_account_credentials(
        path: &std::path::Path,
        credentials: &AccountCredentials,
    ) -> Result<(), AcmeError> {
        let json = serde_json::to_string_pretty(credentials)
            .map_err(|e| AcmeError::Account(format!("Serialization failed: {}", e)))?;
        crate::account_store::save(path, &json)
            .map_err(|e| AcmeError::Account(format!("Write failed: {}", e)))
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

    #[test]
    fn certificate_expiry_uses_the_leaf_not_after_timestamp() {
        let mut parameters =
            rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        parameters.not_after = rcgen::date_time_ymd(2035, 1, 2);
        let expected_expiry = parameters.not_after.unix_timestamp();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let certificate = parameters.self_signed(&key_pair).unwrap();

        assert_eq!(
            certificate_expiry(&certificate.pem()).unwrap(),
            expected_expiry
        );
    }

    #[test]
    fn certificate_expiry_rejects_malformed_pem() {
        assert!(certificate_expiry("not a certificate").is_err());
    }

    /// A serialized credentials payload with a syntactically valid
    /// (base64url-encoded) key, matching the `AccountCredentials` JSON shape.
    const TEST_CREDENTIALS_JSON: &str = r#"{
        "id": "https://acme.example/acct/1",
        "key_pkcs8": "QUJD",
        "directory": "https://acme-v02.api.letsencrypt.org/directory"
    }"#;

    #[test]
    fn load_account_credentials_returns_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = crate::account_store::credentials_path(dir.path(), false);
        assert!(AcmeClient::load_account_credentials(&path).unwrap().is_none());
    }

    #[test]
    fn load_account_credentials_rejects_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = crate::account_store::credentials_path(dir.path(), false);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{ not valid json").unwrap();
        assert!(AcmeClient::load_account_credentials(&path).is_err());
    }

    #[test]
    fn stored_account_credentials_survive_a_second_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = crate::account_store::credentials_path(dir.path(), false);

        // First run: no file yet.
        assert!(AcmeClient::load_account_credentials(&path).unwrap().is_none());

        // Simulate a first issuance persisting the freshly created account.
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, TEST_CREDENTIALS_JSON).unwrap();

        // Second run: the same credentials are loaded back.
        let credentials = AcmeClient::load_account_credentials(&path)
            .unwrap()
            .expect("credentials should load");

        // Re-persisting through the store helper must not change the identity
        // of the account: the serialized form stays identical.
        AcmeClient::store_account_credentials(&path, &credentials).unwrap();
        let reloaded = AcmeClient::load_account_credentials(&path)
            .unwrap()
            .expect("credentials should reload");
        let first = serde_json::to_string(&credentials).unwrap();
        let second = serde_json::to_string(&reloaded).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn staging_and_production_use_separate_credential_files() {
        let dir = tempfile::tempdir().unwrap();
        let prod = crate::account_store::credentials_path(dir.path(), false);
        let staging = crate::account_store::credentials_path(dir.path(), true);
        assert_ne!(prod, staging);

        // Writing staging credentials must not make them visible to production.
        crate::account_store::save(&staging, TEST_CREDENTIALS_JSON).unwrap();
        assert!(AcmeClient::load_account_credentials(&prod).unwrap().is_none());
        assert!(AcmeClient::load_account_credentials(&staging).unwrap().is_some());
    }
}
