// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

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
    // TODO(v0.3): implement a DNS provider abstraction and TXT-record
    // deployment; wildcard certificates depend on this.
    Dns01,
    /// 🔒 TLS-ALPN-01: Validates via TLS handshake on port 443.
    // TODO(v0.3): implement the acme-tls/1 ALPN responder in the TLS
    // acceptor; requires coordinated H1/H2/H3 changes.
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

/// 🔄 The fraction of a certificate's lifetime that must remain before it is
/// renewed, when the configuration names none.
///
/// A third, which is what the format this server follows defaults to. On the
/// 90-day certificates public CAs issue today that is 30 days.
pub const DEFAULT_RENEWAL_WINDOW_RATIO: f64 = 1.0 / 3.0;

impl Certificate {
    /// 🔄 Whether this certificate is close enough to expiry to renew.
    ///
    /// The window is a **fraction of the certificate's own lifetime**, not a
    /// fixed number of days, and that distinction is the whole point:
    ///
    /// > 🤡 This used to renew whenever fewer than 30 days remained, full
    /// > stop. For the 90-day certificates public CAs issue that happens to be
    /// > a third, which is why it looked right. For a 7-day certificate — the
    /// > direction the ACME world is moving — it is true from the moment of
    /// > issuance, so every scan would renew every certificate, forever,
    /// > against the CA's rate limits.
    ///
    /// Falls back to the fixed 30 days only when the lifetime cannot be read
    /// from the certificate, which means a stored PEM this build cannot parse.
    /// Renewing on a fixed window is wrong in one direction; never renewing is
    /// wrong in the worse one.
    pub fn needs_renewal(&self, ratio: f64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let remaining = self.expires_at - now;

        match certificate_lifetime_seconds(&self.cert_pem) {
            Some(lifetime) if lifetime > 0 => {
                remaining < (lifetime as f64 * ratio.clamp(0.0, 1.0)) as i64
            }
            _ => remaining < 30 * 24 * 60 * 60,
        }
    }
}

/// 📅 How long the leaf certificate is valid for, in seconds.
fn certificate_lifetime_seconds(cert_pem: &str) -> Option<i64> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes()).ok()?;
    let (_, certificate) = parse_x509_certificate(&pem.contents).ok()?;
    let validity = certificate.validity();
    Some(validity.not_after.timestamp() - validity.not_before.timestamp())
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
    let (_, certificate) = parse_x509_certificate(&pem.contents).map_err(|error| {
        AcmeError::CertGeneration(format!("Invalid X.509 certificate: {error}"))
    })?;
    Ok(certificate.validity().not_after.timestamp())
}

/// 🧩 A challenge type and the handler that can answer it, kept together.
///
/// They are one decision, not two. Pairing HTTP-01 with a handler that writes
/// DNS records — or the reverse — produces an order that deploys nothing the
/// CA will look at, and fails several minutes later with an error about
/// validation rather than about configuration. Passing them as a pair means
/// the mismatch cannot be expressed.
pub struct ChallengeSolver {
    /// The challenge this solver answers.
    pub challenge_type: ChallengeType,
    /// The handler that deploys and cleans it up.
    pub handler: std::sync::Arc<dyn ChallengeHandler>,
}

impl ChallengeSolver {
    /// 🌐 The HTTP-01 solver, which is what a site gets unless it asked for
    /// something else.
    pub fn http01(handler: std::sync::Arc<dyn ChallengeHandler>) -> Self {
        Self {
            challenge_type: ChallengeType::Http01,
            handler,
        }
    }

    /// 📡 The DNS-01 solver, which a wildcard name has no alternative to.
    pub fn dns01(handler: std::sync::Arc<dyn ChallengeHandler>) -> Self {
        Self {
            challenge_type: ChallengeType::Dns01,
            handler,
        }
    }
}

/// 🗺️ Which challenge proves which name.
///
/// Almost every deployment has one answer for everything, and a few have two:
/// a wildcard that must use DNS-01 sitting beside ordinary names that are
/// happy with HTTP-01. Resolved from configuration once at startup, so an
/// issuance never re-derives it and the two transports cannot disagree.
pub struct ChallengePolicy {
    /// 🌐 What a name gets when it asked for nothing in particular.
    default: ChallengeSolver,
    /// 📡 Names that asked for something else, by the exact string the
    /// configuration used — including the leading `*.` of a wildcard, because
    /// that is the identifier the certificate is ordered under.
    overrides: std::collections::HashMap<String, ChallengeSolver>,
}

impl ChallengePolicy {
    /// 🌐 A policy where everything uses one solver.
    pub fn uniform(default: ChallengeSolver) -> Self {
        Self {
            default,
            overrides: std::collections::HashMap::new(),
        }
    }

    /// 📡 Gives one name its own solver.
    pub fn with_override(mut self, domain: impl Into<String>, solver: ChallengeSolver) -> Self {
        self.overrides.insert(domain.into(), solver);
        self
    }

    /// 🔎 The solver that proves this name.
    pub fn solver_for(&self, domain: &str) -> &ChallengeSolver {
        self.overrides.get(domain).unwrap_or(&self.default)
    }

    /// 🧾 Whether any name uses something other than the default.
    pub fn has_overrides(&self) -> bool {
        !self.overrides.is_empty()
    }
}

// MARK: - Certificate issuer

/// 🏛️ Whatever actually goes and gets a certificate.
///
/// One method, and it exists so the thing above it can be tested. Certificate
/// issuance is the part of this server that reaches out to a stranger's
/// machine and is counted against a quota when it does, which makes it exactly
/// the part where "we believe it only runs when it should" is not good enough
/// — and also the part a test cannot exercise for real. Behind this trait a
/// test can hand [`AutoHttps`](crate::auto_https::AutoHttps) an issuer that
/// records what it was asked for and answers instantly, so questions like "did
/// an unconfigured name reach a CA" and "how many orders ran at once" have
/// measured answers rather than arguments.
///
/// [`AcmeClient`] is the real implementation and the only one outside tests.
#[async_trait::async_trait]
pub trait CertificateIssuer: Send + Sync {
    /// 📜 Obtains one certificate covering `domains`, proving control with
    /// `solver`.
    async fn obtain_certificate(
        &self,
        domains: &[String],
        solver: &ChallengeSolver,
    ) -> Result<Certificate, AcmeError>;
}

#[async_trait::async_trait]
impl CertificateIssuer for AcmeClient {
    async fn obtain_certificate(
        &self,
        domains: &[String],
        solver: &ChallengeSolver,
    ) -> Result<Certificate, AcmeError> {
        AcmeClient::obtain_certificate(self, domains, solver).await
    }
}

// MARK: - ACME Client

/// The high-level client for ACME operations.
pub struct AcmeClient {
    /// If true, uses the Let's Encrypt Staging environment.
    staging: bool,

    /// Contact email for account registration and expiration notices.
    email: Option<String>,

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
            account_store_root: None,
        }
    }

    /// Creates a client configured for the Staging environment.
    pub fn staging() -> Self {
        Self {
            staging: true,
            email: None,
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

    /// Obtains a certificate for the specified domains.
    ///
    /// This method executes the full ACME workflow:
    /// 1. Account creation/retrieval.
    /// 2. Order placement.
    /// 3. Authorization & Challenge solving.
    /// 4. Polling for validity.
    /// 5. Certificate finalization & download.
    pub async fn obtain_certificate(
        &self,
        domains: &[String],
        solver: &ChallengeSolver,
    ) -> Result<Certificate, AcmeError> {
        let handler = solver.handler.as_ref();
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
        let identifiers: Vec<Identifier> =
            domains.iter().map(|d| Identifier::Dns(d.clone())).collect();

        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|e| AcmeError::OrderFailed(format!("Failed to create order: {e}")))?;

        tracing::info!("✅ Order created. URL: {}", order.url());

        // 4. Process Authorizations
        let mut auths_stream = order.authorizations();
        let mut active_challenges = Vec::new(); // Keep track for cleanup

        while let Some(auth_result) = auths_stream.next().await {
            let mut auth = auth_result.map_err(|e| {
                AcmeError::OrderFailed(format!("Failed to fetch authorization: {e}"))
            })?;

            let domain = auth.identifier().to_string();

            if auth.status == AuthorizationStatus::Valid {
                tracing::info!("✅ Authorization already valid for {}", domain);
                continue;
            }

            tracing::info!("🧩 Solving challenge for {}", domain);

            // 4a. Pick Challenge
            let target_type = match solver.challenge_type {
                ChallengeType::Http01 => AcmeChallengeType::Http01,
                ChallengeType::Dns01 => AcmeChallengeType::Dns01,
                ChallengeType::TlsAlpn01 => AcmeChallengeType::TlsAlpn01,
            };

            let mut challenge = auth.challenge(target_type).ok_or_else(|| {
                AcmeError::ChallengeFailed(format!(
                    "Challenge type {:?} not offered for {}",
                    solver.challenge_type, domain
                ))
            })?;

            // 4b. Deploy Solution
            let response = ChallengeResponse {
                domain: domain.clone(),
                challenge_type: solver.challenge_type,
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
            return Err(AcmeError::OrderFailed(format!(
                "Order ended in state: {state:?}"
            )));
        }

        // 6. Finalize & Download
        tracing::info!("�️ Finalizing order...");
        let key_pem = order
            .finalize()
            .await
            .map_err(|e| AcmeError::CertGeneration(format!("Finalization failed: {e}")))?;

        let cert_pem = order
            .poll_certificate(&retry_policy)
            .await
            .map_err(|e| AcmeError::CertGeneration(format!("Download failed: {e}")))?;

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
        let credentials_path = self
            .account_store_root
            .as_ref()
            .map(|root| crate::account_store::credentials_path(root, self.staging));

        // 1. Try to restore the account from persisted credentials.
        if let Some(path) = &credentials_path {
            match Self::load_account_credentials(path) {
                Ok(Some(credentials)) => {
                    let builder = Account::builder()
                        .map_err(|e| AcmeError::Account(format!("Builder init failed: {e}")))?;
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
                    tracing::debug!(
                        "No persisted ACME account at {:?}; registering a new one",
                        path
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "⚠️ Failed to load ACME account credentials from {:?}: {}; registering a new account",
                        path,
                        e
                    );
                }
            }
        }

        // 2. Register a new account.
        let contact: Vec<String> = self
            .email
            .as_ref()
            .map(|e| vec![format!("mailto:{}", e)])
            .unwrap_or_default();

        let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();

        let new_account = NewAccount {
            contact: &contact_refs,
            terms_of_service_agreed: true,
            only_return_existing: false,
        };

        let builder = Account::builder()
            .map_err(|e| AcmeError::Account(format!("Builder init failed: {e}")))?;

        let (account, credentials) = builder
            .create(&new_account, directory_url.to_string(), None)
            .await
            .map_err(|e| AcmeError::Account(format!("Registration failed: {e}")))?;

        // 3. Persist the credentials for future restarts. A failure here is
        //    non-fatal: issuance can proceed with the in-memory account.
        if let Some(path) = &credentials_path {
            if let Err(e) = Self::store_account_credentials(path, &credentials) {
                tracing::warn!(
                    "⚠️ Failed to persist ACME account credentials to {:?}: {}",
                    path,
                    e
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
    fn load_account_credentials(
        path: &std::path::Path,
    ) -> Result<Option<AccountCredentials>, AcmeError> {
        match crate::account_store::load(path)
            .map_err(|e| AcmeError::Account(format!("Read failed: {e}")))?
        {
            Some(json) => {
                let credentials = serde_json::from_str(&json)
                    .map_err(|e| AcmeError::Account(format!("Corrupt credentials: {e}")))?;
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
            .map_err(|e| AcmeError::Account(format!("Serialization failed: {e}")))?;
        crate::account_store::save(path, &json)
            .map_err(|e| AcmeError::Account(format!("Write failed: {e}")))
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
            cert_pem: "".into(),
            key_pem: "".into(),
            domains: vec![],
            expires_at: now - 3600,
        };
        assert!(expired.needs_renewal(DEFAULT_RENEWAL_WINDOW_RATIO));

        // Case 2: Fresh (60 days left)
        let fresh = Certificate {
            cert_pem: "".into(),
            key_pem: "".into(),
            domains: vec![],
            expires_at: now + 60 * 86400,
        };
        assert!(!fresh.needs_renewal(DEFAULT_RENEWAL_WINDOW_RATIO));

        // Case 3: Nearing expiry (29 days left)
        let near = Certificate {
            cert_pem: "".into(),
            key_pem: "".into(),
            domains: vec![],
            expires_at: now + 29 * 86400,
        };
        assert!(near.needs_renewal(DEFAULT_RENEWAL_WINDOW_RATIO));
    }

    /// 🔄 A short-lived certificate must not be renewed the moment it is
    /// issued.
    ///
    /// The fixed thirty-day window this replaced said "renew" for every
    /// certificate valid for less than a month, from the second it was signed
    /// — so a seven-day certificate would be re-requested on every scan,
    /// forever, until the CA's rate limit stopped it. The window has to be a
    /// fraction of the certificate's own lifetime for the answer to change
    /// with the certificate.
    #[test]
    fn a_short_lived_certificate_is_not_renewed_the_day_it_is_issued() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // 📅 Seven days of validity, issued moments ago.
        let mut parameters =
            rcgen::CertificateParams::new(vec!["short.example".to_string()]).unwrap();
        parameters.not_before = std::time::SystemTime::now().into();
        parameters.not_after =
            (std::time::SystemTime::now() + std::time::Duration::from_secs(7 * 86400)).into();
        let key = rcgen::KeyPair::generate().unwrap();
        let issued = parameters.self_signed(&key).unwrap();

        let certificate = Certificate {
            cert_pem: issued.pem(),
            key_pem: key.serialize_pem(),
            domains: vec!["short.example".to_string()],
            expires_at: now + 7 * 86400,
        };

        assert!(
            !certificate.needs_renewal(DEFAULT_RENEWAL_WINDOW_RATIO),
            "a week-old-at-most certificate with a week to run is not due"
        );

        // 🕰️ Two thirds through its life, it is.
        let past_two_thirds = Certificate {
            expires_at: now + 2 * 86400,
            ..certificate
        };
        assert!(
            past_two_thirds.needs_renewal(DEFAULT_RENEWAL_WINDOW_RATIO),
            "under a third of a seven-day lifetime remaining is due"
        );
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
        assert!(
            AcmeClient::load_account_credentials(&path)
                .unwrap()
                .is_none()
        );
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
        assert!(
            AcmeClient::load_account_credentials(&path)
                .unwrap()
                .is_none()
        );

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
        assert!(
            AcmeClient::load_account_credentials(&prod)
                .unwrap()
                .is_none()
        );
        assert!(
            AcmeClient::load_account_credentials(&staging)
                .unwrap()
                .is_some()
        );
    }
}
