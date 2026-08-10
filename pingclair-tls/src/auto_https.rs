// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Automatic HTTPS Management
//!
//! 🔐 Orchestra component that combines `AcmeClient` and `CertStore` to provide
//! "Zero Configuration" HTTPS. Handles the certificate lifecycle: issuance, storage, and renewal.

use crate::acme::{AcmeClient, AcmeError, Certificate, ChallengePolicy, ChallengeSolver};
use crate::cert_store::{CertStore, CertStoreError};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
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
        // TODO(v0.3): try a fallback issuer (ZeroSSL) after Let's Encrypt
        // fails; requires external-account-binding support.
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

        // Persist the ACME account next to the certificates so it is reused
        // across restarts instead of re-registering on every issuance.
        let acme = acme.with_account_store(store.path().to_path_buf());

        Self {
            config,
            acme,
            store,
            processing: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }

    /// 📁 Hydrates the persistent certificate cache before any handshake.
    pub(crate) async fn init_store(&self) -> Result<(), CertStoreError> {
        self.store.init().await
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
    ///   - solver: The challenge type this domain uses and the handler that
    ///     answers it. Chosen per domain by the caller, because a wildcard
    ///     needs DNS-01 while its neighbours are happy with HTTP-01.
    pub async fn get_certificate(
        &self,
        domain: &str,
        solver: &ChallengeSolver,
    ) -> Result<Certificate, AutoHttpsError> {
        // 1. Fast Path: Check Store
        if let Some(cert) = self.store.get(domain).await {
            if !cert.needs_renewal() {
                tracing::debug!("✅ Cache Hit: Valid certificate found for {}", domain);
                return Ok(cert);
            }
            tracing::info!(
                "⏰ Expiry Warning: Certificate for {} needs renewal",
                domain
            );
        }

        // 2. Concurrency Check
        {
            let processing = self.processing.read().await;
            if processing.contains(domain) {
                return Err(AutoHttpsError::Config(format!(
                    "🔄 Race Protection: Certificate for {domain} is already being issued"
                )));
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
        let result = self
            .acme
            .obtain_certificate(&[domain.to_string()], solver)
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
    pub fn start_renewal_task(self: Arc<Self>, policy: Arc<ChallengePolicy>) {
        let interval = self.config.renewal_interval;

        tracing::info!("🔄 Starting Renewal Daemon (Interval: {:?})", interval);

        tokio::spawn(async move {
            // 🕰️ Consecutive failures back off exponentially so a down CA or a
            // broken DNS record does not hammer the ACME endpoint every
            // interval. Each domain records the earliest instant it may be
            // retried; success removes the entry.
            let mut next_attempt: HashMap<String, (u32, Instant)> = HashMap::new();
            loop {
                tokio::time::sleep(interval).await;

                tracing::debug!("🔍 Renewal Daemon: Scanning certificates...");

                let renewal_candidates = self.store.get_needing_renewal().await;

                if renewal_candidates.is_empty() {
                    tracing::debug!("✅ Renewal Daemon: All certificates healthy");
                    continue;
                }

                tracing::info!(
                    "⏰ Renewal Daemon: found {} cert(s) needing attention",
                    renewal_candidates.len()
                );

                for cert in renewal_candidates {
                    if let Some(domain) = cert.domains.first() {
                        if next_attempt
                            .get(domain)
                            .is_some_and(|(_, until)| Instant::now() < *until)
                        {
                            tracing::debug!("⏳ {} is in backoff; skipping this scan", domain);
                            continue;
                        }
                        tracing::info!("🔄 Renewing {}...", domain);

                        match self
                            .get_certificate(domain, policy.solver_for(domain))
                            .await
                        {
                            Ok(_) => {
                                tracing::info!("✅ Renewed successfully: {}", domain);
                                next_attempt.remove(domain);
                            }
                            Err(e) => {
                                tracing::error!("❌ Renew failed for {}: {}", domain, e);
                                let failures = next_attempt
                                    .get(domain)
                                    .map_or(0, |(failures, _)| *failures + 1);
                                let backoff = interval
                                    .saturating_mul(2u32.saturating_pow(failures.min(10)))
                                    .min(Duration::from_secs(24 * 60 * 60));
                                next_attempt
                                    .insert(domain.clone(), (failures, Instant::now() + backoff));
                                tracing::warn!("⏳ Backing off {} for {:?}", domain, backoff);
                            }
                        }
                    }
                }
            }
        });
    }

    /// 🚀 Eagerly obtains certificates for every configured `tls auto`
    /// hostname at startup, so the first TLS handshake never blocks on ACME.
    /// Domains that already have a valid certificate are skipped.
    pub fn start_eager_issuance(
        self: Arc<Self>,
        domains: Vec<String>,
        policy: Arc<ChallengePolicy>,
    ) {
        if domains.is_empty() {
            return;
        }
        tracing::info!("🚀 Eager issuance for {} hostname(s)", domains.len());
        tokio::spawn(async move {
            for domain in domains {
                if self.has_certificate(&domain).await {
                    tracing::debug!("✅ {} already has a valid certificate", domain);
                    continue;
                }
                match self
                    .get_certificate(&domain, policy.solver_for(&domain))
                    .await
                {
                    Ok(_) => tracing::info!("🎉 Eager issuance complete for {}", domain),
                    Err(e) => {
                        // ⚠️ Failure is not fatal: the lazy handshake path will
                        // retry, and the renewal daemon keeps trying with
                        // backoff.
                        tracing::warn!("⚠️ Eager issuance failed for {}: {}", domain, e);
                    }
                }
            }
        });
    }

    /// Checks if a valid certificate currently exists for a domain.
    pub async fn has_certificate(&self, domain: &str) -> bool {
        self.store.has_valid(domain).await
    }

    /// 🛑 Drops every in-flight issuance marker. Called on configuration
    /// reload so a new config can immediately start its own issuance instead
    /// of waiting for the previous config's ACME transaction to finish. The
    /// abandoned task still completes and stores its certificate, which is
    /// harmless.
    pub async fn cancel_pending_issuance(&self) {
        self.processing.write().await.clear();
    }

    /// Returns an already-issued certificate from the store's cache, if any.
    ///
    /// Unlike [`AutoHttps::get_certificate`] this never triggers an ACME
    /// issuance flow — it only surfaces certificates that already exist.
    /// Used by the HTTP/3 SNI certificate table, which cannot await an
    /// issuance inside a handshake callback.
    pub async fn cached_certificate(&self, domain: &str) -> Option<Certificate> {
        self.store.get(domain).await
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
