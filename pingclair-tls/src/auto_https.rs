// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Automatic HTTPS Management
//!
//! 🔐 Orchestra component that combines `AcmeClient` and `CertStore` to provide
//! "Zero Configuration" HTTPS. Handles the certificate lifecycle: issuance, storage, and renewal.

use crate::acme::{
    AcmeClient, AcmeError, Certificate, CertificateIssuer, ChallengePolicy, ChallengeSolver,
};
use crate::cert_store::{CertStore, CertStoreError};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Semaphore;

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

    /// 🔄 Fraction of a certificate's lifetime that must remain before it is
    /// renewed. How *early* to renew, where `renewal_interval` is how often to
    /// look — two different questions that are easy to confuse.
    pub renewal_window_ratio: f64,

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
            renewal_window_ratio: crate::acme::DEFAULT_RENEWAL_WINDOW_RATIO,
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

/// 🚦 How many ACME transactions this process will run at once.
///
/// Issuance is slow, remote, and rate-limited at the other end, so the useful
/// question is not "how fast can we go" but "how much can one process have in
/// flight before it is hurting itself". Four is enough that a fresh
/// configuration with a handful of sites comes up promptly, and small enough
/// that a configuration with three hundred names walks through them instead of
/// opening three hundred orders and being throttled for it.
///
/// 🛡️ It is also the last line of defence behind the allowlist: if a future
/// change ever lets an unconfigured name reach here again, the damage is
/// bounded by this number rather than by how fast a client can open sockets.
const MAX_CONCURRENT_ISSUANCES: usize = 4;

/// The high-level manager that automates the acquisition and renewal of TLS
/// certificates.
///
/// It coordinates:
/// 1. Checking the `CertStore` for existing valid certificates.
/// 2. Requesting new certificates via the issuer if missing or expired.
/// 3. Running a background task to renew certificates automatically.
///
/// 🚦 Between steps 1 and 2 sit the gates that decide whether a certificate
/// authority is contacted at all: the configuration's on/off switch, a
/// per-name claim so two callers cannot open two orders for one site, and a
/// process-wide ceiling on how many orders run at once. The allowlist that
/// decides *which names* may get this far lives one layer up, in
/// [`TlsManager`](crate::manager::TlsManager), because it is the layer that
/// knows what the configuration serves.
pub struct AutoHttps {
    config: AutoHttpsConfig,
    /// 🏛️ The certificate authority, behind a trait so a test can stand in for
    /// it. In production this is always the real `AcmeClient`.
    issuer: Arc<dyn CertificateIssuer>,
    store: Arc<CertStore>,

    /// 🔁 Domains with an ACME transaction in flight, so a second caller for
    /// the same name does not open a second order.
    ///
    /// A plain `Mutex` rather than an async lock on purpose: it is held for one
    /// set insertion and never across an `await`, and [`IssuanceSlot`] has to
    /// be able to release it from `Drop`, where awaiting is not possible.
    processing: Arc<Mutex<HashSet<String>>>,

    /// 🚦 Bounds concurrent ACME work across the whole process.
    issuance_slots: Arc<Semaphore>,
}

/// 🎟️ One claim on the right to issue for a domain, released however the
/// caller leaves.
///
/// The claim has to be an RAII guard rather than a pair of statements around
/// the ACME call, because the ACME call is awaited inside a TLS handshake: if
/// the client hangs up, the future is dropped and the code after it never
/// runs. A hand-written "remove the marker afterwards" leaves the domain
/// marked as in-flight forever, and every later attempt to issue for that name
/// is refused for the lifetime of the process.
struct IssuanceSlot {
    processing: Arc<Mutex<HashSet<String>>>,
    domain: String,
}

impl IssuanceSlot {
    /// 🔒 Claims `domain` if nothing else holds it, in one locked step.
    ///
    /// Checking membership and then inserting under two separate locks is a
    /// race with a real consequence: two handshakes for the same new name both
    /// see an empty set, both start an order, and the CA counts both against
    /// the account's rate limit. `HashSet::insert` answers both questions at
    /// once — it returns `false` when the name was already there.
    fn claim(processing: &Arc<Mutex<HashSet<String>>>, domain: &str) -> Option<Self> {
        processing.lock().insert(domain.to_string()).then(|| Self {
            processing: Arc::clone(processing),
            domain: domain.to_string(),
        })
    }
}

impl Drop for IssuanceSlot {
    fn drop(&mut self) {
        self.processing.lock().remove(&self.domain);
    }
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

        // 💾 Persist the ACME account next to the certificates so it is reused
        // across restarts instead of re-registering on every issuance.
        let acme = acme.with_account_store(store.path().to_path_buf());

        Self::with_issuer(config, store, Arc::new(acme))
    }

    /// 🧪 Builds the manager around a given issuer.
    ///
    /// The one seam this subsystem has. Everything else here — the allowlist
    /// above it, the disabled switch, the per-domain claim, the concurrency
    /// bound — decides *whether* to call a certificate authority, and none of
    /// it can be checked against a real one. Tests pass an issuer that counts
    /// its calls; production goes through [`Self::new`].
    pub fn with_issuer(
        config: AutoHttpsConfig,
        store: Arc<CertStore>,
        issuer: Arc<dyn CertificateIssuer>,
    ) -> Self {
        Self {
            config,
            issuer,
            store,
            processing: Arc::new(Mutex::new(HashSet::new())),
            issuance_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_ISSUANCES)),
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
            if !cert.needs_renewal(self.store.renewal_window_ratio()) {
                tracing::debug!("✅ Cache Hit: Valid certificate found for {}", domain);
                return Ok(cert);
            }
            tracing::info!(
                "⏰ Expiry Warning: Certificate for {} needs renewal",
                domain
            );
        }

        // 2. 🚫 The disabled policy stops here.
        //
        // Reading a certificate that already exists is left alone above: it
        // makes no outbound call and spends none of the account's quota, so
        // turning automatic HTTPS off does not have to take a working site
        // down. What it must stop is *acquiring* one, which is everything
        // below this line.
        if !self.config.enabled {
            return Err(AutoHttpsError::Config(format!(
                "🚫 Automatic HTTPS is off, so no certificate will be requested for {domain}"
            )));
        }

        // 3. 🎟️ Claim the domain, atomically, for as long as this call lives.
        let Some(_slot) = IssuanceSlot::claim(&self.processing, domain) else {
            return Err(AutoHttpsError::Config(format!(
                "🔄 Race Protection: Certificate for {domain} is already being issued"
            )));
        };

        // 4. 🚦 Take a process-wide slot, or decline now rather than queue.
        //
        // Waiting would be the friendlier answer for a legitimate caller and
        // the wrong one here: a queue is unbounded memory and unbounded
        // latency held open by whoever is asking. Declining costs one failed
        // handshake, and the renewal daemon and the next handshake both retry.
        let Ok(_permit) = self.issuance_slots.try_acquire() else {
            return Err(AutoHttpsError::Config(format!(
                "🚦 {MAX_CONCURRENT_ISSUANCES} certificate issuances are already in flight; \
                 {domain} was not started"
            )));
        };

        tracing::info!("🚀 Starting issuance workflow for {}", domain);

        // 5. Perform ACME Operation. The slot and the permit both release when
        // this function returns, including on the early `?` below and
        // including when the awaiting handshake is dropped.
        let cert = self
            .issuer
            .obtain_certificate(&[domain.to_string()], solver)
            .await?;

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
        self.processing.lock().clear();
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

    // MARK: - Issuance gates

    use crate::acme::MemoryChallengeHandler;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::{Notify, mpsc};

    /// 🧪 An issuer that reports when it is entered and waits to be released.
    ///
    /// Blocking on a `Notify` rather than sleeping is what makes these tests
    /// answer the question asked. "Sleep 50ms and hope both calls overlap"
    /// passes on an idle laptop and fails on a loaded CI box, and when it
    /// fails it says nothing about the code — this repository has paid for
    /// that lesson already. Here the test knows a call is inside the issuer
    /// because the issuer said so.
    struct GatedIssuer {
        entered: mpsc::UnboundedSender<String>,
        release: Arc<Notify>,
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl CertificateIssuer for GatedIssuer {
        async fn obtain_certificate(
            &self,
            domains: &[String],
            _solver: &ChallengeSolver,
        ) -> Result<Certificate, AcmeError> {
            let domain = domains.first().cloned().unwrap_or_default();
            self.calls.fetch_add(1, Ordering::SeqCst);
            let _ = self.entered.send(domain.clone());
            self.release.notified().await;
            Ok(Certificate {
                cert_pem: "CERT".to_string(),
                key_pem: "KEY".to_string(),
                domains: domains.to_vec(),
                expires_at: 4_102_444_800,
            })
        }
    }

    struct Harness {
        auto: Arc<AutoHttps>,
        issuer: Arc<GatedIssuer>,
        entered: mpsc::UnboundedReceiver<String>,
        release: Arc<Notify>,
        _directory: tempfile::TempDir,
    }

    fn harness(enabled: bool) -> Harness {
        let directory = tempfile::tempdir().unwrap();
        let (entered_tx, entered) = mpsc::unbounded_channel();
        let release = Arc::new(Notify::new());
        let issuer = Arc::new(GatedIssuer {
            entered: entered_tx,
            release: release.clone(),
            calls: AtomicUsize::new(0),
        });
        let store = Arc::new(CertStore::new(directory.path()));
        let auto = Arc::new(AutoHttps::with_issuer(
            AutoHttpsConfig {
                enabled,
                ..Default::default()
            },
            store,
            issuer.clone() as Arc<dyn CertificateIssuer>,
        ));
        Harness {
            auto,
            issuer,
            entered,
            release,
            _directory: directory,
        }
    }

    fn solver() -> ChallengeSolver {
        ChallengeSolver::http01(Arc::new(MemoryChallengeHandler::new()))
    }

    /// ⏳ Waits for the issuer to report entry, and fails rather than hangs.
    ///
    /// The signal is what makes these tests deterministic, but a bare
    /// `recv().await` turns "the gate under test is broken" into a run that
    /// never finishes — which is the least useful way for a test to say no. A
    /// generous ceiling keeps the deterministic behaviour on a loaded machine
    /// while still reporting a real failure as one.
    async fn expect_entered(entered: &mut mpsc::UnboundedReceiver<String>, what: &str) -> String {
        tokio::time::timeout(Duration::from_secs(10), entered.recv())
            .await
            .unwrap_or_else(|_| panic!("the issuer was never entered: {what}"))
            .expect("the issuer channel closed")
    }

    /// 🚫 Asserts a call is turned away *before* it reaches the issuer.
    ///
    /// The same reasoning as [`expect_entered`], pointed the other way. These
    /// tests assert that a gate refuses a caller, and the mock issuer blocks
    /// until released — so a removed gate does not make the assertion fail, it
    /// makes the call never return. Bounding it turns "the gate is gone" back
    /// into a failing test instead of a run that sits there.
    async fn expect_refused(
        call: impl std::future::Future<Output = Result<Certificate, AutoHttpsError>>,
        what: &str,
    ) {
        match tokio::time::timeout(Duration::from_secs(10), call).await {
            Ok(Err(_)) => {}
            Ok(Ok(_)) => panic!("the call was allowed through: {what}"),
            Err(_) => panic!("the call reached the issuer instead of being refused: {what}"),
        }
    }

    /// 🎟️ Claiming a name answers "was it free" and "it is mine now" in one
    /// locked step.
    ///
    /// Worth its own test because the interesting property is not visible from
    /// the outside. The version this replaced read the set under one lock and
    /// inserted under another, and between those two locks a second caller
    /// could read the same empty set — a race no single-threaded test can
    /// reproduce and no assertion on `get_certificate` can distinguish. What
    /// can be pinned is the contract the fix rests on: one call, one answer,
    /// released on drop.
    #[test]
    fn a_claim_is_exclusive_until_it_is_dropped() {
        let processing = Arc::new(Mutex::new(HashSet::new()));

        let first = IssuanceSlot::claim(&processing, "example.com").expect("a free name claims");
        assert!(
            IssuanceSlot::claim(&processing, "example.com").is_none(),
            "the same name was claimed twice at once"
        );
        // 🧭 A different name is unaffected; the claim is per-name, and the
        // process-wide bound is a separate mechanism.
        let other = IssuanceSlot::claim(&processing, "other.example").expect("a second name");

        drop(first);
        let again =
            IssuanceSlot::claim(&processing, "example.com").expect("a released name claims again");

        drop(other);
        drop(again);
        assert!(
            processing.lock().is_empty(),
            "a claim outlived its guard: {:?}",
            processing.lock()
        );
    }

    /// 🚫 `auto_https off` must mean nobody is contacted.
    ///
    /// The switch existed and was written into the configuration, and nothing
    /// at runtime ever read it — so an operator who turned automatic HTTPS off
    /// still had a server that would go and talk to a certificate authority.
    /// A setting that is accepted and ignored is worse than one that is
    /// refused, because the operator believes the thing they asked for.
    #[tokio::test]
    async fn a_disabled_policy_contacts_nobody() {
        let harness = harness(false);

        expect_refused(
            harness.auto.get_certificate("example.com", &solver()),
            "issuance ran with automatic HTTPS off",
        )
        .await;
        assert_eq!(harness.issuer.calls.load(Ordering::SeqCst), 0);
    }

    /// 🔁 Two callers for the same name produce one order, not two.
    ///
    /// The in-flight check and the insertion used to happen under two separate
    /// locks, so two handshakes arriving together for a name with no
    /// certificate both saw an empty set and both opened an order. The CA
    /// counts both against the account, and doing it often enough is how an
    /// account gets rate-limited out of issuing anything at all.
    #[tokio::test]
    async fn the_same_name_is_only_ever_issued_once_at_a_time() {
        let mut harness = harness(true);

        let first = tokio::spawn({
            let auto = harness.auto.clone();
            async move { auto.get_certificate("example.com", &solver()).await }
        });
        // ⏳ Deterministic: the issuer itself says when it has been entered.
        assert_eq!(
            expect_entered(&mut harness.entered, "the first caller").await,
            "example.com"
        );

        expect_refused(
            harness.auto.get_certificate("example.com", &solver()),
            "a second order was opened for a name already being issued",
        )
        .await;

        harness.release.notify_waiters();
        assert!(first.await.unwrap().is_ok());
        assert_eq!(harness.issuer.calls.load(Ordering::SeqCst), 1);
    }

    /// 🧹 An abandoned handshake releases its claim.
    ///
    /// The claim is taken inside a TLS handshake, and a client that hangs up
    /// mid-issuance drops that future — so any "remove the marker afterwards"
    /// written as a statement after the await simply never runs. The name
    /// stays marked in flight for the life of the process and every later
    /// attempt to issue for it is refused, which turns a client disconnect
    /// into a permanently broken site.
    #[tokio::test]
    async fn a_dropped_issuance_does_not_wedge_the_name_forever() {
        let mut harness = harness(true);

        let abandoned = tokio::spawn({
            let auto = harness.auto.clone();
            async move { auto.get_certificate("example.com", &solver()).await }
        });
        assert_eq!(
            expect_entered(&mut harness.entered, "the abandoned caller").await,
            "example.com"
        );
        abandoned.abort();
        // 🧭 Awaiting the aborted handle is what guarantees the future has been
        // dropped, and therefore that the guard has run.
        assert!(abandoned.await.unwrap_err().is_cancelled());

        let retry = tokio::spawn({
            let auto = harness.auto.clone();
            async move { auto.get_certificate("example.com", &solver()).await }
        });
        assert_eq!(
            expect_entered(
                &mut harness.entered,
                "the name stayed marked as in flight after its handshake went away"
            )
            .await,
            "example.com"
        );
        harness.release.notify_waiters();
        assert!(retry.await.unwrap().is_ok());
        assert_eq!(harness.issuer.calls.load(Ordering::SeqCst), 2);
    }

    /// 🚦 Distinct names are bounded too, not just repeats of one.
    ///
    /// The per-name claim says nothing about how many *different* names may be
    /// in flight, and a process that opens one ACME order per simultaneous
    /// handshake has no ceiling at all. The cap declines rather than queues:
    /// a queue is memory and latency held open by whoever is asking, while a
    /// refusal costs one handshake that the next attempt retries.
    #[tokio::test]
    async fn concurrent_issuance_for_different_names_is_capped() {
        let mut harness = harness(true);

        let attempts: Vec<_> = (0..MAX_CONCURRENT_ISSUANCES * 2)
            .map(|index| {
                let auto = harness.auto.clone();
                tokio::spawn(async move {
                    auto.get_certificate(&format!("site{index}.example"), &solver())
                        .await
                })
            })
            .collect();

        // ⏳ Wait until exactly the cap is inside the issuer. This cannot
        // over-count: nothing is released until the line after it.
        for _ in 0..MAX_CONCURRENT_ISSUANCES {
            expect_entered(&mut harness.entered, "one of the capped attempts").await;
        }
        harness.release.notify_waiters();

        let mut issued = 0;
        let mut refused = 0;
        for attempt in attempts {
            match attempt.await.unwrap() {
                Ok(_) => issued += 1,
                Err(_) => refused += 1,
            }
        }
        assert_eq!(issued, MAX_CONCURRENT_ISSUANCES, "the cap did not hold");
        assert_eq!(refused, MAX_CONCURRENT_ISSUANCES);
        assert_eq!(
            harness.issuer.calls.load(Ordering::SeqCst),
            MAX_CONCURRENT_ISSUANCES,
            "more orders reached the issuer than the cap allows"
        );
    }
}
