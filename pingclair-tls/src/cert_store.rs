// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Certificate Storage Management
//!
//! 💾 Handles the persistent storage and lifecycle of TLS certificates.
//! Supports disk-based persistence with an in-memory readout cache for high performance.
//!
//! **Two on-disk shapes, because two kinds of store use this.**
//!
//! 🏠 A local authority's leaves follow Caddy:
//! `certificates/local/<site>/<site>.{crt,key,json}`. The chain is a file that a
//! `.crt` walker finds, the key is a file of its own, and the metadata is not
//! secret — so a backup, an expiry report or an audit written against a Caddy
//! tree reads this one the same way (#169, #173).
//!
//! 🧾 The public-ACME store still writes one `<site>.json` in the store root,
//! holding the PEMs and the metadata together. That is a known divergence rather
//! than an oversight: Caddy files an ACME certificate under
//! `certificates/<issuer-directory>/…`, and which directory that is depends on
//! which CA issued it — a naming question the `acme_ca` configuration item
//! (#143) owns, not this change.

use crate::acme::Certificate;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

// MARK: - Errors

#[derive(Debug, Error)]
pub enum CertStoreError {
    #[error("💥 IO Error: {0}")]
    Io(#[from] std::io::Error),

    #[error("🔍 Not Found: Certificate for {0} does not exist")]
    NotFound(String),

    #[error("⚠️ Invalid Format: {0}")]
    Invalid(String),

    /// 🚫 Two different sites must never be filed in one place.
    ///
    /// Caddy spells a wildcard's directory `wildcard_.example.com`, and a host
    /// name may legally contain an underscore, so a site configured as
    /// `*.example.com` and one configured as `wildcard_.example.com` both map to
    /// that directory. Writing both leaves one site presenting the other's
    /// certificate, which is a data-loss shape rather than a naming preference —
    /// so the second one is refused and the operator is told which two names
    /// collided.
    #[error(
        "🚫 Certificate storage collision: {requested} would be filed where {held_by} already \
         is ({directory})"
    )]
    Collision {
        directory: String,
        held_by: String,
        requested: String,
    },
}

// MARK: - On-disk shapes

/// 🗂️ How a store turns a certificate into files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Layout {
    /// 🧾 One `<site>.json` in the store directory, holding chain, key and
    /// metadata together. Used by the public-ACME store.
    Flat,

    /// 🏠 One directory per site, holding `<site>.crt`, `<site>.key` and
    /// `<site>.json`. Used by the local authority.
    SiteDirectories,
}

/// 🌐 The name Caddy files a site's directory and files under.
///
/// 📌 `*.example.com` becomes `wildcard_.example.com`. That spelling is measured
/// rather than guessed — `caddy` 2.11.4 files a site configured as
/// `*.wildcard.test` under `certificates/local/wildcard_.wildcard.test/`, and
/// Caddy's source spells the substitution `"wildcard_" + name[1:]`. Every other
/// name is used verbatim.
///
/// 🎯 Using the name verbatim is the point. The rule this replaces replaced
/// every `.` with `_`, which is not reversible: `example.com` and `example_com`
/// produced the same filename, so two sites shared one certificate file with
/// nothing to say which had won (E-5).
fn site_directory_name(domain: &str) -> String {
    match domain.strip_prefix('*') {
        Some(rest) => format!("wildcard_{rest}"),
        None => domain.to_string(),
    }
}

impl Layout {
    /// 🏷️ The on-disk name a certificate's primary domain maps to.
    fn key_for(self, primary_domain: &str) -> String {
        match self {
            Self::Flat => primary_domain.replace('.', "_"),
            Self::SiteDirectories => site_directory_name(primary_domain),
        }
    }
}

// MARK: - Record formats

/// 🧾 The single file a flat store writes for one certificate.
#[derive(serde::Serialize, serde::Deserialize)]
struct FlatRecord {
    cert_pem: String,
    key_pem: String,
    domains: Vec<String>,
    expires_at: i64,
}

/// 🏷️ What `certificates/local/<site>/<site>.json` holds.
///
/// 🔐 Nothing secret. The chain lives in the sibling `.crt` and the key in the
/// sibling `.key`, which is the whole purpose of the three-file shape: an
/// operator can copy, diff or publish this file without handling the private
/// key at the same time. So the private key is **not** serialized here — that
/// was #173's open question, and the answer is Caddy's own: its metadata file
/// carries the subject names and nothing else.
///
/// 🌐 The field names are Caddy's, so a reader written for a Caddy tree finds
/// what it expects. `issuer_data` records which ACME account issued a
/// certificate; a local authority has no account, so it is always `null` —
/// written rather than omitted because Caddy's file has the key and a reader
/// that looks for it should find it.
#[derive(serde::Serialize, serde::Deserialize)]
struct SiteMetadata {
    /// 🌐 Every name the chain covers; the first is the one the directory is
    /// named after.
    sans: Vec<String>,

    /// 🔗 Always `null` for a local authority, which has no ACME account.
    #[serde(default)]
    issuer_data: Option<serde_json::Value>,
}

// MARK: - Certificate Store

/// A thread-safe, persistent store for TLS certificates.
pub struct CertStore {
    /// Root directory for persistence.
    path: PathBuf,

    /// 🗂️ Which files one certificate occupies here.
    layout: Layout,

    /// Write-through cache of loaded certificates.
    /// Key: Domain name (each SAN entry points to the cert).
    cache: Arc<RwLock<HashMap<String, Certificate>>>,

    /// 🔄 Fraction of a certificate's lifetime that must remain before it is
    /// renewed. Lives on the store because the store is what decides which
    /// certificates need attention.
    renewal_window_ratio: f64,

    /// 🔄 Per-name renewal windows, each written for the site that asked for it.
    ///
    /// The scalar above is what every name used before this map existed, and it
    /// stays the answer for every name the map does not cover — a site that
    /// sets a ratio gets its own policy rather than replacing anyone else's,
    /// which is how Caddy models the same option.
    ///
    /// ⚡ Empty is the overwhelmingly common case, and it is checked first: the
    /// lookup below runs on every handshake through `has_valid`, so with nothing
    /// configured it must cost one comparison and no hashing.
    per_domain_renewal_window: HashMap<String, f64>,
}

impl CertStore {
    /// Creates a new `CertStore` backed by the specified directory.
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self::flat(path, crate::acme::DEFAULT_RENEWAL_WINDOW_RATIO)
    }

    /// 🔄 As [`Self::new`], with an explicit renewal window.
    pub fn with_renewal_window(path: impl AsRef<Path>, renewal_window_ratio: f64) -> Self {
        Self::flat(path, renewal_window_ratio)
    }

    /// 🏠 A store that files each certificate the way Caddy files a local one.
    ///
    /// 📌 The renewal window is the default rather than a parameter because this
    /// shape is only ever the local authority's, and a local authority issues
    /// its own certificates with a lifetime it chooses — an operator's
    /// `renewal_window_ratio` is about the public CA's certificates.
    pub fn site_directories(path: impl AsRef<Path>) -> Self {
        Self::with_layout(
            path,
            crate::acme::DEFAULT_RENEWAL_WINDOW_RATIO,
            Layout::SiteDirectories,
        )
    }

    /// 🧾 A store that writes one `<site>.json` per certificate.
    fn flat(path: impl AsRef<Path>, renewal_window_ratio: f64) -> Self {
        Self::with_layout(path, renewal_window_ratio, Layout::Flat)
    }

    fn with_layout(path: impl AsRef<Path>, renewal_window_ratio: f64, layout: Layout) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            layout,
            cache: Arc::new(RwLock::new(HashMap::new())),
            renewal_window_ratio,
            per_domain_renewal_window: HashMap::new(),
        }
    }

    /// 🔄 A store whose renewal windows are the ones this configuration asked
    /// for: a default for every name, and one policy per site that named its
    /// own.
    pub fn from_auto_https(
        config: &crate::auto_https::AutoHttpsConfig,
        path: impl AsRef<Path>,
    ) -> Self {
        let mut store = Self::with_renewal_window(path, config.renewal_window_ratio);
        store.per_domain_renewal_window = config.renewal_windows.clone();
        store
    }

    /// 🔄 The renewal window this store applies by default, so callers that
    /// hold a certificate can ask the same question the scan does rather than
    /// inventing a second threshold.
    pub fn renewal_window_ratio(&self) -> f64 {
        self.renewal_window_ratio
    }

    /// 🔄 The renewal window that applies to one name.
    ///
    /// A site that wrote its own ratio gets it; anything else gets the default.
    /// The wildcard rule is the one the handshake uses — `*.example.com` covers
    /// `a.example.com` and nothing deeper — so a site and the certificate issued
    /// for it agree about which policy is theirs.
    pub fn renewal_window_ratio_for(&self, domain: &str) -> f64 {
        self.window_covering(domain)
            .unwrap_or(self.renewal_window_ratio)
    }

    /// 🔄 The window covering one name, if the configuration named one.
    fn window_covering(&self, domain: &str) -> Option<f64> {
        if self.per_domain_renewal_window.is_empty() {
            return None;
        }
        if let Some(ratio) = self.per_domain_renewal_window.get(domain) {
            return Some(*ratio);
        }
        self.per_domain_renewal_window
            .iter()
            .find_map(|(pattern, ratio)| {
                crate::acme::pattern_covers(pattern, domain).then_some(*ratio)
            })
    }

    /// 🔄 The window that applies to one certificate.
    ///
    /// A certificate carries several names, and the policy that matters is the
    /// one written for a name it actually serves — the first such name wins,
    /// which puts the certificate's own primary subject ahead of a SAN that
    /// merely happens to be listed first in the map.
    fn window_for_certificate(&self, certificate: &Certificate) -> f64 {
        if self.per_domain_renewal_window.is_empty() {
            return self.renewal_window_ratio;
        }
        certificate
            .domains
            .iter()
            .find_map(|domain| self.window_covering(domain))
            .unwrap_or(self.renewal_window_ratio)
    }

    /// Returns the root directory backing this store.
    pub fn path(&self) -> &Path {
        &self.path
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

    /// Loads every certificate the store directory holds into memory.
    async fn load_all(&self) -> Result<(), CertStoreError> {
        let loaded = match self.layout {
            Layout::Flat => self.load_flat().await?,
            Layout::SiteDirectories => self.load_site_directories().await?,
        };

        let count = loaded.len();
        let mut cache = self.cache.write().await;
        for certificate in loaded {
            // Map all domains in the cert to this entry
            for domain in &certificate.domains {
                cache.insert(domain.clone(), certificate.clone());
            }
        }

        if count > 0 {
            tracing::info!("📜 Hydrated {} certificate(s) from disk", count);
        }
        Ok(())
    }

    /// 📚 Loads every `<site>.json` a flat store holds.
    ///
    /// A file that will not parse is reported and skipped, not fatal: one
    /// unreadable certificate must not stop the process from serving the rest.
    async fn load_flat(&self) -> Result<Vec<Certificate>, CertStoreError> {
        let mut loaded = Vec::new();
        let mut entries = tokio::fs::read_dir(&self.path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path
                .extension()
                .map(|extension| extension != "json")
                .unwrap_or(true)
            {
                continue;
            }
            // 📄 The persistent challenge journal lives in the store root but is
            // not a certificate bundle; loading it as one would emit a
            // misleading "corrupt cert" warning on every start.
            if path.file_name().and_then(|name| name.to_str()) == Some("acme-challenges.json") {
                continue;
            }

            let contents = match tokio::fs::read_to_string(&path).await {
                Ok(contents) => contents,
                Err(error) => {
                    tracing::warn!("⚠️ Failed to read cert file {:?}: {}", path, error);
                    continue;
                }
            };
            match serde_json::from_str::<FlatRecord>(&contents) {
                Ok(record) => loaded.push(Certificate {
                    cert_pem: record.cert_pem,
                    key_pem: record.key_pem,
                    domains: record.domains,
                    expires_at: record.expires_at,
                }),
                Err(error) => {
                    tracing::warn!("⚠️ Skipping corrupt cert file {:?}: {}", path, error);
                }
            }
        }

        Ok(loaded)
    }

    /// 📚 Loads every site directory a `certificates/local/` store holds.
    ///
    /// 🛡️ A site whose chain and key do not belong together is skipped rather
    /// than loaded. The three files are written one at a time, so a crash
    /// between two of the writes can leave a mismatched pair on disk — and a
    /// server presenting it cannot complete a handshake. Skipping it re-issues
    /// the site on the next request, which for a local authority costs one
    /// signature; the same check also covers an operator who replaced a `.crt`
    /// by hand and did not replace its `.key`.
    async fn load_site_directories(&self) -> Result<Vec<Certificate>, CertStoreError> {
        let mut loaded = Vec::new();
        let mut entries = tokio::fs::read_dir(&self.path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let directory = entry.path();
            if !entry
                .file_type()
                .await
                .map(|kind| kind.is_dir())
                .unwrap_or(false)
            {
                continue;
            }
            let Some(stem) = directory
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
            else {
                continue;
            };

            match read_site_certificate(&directory, &stem).await {
                Ok(certificate) => loaded.push(certificate),
                Err(error) => {
                    tracing::warn!(
                        "⚠️ Skipping unusable certificate in {:?}: {}",
                        directory,
                        error
                    );
                }
            }
        }

        Ok(loaded)
    }

    /// Persists a certificate to disk and updates the cache.
    ///
    /// The filename is derived from the primary (first) domain in the list.
    pub async fn store(&self, cert: &Certificate) -> Result<(), CertStoreError> {
        let primary_domain = cert
            .domains
            .first()
            .ok_or_else(|| CertStoreError::Invalid("Certificate has no domains".to_string()))?
            .clone();

        tracing::debug!("💾 Persisting certificate for {}", primary_domain);
        self.refuse_collision(&primary_domain).await?;

        match self.layout {
            Layout::Flat => self.store_flat(cert, &primary_domain).await?,
            Layout::SiteDirectories => self.store_site_directory(cert, &primary_domain).await?,
        }

        // Update Cache
        let mut cache = self.cache.write().await;
        for domain in &cert.domains {
            cache.insert(domain.clone(), cert.clone());
        }

        tracing::info!("✅ Certificate stored successfully: {}", primary_domain);
        Ok(())
    }

    /// 🚫 Refuses a certificate whose on-disk name another site already holds.
    ///
    /// Checked against the cache rather than the directory so that a stale file
    /// left by an interrupted write cannot block a legitimate re-issue, and so
    /// that the answer is the same before and after the write completes.
    ///
    /// 📌 The cache lock is released before the write, so two *different* names
    /// that collide could both pass this check in the same instant and the
    /// later one would take the file — the overwrite this replaced. Closing
    /// that would mean holding a lock across an `await`, which this codebase
    /// treats as a defect rather than a trade: the local authority serialises
    /// its issuance behind its own state anyway, and a wildcard and a
    /// look-alike hostname being issued in the same instant is not a case worth
    /// one.
    async fn refuse_collision(&self, primary_domain: &str) -> Result<(), CertStoreError> {
        let key = self.layout.key_for(primary_domain);
        let cache = self.cache.read().await;

        let held_by = cache
            .values()
            .filter_map(|certificate| certificate.domains.first())
            .find(|other| other.as_str() != primary_domain && self.layout.key_for(other) == key);

        match held_by {
            Some(other) => Err(CertStoreError::Collision {
                directory: key,
                held_by: other.clone(),
                requested: primary_domain.to_string(),
            }),
            None => Ok(()),
        }
    }

    /// 🧾 Writes the one file a flat store uses.
    async fn store_flat(
        &self,
        cert: &Certificate,
        primary_domain: &str,
    ) -> Result<(), CertStoreError> {
        let record = FlatRecord {
            cert_pem: cert.cert_pem.clone(),
            key_pem: cert.key_pem.clone(),
            domains: cert.domains.clone(),
            expires_at: cert.expires_at,
        };
        let json = serde_json::to_string_pretty(&record)
            .map_err(|error| CertStoreError::Invalid(error.to_string()))?;

        let path = self
            .path
            .join(format!("{}.json", self.layout.key_for(primary_domain)));
        write_private_files(vec![(path, json.into_bytes())]).await
    }

    /// 🏠 Writes `<site>/<site>.crt`, `<site>.key` and `<site>.json`.
    ///
    /// 📌 The three files are written with the metadata last, but that ordering
    /// buys no atomicity across files — only [`write_private_files`] is atomic,
    /// and only per file. What makes a torn write safe is the pair check in
    /// [`load_site_directories`], which refuses to load a chain and a key that
    /// disagree.
    async fn store_site_directory(
        &self,
        cert: &Certificate,
        primary_domain: &str,
    ) -> Result<(), CertStoreError> {
        let stem = site_directory_name(primary_domain);
        let directory = self.path.join(&stem);
        let metadata = SiteMetadata {
            sans: cert.domains.clone(),
            issuer_data: None,
        };
        let json = serde_json::to_string_pretty(&metadata)
            .map_err(|error| CertStoreError::Invalid(error.to_string()))?;

        write_private_files(vec![
            (
                directory.join(format!("{stem}.key")),
                cert.key_pem.clone().into_bytes(),
            ),
            (
                directory.join(format!("{stem}.crt")),
                cert.cert_pem.clone().into_bytes(),
            ),
            (directory.join(format!("{stem}.json")), json.into_bytes()),
        ])
        .await
    }

    /// Retrieves a certificate from the in-memory cache.
    ///
    /// 🃏 The exact name wins; failing that, a wildcard leaf answers for the one
    /// label it covers. A certificate for `*.example.com` is stored under that
    /// key and nowhere else, so without this fallback every handshake for a name
    /// under a wildcard site would miss the store and order its own
    /// certificate — which is exactly what the wildcard exists to avoid.
    pub async fn get(&self, domain: &str) -> Option<Certificate> {
        let cache = self.cache.read().await;
        if let Some(cert) = cache.get(domain) {
            return Some(cert.clone());
        }
        let wildcard = wildcard_covering(domain)?;
        cache.get(&wildcard).cloned()
    }

    /// Checks if a non-expired certificate exists for the domain.
    pub async fn has_valid(&self, domain: &str) -> bool {
        if let Some(cert) = self.get(domain).await {
            !cert.needs_renewal(self.renewal_window_ratio_for(domain))
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

            if !primary_key.is_empty()
                && !seen_primary_keys.contains(&primary_key)
                && cert.needs_renewal(self.window_for_certificate(cert))
            {
                seen_primary_keys.insert(primary_key);
                candidates.push(cert.clone());
            }
        }

        candidates
    }

    /// Deletes a certificate (and its mappings) from both disk and cache.
    pub async fn remove(&self, domain: &str) -> Result<(), CertStoreError> {
        tracing::info!("🗑️ Requested removal of certificate for {}", domain);

        let mut cache = self.cache.write().await;

        if let Some(cert) = cache.get(domain).cloned() {
            if let Some(primary) = cert.domains.first() {
                let key = self.layout.key_for(primary);
                match self.layout {
                    Layout::Flat => {
                        let file_path = self.path.join(format!("{key}.json"));
                        if file_path.exists() {
                            tokio::fs::remove_file(&file_path).await?;
                        }
                    }
                    // 🧹 The whole directory goes, so no `.crt` or `.key` is
                    // left behind for a walker to find without its siblings.
                    Layout::SiteDirectories => {
                        let directory = self.path.join(&key);
                        if directory.exists() {
                            tokio::fs::remove_dir_all(&directory).await?;
                        }
                    }
                }
            }

            // Clear Cache Entries
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

// MARK: - Reading stored files

/// 📜 Reads a site's three files back into one certificate.
///
/// 🛡️ The chain and the key are checked against each other before either is
/// trusted: the files are separate, so nothing but this check stops a torn write
/// or a hand-replaced `.crt` from producing a certificate that cannot complete a
/// handshake.
///
/// ⏰ The expiry is read off the chain rather than off the metadata, so the
/// served certificate and the stored expiry cannot drift apart — which is what
/// makes it safe for an operator to replace a `.crt` and `.key` by hand, the
/// workflow this layout exists to support.
async fn read_site_certificate(
    directory: &Path,
    stem: &str,
) -> Result<Certificate, CertStoreError> {
    let cert_pem = tokio::fs::read_to_string(directory.join(format!("{stem}.crt"))).await?;
    let key_pem = tokio::fs::read_to_string(directory.join(format!("{stem}.key"))).await?;
    let metadata = tokio::fs::read_to_string(directory.join(format!("{stem}.json"))).await?;

    let facts = read_leaf(&cert_pem)?;
    if facts.public_key != read_key_public_key(&key_pem)? {
        return Err(CertStoreError::Invalid(format!(
            "{stem}.crt and {stem}.key hold different keys"
        )));
    }

    let metadata: SiteMetadata = serde_json::from_str(&metadata).map_err(|error| {
        CertStoreError::Invalid(format!("{stem}.json is not certificate metadata: {error}"))
    })?;
    if metadata.sans.is_empty() {
        return Err(CertStoreError::Invalid(format!(
            "{stem}.json names no domains"
        )));
    }

    Ok(Certificate {
        cert_pem,
        key_pem,
        domains: metadata.sans,
        expires_at: facts.expires_at,
    })
}

/// 📜 The facts the store needs from the leaf end of a PEM chain.
struct LeafFacts {
    /// ⏰ When the leaf stops being valid, in Unix epoch seconds.
    expires_at: i64,

    /// 🔑 The leaf's public key, for checking the key file belongs to it.
    public_key: Vec<u8>,
}

/// 📜 Reads the first certificate of a PEM chain.
fn read_leaf(cert_pem: &str) -> Result<LeafFacts, CertStoreError> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).map_err(|error| {
        CertStoreError::Invalid(format!("certificate chain is not PEM: {error}"))
    })?;
    let (_, certificate) = X509Certificate::from_der(&pem.contents).map_err(|error| {
        CertStoreError::Invalid(format!("certificate chain is not X.509: {error}"))
    })?;

    Ok(LeafFacts {
        expires_at: certificate.validity().not_after.timestamp(),
        public_key: certificate.public_key().raw.to_vec(),
    })
}

/// 🔑 Reads the public key out of a PEM private key.
fn read_key_public_key(key_pem: &str) -> Result<Vec<u8>, CertStoreError> {
    use rcgen::PublicKeyData;

    let key = rcgen::KeyPair::from_pem(key_pem)
        .map_err(|error| CertStoreError::Invalid(format!("private key is not PEM: {error}")))?;
    Ok(key.subject_public_key_info())
}

// MARK: - Writing

/// 🔒 Writes each file through the private-material writer, off the reactor.
///
/// 🔁 One spawn for the whole set rather than one per file: these are written
/// together, and a single blocking task keeps them in order on one thread.
async fn write_private_files(files: Vec<(PathBuf, Vec<u8>)>) -> Result<(), CertStoreError> {
    tokio::task::spawn_blocking(move || {
        for (path, contents) in files {
            crate::secure_file::write_private_file(&path, &contents)?;
        }
        Ok::<(), std::io::Error>(())
    })
    .await
    .map_err(|error| {
        CertStoreError::Io(std::io::Error::other(format!(
            "certificate writer failed: {error}"
        )))
    })?
    .map_err(CertStoreError::Io)
}

/// 🃏 The wildcard key that would cover `domain`, if one can exist.
///
/// `a.example.com` asks for `*.example.com`. The one-label rule is not checked
/// here, it falls out of the construction: `a.b.example.com` asks for
/// `*.b.example.com`, so a certificate for `*.example.com` cannot be reached
/// from a two-label subdomain by this path.
///
/// A two-label name like `example.com` asks for nothing — there is no `*.com`
/// to hold a certificate, and a wildcard has never covered a registrable name.
fn wildcard_covering(domain: &str) -> Option<String> {
    let (_, rest) = domain.split_once('.')?;
    rest.contains('.').then(|| format!("*.{rest}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🧪 A real self-signed certificate and its matching key.
    ///
    /// The store parses and cross-checks everything it loads, so a test that
    /// stands in for a stored certificate needs a genuine pair rather than
    /// placeholder strings.
    fn self_signed(domain: &str) -> (String, String) {
        use rcgen::{CertificateParams, KeyPair};

        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec![domain.to_string()]).unwrap();
        let certificate = params.self_signed(&key).unwrap();
        (certificate.pem(), key.serialize_pem())
    }

    /// 🔄 A site's own renewal window covers that site's names, and only those.
    ///
    /// Two halves, and the second is the one worth pinning. A site that wrote a
    /// ratio has to get it, or the option does nothing. And a site that wrote
    /// none has to keep the process-wide default, because the tempting
    /// implementation — one value that the site-level option overwrites — makes
    /// the last site in the configuration decide for every other one.
    #[test]
    fn a_site_renewal_window_covers_its_names_by_the_handshakes_wildcard_rule() {
        use crate::auto_https::AutoHttpsConfig;

        let mut config = AutoHttpsConfig::default();
        config.renewal_window_ratio = 0.5;
        config
            .renewal_windows
            .insert("short.example".to_string(), 0.1);
        config
            .renewal_windows
            .insert("*.wild.example".to_string(), 0.2);

        let temp_dir = tempfile::tempdir().unwrap();
        let store = CertStore::from_auto_https(&config, temp_dir.path());

        assert_eq!(
            store.renewal_window_ratio_for("short.example"),
            0.1,
            "the site that asked for a window gets it"
        );
        assert_eq!(
            store.renewal_window_ratio_for("a.wild.example"),
            0.2,
            "a wildcard policy covers the one label under it, as a wildcard certificate does"
        );
        assert_eq!(
            store.renewal_window_ratio_for("deep.a.wild.example"),
            0.5,
            "and nothing deeper, so a name no such certificate could serve does not \
             silently inherit the policy written for one that is"
        );
        assert_eq!(
            store.renewal_window_ratio_for("other.example"),
            0.5,
            "a site that named no window keeps the default"
        );
    }

    /// 🔄 A certificate's window comes from a name it actually serves.
    ///
    /// The choice matters when one certificate carries several names and the
    /// configuration named a window for one of them: picking by the order the
    /// map happens to iterate in would make the answer depend on hashing.
    #[test]
    fn a_certificates_window_comes_from_a_name_it_serves() {
        use crate::auto_https::AutoHttpsConfig;

        let mut config = AutoHttpsConfig::default();
        config.renewal_window_ratio = 0.5;
        config
            .renewal_windows
            .insert("second.example".to_string(), 0.25);

        let temp_dir = tempfile::tempdir().unwrap();
        let store = CertStore::from_auto_https(&config, temp_dir.path());

        let certificate = |domains: &[&str]| Certificate {
            cert_pem: "CERT".into(),
            key_pem: "KEY".into(),
            domains: domains.iter().map(|name| name.to_string()).collect(),
            expires_at: 4_102_444_800,
        };

        assert_eq!(
            store.window_for_certificate(&certificate(&["first.example", "second.example"])),
            0.25,
            "a window written for a name the certificate serves applies to it"
        );
        assert_eq!(
            store.window_for_certificate(&certificate(&["first.example", "third.example"])),
            0.5,
            "a certificate serving none of the configured names keeps the default"
        );
    }

    /// 🃏 A wildcard leaf answers for the one label under it, and for nothing
    /// that a TLS client would not accept it for.
    ///
    /// This is what lets one order for `*.example.com` serve every name beneath
    /// it. Without it the store misses on every concrete name — the certificate
    /// is filed under the wildcard — and each handshake orders its own
    /// certificate, which is the cost the wildcard exists to remove.
    #[tokio::test]
    async fn a_wildcard_certificate_answers_for_one_label_under_it() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = CertStore::new(temp_dir.path());
        store.init().await.expect("Init failed");

        let cert = Certificate {
            cert_pem: "CERT".into(),
            key_pem: "KEY".into(),
            domains: vec!["*.example.com".into()],
            expires_at: 4_102_444_800,
        };
        store.store(&cert).await.expect("Store failed");

        assert!(store.get("*.example.com").await.is_some());
        assert!(store.get("a.example.com").await.is_some());
        assert!(
            store.get("a.b.example.com").await.is_none(),
            "a wildcard covers one label"
        );
        assert!(
            store.get("example.com").await.is_none(),
            "the apex is not covered by its own wildcard"
        );
        assert!(store.get("notexample.com").await.is_none());
    }

    #[tokio::test]
    async fn test_store_lifecycle() {
        let temp_dir = tempfile::tempdir().unwrap();

        let store = CertStore::new(temp_dir.path());
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
        let store2 = CertStore::new(temp_dir.path());
        store2.init().await.expect("Re-init failed");

        assert!(store2.get("a.com").await.is_some());
        assert!(store2.get("b.com").await.is_some());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let certificate_path = temp_dir.path().join("a_com.json");
            let mode = std::fs::metadata(certificate_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    /// 🌐 The three-file shape, end to end.
    ///
    /// It is asserted as a whole tree rather than file by file, because the
    /// shape is the deliverable: `certificates/local/<site>/<site>.{crt,key,json}`
    /// is what a Caddy-shaped backup or audit tool walks for.
    #[tokio::test]
    async fn a_site_directory_holds_the_three_files_caddy_names() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = CertStore::site_directories(temp_dir.path());
        store.init().await.expect("Init failed");

        let (cert_pem, key_pem) = self_signed("stored_sandbox.test");
        let cert = Certificate {
            cert_pem: cert_pem.clone(),
            key_pem: key_pem.clone(),
            domains: vec!["stored_sandbox.test".into()],
            expires_at: 1234567890,
        };
        store.store(&cert).await.expect("Store failed");

        let directory = temp_dir.path().join("stored_sandbox.test");
        let mut found: Vec<String> = std::fs::read_dir(&directory)
            .expect("the site directory must exist")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        found.sort();
        assert_eq!(
            found,
            vec![
                "stored_sandbox.test.crt",
                "stored_sandbox.test.json",
                "stored_sandbox.test.key",
            ]
        );

        // 🔐 The metadata must not carry the private key: the whole reason the
        // three files are separate is that this one is not secret.
        let metadata = std::fs::read_to_string(directory.join("stored_sandbox.test.json")).unwrap();
        assert!(
            !metadata.contains("PRIVATE KEY"),
            "the metadata file must hold no private key: {metadata}"
        );
        assert!(
            metadata.contains(r#""sans""#),
            "Caddy's field name: {metadata}"
        );

        // 🔁 And the pair survives a reload with the expiry read off the chain.
        let reloaded = CertStore::site_directories(temp_dir.path());
        reloaded.init().await.expect("Re-init failed");
        let restored = reloaded
            .get("stored_sandbox.test")
            .await
            .expect("the stored certificate must hydrate");
        assert_eq!(restored.cert_pem, cert_pem);
        assert_eq!(restored.key_pem, key_pem);
        assert_eq!(restored.domains, vec!["stored_sandbox.test".to_string()]);
        assert_ne!(
            restored.expires_at, 1234567890,
            "the expiry comes from the certificate, not from the metadata"
        );
    }

    /// 🚫 A chain and a key that do not belong together are refused, not served.
    ///
    /// Two sites can be left in this state by a crash between the writes, and
    /// one site reaches it whenever an operator replaces a `.crt` without its
    /// `.key`. Loading it would hand a mismatched pair to the TLS layer, so the
    /// store skips it and the site is re-issued instead.
    #[tokio::test]
    async fn a_mismatched_chain_and_key_are_not_loaded() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = CertStore::site_directories(temp_dir.path());
        store.init().await.expect("Init failed");

        let (cert_pem, _) = self_signed("mixed.test");
        let (_, other_key) = self_signed("other.test");
        let cert = Certificate {
            cert_pem,
            key_pem: other_key,
            domains: vec!["mixed.test".into()],
            expires_at: 1234567890,
        };
        store.store(&cert).await.expect("Store failed");

        let reloaded = CertStore::site_directories(temp_dir.path());
        reloaded.init().await.expect("Re-init failed");
        assert!(
            reloaded.get("mixed.test").await.is_none(),
            "a chain whose key does not match it must not be loaded"
        );
    }

    /// 🚫 Two sites that would share one directory are refused, and the message
    /// says which two names collided.
    ///
    /// Caddy spells `*.example.com` as `wildcard_.example.com`, and an
    /// underscore is legal in a host name — `rustls-pki-types` documents its
    /// validation as "RFC1035, but with underscores allowed" — so a site
    /// configured as `wildcard_.example.com` maps to the same directory. Filing
    /// both would leave one site presenting the other's certificate.
    #[tokio::test]
    async fn a_wildcard_and_a_lookalike_hostname_may_not_share_a_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = CertStore::site_directories(temp_dir.path());
        store.init().await.expect("Init failed");

        let (cert_pem, key_pem) = self_signed("*.example.com");
        store
            .store(&Certificate {
                cert_pem: cert_pem.clone(),
                key_pem: key_pem.clone(),
                domains: vec!["*.example.com".into()],
                expires_at: 1234567890,
            })
            .await
            .expect("the wildcard itself stores");

        let error = store
            .store(&Certificate {
                cert_pem,
                key_pem,
                domains: vec!["wildcard_.example.com".into()],
                expires_at: 1234567890,
            })
            .await
            .expect_err("a collision must be refused");

        let message = format!("{error}");
        assert!(message.contains("wildcard_.example.com"), "{message}");
        assert!(message.contains("*.example.com"), "{message}");
    }

    /// 🏷️ The old `.`-to-`_` substitution produced one filename for two
    /// hostnames; Caddy's naming does not, and this pins that it has not
    /// quietly come back for the names that motivated the change.
    #[test]
    fn a_site_directory_name_keeps_the_hostname_and_spells_wildcards_like_caddy() {
        assert_eq!(site_directory_name("example.com"), "example.com");
        assert_eq!(site_directory_name("example_com"), "example_com");
        assert_ne!(
            site_directory_name("example.com"),
            site_directory_name("example_com"),
            "two hostnames must not share one directory"
        );
        assert_eq!(
            site_directory_name("*.wildcard.test"),
            "wildcard_.wildcard.test"
        );
    }
}
