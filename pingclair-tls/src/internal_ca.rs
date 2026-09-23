// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🏛️ Provides a persistent local certificate authority for private origins.
//!
//! **The tree is Caddy's, because the tools that read it are.**
//!
//! ```text
//! <store>/pki/authorities/local/root.crt          root certificate
//! <store>/pki/authorities/local/root.key          root private key
//! <store>/pki/authorities/local/intermediate.crt  signing certificate
//! <store>/pki/authorities/local/intermediate.key  signing private key
//! <store>/certificates/local/<site>/<site>.crt    leaf chain (leaf + intermediate)
//! <store>/certificates/local/<site>/<site>.key    leaf private key
//! <store>/certificates/local/<site>/<site>.json   subject names, not secret
//! ```
//!
//! 🎯 The names are the deliverable, not decoration. A backup procedure, a
//! "which certificates expire this month" report and a certificate audit are
//! all written against this shape by other tools, and a store this server
//! writes can be read by them without a translation step (#169, #173).
//!
//! 🌳 Two tiers rather than one, for the same reason: the files are named
//! `root` and `intermediate`, and a single self-signed authority written into
//! both would be a trust anchor wearing the wrong label. Leaves are signed by
//! the intermediate, and the intermediate by the root.

use crate::acme::Certificate;
use crate::cert_store::{CertStore, CertStoreError};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PublicKeyData,
};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::Mutex;

/// 📂 Where the authority's four files live, relative to the store root.
const AUTHORITY_DIRECTORY: &str = "pki/authorities/local";

/// 📂 Where the authority's leaf certificates live, relative to the store root.
const CERTIFICATES_DIRECTORY: &str = "certificates/local";

/// 📂 Where the authority lived before this layout, relative to the store root.
///
/// 🚫 Only ever looked for, to warn an upgrade that is about to lose the trust
/// of every client that has the old root installed.
const LEGACY_AUTHORITY_DIRECTORY: &str = "internal";

const AUTHORITY_LIFETIME: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);
const LEAF_LIFETIME: Duration = Duration::from_secs(90 * 24 * 60 * 60);
const CLOCK_SKEW_ALLOWANCE: Duration = Duration::from_secs(24 * 60 * 60);

/// ⏳ How much of the root's remaining life an intermediate must leave unused.
///
/// The two tiers are checked separately by anything validating the chain, so an
/// intermediate that expires after its root leaves a window in which the chain
/// does not validate. A day is enough margin for the clock differences that
/// already motivate [`CLOCK_SKEW_ALLOWANCE`].
const INTERMEDIATE_ROOT_MARGIN: Duration = Duration::from_secs(24 * 60 * 60);

/// 🧯 Describes a local authority initialization or issuance failure.
#[derive(Debug, Error)]
pub enum InternalCaError {
    #[error("💥 Internal CA I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("💾 Internal certificate store error: {0}")]
    Store(#[from] CertStoreError),

    #[error("🔐 Internal certificate generation error: {0}")]
    Certificate(#[from] rcgen::Error),

    #[error("📄 Internal CA data error: {0}")]
    Data(#[from] serde_json::Error),

    #[error("⏰ System clock is earlier than the Unix epoch")]
    InvalidClock,

    #[error("🌐 Invalid internal certificate domain: {0}")]
    InvalidDomain(String),

    #[error("🧯 Invalid internal certificate authority: {0}")]
    InvalidAuthority(String),

    /// 🚫 The root is too close to expiry to sign an intermediate for it.
    ///
    /// Refused rather than repaired. Replacing the root would keep the server
    /// answering while silently withdrawing the authority every client already
    /// trusts, which is the failure the import guard exists to prevent — and
    /// the operator is the only one who can decide whether to re-trust.
    #[error("⏳ The internal root CA expires too soon to sign an intermediate for it")]
    RootExpiringSoon,
}

/// 🔐 One certificate and the private key that matches it.
struct AuthorityKeyPair {
    cert_pem: String,
    key_pem: String,

    /// ⏰ When the certificate stops being valid, read out of the certificate
    /// rather than recomputed from the lifetime constant, so a pair that has
    /// been on disk for years is measured against the date actually in it.
    expires_at: SystemTime,
}

/// 🏛️ The two tiers a local authority is made of.
struct LocalAuthority {
    root: AuthorityKeyPair,
    intermediate: AuthorityKeyPair,
}

/// 🏷️ Which tier of the authority is being loaded.
///
/// The two behave differently when their files are unusable, because they mean
/// different things. The root is the trust anchor: half of it is a damaged store,
/// and replacing it silently would withdraw the authority every client trusts.
/// The intermediate is derived material — it can be re-signed from the root,
/// which leaves every client's trust intact.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tier {
    Root,
    Intermediate,
}

impl Tier {
    /// 🩹 Whether an unusable pair can be rebuilt instead of refused.
    fn is_repairable(self) -> bool {
        matches!(self, Self::Intermediate)
    }
}

/// 🧭 Serializes initialization and issuance around one authority snapshot.
#[derive(Default)]
struct AuthorityState {
    authority: Option<LocalAuthority>,
}

/// 🏛️ Issues and persists private leaf certificates under one local authority.
pub struct InternalCa {
    /// 📂 The directory holding the four authority files.
    authority_directory: PathBuf,

    /// 📂 Where this store's authority lived before the layout became Caddy's.
    ///
    /// 🚫 Never read and never migrated — that is the decision. It is only
    /// looked for, because the upgrade it costs something must not be silent:
    /// on the first start after one, the server mints a new authority and every
    /// client that trusted the old root stops trusting this one. Both the
    /// READMEs and the changelog say so, which does an operator who pulled a
    /// new container image no good at all.
    legacy_directory: PathBuf,

    /// 📜 The leaves this authority has issued, in Caddy's layout.
    certificates: CertStore,

    state: Mutex<AuthorityState>,
}

impl InternalCa {
    /// 🏗️ Creates a lazy local authority rooted below the shared TLS store.
    pub fn new(store_path: impl AsRef<Path>) -> Self {
        let store_path = store_path.as_ref();
        Self {
            authority_directory: store_path.join(AUTHORITY_DIRECTORY),
            legacy_directory: store_path.join(LEGACY_AUTHORITY_DIRECTORY),
            certificates: CertStore::site_directories(store_path.join(CERTIFICATES_DIRECTORY)),
            state: Mutex::new(AuthorityState::default()),
        }
    }

    /// 📜 Returns a valid leaf chain, issuing or renewing it when necessary.
    pub async fn get_or_issue(&self, domain: &str) -> Result<Certificate, InternalCaError> {
        validate_domain(domain)?;
        let mut state = self.state.lock().await;
        let authority = self.ensure_authority(&mut state).await?;

        if let Some(certificate) = self.certificates.get(domain).await
            && chains_to(&certificate, &authority.intermediate)
            // 🏠 The internal authority issues its own certificates with a
            // lifetime it chooses, so the default window is the right question
            // here — an operator's `renewal_window_ratio` is about the public
            // CA's certificates, which this path never touches.
            && !certificate.needs_renewal(crate::acme::DEFAULT_RENEWAL_WINDOW_RATIO)
        {
            return Ok(certificate);
        }

        let certificate = issue_leaf(domain, &authority.intermediate)?;
        self.certificates.store(&certificate).await?;
        tracing::info!("🏛️ Issued an internal TLS certificate for {}", domain);
        Ok(certificate)
    }

    /// 🌳 Returns the public root certificate for trust-store installation.
    ///
    /// 📌 The root and not the intermediate: this is the trust anchor an
    /// operator installs, and it is the only file of the four that is meant to
    /// leave the machine.
    pub async fn root_certificate_pem(&self) -> Result<String, InternalCaError> {
        let mut state = self.state.lock().await;
        Ok(self
            .ensure_authority(&mut state)
            .await?
            .root
            .cert_pem
            .clone())
    }

    // MARK: - Paths

    fn root_certificate_path(&self) -> PathBuf {
        self.authority_directory.join("root.crt")
    }

    fn root_key_path(&self) -> PathBuf {
        self.authority_directory.join("root.key")
    }

    fn intermediate_certificate_path(&self) -> PathBuf {
        self.authority_directory.join("intermediate.crt")
    }

    fn intermediate_key_path(&self) -> PathBuf {
        self.authority_directory.join("intermediate.key")
    }

    // MARK: - Loading

    /// 🔐 Initializes the certificate cache and loads one atomic authority.
    async fn ensure_authority<'a>(
        &self,
        state: &'a mut AuthorityState,
    ) -> Result<&'a LocalAuthority, InternalCaError> {
        if state.authority.is_none() {
            if self.legacy_directory.is_dir() {
                tracing::warn!(
                    "⚠️ {:?} holds a TLS store written before this server moved to Caddy's \
                     layout. It is not migrated, so a new local authority is being created and \
                     every client that trusted the old root must be given the new one \
                     (`pingclair trust`)",
                    self.legacy_directory
                );
            }
            self.certificates.init().await?;
            state.authority = Some(self.load_or_create_authority().await?);
        }

        Ok(state
            .authority
            .as_ref()
            .expect("the internal authority was initialized"))
    }

    /// 🧭 Reads the four authority files, creating what is missing.
    ///
    /// 📌 The one invariant this function exists to keep is that the two tiers
    /// belong to each other: a leaf is signed by the intermediate, and the
    /// intermediate by the root, so a root that did not sign the intermediate
    /// on disk cannot anchor the chains this server issues. Everything below is
    /// that rule.
    ///
    /// 🩹 A root that is *absent* means the whole authority is new, and the
    /// intermediate is re-signed rather than reused: an intermediate that
    /// outlived its root belongs to an authority this store no longer has, and
    /// serving its leaves would hand every client a chain that chains to
    /// nothing they trust. A root that is present means the intermediate is
    /// kept if it is genuinely signed by it, and re-signed if it is not.
    async fn load_or_create_authority(&self) -> Result<LocalAuthority, InternalCaError> {
        let (root, root_is_new) = match self
            .load_pair(
                Tier::Root,
                &self.root_certificate_path(),
                &self.root_key_path(),
            )
            .await?
        {
            Some(root) => {
                tracing::info!(
                    "🏛️ Loaded the persistent internal root CA from {:?}",
                    self.root_certificate_path()
                );
                (root, false)
            }
            None => {
                let root = generate_root()?;
                self.persist_pair(&self.root_certificate_path(), &self.root_key_path(), &root)
                    .await?;
                tracing::info!(
                    "🏛️ Created a persistent internal root CA at {:?}",
                    self.root_certificate_path()
                );
                (root, true)
            }
        };

        let loaded_intermediate = if root_is_new {
            None
        } else {
            self.load_pair(
                Tier::Intermediate,
                &self.intermediate_certificate_path(),
                &self.intermediate_key_path(),
            )
            .await?
        };

        let intermediate = match loaded_intermediate {
            Some(intermediate) if signed_by(&intermediate.cert_pem, &root.cert_pem)? => {
                intermediate
            }
            Some(_) => {
                tracing::warn!(
                    "⚠️ The internal intermediate CA at {:?} was not signed by the root \
                     beside it; re-signing it",
                    self.intermediate_certificate_path()
                );
                self.sign_and_persist_intermediate(&root).await?
            }
            None => self.sign_and_persist_intermediate(&root).await?,
        };

        Ok(LocalAuthority { root, intermediate })
    }

    /// 🌿 Signs an intermediate from `root` and publishes it.
    async fn sign_and_persist_intermediate(
        &self,
        root: &AuthorityKeyPair,
    ) -> Result<AuthorityKeyPair, InternalCaError> {
        let intermediate = issue_intermediate(root)?;
        self.persist_pair(
            &self.intermediate_certificate_path(),
            &self.intermediate_key_path(),
            &intermediate,
        )
        .await?;
        tracing::info!(
            "🏛️ Signed an internal intermediate CA at {:?}",
            self.intermediate_certificate_path()
        );
        Ok(intermediate)
    }

    /// 📂 Reads one tier's two files, or reports that it has none.
    ///
    /// 🚫 A root that is present but unusable is an error, not a regeneration.
    /// Silently minting a replacement would leave the server answering while
    /// every client that trusts the current root refuses it — and nothing in
    /// the operator's logs would say why.
    ///
    /// 🩹 An intermediate that is present but unusable is re-signed instead,
    /// whatever went wrong with it: missing, half-written by a crash between
    /// the two file writes, or corrupt. Re-signing is safe for that tier alone
    /// because it leaves the root — and so every client's trust — untouched,
    /// which is the whole reason the two tiers are separate files.
    async fn load_pair(
        &self,
        tier: Tier,
        certificate_path: &Path,
        key_path: &Path,
    ) -> Result<Option<AuthorityKeyPair>, InternalCaError> {
        let (has_certificate, has_key) = (certificate_path.exists(), key_path.exists());
        if !has_certificate && !has_key {
            return Ok(None);
        }

        let loaded = if has_certificate && has_key {
            self.read_pair(certificate_path, key_path).await
        } else {
            // 🚫 Named rather than left to the I/O error that reading a missing
            // file would raise: half a pair is a state an operator has to
            // recognise from the message, and "No such file or directory" does
            // not say which of the two files the other one disagrees with.
            Err(InternalCaError::InvalidAuthority(format!(
                "{} exists but {} does not",
                if has_certificate {
                    certificate_path
                } else {
                    key_path
                }
                .display(),
                if has_certificate {
                    key_path
                } else {
                    certificate_path
                }
                .display(),
            )))
        };

        match loaded {
            Ok(pair) => Ok(Some(pair)),
            Err(error) if tier.is_repairable() => {
                tracing::warn!(
                    "⚠️ The internal intermediate CA could not be used ({}); re-signing it from \
                     the root",
                    error
                );
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// 📄 Reads and checks one tier's certificate and key.
    async fn read_pair(
        &self,
        certificate_path: &Path,
        key_path: &Path,
    ) -> Result<AuthorityKeyPair, InternalCaError> {
        let cert_pem = tokio::fs::read_to_string(certificate_path).await?;
        let key_pem = tokio::fs::read_to_string(key_path).await?;
        let expires_at = validate_pair(&cert_pem, &key_pem)?;
        Ok(AuthorityKeyPair {
            cert_pem,
            key_pem,
            expires_at,
        })
    }

    /// 💾 Writes a tier's certificate and key as two files.
    ///
    /// 🔁 One blocking task for both files rather than one each, so they are
    /// written in order on one thread. Each write is atomic on its own; the pair
    /// is not, which is why a half-written tier is a state the loader handles
    /// rather than one it can rule out.
    async fn persist_pair(
        &self,
        certificate_path: &Path,
        key_path: &Path,
        pair: &AuthorityKeyPair,
    ) -> Result<(), InternalCaError> {
        let files = vec![
            (key_path.to_path_buf(), pair.key_pem.clone().into_bytes()),
            (
                certificate_path.to_path_buf(),
                pair.cert_pem.clone().into_bytes(),
            ),
        ];
        tokio::task::spawn_blocking(move || {
            for (path, contents) in files {
                crate::secure_file::write_private_file(&path, &contents)?;
            }
            Ok::<(), std::io::Error>(())
        })
        .await
        .map_err(|error| std::io::Error::other(format!("internal CA writer failed: {error}")))??;
        Ok(())
    }
}

/// 🌐 Accepts concrete DNS names, IP literals, and one-level wildcard DNS
/// names (`*.example.com`) that the internal authority can issue for.
fn validate_domain(domain: &str) -> Result<(), InternalCaError> {
    if domain.is_empty() {
        return Err(InternalCaError::InvalidDomain(domain.to_string()));
    }
    let concrete = domain.strip_prefix("*.").unwrap_or(domain);
    if concrete.is_empty()
        || concrete.contains('*')
        || rustls::pki_types::ServerName::try_from(concrete.to_string()).is_err()
    {
        return Err(InternalCaError::InvalidDomain(domain.to_string()));
    }
    Ok(())
}

/// 🧭 Whether a stored leaf chain was issued by the authority loaded now.
///
/// 🔗 A leaf is stored as its own certificate followed by the intermediate that
/// signed it, so a chain that does not end with the current intermediate came
/// from an authority this server no longer has — after a root was replaced, or
/// a store was restored from a mixture of backups. Serving it would hand the
/// client a chain anchored at a root nobody holds, and nothing else would
/// notice until the leaf expired: up to ninety days of handshakes that cannot
/// validate, with the certificate looking perfectly valid to every check this
/// server makes.
fn chains_to(certificate: &Certificate, intermediate: &AuthorityKeyPair) -> bool {
    certificate.cert_pem.ends_with(&intermediate.cert_pem)
}

/// 🧪 Whether one certificate was signed by another.
///
/// 🔗 Answered through the key identifiers rather than through verified
/// signatures: the issued certificate's authority key identifier, which names
/// the key that signed it, against the issuer's subject key identifier, which
/// is a hash of that key. That pair exists for exactly this question.
///
/// 🚫 Not compared by distinguished name, which is the obvious cheaper check
/// and a wrong one — two authorities built by this server carry the same name
/// by construction, so a store holding one root and another's intermediate
/// would pass it while serving chains that anchor nowhere. It is the case this
/// is here for.
///
/// 🚫 And a missing identifier answers "no" rather than "unknown": a
/// certificate that does not say which key signed it cannot be shown to belong
/// to this root, and treating that as agreement is how a mixed-up store keeps
/// answering.
fn signed_by(cert_pem: &str, issuer_cert_pem: &str) -> Result<bool, InternalCaError> {
    use x509_parser::extensions::ParsedExtension;
    use x509_parser::prelude::{FromDer, X509Certificate};

    let issued_der = pem_contents(cert_pem)?;
    let issuer_der = pem_contents(issuer_cert_pem)?;
    let (_, issued) = X509Certificate::from_der(&issued_der)
        .map_err(|error| InternalCaError::InvalidAuthority(error.to_string()))?;
    let (_, issuer) = X509Certificate::from_der(&issuer_der)
        .map_err(|error| InternalCaError::InvalidAuthority(error.to_string()))?;

    let authority_key_id =
        issued
            .extensions()
            .iter()
            .find_map(|extension| match extension.parsed_extension() {
                ParsedExtension::AuthorityKeyIdentifier(identifier) => {
                    identifier.key_identifier.as_ref()
                }
                _ => None,
            });
    let subject_key_id =
        issuer
            .extensions()
            .iter()
            .find_map(|extension| match extension.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(identifier) => Some(identifier),
                _ => None,
            });

    Ok(match (authority_key_id, subject_key_id) {
        (Some(authority), Some(subject)) => authority.0 == subject.0,
        _ => false,
    })
}

/// 🧾 The subject and issuer of a PEM certificate, as RFC 2253 strings.
fn subject_and_issuer(cert_pem: &str) -> Result<(String, String), InternalCaError> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let der = pem_contents(cert_pem)?;
    let (_, certificate) = X509Certificate::from_der(&der)
        .map_err(|error| InternalCaError::InvalidAuthority(error.to_string()))?;
    Ok((
        certificate.subject().to_string(),
        certificate.issuer().to_string(),
    ))
}

/// 📄 The DER bytes of the first certificate in a PEM chain.
fn pem_contents(cert_pem: &str) -> Result<Vec<u8>, InternalCaError> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
        .map_err(|error| InternalCaError::InvalidAuthority(error.to_string()))?;
    Ok(pem.contents)
}

/// 🧪 Verifies that a certificate and its key belong together, and reads the
/// certificate's expiry as it goes.
fn validate_pair(cert_pem: &str, key_pem: &str) -> Result<SystemTime, InternalCaError> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let key = KeyPair::from_pem(key_pem)?;
    Issuer::from_ca_cert_pem(cert_pem, key)?;
    let key = KeyPair::from_pem(key_pem)?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
        .map_err(|error| InternalCaError::InvalidAuthority(error.to_string()))?;
    let (_, certificate) = X509Certificate::from_der(&pem.contents)
        .map_err(|error| InternalCaError::InvalidAuthority(error.to_string()))?;
    if certificate.public_key().raw != key.subject_public_key_info() {
        return Err(InternalCaError::InvalidAuthority(
            "the certificate and private key do not match".to_string(),
        ));
    }

    let seconds = certificate.validity().not_after.timestamp();
    let seconds = u64::try_from(seconds).map_err(|_| InternalCaError::InvalidClock)?;
    Ok(UNIX_EPOCH + Duration::from_secs(seconds))
}

/// 🌳 Generates a ten-year root authority with certificate-signing usage.
fn generate_root() -> Result<AuthorityKeyPair, InternalCaError> {
    let now = SystemTime::now();
    let expires_at = now
        .checked_add(AUTHORITY_LIFETIME)
        .ok_or(InternalCaError::InvalidClock)?;

    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.not_before = now
        .checked_sub(CLOCK_SKEW_ALLOWANCE)
        .unwrap_or(UNIX_EPOCH)
        .into();
    params.not_after = expires_at.into();
    // 🛡️ The root signs intermediates and nothing below them. The limit is
    // written into the certificate so that a client enforces it, which is the
    // only kind that still holds if the root key is ever exposed.
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::OrganizationName, "Pingclair");
    distinguished_name.push(DnType::CommonName, "Pingclair Local Authority Root");
    params.distinguished_name = distinguished_name;

    let key = KeyPair::generate()?;
    let certificate = params.self_signed(&key)?;
    Ok(AuthorityKeyPair {
        cert_pem: certificate.pem(),
        key_pem: key.serialize_pem(),
        expires_at,
    })
}

/// 🌿 Signs the intermediate that leaf certificates are actually issued from.
///
/// 🛡️ `pathlen:0`, so the intermediate signs leaf certificates and no further
/// authorities. Together with the root's `pathlen:1` that is what makes this a
/// two-tier chain rather than an unbounded one.
fn issue_intermediate(root: &AuthorityKeyPair) -> Result<AuthorityKeyPair, InternalCaError> {
    let now = SystemTime::now();
    let expires_at = root
        .expires_at
        .checked_sub(INTERMEDIATE_ROOT_MARGIN)
        .filter(|expires_at| *expires_at > now)
        .ok_or(InternalCaError::RootExpiringSoon)?;

    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.not_before = now
        .checked_sub(CLOCK_SKEW_ALLOWANCE)
        .unwrap_or(UNIX_EPOCH)
        .into();
    params.not_after = expires_at.into();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params.use_authority_key_identifier_extension = true;
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::OrganizationName, "Pingclair");
    distinguished_name.push(DnType::CommonName, "Pingclair Local Authority Intermediate");
    params.distinguished_name = distinguished_name;

    let root_key = KeyPair::from_pem(&root.key_pem)?;
    let issuer = Issuer::from_ca_cert_pem(&root.cert_pem, root_key)?;
    let key = KeyPair::generate()?;
    let certificate = params.signed_by(&key, &issuer)?;
    Ok(AuthorityKeyPair {
        cert_pem: certificate.pem(),
        key_pem: key.serialize_pem(),
        expires_at,
    })
}

/// 🍃 Signs a short-lived server certificate and returns its complete chain.
///
/// 🌊 The chain is the leaf followed by the intermediate, and **not** the root.
/// A client that trusts the root already has it, so sending it again is a
/// kilobyte per handshake that every client discards. Measured against `caddy`
/// 2.11.4, whose `certificates/local/localhost/localhost.crt` holds exactly the
/// leaf and the intermediate, in that order.
fn issue_leaf(
    domain: &str,
    intermediate: &AuthorityKeyPair,
) -> Result<Certificate, InternalCaError> {
    let now = SystemTime::now();
    let expires_at = now
        .checked_add(LEAF_LIFETIME)
        .ok_or(InternalCaError::InvalidClock)?;
    let mut params = CertificateParams::new(vec![domain.to_string()])?;
    params.not_before = now
        .checked_sub(CLOCK_SKEW_ALLOWANCE)
        .unwrap_or(UNIX_EPOCH)
        .into();
    params.not_after = expires_at.into();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::OrganizationName, "Pingclair");
    distinguished_name.push(DnType::CommonName, domain);
    params.distinguished_name = distinguished_name;

    let issuer_key = KeyPair::from_pem(&intermediate.key_pem)?;
    let issuer = Issuer::from_ca_cert_pem(&intermediate.cert_pem, issuer_key)?;
    let leaf_key = KeyPair::generate()?;
    let leaf = params.signed_by(&leaf_key, &issuer)?;
    let mut cert_pem = leaf.pem();
    if !cert_pem.ends_with('\n') {
        cert_pem.push('\n');
    }
    cert_pem.push_str(&intermediate.cert_pem);

    Ok(Certificate {
        cert_pem,
        key_pem: leaf_key.serialize_pem(),
        domains: vec![domain.to_string()],
        expires_at: expires_at
            .duration_since(UNIX_EPOCH)
            .map_err(|_| InternalCaError::InvalidClock)?
            .as_secs() as i64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🧾 The subject and issuer of the first certificate in a PEM chain, for
    /// the tests that assert which file means what.
    fn names(cert_pem: &str) -> (String, String) {
        subject_and_issuer(cert_pem).unwrap()
    }

    #[tokio::test]
    async fn authority_and_leaf_survive_restart() {
        let directory = tempfile::tempdir().unwrap();
        let first = InternalCa::new(directory.path());
        let first_root = first.root_certificate_pem().await.unwrap();
        let first_leaf = first.get_or_issue("origin.example.test").await.unwrap();
        drop(first);

        let second = InternalCa::new(directory.path());
        let second_root = second.root_certificate_pem().await.unwrap();
        let second_leaf = second.get_or_issue("origin.example.test").await.unwrap();

        assert_eq!(first_root, second_root);
        assert_eq!(first_leaf.cert_pem, second_leaf.cert_pem);
        assert_eq!(first_leaf.key_pem, second_leaf.key_pem);
        assert_eq!(second_leaf.cert_pem.matches("BEGIN CERTIFICATE").count(), 2);
        assert_eq!(
            std::fs::read_to_string(directory.path().join("pki/authorities/local/root.crt"))
                .unwrap(),
            second_root
        );
    }

    /// 🌳 The chain is a real two-tier one: the root signs the intermediate, the
    /// intermediate signs the leaf, and the chain the client is served stops at
    /// the intermediate.
    ///
    /// Asserted as whole subjects rather than by checking a signature, because
    /// what the layout promises is *which file means what* — a store whose
    /// `intermediate.crt` held a root would satisfy every path-based test and
    /// still be a lying tree.
    #[tokio::test]
    async fn the_chain_runs_root_to_intermediate_to_leaf() {
        let directory = tempfile::tempdir().unwrap();
        let authority = InternalCa::new(directory.path());
        let leaf = authority.get_or_issue("chain.example.test").await.unwrap();

        let root_pem = authority.root_certificate_pem().await.unwrap();
        let intermediate_pem = std::fs::read_to_string(
            directory
                .path()
                .join("pki/authorities/local/intermediate.crt"),
        )
        .expect("the intermediate certificate must be on disk");

        let (root_subject, root_issuer) = names(&root_pem);
        let (intermediate_subject, intermediate_issuer) = names(&intermediate_pem);
        let (leaf_subject, leaf_issuer) = names(&leaf.cert_pem);

        assert!(
            root_subject.contains("Local Authority Root"),
            "{root_subject}"
        );
        assert_eq!(root_subject, root_issuer, "the root is self-signed");
        assert!(
            intermediate_subject.contains("Local Authority Intermediate"),
            "{intermediate_subject}"
        );
        assert_eq!(
            intermediate_issuer, root_subject,
            "the intermediate must be issued by the root"
        );
        assert!(
            leaf_subject.contains("chain.example.test"),
            "{leaf_subject}"
        );
        assert_eq!(
            leaf_issuer, intermediate_subject,
            "the leaf must be issued by the intermediate"
        );

        // 🌊 And the served chain is leaf + intermediate, with the root left out.
        assert_eq!(leaf.cert_pem.matches("BEGIN CERTIFICATE").count(), 2);
        assert_eq!(
            names(&leaf.cert_pem).1,
            intermediate_subject,
            "the second certificate of the chain is the intermediate"
        );
    }

    /// 🩹 Deleting the intermediate re-signs it from the root that is still
    /// there, so client trust survives what would otherwise look like a lost
    /// authority.
    #[tokio::test]
    async fn a_missing_intermediate_is_resigned_by_the_same_root() {
        let directory = tempfile::tempdir().unwrap();
        let authority = InternalCa::new(directory.path());
        let original_root = authority.root_certificate_pem().await.unwrap();
        let original_intermediate = std::fs::read_to_string(
            directory
                .path()
                .join("pki/authorities/local/intermediate.crt"),
        )
        .unwrap();
        drop(authority);

        std::fs::remove_file(
            directory
                .path()
                .join("pki/authorities/local/intermediate.crt"),
        )
        .unwrap();
        std::fs::remove_file(
            directory
                .path()
                .join("pki/authorities/local/intermediate.key"),
        )
        .unwrap();

        let reloaded = InternalCa::new(directory.path());
        assert_eq!(
            reloaded.root_certificate_pem().await.unwrap(),
            original_root,
            "the trust anchor must survive"
        );
        let reissued_intermediate = std::fs::read_to_string(
            directory
                .path()
                .join("pki/authorities/local/intermediate.crt"),
        )
        .unwrap();
        assert_ne!(
            reissued_intermediate, original_intermediate,
            "the intermediate must actually have been re-signed"
        );
        assert_eq!(
            names(&reissued_intermediate).1,
            names(&original_root).0,
            "the replacement must still chain to the same root"
        );
    }

    /// 🩹 An intermediate that is present but unusable is re-signed, not
    /// refused, and not fatal.
    ///
    /// A crash between the two file writes on the repair path leaves a fresh
    /// `intermediate.key` beside the previous `intermediate.crt`: both files
    /// exist, so the "missing" case does not cover it, and the pair fails to
    /// validate. Treating that as a damaged store would leave the server
    /// unable to issue until an operator deleted a file by hand — for a tier
    /// that can be rebuilt from the root without touching anyone's trust.
    #[tokio::test]
    async fn an_unusable_intermediate_is_resigned_rather_than_refused() {
        let directory = tempfile::tempdir().unwrap();
        let authority = InternalCa::new(directory.path());
        let root = authority.root_certificate_pem().await.unwrap();
        drop(authority);

        // 🧾 A key that parses, and does not match the certificate beside it.
        let replacement = KeyPair::generate().unwrap().serialize_pem();
        crate::secure_file::write_private_file(
            &directory
                .path()
                .join("pki/authorities/local/intermediate.key"),
            replacement.as_bytes(),
        )
        .unwrap();

        let reloaded = InternalCa::new(directory.path());
        assert_eq!(
            reloaded.root_certificate_pem().await.unwrap(),
            root,
            "the trust anchor must survive"
        );
        let repaired = std::fs::read_to_string(
            directory
                .path()
                .join("pki/authorities/local/intermediate.crt"),
        )
        .unwrap();
        assert_eq!(
            names(&repaired).1,
            names(&root).0,
            "the replacement must chain to the root that is still here"
        );
        assert!(reloaded.get_or_issue("repaired.test").await.is_ok());
    }

    /// 🚫 An intermediate signed by some other root is replaced, because a
    /// chain through it anchors at a root this server does not have.
    ///
    /// This is the state a half-restored backup produces: a root and an
    /// intermediate that are each valid, and do not belong together.
    #[tokio::test]
    async fn an_intermediate_from_another_root_is_resigned() {
        let store = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();

        let authority = InternalCa::new(store.path());
        let root = authority.root_certificate_pem().await.unwrap();
        drop(authority);
        let elsewhere = InternalCa::new(other.path());
        elsewhere.root_certificate_pem().await.unwrap();
        let foreign_intermediate =
            std::fs::read_to_string(other.path().join("pki/authorities/local/intermediate.crt"))
                .unwrap();
        drop(elsewhere);

        std::fs::copy(
            other.path().join("pki/authorities/local/intermediate.crt"),
            store.path().join("pki/authorities/local/intermediate.crt"),
        )
        .unwrap();
        std::fs::copy(
            other.path().join("pki/authorities/local/intermediate.key"),
            store.path().join("pki/authorities/local/intermediate.key"),
        )
        .unwrap();

        let reloaded = InternalCa::new(store.path());
        assert_eq!(reloaded.root_certificate_pem().await.unwrap(), root);
        let repaired =
            std::fs::read_to_string(store.path().join("pki/authorities/local/intermediate.crt"))
                .unwrap();
        assert_ne!(
            repaired, foreign_intermediate,
            "the foreign intermediate must not be kept"
        );
        assert_eq!(names(&repaired).1, names(&root).0);
    }

    /// 🚫 A leaf issued by an authority this store no longer has must be
    /// re-issued rather than served.
    ///
    /// 🤡 The leaf looks valid to every check the server makes on its own — it
    /// parses, it is not near expiry, and its key matches. What it does not do
    /// is chain to a root this server can be trusted for, because the chain it
    /// carries ends with an intermediate the new root never signed. Serving it
    /// hands the client a handshake that cannot validate, for as long as the
    /// leaf lives.
    #[tokio::test]
    async fn a_leaf_from_a_previous_authority_is_reissued_not_served() {
        let directory = tempfile::tempdir().unwrap();
        let authority = InternalCa::new(directory.path());
        let stale = authority.get_or_issue("kept.test").await.unwrap();
        drop(authority);

        // 🧹 The whole authority goes, as a store restored without its backing
        // sets would look: the leaves survive, the authority does not.
        std::fs::remove_file(directory.path().join("pki/authorities/local/root.crt")).unwrap();
        std::fs::remove_file(directory.path().join("pki/authorities/local/root.key")).unwrap();
        std::fs::remove_file(
            directory
                .path()
                .join("pki/authorities/local/intermediate.crt"),
        )
        .unwrap();
        std::fs::remove_file(
            directory
                .path()
                .join("pki/authorities/local/intermediate.key"),
        )
        .unwrap();

        let reloaded = InternalCa::new(directory.path());
        let fresh = reloaded.get_or_issue("kept.test").await.unwrap();
        assert_ne!(
            fresh.cert_pem, stale.cert_pem,
            "a leaf from the previous authority must not be served"
        );
        let intermediate = std::fs::read_to_string(
            directory
                .path()
                .join("pki/authorities/local/intermediate.crt"),
        )
        .unwrap();
        assert!(
            fresh.cert_pem.ends_with(&intermediate),
            "the re-issued chain must carry the intermediate that signed it"
        );
        assert_eq!(
            names(&fresh.cert_pem).1,
            names(&intermediate).0,
            "and it must be signed by that intermediate"
        );
    }

    #[tokio::test]
    async fn invalid_domain_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let authority = InternalCa::new(directory.path());

        assert!(authority.get_or_issue("../escape").await.is_err());
        assert!(authority.get_or_issue("foo.*.bar").await.is_err());
        assert!(authority.get_or_issue("*.").await.is_err());
        assert!(
            !directory.path().join("certificates").exists(),
            "a refused domain must not touch the store"
        );
    }

    /// 🏗️ A wildcard site name is issuable, and the leaf must carry the
    /// wildcard SAN so every subdomain handshake can present it.
    #[tokio::test]
    async fn wildcard_domains_are_issuable_for_subdomains() {
        use x509_parser::extensions::GeneralName;
        use x509_parser::prelude::FromDer;

        let directory = tempfile::tempdir().unwrap();
        let authority = InternalCa::new(directory.path());
        let leaf = authority
            .get_or_issue("*.sandbox.localhost")
            .await
            .expect("a wildcard internal leaf must issue");

        assert_eq!(leaf.domains, vec!["*.sandbox.localhost"]);
        let (_, pem) = x509_parser::pem::parse_x509_pem(leaf.cert_pem.as_bytes()).unwrap();
        let (_, certificate) =
            x509_parser::prelude::X509Certificate::from_der(&pem.contents).unwrap();
        let sans = certificate
            .subject_alternative_name()
            .expect("a SAN extension")
            .expect("a SAN value");
        let names: Vec<String> = sans
            .value
            .general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::DNSName(name) => Some(name.to_string()),
                _ => None,
            })
            .collect();
        assert!(
            names.iter().any(|name| name == "*.sandbox.localhost"),
            "the leaf must carry the wildcard SAN: {names:?}"
        );
        assert!(
            directory
                .path()
                .join("certificates/local/wildcard_.sandbox.localhost")
                .is_dir(),
            "the leaf must be filed under Caddy's spelling of the wildcard"
        );
    }

    #[tokio::test]
    async fn mismatched_persistent_authority_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let authority = InternalCa::new(directory.path());
        authority.root_certificate_pem().await.unwrap();
        drop(authority);

        let key_path = directory.path().join("pki/authorities/local/root.key");
        crate::secure_file::write_private_file(
            &key_path,
            KeyPair::generate().unwrap().serialize_pem().as_bytes(),
        )
        .unwrap();

        let reloaded = InternalCa::new(directory.path());
        assert!(matches!(
            reloaded.root_certificate_pem().await,
            Err(InternalCaError::InvalidAuthority(_))
        ));
    }

    /// 🚫 A root with no key is a damaged store, not one to re-mint: replacing
    /// it would withdraw the authority every client trusts, and only the
    /// operator can decide to re-trust a new one.
    #[tokio::test]
    async fn a_half_written_root_is_refused_rather_than_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let authority = InternalCa::new(directory.path());
        authority.root_certificate_pem().await.unwrap();
        drop(authority);

        std::fs::remove_file(directory.path().join("pki/authorities/local/root.key")).unwrap();

        let reloaded = InternalCa::new(directory.path());
        assert!(matches!(
            reloaded.root_certificate_pem().await,
            Err(InternalCaError::InvalidAuthority(_))
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn private_authority_material_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let authority = InternalCa::new(directory.path());
        authority.root_certificate_pem().await.unwrap();

        for name in [
            "root.key",
            "intermediate.key",
            "root.crt",
            "intermediate.crt",
        ] {
            let mode = std::fs::metadata(directory.path().join("pki/authorities/local").join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{name}");
        }
    }
}
