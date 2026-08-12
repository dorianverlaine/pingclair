// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🏛️ Provides a persistent local certificate authority for private origins.

use crate::acme::Certificate;
use crate::cert_store::{CertStore, CertStoreError};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PublicKeyData,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::Mutex;

const AUTHORITY_LIFETIME: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);
const LEAF_LIFETIME: Duration = Duration::from_secs(90 * 24 * 60 * 60);
const CLOCK_SKEW_ALLOWANCE: Duration = Duration::from_secs(24 * 60 * 60);

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
}

/// 🔐 Keeps the authority certificate and private key in one atomic record.
#[derive(Clone, Deserialize, Serialize)]
struct AuthorityData {
    cert_pem: String,
    key_pem: String,
}

/// 🧭 Serializes initialization and issuance around one authority snapshot.
#[derive(Default)]
struct AuthorityState {
    authority: Option<AuthorityData>,
}

/// 🏛️ Issues and persists private leaf certificates under one local authority.
pub struct InternalCa {
    authority_path: PathBuf,
    root_certificate_path: PathBuf,
    certificates: CertStore,
    state: Mutex<AuthorityState>,
}

impl InternalCa {
    /// 🏗️ Creates a lazy local authority rooted below the shared TLS store.
    pub fn new(store_path: impl AsRef<Path>) -> Self {
        let internal_path = store_path.as_ref().join("internal");
        Self {
            authority_path: internal_path.join("authority.json"),
            root_certificate_path: internal_path.join("root.crt"),
            certificates: CertStore::new(internal_path.join("certificates")),
            state: Mutex::new(AuthorityState::default()),
        }
    }

    /// 📜 Returns a valid leaf chain, issuing or renewing it when necessary.
    pub async fn get_or_issue(&self, domain: &str) -> Result<Certificate, InternalCaError> {
        validate_domain(domain)?;
        let mut state = self.state.lock().await;
        let authority = self.ensure_authority(&mut state).await?;

        if let Some(certificate) = self.certificates.get(domain).await
            // 🏠 The internal authority issues its own certificates with a
            // lifetime it chooses, so the default window is the right question
            // here — an operator's `renewal_window_ratio` is about the public
            // CA's certificates, which this path never touches.
            && !certificate.needs_renewal(crate::acme::DEFAULT_RENEWAL_WINDOW_RATIO)
        {
            return Ok(certificate);
        }

        let certificate = issue_leaf(domain, authority)?;
        self.certificates.store(&certificate).await?;
        tracing::info!("🏛️ Issued an internal TLS certificate for {}", domain);
        Ok(certificate)
    }

    /// 🌳 Returns the public root certificate for trust-store installation.
    pub async fn root_certificate_pem(&self) -> Result<String, InternalCaError> {
        let mut state = self.state.lock().await;
        Ok(self.ensure_authority(&mut state).await?.cert_pem.clone())
    }

    /// 🔐 Initializes the certificate cache and loads one atomic authority record.
    async fn ensure_authority<'a>(
        &self,
        state: &'a mut AuthorityState,
    ) -> Result<&'a AuthorityData, InternalCaError> {
        if state.authority.is_none() {
            self.certificates.init().await?;
            let authority = if self.authority_path.exists() {
                let contents = tokio::fs::read_to_string(&self.authority_path).await?;
                let authority: AuthorityData = serde_json::from_str(&contents)?;
                validate_authority(&authority)?;
                tracing::info!(
                    "🏛️ Loaded the persistent internal CA from {:?}",
                    self.authority_path
                );
                authority
            } else {
                let authority = generate_authority()?;
                persist_authority(&self.authority_path, &authority).await?;
                tracing::info!(
                    "🏛️ Created a persistent internal CA at {:?}",
                    self.authority_path
                );
                authority
            };

            publish_root_certificate(&self.root_certificate_path, &authority.cert_pem).await?;
            state.authority = Some(authority);
        }

        Ok(state
            .authority
            .as_ref()
            .expect("the internal authority was initialized"))
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

/// 🧪 Verifies that both authority components parse and contain the same public key.
fn validate_authority(authority: &AuthorityData) -> Result<(), InternalCaError> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let key = KeyPair::from_pem(&authority.key_pem)?;
    Issuer::from_ca_cert_pem(&authority.cert_pem, key)?;
    let key = KeyPair::from_pem(&authority.key_pem)?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(authority.cert_pem.as_bytes())
        .map_err(|error| InternalCaError::InvalidAuthority(error.to_string()))?;
    let (_, certificate) = X509Certificate::from_der(&pem.contents)
        .map_err(|error| InternalCaError::InvalidAuthority(error.to_string()))?;
    if certificate.public_key().raw != key.subject_public_key_info() {
        return Err(InternalCaError::InvalidAuthority(
            "the certificate and private key do not match".to_string(),
        ));
    }
    Ok(())
}

/// 🌳 Generates a ten-year local authority with certificate-signing usage.
fn generate_authority() -> Result<AuthorityData, InternalCaError> {
    let now = SystemTime::now();
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.not_before = now
        .checked_sub(CLOCK_SKEW_ALLOWANCE)
        .unwrap_or(UNIX_EPOCH)
        .into();
    params.not_after = now
        .checked_add(AUTHORITY_LIFETIME)
        .ok_or(InternalCaError::InvalidClock)?
        .into();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::OrganizationName, "Pingclair");
    distinguished_name.push(DnType::CommonName, "Pingclair Local Authority");
    params.distinguished_name = distinguished_name;

    let key = KeyPair::generate()?;
    let certificate = params.self_signed(&key)?;
    Ok(AuthorityData {
        cert_pem: certificate.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// 🍃 Signs a short-lived server certificate and returns its complete chain.
fn issue_leaf(domain: &str, authority: &AuthorityData) -> Result<Certificate, InternalCaError> {
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

    let authority_key = KeyPair::from_pem(&authority.key_pem)?;
    let issuer = Issuer::from_ca_cert_pem(&authority.cert_pem, authority_key)?;
    let leaf_key = KeyPair::generate()?;
    let leaf = params.signed_by(&leaf_key, &issuer)?;
    let mut cert_pem = leaf.pem();
    if !cert_pem.ends_with('\n') {
        cert_pem.push('\n');
    }
    cert_pem.push_str(&authority.cert_pem);

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

/// 💾 Persists the certificate and key together so a crash cannot mismatch them.
async fn persist_authority(path: &Path, authority: &AuthorityData) -> Result<(), InternalCaError> {
    let contents = serde_json::to_vec_pretty(authority)?;
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || crate::secure_file::write_private_file(&path, &contents))
        .await
        .map_err(|error| std::io::Error::other(format!("internal CA writer failed: {error}")))??;
    Ok(())
}

/// 🌳 Publishes a stable root certificate path without treating it as authority state.
async fn publish_root_certificate(path: &Path, cert_pem: &str) -> Result<(), InternalCaError> {
    if tokio::fs::read_to_string(path)
        .await
        .is_ok_and(|current| current == cert_pem)
    {
        return Ok(());
    }

    let path = path.to_path_buf();
    let cert_pem = cert_pem.as_bytes().to_vec();
    tokio::task::spawn_blocking(move || crate::secure_file::write_private_file(&path, &cert_pem))
        .await
        .map_err(|error| {
            std::io::Error::other(format!("internal root certificate writer failed: {error}"))
        })??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            std::fs::read_to_string(directory.path().join("internal/root.crt")).unwrap(),
            second_root
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
            !directory
                .path()
                .join("internal/certificates/___escape.json")
                .exists()
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
    }

    #[tokio::test]
    async fn mismatched_persistent_authority_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let authority = InternalCa::new(directory.path());
        authority.root_certificate_pem().await.unwrap();
        drop(authority);

        let authority_path = directory.path().join("internal/authority.json");
        let mut data: AuthorityData =
            serde_json::from_slice(&std::fs::read(&authority_path).unwrap()).unwrap();
        data.key_pem = KeyPair::generate().unwrap().serialize_pem();
        crate::secure_file::write_private_file(
            &authority_path,
            &serde_json::to_vec_pretty(&data).unwrap(),
        )
        .unwrap();

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

        let mode = std::fs::metadata(directory.path().join("internal/authority.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
