// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔐 Compiled upstream TLS trust and identity.
//!
//! # Why this is compiled once and not per request
//!
//! Turning PEM text into BoringSSL objects costs milliseconds and allocates.
//! Doing it per request would put a parser on the hot path and, worse, would
//! let a certificate rotation take effect mid-request in one route and not
//! another. So every reverse-proxy route compiles its TLS material exactly
//! once, when the configuration loads, and the request path only clones an
//! `Arc`.
//!
//! # What a failure here means
//!
//! Compilation is where an operator's mistake becomes visible. A missing CA
//! file, an unreadable key, or a certificate that does not match its key are
//! all reported with the path that caused them — never swallowed. The caller
//! is expected to **fail the route closed**: an upstream leg that was asked to
//! authenticate and then could not must not fall back to an unverified
//! handshake, because that is exactly the outcome the configuration was
//! written to prevent.
//!
//! # Trust roots replace, they do not extend
//!
//! `trusted_ca_certs` installs a verify store via BoringSSL's
//! `SSL_set1_verify_cert_store`, which *replaces* the connector's system
//! store rather than adding to it. That is the semantics we want and the
//! semantics we document: a route pinned to an internal CA must not also
//! accept a publicly issued certificate for the same name.

use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pingclair_core::config::UpstreamTlsConfig;
use pingora_core::tls::pkey::{PKey, Private};
use pingora_core::tls::x509::X509;
use pingora_core::utils::tls::CertKey;

// MARK: - Errors

/// 🚨 A configuration mistake that must stop the route from serving.
///
/// Every variant names the file that caused it. A TLS failure reported without
/// a path is the single least actionable thing an operator can be handed.
#[derive(Debug)]
pub enum UpstreamTlsError {
    /// 📂 The PEM file could not be read.
    Unreadable {
        role: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    /// 📜 The file was read but held no usable PEM of the expected kind.
    Unparsable {
        role: &'static str,
        path: PathBuf,
        detail: String,
    },
    /// 📭 The file parsed cleanly but contained zero certificates.
    Empty { role: &'static str, path: PathBuf },
    /// 🔑 The client certificate and key are a valid pair individually but do
    /// not belong together.
    KeyMismatch { cert: PathBuf, key: PathBuf },
    /// 🧩 Only one half of the client identity was configured.
    IncompleteIdentity { detail: &'static str },
}

impl fmt::Display for UpstreamTlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { role, path, source } => write!(
                formatter,
                "cannot read upstream TLS {role} at {}: {source}",
                path.display()
            ),
            Self::Unparsable { role, path, detail } => write!(
                formatter,
                "upstream TLS {role} at {} is not valid PEM: {detail}",
                path.display()
            ),
            Self::Empty { role, path } => write!(
                formatter,
                "upstream TLS {role} at {} contains no certificate",
                path.display()
            ),
            Self::KeyMismatch { cert, key } => write!(
                formatter,
                "client certificate {} does not match private key {}: \
                 the upstream would reject this handshake",
                cert.display(),
                key.display()
            ),
            Self::IncompleteIdentity { detail } => write!(formatter, "{detail}"),
        }
    }
}

impl std::error::Error for UpstreamTlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unreadable { source, .. } => Some(source),
            _ => None,
        }
    }
}

// MARK: - Compiled policy

/// 🔐 Everything one route needs to open an authenticated upstream connection.
pub struct UpstreamTls {
    /// 🔒 Speak TLS even when the address carries no scheme.
    force_tls: bool,
    /// 🏷️ SNI and verification-name override.
    server_name: Option<String>,
    /// 📜 Trust roots replacing the system store, in Pingora's peer shape.
    ca: Option<Arc<Box<[X509]>>>,
    /// 🎫 Client identity for mutual TLS.
    client_cert_key: Option<Arc<CertKey>>,
    /// ✅ Whether the upstream chain and hostname are verified at all.
    verify: bool,
    /// 🧊 Distinguishes connection pools that must not be shared.
    pool_key: u64,
    /// 🔎 Operator-facing summary, safe to log.
    summary: TlsSummary,
}

/// 🔎 A log-safe description of what a route's TLS policy actually resolved to.
///
/// Only public certificate material and file paths appear here. Private keys
/// are never summarised, printed, or hashed into anything reachable from a log
/// line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSummary {
    /// 🏷️ Name that will be sent as SNI, when overridden.
    pub server_name: Option<String>,
    /// 📜 CA bundle paths, in configuration order.
    pub trusted_ca_paths: Vec<String>,
    /// 🔢 How many roots those bundles contributed.
    pub trusted_ca_count: usize,
    /// 🎫 Subject of the client leaf certificate, when mutual TLS is on.
    pub client_subject: Option<String>,
    /// 📅 `notAfter` of the client leaf, so an expired identity is visible.
    pub client_not_after: Option<String>,
    /// ✅ Whether the upstream chain is verified.
    pub verify: bool,
}

impl fmt::Display for TlsSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "verify={}", self.verify)?;
        if let Some(name) = &self.server_name {
            write!(formatter, ", sni={name}")?;
        }
        if self.trusted_ca_count > 0 {
            write!(
                formatter,
                ", trust={} root(s) from [{}]",
                self.trusted_ca_count,
                self.trusted_ca_paths.join(", ")
            )?;
        } else {
            write!(formatter, ", trust=system")?;
        }
        match (&self.client_subject, &self.client_not_after) {
            (Some(subject), Some(not_after)) => {
                write!(formatter, ", client_cert={subject} (notAfter {not_after})")?;
            }
            (Some(subject), None) => write!(formatter, ", client_cert={subject}")?,
            _ => write!(formatter, ", client_cert=none")?,
        }
        Ok(())
    }
}

impl UpstreamTls {
    /// 🏗️ Compiles a route's TLS block, reading every referenced file.
    ///
    /// Returns `Ok(None)` when the block is entirely default, which lets the
    /// caller keep the shared system-trust path instead of allocating
    /// per-route state for a route that asked for nothing.
    pub fn compile(config: &UpstreamTlsConfig) -> Result<Option<Arc<Self>>, UpstreamTlsError> {
        if !config.is_customized() {
            return Ok(None);
        }

        let identity = config
            .client_identity()
            .map_err(|detail| UpstreamTlsError::IncompleteIdentity { detail })?;

        let mut roots: Vec<X509> = Vec::new();
        let mut trusted_ca_paths = Vec::with_capacity(config.trusted_ca_certs.len());
        for path in &config.trusted_ca_certs {
            let certificates = read_certificates("trust root", Path::new(path))?;
            trusted_ca_paths.push(path.clone());
            roots.extend(certificates);
        }

        let client = match identity {
            Some((cert_path, key_path)) => Some(load_client_identity(
                Path::new(cert_path),
                Path::new(key_path),
            )?),
            None => None,
        };

        // 🔎 Captured before the certificates move into the shared `CertKey`,
        // so the summary describes exactly what will be presented.
        let summary = TlsSummary {
            server_name: config.server_name.clone(),
            trusted_ca_count: roots.len(),
            trusted_ca_paths,
            client_subject: client.as_ref().map(|identity| identity.subject.clone()),
            client_not_after: client.as_ref().map(|identity| identity.not_after.clone()),
            verify: !config.insecure_skip_verify,
        };

        let pool_key = compute_pool_key(config, &roots, client.as_ref());

        Ok(Some(Arc::new(Self {
            force_tls: config.enable,
            server_name: config.server_name.clone(),
            ca: (!roots.is_empty()).then(|| Arc::new(roots.into_boxed_slice())),
            client_cert_key: client.map(|identity| {
                Arc::new(CertKey::new(identity.certificates, identity.private_key))
            }),
            verify: !config.insecure_skip_verify,
            pool_key,
            summary,
        })))
    }

    /// 🔒 Reports whether this route upgrades a scheme-less upstream to TLS.
    pub fn forces_tls(&self) -> bool {
        self.force_tls
    }

    /// 🏷️ Returns the SNI override, if the operator set one.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// ✅ Reports whether the upstream chain is verified.
    pub fn verifies(&self) -> bool {
        self.verify
    }

    /// 🧊 Returns the value that keeps incompatible trust domains in separate
    /// connection pools.
    ///
    /// Pingora hashes a peer's client certificate and verify flags when
    /// deciding whether a pooled connection may be reused, but it does **not**
    /// hash the CA bundle. Two routes reaching the same address with the same
    /// SNI but different trust roots would therefore share a connection, and
    /// the route with the stricter roots would inherit a session that was
    /// verified under the looser ones. Folding the trust material into the
    /// peer's group key closes that.
    pub fn pool_key(&self) -> u64 {
        self.pool_key
    }

    /// 🔎 Returns the log-safe description of this policy.
    pub fn summary(&self) -> &TlsSummary {
        &self.summary
    }

    /// 🔧 Stamps this policy onto a peer that is about to connect.
    pub fn apply(&self, peer: &mut pingora_core::upstreams::peer::HttpPeer) {
        if let Some(name) = &self.server_name {
            peer.sni = name.clone();
        }
        if let Some(ca) = &self.ca {
            peer.options.ca = Some(ca.clone());
        }
        if let Some(client_cert_key) = &self.client_cert_key {
            peer.client_cert_key = Some(client_cert_key.clone());
        }
        peer.options.verify_cert = self.verify;
        peer.options.verify_hostname = self.verify;
    }
}

impl fmt::Debug for UpstreamTls {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 🔑 Deliberately omits the private key rather than relying on
        // `CertKey`'s own redaction, so this stays true if that changes.
        formatter
            .debug_struct("UpstreamTls")
            .field("force_tls", &self.force_tls)
            .field("summary", &self.summary)
            .field("pool_key", &self.pool_key)
            .finish()
    }
}

// MARK: - PEM loading

/// 🎫 A client identity that has been proven internally consistent.
struct ClientIdentity {
    certificates: Vec<X509>,
    private_key: PKey<Private>,
    subject: String,
    not_after: String,
}

/// 📜 Reads a PEM bundle and rejects one that contributes nothing.
///
/// An empty bundle is treated as an error rather than as "no extra trust",
/// because a route that names a CA file and then trusts the system store
/// instead is the exact silent downgrade this module exists to prevent.
fn read_certificates(role: &'static str, path: &Path) -> Result<Vec<X509>, UpstreamTlsError> {
    let bytes = std::fs::read(path).map_err(|source| UpstreamTlsError::Unreadable {
        role,
        path: path.to_path_buf(),
        source,
    })?;
    let certificates =
        X509::stack_from_pem(&bytes).map_err(|error| UpstreamTlsError::Unparsable {
            role,
            path: path.to_path_buf(),
            detail: error.to_string(),
        })?;
    if certificates.is_empty() {
        return Err(UpstreamTlsError::Empty {
            role,
            path: path.to_path_buf(),
        });
    }
    Ok(certificates)
}

/// 🎫 Loads a client chain and key, proving they belong together.
///
/// The mismatch check matters more than it looks: BoringSSL accepts a
/// mismatched pair at configuration time and only fails during the handshake,
/// where the upstream's `bad certificate` alert is indistinguishable from a
/// dozen unrelated network problems.
fn load_client_identity(
    cert_path: &Path,
    key_path: &Path,
) -> Result<ClientIdentity, UpstreamTlsError> {
    let certificates = read_certificates("client certificate", cert_path)?;
    let key_bytes = std::fs::read(key_path).map_err(|source| UpstreamTlsError::Unreadable {
        role: "client key",
        path: key_path.to_path_buf(),
        source,
    })?;
    let private_key =
        PKey::private_key_from_pem(&key_bytes).map_err(|error| UpstreamTlsError::Unparsable {
            role: "client key",
            path: key_path.to_path_buf(),
            detail: error.to_string(),
        })?;

    let leaf = &certificates[0];
    let leaf_public = leaf
        .public_key()
        .map_err(|error| UpstreamTlsError::Unparsable {
            role: "client certificate",
            path: cert_path.to_path_buf(),
            detail: format!("public key is unreadable: {error}"),
        })?;
    if !leaf_public.public_eq(&private_key) {
        return Err(UpstreamTlsError::KeyMismatch {
            cert: cert_path.to_path_buf(),
            key: key_path.to_path_buf(),
        });
    }

    Ok(ClientIdentity {
        subject: describe_subject(leaf),
        not_after: leaf.not_after().to_string(),
        certificates,
        private_key,
    })
}

/// 🏷️ Renders a certificate subject in a form an operator can match against
/// what their CA issued.
fn describe_subject(certificate: &X509) -> String {
    let rendered: Vec<String> = certificate
        .subject_name()
        .entries()
        .map(|entry| {
            let key = entry.object().nid().short_name().unwrap_or("?").to_string();
            let value = entry
                .data()
                .as_utf8()
                .map(|value| value.to_string())
                .unwrap_or_else(|_| "<non-utf8>".to_string());
            format!("{key}={value}")
        })
        .collect();
    if rendered.is_empty() {
        "<empty subject>".to_string()
    } else {
        rendered.join(",")
    }
}

/// 🧊 Derives a stable identifier for everything that changes who we will talk to.
///
/// The DER of each trust root and of the client leaf goes in, so rotating a
/// certificate produces a different key and connections opened under the old
/// material are not reused under the new. Private keys are never hashed: the
/// leaf certificate already changes when the key does, and a key must not
/// reach a value that is cheap to compare against a guess.
fn compute_pool_key(
    config: &UpstreamTlsConfig,
    roots: &[X509],
    client: Option<&ClientIdentity>,
) -> u64 {
    let mut hasher = DefaultHasher::new();
    config.enable.hash(&mut hasher);
    config.server_name.hash(&mut hasher);
    config.insecure_skip_verify.hash(&mut hasher);
    for root in roots {
        if let Ok(der) = root.to_der() {
            der.hash(&mut hasher);
        }
    }
    if let Some(identity) = client {
        for certificate in &identity.certificates {
            if let Ok(der) = certificate.to_der() {
                der.hash(&mut hasher);
            }
        }
    }
    hasher.finish()
}

// MARK: - Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// 🧪 Produces a self-signed leaf and its key.
    fn issue_pair() -> (String, String) {
        issue_named("upstream.test")
    }

    /// 🧪 Produces a self-signed leaf whose subject carries `common_name`.
    ///
    /// The name is what makes two independently issued certificates
    /// distinguishable in a summary: rcgen gives every certificate the same
    /// far-future `notAfter`, so validity alone cannot tell them apart.
    fn issue_named(common_name: &str) -> (String, String) {
        let mut params = rcgen::CertificateParams::new(vec![common_name.to_string()])
            .expect("certificate parameters");
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        let key = rcgen::KeyPair::generate().expect("key pair");
        let certificate = params.self_signed(&key).expect("self-signed certificate");
        (certificate.pem(), key.serialize_pem())
    }

    /// 🧪 Writes a PEM into a directory the caller keeps alive.
    ///
    /// The `TempDir` is returned to the test rather than dropped here: dropping
    /// it removes the file, and a test that reads a deleted path fails for the
    /// wrong reason.
    fn write_temp(directory: &tempfile::TempDir, name: &str, contents: &str) -> PathBuf {
        let path = directory.path().join(name);
        let mut file = std::fs::File::create(&path).expect("create temp pem");
        file.write_all(contents.as_bytes()).expect("write temp pem");
        path
    }

    #[test]
    fn default_block_compiles_to_no_policy() {
        // Setup scenarios
        let config = UpstreamTlsConfig::default();

        // Verification
        let compiled = UpstreamTls::compile(&config).expect("default block compiles");
        assert!(
            compiled.is_none(),
            "a route that asked for nothing must not allocate per-route TLS state"
        );
    }

    #[test]
    fn missing_ca_file_is_reported_with_its_path() {
        // Setup scenarios
        let config = UpstreamTlsConfig {
            trusted_ca_certs: vec!["/nonexistent/pingclair-ca.pem".to_string()],
            ..Default::default()
        };

        // Verification
        let error = UpstreamTls::compile(&config).expect_err("a missing trust root must fail");
        let message = error.to_string();
        assert!(
            message.contains("/nonexistent/pingclair-ca.pem"),
            "diagnostic must name the file: {message}"
        );
        assert!(
            message.contains("trust root"),
            "diagnostic must name the role: {message}"
        );
    }

    #[test]
    fn garbage_pem_is_rejected_rather_than_ignored() {
        // Setup scenarios
        let directory = tempfile::tempdir().expect("temp dir");
        let path = write_temp(&directory, "garbage.pem", "this is not a certificate\n");
        let config = UpstreamTlsConfig {
            trusted_ca_certs: vec![path.to_string_lossy().to_string()],
            ..Default::default()
        };

        // Verification
        let error = UpstreamTls::compile(&config).expect_err("garbage must not silently vanish");
        assert!(
            matches!(
                error,
                UpstreamTlsError::Unparsable { .. } | UpstreamTlsError::Empty { .. }
            ),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn half_configured_client_identity_is_rejected() {
        // Setup scenarios
        let config = UpstreamTlsConfig {
            client_cert: Some("/tmp/client.crt".to_string()),
            ..Default::default()
        };

        // Verification
        let error = UpstreamTls::compile(&config).expect_err("a lone certificate must fail");
        assert!(
            matches!(error, UpstreamTlsError::IncompleteIdentity { .. }),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn mismatched_client_cert_and_key_fail_before_any_handshake() {
        // Setup scenarios
        let directory = tempfile::tempdir().expect("temp dir");
        let (cert_pem, _) = issue_pair();
        let (_, unrelated_key_pem) = issue_pair();
        let cert_path = write_temp(&directory, "mismatch.crt", &cert_pem);
        let key_path = write_temp(&directory, "mismatch.key", &unrelated_key_pem);
        let config = UpstreamTlsConfig {
            client_cert: Some(cert_path.to_string_lossy().to_string()),
            client_key: Some(key_path.to_string_lossy().to_string()),
            ..Default::default()
        };

        // Verification
        let error = UpstreamTls::compile(&config).expect_err("a mismatched pair must fail");
        assert!(
            matches!(error, UpstreamTlsError::KeyMismatch { .. }),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn matching_client_identity_compiles_and_summarises() {
        // Setup scenarios
        let directory = tempfile::tempdir().expect("temp dir");
        let (cert_pem, key_pem) = issue_pair();
        let cert_path = write_temp(&directory, "match.crt", &cert_pem);
        let key_path = write_temp(&directory, "match.key", &key_pem);
        let config = UpstreamTlsConfig {
            client_cert: Some(cert_path.to_string_lossy().to_string()),
            client_key: Some(key_path.to_string_lossy().to_string()),
            ..Default::default()
        };

        // Verification
        let compiled = UpstreamTls::compile(&config)
            .expect("a matching pair compiles")
            .expect("a client identity is a customisation");
        let summary = compiled.summary();
        assert!(summary.verify, "verification stays on by default");
        assert!(
            summary.client_subject.is_some(),
            "the client subject must be reported so an operator can match it"
        );
        assert!(
            summary.client_not_after.is_some(),
            "an expiring identity must be visible without opening the file"
        );
        assert!(
            !format!("{summary}").contains("PRIVATE KEY"),
            "the summary must never carry key material"
        );
    }

    #[test]
    fn skipping_verification_turns_both_checks_off() {
        // Setup scenarios
        let config = UpstreamTlsConfig {
            insecure_skip_verify: true,
            ..Default::default()
        };

        // Verification
        let compiled = UpstreamTls::compile(&config)
            .expect("compiles")
            .expect("is a customisation");
        assert!(!compiled.verifies());

        let mut peer = pingora_core::upstreams::peer::HttpPeer::new(
            "127.0.0.1:8443",
            true,
            "upstream.test".to_string(),
        );
        compiled.apply(&mut peer);
        assert!(!peer.options.verify_cert);
        assert!(
            !peer.options.verify_hostname,
            "hostname verification must not survive a disabled chain check"
        );
    }

    #[test]
    fn different_trust_roots_get_different_pool_keys() {
        // Setup scenarios
        let directory = tempfile::tempdir().expect("temp dir");
        let (first_pem, _) = issue_pair();
        let (second_pem, _) = issue_pair();
        let first = write_temp(&directory, "root-a.pem", &first_pem);
        let second = write_temp(&directory, "root-b.pem", &second_pem);

        let compile = |path: &PathBuf| {
            UpstreamTls::compile(&UpstreamTlsConfig {
                trusted_ca_certs: vec![path.to_string_lossy().to_string()],
                ..Default::default()
            })
            .expect("compiles")
            .expect("is a customisation")
        };

        // Verification
        let left = compile(&first);
        let right = compile(&second);
        assert_ne!(
            left.pool_key(),
            right.pool_key(),
            "two trust domains must never share a pooled connection"
        );
        assert_eq!(
            left.pool_key(),
            compile(&first).pool_key(),
            "the same trust material must produce a stable pool key"
        );
    }

    #[test]
    fn rotating_a_certificate_in_place_changes_what_the_next_load_compiles() {
        // Setup scenarios
        //
        // Rotation happens on configuration reload: the same paths are read
        // again. Two properties have to hold. The new material must actually
        // be picked up, and the pool key must change so connections opened
        // under the retired certificate are not reused under the new one.
        let directory = tempfile::tempdir().expect("temp dir");
        let (first_cert, first_key) = issue_named("identity-2025.upstream.test");
        let cert_path = write_temp(&directory, "rotating.crt", &first_cert);
        let key_path = write_temp(&directory, "rotating.key", &first_key);
        let config = UpstreamTlsConfig {
            client_cert: Some(cert_path.to_string_lossy().to_string()),
            client_key: Some(key_path.to_string_lossy().to_string()),
            ..Default::default()
        };
        let before = UpstreamTls::compile(&config)
            .expect("compiles")
            .expect("is a customisation");

        // Rewrite both halves in place, the way a certificate manager does.
        let (second_cert, second_key) = issue_named("identity-2026.upstream.test");
        std::fs::write(&cert_path, second_cert).expect("rotate certificate");
        std::fs::write(&key_path, second_key).expect("rotate key");

        // Verification
        let after = UpstreamTls::compile(&config)
            .expect("recompiles")
            .expect("is a customisation");
        assert_ne!(
            before.pool_key(),
            after.pool_key(),
            "a rotated identity must not inherit connections opened with the old one"
        );
        assert!(
            before
                .summary()
                .client_subject
                .as_deref()
                .is_some_and(|subject| subject.contains("identity-2025")),
            "the first load must describe the certificate it actually read"
        );
        assert!(
            after
                .summary()
                .client_subject
                .as_deref()
                .is_some_and(|subject| subject.contains("identity-2026")),
            "the reload must read the new file, not a cached parse"
        );
    }

    #[test]
    fn a_key_that_stops_matching_after_rotation_fails_the_reload() {
        // Setup scenarios
        //
        // Half-completed rotations are the common failure: the certificate is
        // replaced and the key is not. The reload must refuse rather than
        // install a pair that only fails during the handshake.
        let directory = tempfile::tempdir().expect("temp dir");
        let (first_cert, first_key) = issue_pair();
        let cert_path = write_temp(&directory, "half.crt", &first_cert);
        let key_path = write_temp(&directory, "half.key", &first_key);
        let config = UpstreamTlsConfig {
            client_cert: Some(cert_path.to_string_lossy().to_string()),
            client_key: Some(key_path.to_string_lossy().to_string()),
            ..Default::default()
        };
        UpstreamTls::compile(&config).expect("the matched pair compiles");

        let (rotated_cert, _) = issue_pair();
        std::fs::write(&cert_path, rotated_cert).expect("rotate only the certificate");

        // Verification
        let error = UpstreamTls::compile(&config).expect_err("a half rotation must fail");
        assert!(
            matches!(error, UpstreamTlsError::KeyMismatch { .. }),
            "unexpected error: {error}"
        );
        let message = error.to_string();
        assert!(
            message.contains(&cert_path.to_string_lossy().to_string())
                && message.contains(&key_path.to_string_lossy().to_string()),
            "the diagnostic must name both halves so the stale one is obvious: {message}"
        );
    }

    #[test]
    fn server_name_override_replaces_the_peer_sni() {
        // Setup scenarios
        let config = UpstreamTlsConfig {
            server_name: Some("internal.example".to_string()),
            ..Default::default()
        };
        let compiled = UpstreamTls::compile(&config)
            .expect("compiles")
            .expect("is a customisation");
        let mut peer = pingora_core::upstreams::peer::HttpPeer::new(
            "10.0.0.5:8443",
            true,
            "10.0.0.5".to_string(),
        );

        // Verification
        compiled.apply(&mut peer);
        assert_eq!(peer.sni, "internal.example");
        assert!(
            peer.options.verify_cert,
            "an SNI override must not weaken verification"
        );
    }
}
