// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🪪 Turning `tls client_auth` into something a handshake actually enforces.
//!
//! Mutual TLS is one of the few features where a configuration that parses and
//! a configuration that protects you are entirely different things. A site can
//! declare `client_auth { mode require_and_verify }`, survive every validation
//! pass, and still admit every client on the internet — the declaration lives
//! in a struct nobody reads at handshake time. That is why this module exists
//! and why the binary refused to start without it.
//!
//! The work splits cleanly in two:
//!
//! - **At startup**, [`CompiledClientAuth::compile`] reads the trust material
//!   off disk, parses it, and builds one BoringSSL trust store per site. Every
//!   expensive thing — file I/O, PEM parsing, base64 decoding — happens exactly
//!   here, because the alternative is doing it inside a TLS handshake.
//! - **At a handshake**, [`CompiledClientAuth::install`] hangs the compiled
//!   policy off the connection. The verification itself borrows the shared
//!   store rather than rebuilding it, so a second connection to the same site
//!   costs one `Arc` clone and no parsing.
//!
//! ## Why a custom verification callback rather than BoringSSL's own
//!
//! BoringSSL has exactly one built-in answer — "build a trust path or fail" —
//! and two of the four modes upstream defines do not want it. `request` asks
//! for a certificate and accepts whatever arrives; `require` insists one is
//! sent but deliberately does not check it. Handing those to the built-in
//! verifier would reject clients the operator asked to admit. A custom callback
//! gives all four modes one shape: the verify *mode* decides whether a
//! certificate is demanded, and the callback decides what, if anything, is
//! checked about it.
//!
//! ## Why this lives here rather than in the binary
//!
//! Both transports need it, and they reach it through different doors.
//! HTTP/1.1 and HTTP/2 install the policy from Pingora's certificate callback;
//! HTTP/3 installs it from `tokio-quiche`'s ClientHello callback, because QUIC
//! never runs BoringSSL's `cert_cb` at all. Both windows are the same moment —
//! the name is known, the `CertificateRequest` has not been written — so one
//! compiled policy serves both. A security control that held on only one
//! transport would be a control any client opts out of by picking the other,
//! and `Alt-Svc` actively invites them to.
//!
//! ## What the handshake still cannot tell you
//!
//! A resumed TLS session carries no `CertificateRequest`, so BoringSSL never
//! re-runs any of this. Both listeners therefore turn resumption off when a
//! policy is present — see the notes in `run.rs` and `quic.rs`.

use boring::error::ErrorStack;
use boring::ssl::{SslAlert, SslRef, SslVerifyError, SslVerifyMode};
use boring::stack::Stack;
use boring::x509::store::{X509Store, X509StoreBuilder};
use boring::x509::{X509, X509StoreContext};
use pingclair_core::config::{ClientAuthConfig, ClientAuthMode, TrustPool};
use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine as _;

/// 🛡️ How deeply `trust_pool combined { … }` may nest before we refuse.
///
/// The Caddyfile adapter already bounds this, but the Admin API deserialises
/// straight into the core types and never sees the adapter. A recursive shape
/// an attacker can post is a recursive shape this loader has to survive, so the
/// bound is repeated on the path that actually walks the tree.
const MAX_TRUST_POOL_DEPTH: usize = 8;

/// 🪪 One site's client-certificate policy, resolved once at startup.
pub struct CompiledClientAuth {
    /// 🎚️ What BoringSSL is told to demand: whether to send a
    /// `CertificateRequest` at all, and whether an empty answer is fatal.
    verify_mode: SslVerifyMode,

    /// 🏛️ The certificates a client's chain is built against.
    ///
    /// `None` for the two modes that never build a chain, which is what makes
    /// `request` and `require` cheap: no store is loaded and none is consulted.
    trust: Option<X509Store>,

    /// 🍃 Leaves pinned individually, in DER, sorted so the check is a binary
    /// search rather than a scan. Empty means "no pinning", which is the case
    /// for almost every configuration.
    pinned_leaves: Vec<Vec<u8>>,
}

impl std::fmt::Debug for CompiledClientAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledClientAuth")
            .field("verify_mode", &self.verify_mode)
            .field("has_trust_store", &self.trust.is_some())
            .field("pinned_leaves", &self.pinned_leaves.len())
            .finish()
    }
}

impl CompiledClientAuth {
    /// 🏗️ Reads every certificate the policy names and builds the trust store.
    ///
    /// Returns a description of the first problem rather than a store that is
    /// missing a CA, because a trust store with a silently dropped root rejects
    /// exactly the clients the operator meant to admit — and does it at
    /// handshake time, to a real user, with an error that says nothing useful.
    pub fn compile(config: &ClientAuthConfig) -> Result<Self, String> {
        let verifies = matches!(
            config.mode,
            ClientAuthMode::VerifyIfGiven | ClientAuthMode::RequireAndVerify
        );
        let demands_certificate = matches!(
            config.mode,
            ClientAuthMode::Require | ClientAuthMode::RequireAndVerify
        );

        // 🙋 Every mode asks for a certificate; they differ only in whether an
        // empty answer ends the handshake and whether the answer is checked.
        let mut verify_mode = SslVerifyMode::PEER;
        if demands_certificate {
            verify_mode |= SslVerifyMode::FAIL_IF_NO_PEER_CERT;
        }

        let pinned_leaves = compile_pinned_leaves(config)?;

        let trust = if verifies {
            Some(compile_trust_store(config)?)
        } else {
            None
        };

        Ok(Self {
            verify_mode,
            trust,
            pinned_leaves,
        })
    }

    /// 🔗 Attaches this policy to one handshake.
    ///
    /// Called from inside BoringSSL's certificate callback, which runs after
    /// the ClientHello and before the `CertificateRequest` is written — the one
    /// moment where the SNI is known and the demand can still be changed.
    pub fn install(self: &Arc<Self>, ssl: &mut SslRef) {
        let policy = Arc::clone(self);
        ssl.set_custom_verify_callback(self.verify_mode, move |ssl| policy.verify(ssl));
    }

    /// 🔍 Decides whether one client's certificate is acceptable.
    ///
    /// Reached only when the client actually sent a certificate: BoringSSL
    /// handles the empty case from the verify mode alone, failing the handshake
    /// when `FAIL_IF_NO_PEER_CERT` is set and skipping verification when it is
    /// not. So the "no certificate" branch below is a belt-and-braces answer,
    /// not the normal path.
    fn verify(&self, ssl: &SslRef) -> Result<(), SslVerifyError> {
        let Some(leaf) = ssl.peer_certificate() else {
            return if self
                .verify_mode
                .contains(SslVerifyMode::FAIL_IF_NO_PEER_CERT)
            {
                Err(SslVerifyError::Invalid(SslAlert::CERTIFICATE_REQUIRED))
            } else {
                Ok(())
            };
        };

        // 🏛️ Chain first, pin second — the same order upstream uses. A pinned
        // leaf still has to be signed by a trusted issuer; pinning narrows the
        // set of acceptable clients, it does not replace the trust path.
        if let Some(trust) = &self.trust {
            let verified = verify_chain(ssl, trust, &leaf).map_err(|error| {
                tracing::error!("🚫 Client certificate verification failed to run: {error}");
                SslVerifyError::Invalid(SslAlert::INTERNAL_ERROR)
            })?;
            if !verified {
                tracing::debug!("🚫 Client certificate did not chain to the configured trust pool");
                return Err(SslVerifyError::Invalid(SslAlert::UNKNOWN_CA));
            }
        }

        if !self.pinned_leaves.is_empty() {
            let der = leaf.to_der().map_err(|error| {
                tracing::error!("🚫 Client certificate could not be re-encoded: {error}");
                SslVerifyError::Invalid(SslAlert::INTERNAL_ERROR)
            })?;
            if self.pinned_leaves.binary_search(&der).is_err() {
                tracing::debug!("🚫 Client certificate is not one of the pinned leaves");
                return Err(SslVerifyError::Invalid(SslAlert::CERTIFICATE_UNKNOWN));
            }
        }

        Ok(())
    }
}

/// 🗺️ One listener's answer to "what does a client for this name have to prove?"
///
/// A listen address carries every site that named it, and those sites can
/// disagree: `secure.example` may demand a certificate while `www.example`
/// shares the socket and demands nothing. The certificate callback knows the
/// SNI, so the choice is made there — which is also why a listener with any
/// mutual TLS on it enforces SNI-against-Host at the HTTP layer. Without that,
/// a client would send the harmless name in the handshake and the protected one
/// in the `Host` header.
#[derive(Debug, Default)]
pub struct ClientAuthTable {
    /// 🏷️ Sites named outright. The common case, and a hash lookup.
    exact: HashMap<Box<str>, Arc<CompiledClientAuth>>,

    /// 🃏 `*.example.com`, stored as the `.example.com` it has to end with.
    /// A `Vec` because a listener has a handful of these at most, and a linear
    /// walk over a handful beats any structure that has to be built first.
    wildcards: Vec<(Box<str>, Arc<CompiledClientAuth>)>,

    /// 🕳️ The catch-all site's policy, used when nothing else matches — which
    /// includes the client that sent no SNI at all.
    fallback: Option<Arc<CompiledClientAuth>>,
}

impl ClientAuthTable {
    /// 🏗️ Records one site's policy under every name it answers to.
    pub fn insert(&mut self, names: &[&str], policy: Arc<CompiledClientAuth>) {
        if names.is_empty() {
            self.fallback = Some(policy);
            return;
        }
        for name in names {
            match *name {
                "_" | "*" => self.fallback = Some(Arc::clone(&policy)),
                name if name.starts_with(':') => self.fallback = Some(Arc::clone(&policy)),
                name => match name.strip_prefix('*') {
                    Some(suffix) if suffix.starts_with('.') => self
                        .wildcards
                        .push((suffix.to_ascii_lowercase().into(), Arc::clone(&policy))),
                    _ => {
                        self.exact
                            .insert(name.to_ascii_lowercase().into(), Arc::clone(&policy));
                    }
                },
            }
        }
    }

    /// 🔎 Picks the policy a handshake for this name must satisfy.
    ///
    /// Exact names win over wildcards, and a wildcard covers exactly one label
    /// — `*.example.com` answers for `a.example.com` and not `a.b.example.com`,
    /// matching how upstream matches an SNI.
    pub fn policy_for(&self, sni: &str) -> Option<&Arc<CompiledClientAuth>> {
        if !sni.is_empty() {
            // 🏷️ SNI is case-insensitive, and almost always already lowercase;
            // only the rare mixed-case name pays for a copy.
            let lowered;
            let name = if sni.bytes().any(|byte| byte.is_ascii_uppercase()) {
                lowered = sni.to_ascii_lowercase();
                lowered.as_str()
            } else {
                sni
            };
            if let Some(policy) = self.exact.get(name) {
                return Some(policy);
            }
            for (suffix, policy) in &self.wildcards {
                if let Some(label) = name.strip_suffix(suffix.as_ref())
                    && !label.is_empty()
                    && !label.contains('.')
                {
                    return Some(policy);
                }
            }
        }
        self.fallback.as_ref()
    }

    /// 🕳️ Reports whether this listener asks anything of any client.
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcards.is_empty() && self.fallback.is_none()
    }
}

/// 🔗 Builds a trust path for the client's leaf using the certificates it sent.
///
/// On a server, BoringSSL's `peer_cert_chain` is the intermediates *without*
/// the leaf, which is precisely the pair `X509_STORE_CTX_init` wants. Borrowing
/// the shared store here rather than installing it on the connection is what
/// keeps a second handshake from re-parsing every CA the operator configured.
fn verify_chain(ssl: &SslRef, trust: &X509Store, leaf: &X509) -> Result<bool, ErrorStack> {
    let empty;
    let intermediates = match ssl.peer_cert_chain() {
        Some(chain) => chain,
        None => {
            empty = Stack::new()?;
            &empty
        }
    };
    let mut context = X509StoreContext::new()?;
    context.init(trust, leaf, intermediates, |context| context.verify_cert())
}

/// 🍃 Decodes the leaves a policy pins, sorted for binary search at handshake.
fn compile_pinned_leaves(config: &ClientAuthConfig) -> Result<Vec<Vec<u8>>, String> {
    let mut pinned = Vec::new();
    for encoded in &config.trusted_leaf_certs {
        pinned.push(
            decode_der(encoded)
                .map_err(|error| format!("trusted_leaf_cert is not a certificate: {error}"))?,
        );
    }
    for path in &config.trusted_leaf_cert_files {
        for certificate in read_pem_bundle(path)? {
            pinned.push(
                certificate
                    .to_der()
                    .map_err(|error| format!("re-encoding a leaf from {path} failed: {error}"))?,
            );
        }
    }
    pinned.sort_unstable();
    pinned.dedup();
    Ok(pinned)
}

/// 🏛️ Assembles the store a verifying mode checks client chains against.
fn compile_trust_store(config: &ClientAuthConfig) -> Result<X509Store, String> {
    let mut builder = X509StoreBuilder::new()
        .map_err(|error| format!("could not create a client trust store: {error}"))?;
    let mut named_anything = false;

    // 📜 Upstream's deprecated flat spellings. They are mutually exclusive with
    // `trust_pool`, which `validate_config` enforces, so loading both here is
    // only ever loading one of them.
    for encoded in &config.trusted_ca_certs {
        let der = decode_der(encoded)
            .map_err(|error| format!("trusted_ca_cert is not a certificate: {error}"))?;
        add_der(&mut builder, &der)?;
        named_anything = true;
    }
    for path in &config.trusted_ca_cert_files {
        for certificate in read_pem_bundle(path)? {
            builder
                .add_cert(certificate)
                .map_err(|error| format!("adding a CA from {path} failed: {error}"))?;
        }
        named_anything = true;
    }

    if let Some(pool) = &config.trust_pool {
        add_trust_pool(&mut builder, pool, 0)?;
        named_anything = true;
    }

    // 🖥️ No trust material and a mode that verifies means the host's own store,
    // which is what upstream ends up doing: its verifier treats an unset pool as
    // "use the system roots". Worth stating out loud, because it is the one
    // branch where a configuration that names no CA still admits clients.
    if !named_anything {
        builder
            .set_default_paths()
            .map_err(|error| format!("loading the system trust store failed: {error}"))?;
    }

    Ok(builder.build())
}

/// 🧩 Folds one trust pool — possibly a tree of them — into the store.
fn add_trust_pool(
    builder: &mut X509StoreBuilder,
    pool: &TrustPool,
    depth: usize,
) -> Result<(), String> {
    if depth > MAX_TRUST_POOL_DEPTH {
        return Err(format!(
            "trust_pool nests more than {MAX_TRUST_POOL_DEPTH} levels deep"
        ));
    }
    match pool {
        TrustPool::Inline { trust_der } => {
            for encoded in trust_der {
                let der = decode_der(encoded)
                    .map_err(|error| format!("inline trust_der is not a certificate: {error}"))?;
                add_der(builder, &der)?;
            }
        }
        TrustPool::File { pem_files } => {
            for path in pem_files {
                for certificate in read_pem_bundle(path)? {
                    builder
                        .add_cert(certificate)
                        .map_err(|error| format!("adding a CA from {path} failed: {error}"))?;
                }
            }
        }
        TrustPool::System => {
            builder
                .set_default_paths()
                .map_err(|error| format!("loading the system trust store failed: {error}"))?;
        }
        // 🏛️ A `pki` authority is configuration this build parses and does not
        // operate: it never becomes a CA, so it has no root to verify against.
        // Refused here, at startup, where the operator can still act on it —
        // an empty store would instead reject every client at handshake time
        // with nothing pointing back at this setting.
        TrustPool::PkiRoot { authority } | TrustPool::PkiIntermediate { authority } => {
            return Err(format!(
                "trust_pool refers to the `pki` authority `{authority}`, and this build does \
                 not act as a certificate authority; name the CA's certificate with \
                 `trust_pool file` instead"
            ));
        }
        TrustPool::Combined { sources } => {
            for source in sources {
                add_trust_pool(builder, source, depth + 1)?;
            }
        }
    }
    Ok(())
}

/// 📜 Reads a PEM bundle from disk, refusing an empty one.
///
/// An empty or non-certificate file is a misconfiguration that would otherwise
/// produce a store missing a CA, and a store missing a CA rejects clients at
/// handshake time with an error nobody can trace back to this file.
fn read_pem_bundle(path: &str) -> Result<Vec<X509>, String> {
    let pem = std::fs::read(path).map_err(|error| format!("cannot read {path}: {error}"))?;
    let certificates = X509::stack_from_pem(&pem)
        .map_err(|error| format!("{path} is not a PEM certificate bundle: {error}"))?;
    if certificates.is_empty() {
        return Err(format!("{path} contains no certificate"));
    }
    Ok(certificates)
}

/// 🔡 Decodes one base64 DER certificate, the shape upstream stores them in.
fn decode_der(encoded: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|error| format!("not valid base64: {error}"))
}

/// 📜 Parses DER and adds it, so a bad certificate is named at startup.
fn add_der(builder: &mut X509StoreBuilder, der: &[u8]) -> Result<(), String> {
    let certificate =
        X509::from_der(der).map_err(|error| format!("not a DER certificate: {error}"))?;
    builder
        .add_cert(certificate)
        .map_err(|error| format!("adding a CA to the trust store failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🏛️ Generates a throwaway CA and one leaf it signed, both in PEM.
    fn ca_and_leaf() -> (String, String) {
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "pingclair test CA");
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let ca = ca_params.self_signed(&ca_key).expect("ca");

        let mut leaf_params =
            rcgen::CertificateParams::new(vec!["client.test".to_string()]).expect("params");
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "client.test");
        let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
        let leaf = leaf_params
            .signed_by(&leaf_key, &rcgen::Issuer::from_params(&ca_params, &ca_key))
            .expect("leaf");

        (ca.pem(), leaf.pem())
    }

    fn der_base64(pem: &str) -> String {
        let certificate = X509::from_pem(pem.as_bytes()).expect("pem");
        base64::engine::general_purpose::STANDARD.encode(certificate.to_der().expect("der"))
    }

    /// 🎚️ The four modes differ in exactly two bits, and getting either wrong
    /// turns a security control into a decoration: without `PEER` no
    /// certificate is ever requested, and without `FAIL_IF_NO_PEER_CERT` a
    /// client that sends nothing is admitted.
    #[test]
    fn each_mode_demands_what_its_name_says() {
        let compile = |mode| {
            CompiledClientAuth::compile(&ClientAuthConfig {
                mode,
                trust_pool: Some(TrustPool::Inline {
                    trust_der: Vec::new(),
                }),
                ..Default::default()
            })
            .expect("compiles")
        };

        let request = compile(ClientAuthMode::Request);
        assert_eq!(request.verify_mode, SslVerifyMode::PEER);
        assert!(request.trust.is_none(), "`request` never checks a chain");

        let require = compile(ClientAuthMode::Require);
        assert_eq!(
            require.verify_mode,
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT
        );
        assert!(require.trust.is_none(), "`require` never checks a chain");

        let verify_if_given = compile(ClientAuthMode::VerifyIfGiven);
        assert_eq!(verify_if_given.verify_mode, SslVerifyMode::PEER);
        assert!(verify_if_given.trust.is_some());

        let require_and_verify = compile(ClientAuthMode::RequireAndVerify);
        assert_eq!(
            require_and_verify.verify_mode,
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT
        );
        assert!(require_and_verify.trust.is_some());
    }

    /// 📂 A trust pool that names a file loads it at startup, so an operator
    /// learns about a missing or malformed bundle before a client does.
    #[test]
    fn a_missing_or_empty_bundle_is_refused_at_compile_time() {
        let missing = CompiledClientAuth::compile(&ClientAuthConfig {
            mode: ClientAuthMode::RequireAndVerify,
            trust_pool: Some(TrustPool::File {
                pem_files: vec!["/definitely/not/here.pem".to_string()],
            }),
            ..Default::default()
        });
        assert!(missing.is_err(), "a missing bundle must not compile");

        let directory = tempfile::tempdir().expect("tempdir");
        let empty = directory.path().join("empty.pem");
        std::fs::write(&empty, b"").expect("write");
        let result = CompiledClientAuth::compile(&ClientAuthConfig {
            mode: ClientAuthMode::RequireAndVerify,
            trust_pool: Some(TrustPool::File {
                pem_files: vec![empty.to_string_lossy().into_owned()],
            }),
            ..Default::default()
        });
        assert!(result.is_err(), "an empty bundle must not compile");
    }

    /// 🧩 `combined` is recursive, so the loader that walks it needs its own
    /// bound: the Admin API posts straight into these types and never passes
    /// through the Caddyfile adapter that bounds the parse.
    #[test]
    fn a_deeply_nested_combined_pool_is_refused() {
        let mut pool = TrustPool::System;
        for _ in 0..(MAX_TRUST_POOL_DEPTH + 2) {
            pool = TrustPool::Combined {
                sources: vec![pool],
            };
        }
        let result = CompiledClientAuth::compile(&ClientAuthConfig {
            mode: ClientAuthMode::RequireAndVerify,
            trust_pool: Some(pool),
            ..Default::default()
        });
        assert!(result.is_err(), "nesting past the bound must be refused");
    }

    /// 📜 Certificates arrive base64-DER from JSON and PEM from disk; both
    /// spellings have to reach the same store, or a configuration that works
    /// through the Caddyfile fails through the Admin API.
    #[test]
    fn both_spellings_of_a_ca_compile() {
        let (ca_pem, _) = ca_and_leaf();
        let directory = tempfile::tempdir().expect("tempdir");
        let bundle = directory.path().join("ca.pem");
        std::fs::write(&bundle, ca_pem.as_bytes()).expect("write");

        let from_file = CompiledClientAuth::compile(&ClientAuthConfig {
            mode: ClientAuthMode::RequireAndVerify,
            trust_pool: Some(TrustPool::File {
                pem_files: vec![bundle.to_string_lossy().into_owned()],
            }),
            ..Default::default()
        });
        assert!(from_file.is_ok(), "{from_file:?}");

        let from_inline = CompiledClientAuth::compile(&ClientAuthConfig {
            mode: ClientAuthMode::RequireAndVerify,
            trust_pool: Some(TrustPool::Inline {
                trust_der: vec![der_base64(&ca_pem)],
            }),
            ..Default::default()
        });
        assert!(from_inline.is_ok(), "{from_inline:?}");

        let garbage = CompiledClientAuth::compile(&ClientAuthConfig {
            mode: ClientAuthMode::RequireAndVerify,
            trust_pool: Some(TrustPool::Inline {
                trust_der: vec!["not base64 at all !!".to_string()],
            }),
            ..Default::default()
        });
        assert!(garbage.is_err(), "a bad certificate must be named at start");
    }

    /// 🍃 Pinned leaves are sorted and de-duplicated once so the handshake can
    /// binary-search them instead of scanning a list per connection.
    #[test]
    fn pinned_leaves_are_sorted_and_deduplicated() {
        let (_, leaf_pem) = ca_and_leaf();
        let encoded = der_base64(&leaf_pem);
        let compiled = CompiledClientAuth::compile(&ClientAuthConfig {
            mode: ClientAuthMode::RequireAndVerify,
            trusted_leaf_certs: vec![encoded.clone(), encoded],
            ..Default::default()
        })
        .expect("compiles");
        assert_eq!(compiled.pinned_leaves.len(), 1);
        assert!(
            compiled
                .pinned_leaves
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
    }
}
