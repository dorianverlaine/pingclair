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

use arc_swap::ArcSwap;
use boring::error::ErrorStack;
use boring::ex_data::Index;
use boring::ssl::{Ssl, SslAlert, SslRef, SslVerifyError, SslVerifyMode};
use boring::stack::{Stack, StackRef};
use boring::x509::store::{X509Store, X509StoreBuilder};
use boring::x509::{X509, X509StoreContext, X509StoreContextRef};
use foreign_types::ForeignTypeRef as _;
use pingclair_core::config::{ClientAuthConfig, ClientAuthMode, TrustPool};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

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

/// 🪪 One immutable listener-security generation used by every TLS transport.
///
/// The table and revision travel together so a connection cannot be admitted
/// under one trust pool and later be mistaken for a connection admitted under
/// another. Reload publishes a new generation only after every trust source
/// has compiled successfully.
#[derive(Debug)]
pub struct ListenerSecuritySnapshot {
    client_auth: Arc<ClientAuthTable>,
    revision: u64,
}

impl ListenerSecuritySnapshot {
    /// 🗺️ Returns the precompiled SNI-to-client-auth table for this generation.
    pub fn client_auth(&self) -> &ClientAuthTable {
        &self.client_auth
    }

    /// 🔢 Returns the generation recorded on a connection at its handshake.
    pub fn revision(&self) -> u64 {
        self.revision
    }
}

/// 🔐 Publishes one listener's handshake policy to H1, H2, and H3 together.
///
/// A short publication gate refuses new handshakes and requests while routing
/// and TLS snapshots are swapped. Connections that began before the gate carry
/// the old revision and are refused after it, so a trust-pool rotation cannot
/// leave a keep-alive or QUIC connection authorised by stale credentials.
pub struct PublishedListenerPolicy {
    current: ArcSwap<ListenerSecuritySnapshot>,
    publishing: AtomicBool,
    client_auth_reload_capable: bool,
}

impl std::fmt::Debug for PublishedListenerPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PublishedListenerPolicy")
            .field("revision", &self.revision())
            .field("publishing", &self.is_publishing())
            .field(
                "client_auth_reload_capable",
                &self.client_auth_reload_capable,
            )
            .finish()
    }
}

impl PublishedListenerPolicy {
    /// 🏗️ Creates the generation installed before the listener begins serving.
    pub fn new(client_auth: Arc<ClientAuthTable>) -> Self {
        let client_auth_reload_capable = !client_auth.is_empty();
        Self {
            current: ArcSwap::from_pointee(ListenerSecuritySnapshot {
                client_auth,
                revision: 0,
            }),
            publishing: AtomicBool::new(false),
            client_auth_reload_capable,
        }
    }

    /// 🚦 Closes the listener's publication gate before any snapshot changes.
    pub fn begin_publish(&self) {
        self.publishing.store(true, Ordering::Release);
    }

    /// 🚦 Reopens the listener after every routing and TLS snapshot is live.
    pub fn finish_publish(&self) {
        self.publishing.store(false, Ordering::Release);
    }

    /// 🚧 Reports whether the listener is between two complete generations.
    pub fn is_publishing(&self) -> bool {
        self.publishing.load(Ordering::Acquire)
    }

    /// 🔁 Reports whether resumption was disabled when this TLS context began.
    ///
    /// Enabling mTLS later is unsafe when the original context issued tickets:
    /// a resumed handshake sends no `CertificateRequest`. Such a change is
    /// therefore restart-required instead of being accepted without effect.
    pub fn client_auth_reload_capable(&self) -> bool {
        self.client_auth_reload_capable
    }

    /// 🪪 Reports whether the active generation asks any client for a certificate.
    pub fn requires_client_auth(&self) -> bool {
        !self.current.load().client_auth.is_empty()
    }

    /// 🔢 Returns the currently published listener-security generation.
    pub fn revision(&self) -> u64 {
        self.current.load().revision
    }

    /// 🤝 Loads one complete generation for a new handshake.
    ///
    /// `None` means publication is in progress; callers must fail the
    /// handshake closed rather than fall back to a certificate-only context.
    pub fn handshake_snapshot(&self) -> Option<Arc<ListenerSecuritySnapshot>> {
        if self.is_publishing() {
            None
        } else {
            Some(self.current.load_full())
        }
    }

    /// 📣 Publishes a fully compiled client-auth table as the next generation.
    pub fn publish_client_auth(&self, client_auth: Arc<ClientAuthTable>) {
        let revision = self.current.load().revision.wrapping_add(1);
        self.current.store(Arc::new(ListenerSecuritySnapshot {
            client_auth,
            revision,
        }));
    }
}

/// 🧷 BoringSSL slot carrying the listener-security generation through TLS.
static LISTENER_SECURITY_REVISION_INDEX: OnceLock<Result<Index<Ssl, u64>, String>> =
    OnceLock::new();

fn listener_security_revision_index() -> Result<Index<Ssl, u64>, String> {
    LISTENER_SECURITY_REVISION_INDEX
        .get_or_init(|| Ssl::new_ex_index().map_err(|error| error.to_string()))
        .clone()
}

/// 🧷 Records which listener-security generation admitted this connection.
pub fn record_listener_security_revision(ssl: &mut SslRef, revision: u64) -> Result<(), String> {
    let index = listener_security_revision_index()?;
    ssl.set_ex_data(index, revision);
    Ok(())
}

/// 🔎 Reads the listener-security generation recorded during the handshake.
pub fn listener_security_revision(ssl: &SslRef) -> Option<u64> {
    let index = listener_security_revision_index().ok()?;
    ssl.ex_data(index).copied()
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
    verify_client_chain(trust, leaf, intermediates)
}

/// 🪪 Verifies one chain *as a client identity*, not merely as a valid chain.
///
/// Split out from [`verify_chain`] so the decision can be exercised with real
/// certificates and no handshake. Everything a client controls arrives here as
/// an argument; nothing is read back off the connection.
fn verify_client_chain(
    trust: &X509Store,
    leaf: &X509,
    intermediates: &StackRef<X509>,
) -> Result<bool, ErrorStack> {
    let mut context = X509StoreContext::new()?;
    context.init(trust, leaf, intermediates, |context| {
        set_ssl_client_purpose(context)?;
        context.verify_cert()
    })
}

/// 🎯 Tells BoringSSL the chain is being checked for *client* authentication.
///
/// A certificate says what it may be used for. A web server's certificate
/// carries an extended key usage of `serverAuth`, a client's carries
/// `clientAuth`, and the two are different permissions granted by the same CA.
/// Without this call BoringSSL never looks: `X509_verify_cert` runs its purpose
/// check only when a purpose has been asked for, so the answer to "is this
/// chain valid" was being taken as the answer to "may this certificate act as a
/// client". Under a private CA that issues both — the common shape, one CA for
/// the fleet — every server in the fleet could log in as a client of every
/// other.
///
/// With the purpose set, BoringSSL enforces what the certificates themselves
/// say, at every level of the chain: an extended key usage that excludes
/// `clientAuth`, a key usage that permits neither digital signature nor key
/// agreement, or a Netscape certificate type that rules out SSL client use,
/// each end the handshake. A certificate that carries no such extension is
/// still accepted — an unrestricted certificate is exactly what "no
/// restrictions" means, and refusing it would break every CA that leaves the
/// extension out.
///
/// 📌 The one side effect, checked rather than assumed: `set_purpose` also sets
/// the context's *trust* to the purpose's default, `X509_TRUST_SSL_CLIENT`.
/// For a trust anchor loaded from an ordinary PEM this changes nothing. Both
/// the old value and the new one land in `trust_compat`, which trusts a
/// self-signed anchor and refuses anything else — the same answer this code got
/// before. Only a PEM carrying explicit trust settings (`X509_CERT_AUX`, the
/// rare `TRUSTED CERTIFICATE` block) could tell the two apart. Read from
/// BoringSSL's `x509_trs.c` as vendored by `boring-sys 4.22.0` on 2026-08-17.
fn set_ssl_client_purpose(context: &mut X509StoreContextRef) -> Result<(), ErrorStack> {
    // SAFETY: The pointer belongs to a context that `X509StoreContext::init`
    // has already initialised and will not clean up until this closure returns,
    // so it is live for the call. `X509_STORE_CTX_set_purpose` only writes the
    // context's own verification parameters — no ownership crosses the
    // boundary, and nothing is retained after it returns.
    let accepted = unsafe {
        boring_sys::X509_STORE_CTX_set_purpose(
            context.as_ptr(),
            boring_sys::X509_PURPOSE_SSL_CLIENT,
        )
    };
    // 🚫 The only documented failure is a purpose id the library does not know,
    // and the id is a constant from the very headers it was built from. So a
    // zero here means the library underneath is not the one this was written
    // against — which is a reason to refuse the handshake, not to verify
    // without the check and call it a pass.
    if accepted == 1 {
        Ok(())
    } else {
        Err(ErrorStack::get())
    }
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
    for folder in &config.trusted_leaf_cert_folders {
        for path in pem_files_under(folder)? {
            let display = path.display().to_string();
            for certificate in read_pem_bundle(&display)? {
                pinned.push(certificate.to_der().map_err(|error| {
                    format!("re-encoding a leaf from {display} failed: {error}")
                })?);
            }
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

/// 📁 Every `.pem` file under a directory, recursively, in a stable order.
///
/// Sorted because the pinned set is compared by content and a directory's
/// iteration order is not stable across filesystems — an unsorted walk would
/// make two identical deployments produce two different configurations, and
/// only one of them would match a reload's.
///
/// 🚫 A directory that does not exist is an error rather than an empty set.
/// This is an authentication control: "no pinned certificates" and "the folder
/// of pinned certificates is missing" must not look the same, because the
/// first one is a policy and the second one is a mistake that would quietly
/// admit clients the operator meant to exclude.
fn pem_files_under(folder: &str) -> Result<Vec<std::path::PathBuf>, String> {
    let mut found = Vec::new();
    let mut pending = vec![std::path::PathBuf::from(folder)];
    while let Some(directory) = pending.pop() {
        let entries = std::fs::read_dir(&directory)
            .map_err(|error| format!("cannot read leaf certificate folder {folder}: {error}"))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| format!("cannot read an entry under {folder}: {error}"))?;
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("pem"))
            {
                found.push(path);
            }
        }
    }
    found.sort();
    Ok(found)
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

    /// 📁 A folder of pinned leaves is walked recursively, and only `.pem`
    /// files count.
    ///
    /// This is what `verifier leaf { folder … }` compiles to. The recursion is
    /// upstream's behaviour; the extension filter is what keeps a `README` or a
    /// stray private key in the same directory from failing the load.
    #[test]
    fn a_leaf_folder_is_walked_recursively_for_pem_files() {
        let (_, leaf_pem) = ca_and_leaf();
        let directory = tempfile::tempdir().expect("temp dir");
        let nested = directory.path().join("nested");
        std::fs::create_dir(&nested).expect("nested dir");
        std::fs::write(directory.path().join("top.pem"), &leaf_pem).expect("top");
        std::fs::write(nested.join("deep.pem"), &leaf_pem).expect("deep");
        // 🙈 Neither of these is a certificate, and neither may break the load.
        std::fs::write(directory.path().join("README"), "not a certificate").expect("readme");
        std::fs::write(directory.path().join("key.txt"), "not a certificate").expect("txt");

        let compiled = CompiledClientAuth::compile(&ClientAuthConfig {
            mode: ClientAuthMode::RequireAndVerify,
            trusted_leaf_cert_folders: vec![directory.path().display().to_string()],
            ..Default::default()
        })
        .expect("a folder of leaves compiles");

        // 🧮 One entry, not two: both files hold the same certificate, and the
        // pinned set is de-duplicated.
        assert_eq!(compiled.pinned_leaves.len(), 1);
    }

    /// 🚫 A missing folder is an error, not an empty pinned set.
    ///
    /// The two must not look alike: one is a policy that pins nothing, the
    /// other is a mistake that would admit clients the operator meant to
    /// exclude. Failing to start is the only way an operator finds out.
    #[test]
    fn a_missing_leaf_folder_fails_the_load_rather_than_pinning_nothing() {
        let error = CompiledClientAuth::compile(&ClientAuthConfig {
            mode: ClientAuthMode::RequireAndVerify,
            trusted_leaf_cert_folders: vec!["/nonexistent/leaf/folder".to_string()],
            ..Default::default()
        })
        .expect_err("a missing folder must be named");
        assert!(
            error.contains("/nonexistent/leaf/folder"),
            "the message must name the folder; got {error}"
        );
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

    // MARK: - Client purpose

    use rcgen::ExtendedKeyUsagePurpose as Eku;
    use rcgen::KeyUsagePurpose as Ku;

    /// 🏛️ A throwaway CA that issues leaves with whatever usages a test asks
    /// for, so two certificates can differ in exactly one extension.
    struct TestAuthority {
        params: rcgen::CertificateParams,
        key: rcgen::KeyPair,
        pem: String,
    }

    impl TestAuthority {
        fn new(common_name: &str) -> Self {
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, common_name);
            let key = rcgen::KeyPair::generate().expect("ca key");
            let pem = params.self_signed(&key).expect("ca").pem();
            Self { params, key, pem }
        }

        fn issuer(&self) -> rcgen::Issuer<'_, &rcgen::KeyPair> {
            rcgen::Issuer::from_params(&self.params, &self.key)
        }

        /// 🍃 Issues one leaf carrying exactly the usages given, and no others.
        fn issue(&self, name: &str, extended: &[Eku], usages: &[Ku]) -> X509 {
            let mut params =
                rcgen::CertificateParams::new(vec![name.to_string()]).expect("leaf params");
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, name);
            params.extended_key_usages = extended.to_vec();
            params.key_usages = usages.to_vec();
            let key = rcgen::KeyPair::generate().expect("leaf key");
            let leaf = params
                .signed_by(&key, &self.issuer())
                .expect("leaf certificate");
            X509::from_pem(leaf.pem().as_bytes()).expect("leaf parses")
        }

        /// 🏛️ Builds the trust store through the production path, so the test
        /// exercises the same store construction a real configuration gets.
        fn trust_store(&self) -> X509Store {
            CompiledClientAuth::compile(&ClientAuthConfig {
                mode: ClientAuthMode::RequireAndVerify,
                trust_pool: Some(TrustPool::Inline {
                    trust_der: vec![der_base64(&self.pem)],
                }),
                ..Default::default()
            })
            .expect("the trust pool compiles")
            .trust
            .expect("require_and_verify builds a store")
        }
    }

    /// 🔍 Runs one leaf through the real verifier and reports the verdict.
    fn admits(trust: &X509Store, leaf: &X509, intermediates: &StackRef<X509>) -> bool {
        verify_client_chain(trust, leaf, intermediates).expect("verification runs")
    }

    fn no_intermediates() -> Stack<X509> {
        Stack::new().expect("empty stack")
    }

    /// 🪪 A certificate issued to be a *server* must not be usable to log in
    /// as a client.
    ///
    /// This is the whole finding in one test. Both leaves below are signed by
    /// the same CA and both build a perfectly valid trust path, so chain
    /// verification alone cannot separate them — and chain verification alone
    /// is what this code used to do. The only difference is the extended key
    /// usage the CA wrote into each one. Under the common private-CA shape,
    /// where one authority issues certificates for the whole fleet, that gap
    /// meant every server in the fleet held a working client identity for
    /// every other.
    #[test]
    fn a_server_only_certificate_cannot_log_in_as_a_client() {
        let authority = TestAuthority::new("Purpose Test CA");
        let trust = authority.trust_store();
        let empty = no_intermediates();

        let client = authority.issue("client.test", &[Eku::ClientAuth], &[]);
        assert!(
            admits(&trust, &client, &empty),
            "a certificate issued for client authentication was turned away"
        );

        let server = authority.issue("server.test", &[Eku::ServerAuth], &[]);
        assert!(
            !admits(&trust, &server, &empty),
            "a certificate issued only for server authentication was accepted as a client identity"
        );

        // 🧩 A certificate allowed to be both is allowed to be either.
        let both = authority.issue("both.test", &[Eku::ClientAuth, Eku::ServerAuth], &[]);
        assert!(
            admits(&trust, &both, &empty),
            "a certificate naming clientAuth alongside serverAuth was turned away"
        );
    }

    /// 🧭 A certificate that restricts nothing is still admitted.
    ///
    /// Plenty of private CAs leave both extensions out, and an absent
    /// restriction is not a restriction — reading it as one would reject
    /// clients that every previous release admitted, for no security gain.
    #[test]
    fn a_certificate_with_no_stated_usage_is_still_admitted() {
        let authority = TestAuthority::new("Unrestricted CA");
        let trust = authority.trust_store();
        let empty = no_intermediates();

        let plain = authority.issue("plain.test", &[], &[]);
        assert!(
            admits(&trust, &plain, &empty),
            "a certificate that states no usage restriction was refused"
        );
    }

    /// 🔑 Key usage is checked too: a client has to be able to sign or agree.
    ///
    /// A certificate whose key may only encipher cannot produce the
    /// `CertificateVerify` signature that proves possession, so admitting it
    /// would mean admitting a client that cannot actually prove anything.
    #[test]
    fn a_key_usage_that_permits_neither_signing_nor_agreement_is_refused() {
        let authority = TestAuthority::new("Key Usage CA");
        let trust = authority.trust_store();
        let empty = no_intermediates();

        let signing = authority.issue("signing.test", &[Eku::ClientAuth], &[Ku::DigitalSignature]);
        assert!(
            admits(&trust, &signing, &empty),
            "a client certificate allowed to sign was turned away"
        );

        let encipher_only =
            authority.issue("encipher.test", &[Eku::ClientAuth], &[Ku::KeyEncipherment]);
        assert!(
            !admits(&trust, &encipher_only, &empty),
            "a certificate whose key may neither sign nor agree was accepted as a client identity"
        );
    }

    /// 🧬 `anyExtendedKeyUsage` on its own does **not** count as clientAuth.
    ///
    /// Recorded because it surprises people rather than because it is a
    /// choice this code made: BoringSSL gives `anyExtendedKeyUsage` its own
    /// bit and the SSL-client check tests for the clientAuth bit, so a leaf
    /// carrying only `any` is refused. Deferring to the library is the point
    /// of doing the check this way — special-casing it here would mean writing
    /// our own purpose logic beside theirs. An operator hitting this adds
    /// `clientAuth` to the certificate.
    #[test]
    fn any_extended_key_usage_alone_does_not_grant_client_use() {
        let authority = TestAuthority::new("Any EKU CA");
        let trust = authority.trust_store();
        let empty = no_intermediates();

        let any = authority.issue("any.test", &[Eku::Any], &[]);
        assert!(
            !admits(&trust, &any, &empty),
            "BoringSSL's anyExtendedKeyUsage handling changed; re-read v3_purp.c before \
             relaxing this"
        );
    }

    /// 🧱 The check applies at every level, not just the leaf.
    ///
    /// An intermediate restricted to `serverAuth` is an intermediate its own
    /// CA said must not issue client identities. Honouring that only at the
    /// leaf would let the restriction be escaped by the very certificates it
    /// was written to constrain.
    #[test]
    fn an_intermediate_restricted_to_servers_cannot_issue_client_identities() {
        let root = TestAuthority::new("Nesting Root CA");
        let trust = root.trust_store();

        let issue_intermediate = |extended: &[Eku]| {
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "Nesting Intermediate");
            params.extended_key_usages = extended.to_vec();
            let key = rcgen::KeyPair::generate().expect("intermediate key");
            let certificate = params
                .signed_by(&key, &root.issuer())
                .expect("intermediate certificate");
            (params, key, certificate.pem())
        };

        let sign_leaf = |params: &rcgen::CertificateParams, key: &rcgen::KeyPair| {
            let mut leaf_params =
                rcgen::CertificateParams::new(vec!["deep.test".to_string()]).expect("params");
            leaf_params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "deep.test");
            leaf_params.extended_key_usages = vec![Eku::ClientAuth];
            let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
            let leaf = leaf_params
                .signed_by(&leaf_key, &rcgen::Issuer::from_params(params, key))
                .expect("leaf certificate");
            X509::from_pem(leaf.pem().as_bytes()).expect("leaf parses")
        };

        let stack_of = |pem: &str| {
            let mut stack = Stack::new().expect("stack");
            stack
                .push(X509::from_pem(pem.as_bytes()).expect("intermediate parses"))
                .expect("push");
            stack
        };

        // 🧭 An unrestricted intermediate still works, so the test below is
        // about the restriction and not about chain depth.
        let (open_params, open_key, open_pem) = issue_intermediate(&[]);
        let under_open = sign_leaf(&open_params, &open_key);
        assert!(
            admits(&trust, &under_open, &stack_of(&open_pem)),
            "a client certificate under an unrestricted intermediate was turned away"
        );

        let (server_params, server_key, server_pem) = issue_intermediate(&[Eku::ServerAuth]);
        let under_server = sign_leaf(&server_params, &server_key);
        assert!(
            !admits(&trust, &under_server, &stack_of(&server_pem)),
            "an intermediate restricted to serverAuth was allowed to issue a client identity"
        );
    }
}
