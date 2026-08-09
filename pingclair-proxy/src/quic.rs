// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! HTTP/3 (QUIC) server built on Cloudflare's tokio-quiche (quiche + BoringSSL).
//!
//! 🏗️ ARCHITECTURE
//!
//! The split is between transport and application. `tokio_quiche` owns the
//! transport: the UDP socket, packet parsing, version negotiation, stateless
//! retry and address validation, connection-ID routing, GSO, pacing, and each
//! connection's timers. This module owns what is left, and it is the part
//! that is actually ours.
//!
//! - [`QuicServer::run`] binds the port, hands `tokio_quiche` a
//!   [`ConnectionParams`](tokio_quiche::ConnectionParams), and then does only
//!   what the transport has no opinion about: the L4 blocklist and the
//!   listener's connection limit.
//! - Each accepted connection is driven by an [`H3App`], the crate's
//!   [`ApplicationOverQuic`](tokio_quiche::ApplicationOverQuic)
//!   implementation. Its four callbacks are the old event loop turned inside
//!   out — `process_reads` pumps HTTP/3 events, `process_writes` flushes
//!   pending response bytes, `wait_for_data` waits on the handler channel.
//! - SNI multi-certificate support uses BoringSSL's
//!   `select_certificate_callback` backed by an [`ArcSwap`]-published
//!   [`CertTable`], installed through a
//!   [`ConnectionHook`](tokio_quiche::quic::ConnectionHook). The certificates
//!   live in memory and are never written to disk; see
//!   [`IN_MEMORY_CERT_SENTINEL`]. Because the lookup is a callback rather than
//!   a snapshot, an ACME renewal applies to the next handshake with no
//!   restart.
//! - 🧭 Every HTTP/3 request is dispatched to a tokio task that reuses
//!   [`PingclairProxy::match_route_index`] (the same route matcher as the
//!   H1/H2 path). Response bytes flow back over a per-connection channel and
//!   are written through quiche with real flow control (pending buffers +
//!   writable-stream events), so large static files and upstream responses
//!   are streamed, never buffered whole.
//! - Reverse-proxying goes through Pingora's [`Connector`], i.e. the same
//!   keepalive connection pool, TLS-to-upstream support and timeout
//!   semantics as the H1/H2 path.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use bytes::Bytes;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc, watch};

use pingclair_core::config::HandlerConfig;
use pingclair_static::ServedResponse;
use pingora_core::protocols::http::client::HttpSession;
use pingora_http::RequestHeader;
use quiche::h3::NameValue;

use crate::connection_filter::PingclairConnectionFilter;
use crate::http_policy::{
    CorsDecision, ResponseHeaderPolicy, authority_host, evaluate_cors, resolve_request_id,
    rewrite_uri,
};
use crate::server::{PingclairProxy, ProxyState, error_reason, resolve_caddy_placeholders};
use crate::server::{is_streaming_content_type, wants_immediate_flush};
use pingclair_core::server::{MatcherPrecompile, MatcherRequest, evaluate};

/// Maximum UDP payload we ask quiche to send (standard Ethernet MTU-safe).
const MAX_DATAGRAM_SIZE: usize = 1350;

/// Size of the per-connection outbound packet buffer lent to tokio-quiche.
///
/// The worker writes as many QUIC packets as fit and flushes them in one
/// GSO-backed `sendmsg` on Linux. A 1350-byte buffer caps every flush at one
/// datagram, turning each packet into its own syscall. 16 KiB was measured
/// against 64 KiB (tokio-quiche's `BufFactory::MAX_BUF_SIZE` and the kernel
/// GSO ceiling): the large-file and small-file gains were identical, so the
/// smaller fixed per-connection cost wins.
const OUT_BUF_SIZE: usize = 16 * 1024;

/// Bound for the per-stream request-body channel between the event loop
/// and a handler task. When full, the event loop stops draining quiche so
/// QUIC flow control pushes back on the client.
const REQ_BODY_CHANNEL_CAPACITY: usize = 16;

/// Bound for the global response channel shared by all handler tasks.
///
/// Each slot can hold a 64 KiB body chunk, so 256 slots meant a connection
/// could buffer 16 MiB of handler output while the worker paced it into
/// quiche — 100 connections × 20 streams measured ~1.6 GiB RSS. With the
/// worker's per-stream queue cap, 32 slots (2 MiB per connection) keep
/// handler backpressure tight without stalling the pipeline.
const RESP_CHANNEL_CAPACITY: usize = 32;

/// Read size for draining request bodies out of quiche.
const BODY_CHUNK_SIZE: usize = 16 * 1024;

/// 🚦 Paces one H3 body stream without retaining any body chunk.
struct StreamPacer {
    rate: u64,
    bytes: u64,
    started: Instant,
}

impl StreamPacer {
    fn new(rate: u64) -> Self {
        Self {
            rate,
            bytes: 0,
            started: Instant::now(),
        }
    }

    fn delay_for(&mut self, bytes: usize) -> Option<Duration> {
        self.bytes = self.bytes.saturating_add(bytes as u64);
        Duration::from_secs_f64(self.bytes as f64 / self.rate as f64)
            .checked_sub(self.started.elapsed())
    }
}

/// 📥 Drains one local H3 request through bounded streaming policy.
async fn drain_local_h3_body(
    body_rx: &mut mpsc::Receiver<Vec<u8>>,
    body_notify: &Arc<Notify>,
    body_limit: u64,
    body_timeout_ms: Option<u64>,
    upload_rate: Option<u64>,
    request_deadline: Option<Instant>,
) -> Result<(), HandlerError> {
    let mut counted = 0u64;
    let mut pacer = upload_rate.map(StreamPacer::new);
    loop {
        let next = match body_timeout_ms {
            Some(timeout_ms) => {
                tokio::time::timeout(Duration::from_millis(timeout_ms), body_rx.recv())
                    .await
                    .map_err(|_| (408, "Request Body Timeout"))?
            }
            None => body_rx.recv().await,
        };
        let Some(chunk) = next else { break };
        body_notify.notify_one();
        counted = counted.saturating_add(chunk.len() as u64);
        if body_limit > 0 && counted > body_limit {
            return Err((413, "Request Entity Too Large"));
        }
        if let Some(delay) = pacer
            .as_mut()
            .and_then(|pacer| pacer.delay_for(chunk.len()))
        {
            if request_deadline.is_some_and(|deadline| Instant::now() + delay >= deadline) {
                return Err((408, "Request Timeout"));
            }
            tokio::time::sleep(delay).await;
        }
    }
    Ok(())
}

/// 📤 Delays one H3 response chunk without retaining additional body data.
async fn pace_h3_body(
    pacer: &mut Option<StreamPacer>,
    request_deadline: Option<Instant>,
    bytes: usize,
) -> Result<(), HandlerError> {
    if request_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err((408, "Request Timeout"));
    }
    if let Some(delay) = pacer.as_mut().and_then(|pacer| pacer.delay_for(bytes)) {
        if request_deadline.is_some_and(|deadline| Instant::now() + delay >= deadline) {
            return Err((408, "Request Timeout"));
        }
        tokio::time::sleep(delay).await;
    }
    Ok(())
}

// MARK: - Errors

/// QUIC server errors
#[derive(Debug, Error)]
pub enum QuicError {
    #[error("💥 IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("🔐 TLS error: {0}")]
    Tls(String),

    #[error("📡 QUIC error: {0}")]
    Quic(String),

    #[error("🌐 HTTP/3 error: {0}")]
    H3(String),
}

impl From<quiche::Error> for QuicError {
    fn from(e: quiche::Error) -> Self {
        QuicError::Quic(e.to_string())
    }
}

// MARK: - Certificate table (SNI)

/// Parsed certificate material for one SNI name, in BoringSSL form.
///
/// BoringSSL `X509`/`PKey` are `Send + Sync`, so entries can be shared
/// with the handshake callback running inside quiche.
pub struct CertEntry {
    /// Full certificate chain, leaf first.
    pub chain: Vec<boring::x509::X509>,
    /// Private key matching the leaf certificate.
    pub key: boring::pkey::PKey<boring::pkey::Private>,
}

#[derive(Clone, Default)]
struct CertTableSnapshot {
    certs: HashMap<String, Arc<CertEntry>>,
    /// Fallback used when no exact/wildcard entry matches the SNI name.
    default_name: Option<String>,
}

/// SNI → certificate table for the QUIC handshake callback.
///
/// Published through `ArcSwap` (read-copy-update) because it is read on
/// every new handshake but written only on startup / periodic refresh —
/// the same trade-off as the router tables in `server.rs`. Renewed
/// certificates therefore reach new handshakes with no restart and no
/// locking.
pub struct CertTable {
    inner: ArcSwap<CertTableSnapshot>,
}

impl CertTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self {
            inner: ArcSwap::from_pointee(CertTableSnapshot::default()),
        }
    }

    /// Parse a PEM chain + key and publish them under `name`.
    ///
    /// The first entry inserted becomes the default certificate (used when
    /// the SNI name has no exact or wildcard match); use
    /// [`CertTable::set_default`] to override.
    pub fn upsert_pem(&self, name: &str, cert_pem: &str, key_pem: &str) -> Result<(), QuicError> {
        let chain = boring::x509::X509::stack_from_pem(cert_pem.as_bytes()).map_err(|e| {
            QuicError::Tls(format!("failed to parse certificate PEM for {name}: {e}"))
        })?;
        if chain.is_empty() {
            return Err(QuicError::Tls(format!("no certificates in PEM for {name}")));
        }
        let key = boring::pkey::PKey::private_key_from_pem(key_pem.as_bytes()).map_err(|e| {
            QuicError::Tls(format!("failed to parse private key PEM for {name}: {e}"))
        })?;

        let entry = Arc::new(CertEntry { chain, key });
        self.inner.rcu(|current| {
            let mut next = (**current).clone();
            next.certs.insert(name.to_string(), entry.clone());
            if next.default_name.is_none() {
                next.default_name = Some(name.to_string());
            }
            Arc::new(next)
        });
        Ok(())
    }

    /// Choose which table entry serves as the default certificate.
    pub fn set_default(&self, name: &str) {
        self.inner.rcu(|current| {
            let mut next = (**current).clone();
            next.default_name = Some(name.to_string());
            Arc::new(next)
        });
    }

    /// Look up certificate material for a handshake SNI name.
    ///
    /// Resolution order: exact match → wildcard match (`*.example.com`,
    /// same loose suffix semantics as the H1 router) → default entry.
    pub fn lookup(&self, servername: &str) -> Option<Arc<CertEntry>> {
        let snap = self.inner.load();

        if let Some(entry) = snap.certs.get(servername) {
            return Some(entry.clone());
        }

        for (pattern, entry) in &snap.certs {
            if let Some(suffix) = pattern.strip_prefix("*.")
                && servername.ends_with(&format!(".{suffix}"))
            {
                return Some(entry.clone());
            }
        }

        snap.default_name
            .as_ref()
            .and_then(|name| snap.certs.get(name).cloned())
    }

    /// Number of entries currently published.
    pub fn len(&self) -> usize {
        self.inner.load().certs.len()
    }

    /// Whether the table has no entries at all.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for CertTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Build an SNI-aware BoringSSL context that serves certificates out of
/// `certs` at handshake time.
///
/// The certificate lookup is a callback, not a snapshot, so it observes every
/// [`CertTable`] publication — an ACME renewal applies to the next handshake
/// without rebuilding the context. BoringSSL builds this context once per
/// socket, so that indirection is the only thing that makes reload work.
fn build_ssl_context_builder(
    certs: Arc<CertTable>,
) -> Result<boring::ssl::SslContextBuilder, QuicError> {
    use boring::ssl::{NameType, SelectCertError, SslContext, SslMethod, SslVersion};

    let mut builder = SslContext::builder(SslMethod::tls())
        .map_err(|e| QuicError::Tls(format!("failed to create SSL context: {e}")))?;

    // QUIC requires TLS 1.3.
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| QuicError::Tls(format!("failed to set min TLS version: {e}")))?;

    let table = certs;
    builder.set_select_certificate_callback(move |mut hello| {
        let sni = hello
            .servername(NameType::HOST_NAME)
            .unwrap_or("")
            .to_string();

        let Some(entry) = table.lookup(&sni) else {
            tracing::warn!(
                "🔐 H3: no certificate available for SNI '{}', rejecting handshake",
                sni
            );
            return Err(SelectCertError::ERROR);
        };

        let ssl = hello.ssl_mut();
        let installed = (|| {
            ssl.set_certificate(&entry.chain[0])?;
            for cert in &entry.chain[1..] {
                ssl.add_chain_cert(cert)?;
            }
            ssl.set_private_key(&entry.key)?;
            Ok::<(), boring::error::ErrorStack>(())
        })();

        match installed {
            Ok(()) => Ok(()),
            Err(e) => {
                tracing::warn!(
                    "🔐 H3: failed to install certificate for SNI '{}': {}",
                    sni,
                    e
                );
                Err(SelectCertError::ERROR)
            }
        }
    });

    Ok(builder)
}

/// Sentinel handed to `tokio_quiche` in place of on-disk certificate paths.
///
/// `tokio-quiche` only calls [`ConnectionHook::create_custom_ssl_context_builder`]
/// when `ConnectionParams::tls_cert` is `Some` — verified in 0.19.1 at
/// `settings/config.rs:122`, the `.zip(params.tls_cert)`. But the paths are
/// only ever *passed to* the hook: the sole reader is `quiche_config_with_tls`
/// (`settings/config.rs:224`), which is the `else` branch taken when the hook
/// returns `None`. A hook that returns `Some(builder)` means these strings are
/// never opened.
///
/// 🔐 That is what keeps private keys in the in-memory [`CertTable`] and off
/// the filesystem. Writing keys to temp files to satisfy the type would be a
/// regression, not a workaround.
pub const IN_MEMORY_CERT_SENTINEL: &str = "<pingclair:in-memory-cert-table>";

/// Serves certificates to `tokio_quiche` from an in-memory [`CertTable`].
pub struct CertTableSslHook {
    certs: Arc<CertTable>,
}

impl CertTableSslHook {
    pub fn new(certs: Arc<CertTable>) -> Self {
        Self { certs }
    }
}

impl tokio_quiche::quic::ConnectionHook for CertTableSslHook {
    fn create_custom_ssl_context_builder(
        &self,
        _settings: tokio_quiche::settings::TlsCertificatePaths<'_>,
    ) -> Option<boring::ssl::SslContextBuilder> {
        // The paths are deliberately ignored; see `IN_MEMORY_CERT_SENTINEL`.
        match build_ssl_context_builder(Arc::clone(&self.certs)) {
            Ok(builder) => Some(builder),
            Err(e) => {
                // Returning `None` makes tokio-quiche fall back to reading the
                // sentinel path, which cannot open — so the listener fails to
                // start rather than serving without our certificates.
                tracing::error!("🔐 H3: failed to build TLS context, listener will not start: {e}");
                None
            }
        }
    }
}

// MARK: - Request/response plumbing

/// One parsed HTTP/3 request, handed to a handler task.
struct H3Request {
    method: String,
    /// 🔌 Preserves extended CONNECT protocols so unsupported tunnels fail clearly.
    protocol: Option<String>,
    /// Path including the query string.
    path: String,
    /// `:authority` (or `host` header) value, may include a port.
    authority: String,
    /// Regular (non-pseudo) headers, lower-cased names.
    headers: Vec<(String, String)>,
}

/// Parse the pseudo-headers of an HTTP/3 request into an [`H3Request`].
fn parse_h3_request(list: &[quiche::h3::Header]) -> Option<H3Request> {
    let mut method = None;
    let mut protocol = None;
    let mut path = None;
    let mut authority = None;
    let mut headers = Vec::new();

    for h in list {
        let value = String::from_utf8_lossy(h.value()).into_owned();
        match h.name() {
            b":method" => method = Some(value),
            b":path" => path = Some(value),
            b":authority" => authority = Some(value),
            b":protocol" => protocol = Some(value),
            b":scheme" => {}
            name if name.starts_with(b":") => return None, // unknown pseudo-header
            name => headers.push((String::from_utf8_lossy(name).into_owned(), value)),
        }
    }

    if authority.is_none() {
        authority = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.clone());
    }

    Some(H3Request {
        method: method?,
        protocol,
        path: path?,
        authority: authority?,
        headers,
    })
}

/// Messages from handler tasks back to the event loop.
enum RespMsg {
    /// 📋 Carries response headers and whether they end the stream.
    Headers(Vec<quiche::h3::Header>, bool),
    /// 🌊 Carries one body chunk and whether it ends the stream.
    Body(Vec<u8>, bool),
    /// 🧾 Carries response trailers that end the stream.
    Trailers(Vec<quiche::h3::Header>),
    /// 🏁 Marks that the handler task finished and dropped its request-body
    /// receiver. Waking the worker on this ordered event lets a deferred
    /// drain observe the closed channel even when the client is blocked by
    /// QUIC flow control and sends no packets.
    HandlerDone,
}

/// One handler task's output, on this connection's own channel.
struct RespEvent {
    stream_id: u64,
    msg: RespMsg,
}

type RespSender = mpsc::Sender<RespEvent>;

/// 🌊 Per-stream cap on response bytes waiting to enter quiche.
///
/// Without a bound, a handler that produces a 1 MiB body hands the whole
/// body to quiche before the client acknowledges it; 2,000 concurrent
/// streams then hold ~2 GiB of QUIC send buffers (measured 1.63 GiB vs
/// nginx's 0.4 GiB on the same 100×20 workload). Two 64 KiB chunks per
/// stream bound the same workload near nginx's footprint while flow control
/// still paces the actual wire rate.
const BODY_QUEUE_CAP: usize = 128 * 1024;

// MARK: - Connection / stream state

/// Per-stream state owned by the event loop.
#[derive(Default)]
struct StreamState {
    /// 📤 Holds response headers until QUIC flow control accepts them.
    pending_headers: Option<(Vec<quiche::h3::Header>, bool)>,
    headers_sent: bool,
    /// 🌊 Holds response chunks that quiche has not accepted yet.
    ///
    /// Chunks keep the event loop from copying a 1 MiB body byte-by-byte
    /// through a `VecDeque<u8>` ring: the handler's `Vec<u8>` moves in, and
    /// `flush_stream` hands the front slice to quiche. `pending_body_head`
    /// tracks partial progress through the front chunk.
    pending_body: VecDeque<Vec<u8>>,
    /// 🌊 Total unconsumed bytes across all queued chunks.
    pending_body_bytes: usize,
    /// 🌊 Bytes already handed to quiche from the front chunk.
    pending_body_head: usize,
    /// 🧾 Holds response trailers until body bytes and QUIC capacity are ready.
    pending_trailers: Option<Vec<quiche::h3::Header>>,
    /// 🏁 Records that the handler signaled the end of the response body.
    body_fin: bool,
    /// 🏁 Records that the response FIN reached the QUIC stream.
    fin_sent: bool,
    /// 📥 Feeds bounded request-body chunks to the handler task.
    req_body_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// 🧹 Records that quiche reported the request stream as finished.
    req_stream_finished: bool,
    /// ⏳ Records that request-body draining is waiting for channel capacity.
    body_read_pending: bool,
    /// 🛑 Cancels the handler when the client or transport abandons the stream.
    cancel_tx: Option<watch::Sender<bool>>,
    /// 🚫 Prevents a rejected request from accepting late handler responses.
    handler_cancelled: bool,
    /// 🧹 Marks a terminated stream so later response messages are ignored.
    dead: bool,
}

/// 🚦 One connection's HTTP/3 layer, driven by tokio-quiche's worker loop.
///
/// The worker owns the socket, the `quiche::Connection`, pacing, timers,
/// address validation and connection-ID routing, and hands the connection in
/// as `qconn` on every callback — which is why this type holds no transport
/// state of its own. What stays here is what the worker has no opinion about:
/// the HTTP/3 connection, per-stream response assembly, and the channels back
/// from the handler tasks.
struct H3App {
    proxy: Arc<PingclairProxy>,
    connector: Arc<pingora_core::connectors::http::Connector>,
    h3_config: Arc<quiche::h3::Config>,
    h3: Option<quiche::h3::Connection>,
    remote_addr: SocketAddr,
    streams: HashMap<u64, StreamState>,
    resp_tx: RespSender,
    resp_rx: mpsc::Receiver<RespEvent>,
    /// 🧮 The channel head that did not fit its stream's body cap.
    ///
    /// Only this single event may be held back: everything behind it stays
    /// in the bounded `resp_rx`, whose capacity is the real backpressure —
    /// a handler whose stream is over [`BODY_QUEUE_CAP`] blocks on send
    /// instead of letting the worker buffer the whole body out of order.
    deferred: Option<RespEvent>,
    body_notify: Arc<Notify>,
    /// 🔢 Releases this connection's slot against `limits.max_connections`.
    _slot: ConnectionSlot,
    /// 📦 Lent to the worker for outbound packets; see `ApplicationOverQuic::buffer`.
    out: Vec<u8>,
}

impl Drop for H3App {
    fn drop(&mut self) {
        // 🛑 Cancels every handler before a closed QUIC connection releases its stream state.
        for stream in self.streams.values_mut() {
            cancel_stream_handler(stream);
        }
        // 🚀 Paired with the increment in `on_conn_established`. Decrementing
        // on drop rather than at an explicit close covers every way a
        // connection ends — idle timeout, client GOAWAY, worker panic — which
        // an explicit path would have to enumerate and would eventually miss,
        // leaving the gauge drifting upward forever.
        //
        // 📌 Guarded on `h3`, so a connection dropped before the handshake
        // completed does not decrement a count it never incremented.
        if self.h3.is_some() {
            crate::metrics::H3_CONNECTIONS.dec();
        }
    }
}

/// 🔢 Holds one connection's admission against `limits.max_connections`.
///
/// The count has to fall when the worker task ends, not when the accept loop
/// moves on, so this rides along inside [`H3App`] and releases on drop.
struct ConnectionSlot(Arc<AtomicUsize>);

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

impl tokio_quiche::ApplicationOverQuic for H3App {
    /// 🤝 Builds the HTTP/3 layer once TLS and the QUIC handshake are done.
    fn on_conn_established(
        &mut self,
        qconn: &mut tokio_quiche::quic::QuicheConnection,
        _handshake_info: &tokio_quiche::quic::HandshakeInfo,
    ) -> tokio_quiche::QuicResult<()> {
        self.h3 = Some(quiche::h3::Connection::with_transport(
            qconn,
            &self.h3_config,
        )?);
        // 🚀 Tracked here rather than at socket accept: a QUIC connection that
        // never completes its handshake is not one this server is serving, and
        // counting it would make the gauge drift upward on scanning traffic.
        crate::metrics::H3_CONNECTIONS.inc();
        Ok(())
    }

    fn should_act(&self) -> bool {
        true
    }

    fn buffer(&mut self) -> &mut [u8] {
        &mut self.out
    }

    /// ⏳ Waits for a handler task to produce output.
    ///
    /// The worker races this against inbound packets and the connection's
    /// timers, so it must only report events this layer originates: responses
    /// from handler tasks, and the notification that a handler freed
    /// request-body channel capacity.
    ///
    /// # Cancel safety
    /// `mpsc::Receiver::recv` and `Notify::notified` are both cancel safe, and
    /// an event taken from the channel is applied to `self` before this returns
    /// — so a cancelled future has either not yet dequeued, or fully applied.
    async fn wait_for_data(
        &mut self,
        _qconn: &mut tokio_quiche::quic::QuicheConnection,
    ) -> tokio_quiche::QuicResult<()> {
        // 🧲 Applies deferred or channel-head events first: a previous
        // iteration may have parked one while its stream was over the body
        // cap, and capacity may have opened since.
        if self.apply_available_events() {
            return Ok(());
        }
        // 🛑 A parked event means the channel head cannot be applied yet.
        // Receiving anything else would violate ordering, so wait for the
        // next worker iteration (an inbound packet) instead; `process_writes`
        // frees capacity and retries the parked event there.
        if self.deferred.is_some() {
            std::future::pending::<()>().await;
            return Ok(());
        }
        tokio::select! {
            event = self.resp_rx.recv() => {
                // 🧯 The sender is held by this app, so the channel outlives
                // every handler; `None` cannot mean "no more work".
                if let Some(event) = event {
                    if Self::event_fits(&self.streams, &event) {
                        self.apply_resp_event(event);
                    } else {
                        self.deferred = Some(event);
                    }
                }
            }
            _ = self.body_notify.notified() => {
                // A handler freed request-body channel capacity; the deferred
                // drains are retried in `process_reads`.
            }
        }
        // 🧲 Applies anything that queued behind the event that woke us.
        self.apply_available_events();
        Ok(())
    }

    /// 📥 Turns received packets into HTTP/3 work.
    fn process_reads(
        &mut self,
        qconn: &mut tokio_quiche::quic::QuicheConnection,
    ) -> tokio_quiche::QuicResult<()> {
        if self.h3.is_none() {
            return Ok(());
        }

        // 🔁 Retries drains that stopped on a full handler channel before
        // polling, so the Finished event that ends a request body is not
        // observed until its bytes have been handed over.
        self.retry_pending_body_drains(qconn);

        self.pump_h3_events(qconn);
        Ok(())
    }

    /// 📤 Hands quiche everything the handlers have produced.
    ///
    /// Called on every worker iteration, immediately before packets go to the
    /// socket, so this is the only place stream writes need to happen.
    fn process_writes(
        &mut self,
        qconn: &mut tokio_quiche::quic::QuicheConnection,
    ) -> tokio_quiche::QuicResult<()> {
        if self.h3.is_none() {
            return Ok(());
        }

        // 🧲 Retries deferred body drains on every worker iteration, not
        // only when a packet arrived: tokio-quiche calls `process_reads`
        // solely on inbound packets, while handler events resolve
        // `wait_for_data`. A client whose upload is blocked by flow control
        // stops sending, so without this the drain (and its WINDOW_UPDATE)
        // would wait for the next packet or PTO and hang the request.
        self.retry_pending_body_drains(qconn);

        // 🧮 Applies deferred events whose streams may have room again.
        self.apply_available_events();

        let dirty: Vec<u64> = self
            .streams
            .iter()
            .filter(|(_, s)| {
                !s.dead
                    && (s.pending_headers.is_some()
                        || s.pending_body_bytes > 0
                        || s.pending_trailers.is_some()
                        || (s.body_fin && !s.fin_sent))
            })
            .map(|(id, _)| *id)
            .collect();
        for stream_id in dirty {
            self.flush_stream(qconn, stream_id);
        }

        // 🌊 Flow control may have opened up on streams with nothing newly
        // queued, which is what lets a blocked large response resume.
        let writable: Vec<u64> = qconn.writable().collect();
        for stream_id in writable {
            self.flush_stream(qconn, stream_id);
        }

        // 🧮 Handing chunks to quiche frees per-stream capacity, so apply
        // deferred events again before the worker goes back to waiting.
        self.apply_available_events();

        self.streams.retain(|_, s| !s.dead);
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum TrailerRejection {
    ResponseQueued,
    ResetRequired,
}

/// 🛑 Signals structured cancellation without treating normal stream cleanup as an abort.
fn cancel_stream_handler(stream: &mut StreamState) {
    if let Some(cancel_tx) = stream.cancel_tx.as_ref() {
        let _ = cancel_tx.send(true);
    }
    stream.req_body_tx = None;
    stream.body_read_pending = false;
}

/// 🚫 Replaces an uncommitted handler response or requests a reset after commitment.
fn reject_request_trailers(stream: &mut StreamState) -> TrailerRejection {
    cancel_stream_handler(stream);
    stream.handler_cancelled = true;
    // 🚀 A client abandoning a stream is normal in small numbers; in large ones
    // it means responses are arriving too slowly to be worth waiting for, which
    // no other metric here would show.
    crate::metrics::H3_REQUESTS_TOTAL
        .with_label_values(&["cancelled"])
        .inc();
    stream.req_stream_finished = true;

    if stream.headers_sent {
        stream.dead = true;
        return TrailerRejection::ResetRequired;
    }

    let body = b"Request Trailers Not Supported";
    stream.pending_headers = Some((
        vec![
            quiche::h3::Header::new(b":status", b"501"),
            quiche::h3::Header::new(b"content-type", b"text/plain"),
            quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
            quiche::h3::Header::new(b"server", b"Pingclair"),
        ],
        false,
    ));
    stream.pending_body = VecDeque::from([body.to_vec()]);
    stream.pending_body_bytes = body.len();
    stream.body_fin = true;
    stream.fin_sent = false;
    stream.dead = false;
    TrailerRejection::ResponseQueued
}

// MARK: - Server

/// 🚀 HTTP/3 (QUIC) server for one listen port.
pub struct QuicServer {
    listen: SocketAddr,
    proxy: Arc<PingclairProxy>,
    certs: Arc<CertTable>,
    connector: Arc<pingora_core::connectors::http::Connector>,
    filter: PingclairConnectionFilter,
}

impl QuicServer {
    /// Create a new HTTP/3 server.
    ///
    /// - `listen`: UDP socket address (the HTTPS port).
    /// - `proxy`: shared routing logic (same object as the H1/H2 listener).
    /// - `certs`: SNI certificate table consulted by every new handshake.
    /// - `upstream_keepalive_pool_size`: Pingora upstream pool size, kept
    ///   consistent with the H1/H2 path.
    /// - `blocked_ips`: L4 blocklist, same semantics as the TCP listener's
    ///   connection filter.
    pub fn new(
        listen: SocketAddr,
        proxy: Arc<PingclairProxy>,
        certs: Arc<CertTable>,
        upstream_keepalive_pool_size: usize,
        blocked_ips: Vec<String>,
    ) -> Self {
        let options = pingora_core::connectors::ConnectorOptions::new(upstream_keepalive_pool_size);
        Self {
            listen,
            proxy,
            certs,
            connector: Arc::new(pingora_core::connectors::http::Connector::new(Some(
                options,
            ))),
            filter: PingclairConnectionFilter::new(&blocked_ips),
        }
    }

    /// Serve HTTP/3 on this listener until the task is aborted.
    ///
    /// tokio-quiche owns the UDP socket, packet parsing, version negotiation,
    /// address validation (stateless retry), connection-ID routing, pacing and
    /// per-connection timers. Everything this server still decides — who is
    /// allowed to connect, how many at once, and what HTTP/3 means — lives in
    /// the accept loop below and in [`H3App`].
    pub async fn run(self) -> Result<(), QuicError> {
        use futures::StreamExt;

        let limits = self.proxy.listener_limits();
        let transport_idle_ms = limits
            .long_connections
            .idle_timeout_ms
            .filter(|value| *value > 0)
            .or(limits.idle_timeout_ms)
            .unwrap_or(30_000);

        let mut h3_config = quiche::h3::Config::new().map_err(|e| QuicError::H3(e.to_string()))?;
        if let Some(max_header_bytes) = limits.max_header_bytes {
            h3_config.set_max_field_section_size(max_header_bytes as u64);
        }
        let h3_config = Arc::new(h3_config);

        // `QuicSettings` is `#[non_exhaustive]`, so these are assignments and
        // not a struct literal — which also keeps every value we deliberately
        // choose sitting next to the reason for it.
        let mut quic_settings = tokio_quiche::settings::QuicSettings::default();
        quic_settings.alpn = vec![quiche::h3::APPLICATION_PROTOCOL[0].to_vec()];
        quic_settings.max_idle_timeout = Some(Duration::from_millis(transport_idle_ms));
        quic_settings.max_recv_udp_payload_size = MAX_DATAGRAM_SIZE;
        quic_settings.max_send_udp_payload_size = MAX_DATAGRAM_SIZE;
        // ⚡ Acknowledges every inbound packet immediately. The 25 ms default
        // delayed-ACK batches replies, which is fine for downloads but makes
        // an upload the server keeps draining (for example an oversized body
        // answered with 413) trickle at one packet per 25 ms round trip —
        // nginx drains the same body at full speed.
        quic_settings.max_ack_delay = 0;
        quic_settings.initial_max_data = 10_000_000;
        quic_settings.initial_max_stream_data_bidi_local = 1_000_000;
        quic_settings.initial_max_stream_data_bidi_remote = 1_000_000;
        quic_settings.initial_max_stream_data_uni = 1_000_000;
        quic_settings.initial_max_streams_bidi = 100;
        quic_settings.initial_max_streams_uni = 100;
        quic_settings.disable_active_migration = true;
        // 🚀 Accept a valid Initial without adding a mandatory stateless Retry
        // round trip. nginx and Caddy use the same default latency tradeoff,
        // while QUIC's pre-validation amplification limit still bounds bytes
        // sent to a spoofed address. Deployment connection limits remain
        // independent of this transport address-validation policy.
        quic_settings.disable_client_ip_validation = true;
        // 🛡️ Two 2^16-entry DATAGRAM queues per connection buy nothing without
        // MASQUE or WebTransport, and quiche turns them on by default — so this
        // must be set, not left alone.
        quic_settings.enable_dgram = false;
        // 🛡️ Keeps 0-RTT disabled until replay-safe route and method policies
        // are explicit.
        quic_settings.enable_early_data = false;

        let socket = UdpSocket::bind(self.listen).await?;
        let local_addr = socket.local_addr()?;

        let hooks = tokio_quiche::settings::Hooks {
            // 🔐 Certificates come from the in-memory table, never from disk;
            // see `IN_MEMORY_CERT_SENTINEL`.
            connection_hook: Some(Arc::new(CertTableSslHook::new(self.certs.clone()))),
        };

        let mut listeners = tokio_quiche::listen(
            [socket],
            tokio_quiche::ConnectionParams::new_server(
                quic_settings,
                tokio_quiche::settings::TlsCertificatePaths {
                    cert: IN_MEMORY_CERT_SENTINEL,
                    private_key: IN_MEMORY_CERT_SENTINEL,
                    kind: tokio_quiche::settings::CertificateKind::X509,
                },
                hooks,
            ),
            tokio_quiche::metrics::DefaultMetrics,
        )?;

        tracing::info!(
            "🚀 HTTP/3 (tokio-quiche) server listening on {} (UDP)",
            local_addr
        );

        let live_connections = Arc::new(AtomicUsize::new(0));
        let mut incoming = listeners.remove(0);

        while let Some(connection) = incoming.next().await {
            let connection = match connection {
                Ok(connection) => connection,
                // 🧯 A failed QUIC initial is one client's problem, not the
                // listener's; the stream keeps producing after this.
                Err(e) => {
                    tracing::debug!("H3: dropping an inbound connection: {}", e);
                    continue;
                }
            };

            let remote_addr = connection.peer_addr();

            // 🚫 L4 blocklist, same semantics and same list as the TCP
            // listener's connection filter. The handshake has already begun by
            // the time we see this, so dropping the connection here refuses
            // service rather than refusing the packet.
            if !self.filter.allows(&remote_addr) {
                continue;
            }

            // 🔢 Only this loop increments, so a load-then-add cannot race
            // itself; drops of `ConnectionSlot` are the only decrements.
            if let Some(limit) = self.proxy.listener_limits().max_connections
                && live_connections.load(Ordering::Acquire) >= limit
            {
                tracing::warn!("🚫 Rejecting an HTTP/3 connection at the configured limit");
                continue;
            }
            live_connections.fetch_add(1, Ordering::AcqRel);

            let (resp_tx, resp_rx) = mpsc::channel::<RespEvent>(RESP_CHANNEL_CAPACITY);
            connection.start(H3App {
                proxy: self.proxy.clone(),
                connector: self.connector.clone(),
                h3_config: Arc::clone(&h3_config),
                h3: None,
                remote_addr,
                streams: HashMap::with_capacity(32),
                resp_tx,
                resp_rx,
                deferred: None,
                body_notify: Arc::new(Notify::new()),
                _slot: ConnectionSlot(Arc::clone(&live_connections)),
                out: vec![0u8; OUT_BUF_SIZE],
            });
        }

        Ok(())
    }
}

/// 🧯 Drops a request-body channel whose handler task has ended.
///
/// A handler that finished early (for example the 413 answer for an
/// oversized body) may leave its channel full and its receiver dropped.
/// A full channel alone would defer the drain forever — nobody can free
/// capacity once the receiver is gone — so the drain loop clears the
/// channel and discards the remaining bytes to keep QUIC flow control
/// moving. Returns true when the channel was cleared.
fn drop_closed_handler_channel(tx: &mut Option<mpsc::Sender<Vec<u8>>>) -> bool {
    if tx.as_ref().is_some_and(|sender| sender.is_closed()) {
        *tx = None;
        true
    } else {
        false
    }
}

/// 🔁 Returns the stream ids whose request-body drains are deferred.
fn pending_body_drain_ids(streams: &HashMap<u64, StreamState>) -> Vec<u64> {
    streams
        .iter()
        .filter(|(_, s)| s.body_read_pending)
        .map(|(id, _)| *id)
        .collect()
}

impl H3App {
    /// Pump queued HTTP/3 events until quiche reports `Error::Done`.
    ///
    /// Must be called after every `conn.recv` AND from the event loop's
    /// maintenance pass: `h3::Connection::recv_body` queues the `Finished`
    /// event internally once the final body bytes are consumed, so a drain
    /// triggered by the maintenance pass (request-body backpressure retry)
    /// can produce events even when no new packet arrived. Without the
    /// maintenance-pass pump a large request body would deadlock: the
    /// handler waits for end-of-body that never gets signaled.
    fn pump_h3_events(&mut self, qconn: &mut tokio_quiche::quic::QuicheConnection) {
        loop {
            let poll_result = {
                let h3 = self.h3.as_mut().expect("checked by the caller");
                h3.poll(qconn)
            };

            match poll_result {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    self.handle_h3_headers(qconn, stream_id, list);
                }
                Ok((stream_id, quiche::h3::Event::Data)) => {
                    self.drain_request_body(qconn, stream_id);
                }
                Ok((stream_id, quiche::h3::Event::Finished)) => {
                    // 🧹 Drains buffered bytes before closing the handler's request channel.
                    if let Some(ss) = self.streams.get_mut(&stream_id) {
                        ss.req_stream_finished = true;
                    }
                    self.drain_request_body(qconn, stream_id);
                }
                Ok((stream_id, quiche::h3::Event::Reset(_))) => {
                    if let Some(ss) = self.streams.get_mut(&stream_id) {
                        cancel_stream_handler(ss);
                        ss.dead = true;
                    }
                }
                Ok((_, quiche::h3::Event::PriorityUpdate)) => (),
                Ok((_, quiche::h3::Event::GoAway)) => (),
                Err(quiche::h3::Error::Done) => break,
                Err(e) => {
                    tracing::error!("{} HTTP/3 error {:?}", qconn.trace_id(), e);
                    break;
                }
            }
        }
    }

    /// Handle a request HEADERS event: parse the request, register stream
    /// state, and spawn the handler task.
    fn handle_h3_headers(
        &mut self,
        qconn: &mut tokio_quiche::quic::QuicheConnection,
        stream_id: u64,
        list: Vec<quiche::h3::Header>,
    ) {
        // 🧭 Accepts requests only on client-initiated bidirectional streams.
        if !stream_id.is_multiple_of(4) {
            return;
        }

        // 🚫 Rejects request trailers explicitly because upstream forwarding is unsupported.
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            tracing::debug!(
                "🚫 H3 request trailers are unsupported on stream {}; rejecting request",
                stream_id
            );
            match reject_request_trailers(stream) {
                TrailerRejection::ResponseQueued => self.flush_stream(qconn, stream_id),
                TrailerRejection::ResetRequired => {
                    let _ = qconn.stream_shutdown(
                        stream_id,
                        quiche::Shutdown::Write,
                        quiche::h3::WireErrorCode::RequestCancelled as u64,
                    );
                }
            }
            return;
        }

        let Some(req) = parse_h3_request(&list) else {
            self.queue_simple_response(qconn, stream_id, 400, "Bad Request");
            return;
        };

        // 🛡️ HTTP/3 carries its own framing, so `Transfer-Encoding` is forbidden
        // outright here rather than merely discouraged, and `Content-Length`
        // still has to be `1*DIGIT`. Same rule set as H1/H2, one implementation
        // — validated over the raw header list so the request is not parsed
        // into a throwaway `HeaderMap` before the handler needs it.
        if let Err(rejection) = crate::http_policy::check_h3_request_framing(&req.headers) {
            tracing::warn!(
                "🚫 H3: rejected a request with untrustworthy message framing: {}",
                rejection.reason()
            );
            self.queue_simple_response(qconn, stream_id, 400, rejection.reason());
            return;
        }

        // 🧭 Same resolution as H1/H2, from the same function, so the two
        // transports cannot drift on which resource a path names.
        let mut req = req;
        if let Some(normalized) = crate::http_policy::normalize_request_path(&req.path) {
            tracing::debug!("🧭 H3: normalized request path to {}", normalized);
            req.path = normalized;
        }

        let (req_body_tx, req_body_rx) = mpsc::channel::<Vec<u8>>(REQ_BODY_CHANNEL_CAPACITY);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        self.streams.insert(
            stream_id,
            StreamState {
                req_body_tx: Some(req_body_tx),
                cancel_tx: Some(cancel_tx),
                ..Default::default()
            },
        );

        let proxy = self.proxy.clone();
        let connector = self.connector.clone();
        let resp_tx = self.resp_tx.clone();
        let done_tx = resp_tx.clone();
        let notify = Arc::clone(&self.body_notify);
        // 🛡️ Same canonicalisation the H1/H2 path applies: a QUIC socket bound
        // dual-stack reports an IPv4 client as `::ffff:…`, and an IPv4 CIDR does
        // not contain an IPv6 address. Parity matters here specifically because
        // `remote_ip` is an access-control matcher — a rule that holds on
        // HTTP/1.1 and not on HTTP/3 is worse than one that fails everywhere.
        let remote_ip = crate::server::canonical_client_ip(self.remote_addr.ip());

        tokio::spawn(async move {
            handle_request(
                proxy,
                connector,
                req,
                remote_ip,
                stream_id,
                req_body_rx,
                resp_tx,
                notify,
                cancel_rx,
            )
            .await;
            // 🧲 The request-body receiver is dropped here. Queue an ordered
            // completion event so the worker wakes up even when no packet
            // arrives — a client blocked by QUIC flow control sends nothing
            // — and a deferred drain can observe the closed channel. A
            // bare `Notify` would be lost when the worker is between
            // wakeups, which is exactly the race that hung 413 uploads.
            let _ = done_tx
                .send(RespEvent {
                    stream_id,
                    msg: RespMsg::HandlerDone,
                })
                .await;
        });
    }

    /// 🚫 Queues a plain-text response without spawning a handler task.
    fn queue_simple_response(
        &mut self,
        qconn: &mut tokio_quiche::quic::QuicheConnection,
        stream_id: u64,
        status: u16,
        body: &str,
    ) {
        let headers = vec![
            quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
            quiche::h3::Header::new(b"content-type", b"text/plain"),
            quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
            quiche::h3::Header::new(b"server", b"Pingclair"),
        ];
        self.streams.insert(
            stream_id,
            StreamState {
                pending_headers: Some((headers, false)),
                pending_body: VecDeque::from([body.as_bytes().to_vec()]),
                pending_body_bytes: body.len(),
                body_fin: true,
                ..Default::default()
            },
        );
        self.flush_stream(qconn, stream_id);
    }

    /// Drain request-body bytes out of quiche into the handler's channel.
    ///
    /// When the channel is full we stop draining and let QUIC flow control
    /// push back on the client; the drain is retried from the maintenance
    /// pass once the handler frees capacity.
    fn drain_request_body(
        &mut self,
        qconn: &mut tokio_quiche::quic::QuicheConnection,
        stream_id: u64,
    ) {
        let Self { h3, streams, .. } = self;
        let conn = qconn;
        let Some(h3) = h3.as_mut() else { return };
        let Some(ss) = streams.get_mut(&stream_id) else {
            return;
        };

        ss.body_read_pending = false;
        let mut tmp = [0u8; BODY_CHUNK_SIZE];

        loop {
            drop_closed_handler_channel(&mut ss.req_body_tx);

            if let Some(tx) = &ss.req_body_tx
                && tx.capacity() == 0
            {
                // Channel full: retry from the maintenance pass once the
                // handler frees capacity. QUIC flow control pushes back
                // on the client in the meantime.
                ss.body_read_pending = true;
                return;
            }

            match h3.recv_body(conn, stream_id, &mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    if let Some(tx) = &ss.req_body_tx {
                        // Capacity was checked above and this task is the
                        // only sender, so try_send can only fail if the
                        // handler is gone.
                        if tx.try_send(tmp[..n].to_vec()).is_err() {
                            ss.req_body_tx = None;
                        }
                    }
                    // No handler channel (e.g. Respond/FileServer handler
                    // that ignores bodies): discard the bytes to keep flow
                    // control moving.
                }
                Err(quiche::h3::Error::Done) => break,
                Err(e) => {
                    tracing::debug!("H3: recv_body failed on stream {}: {:?}", stream_id, e);
                    break;
                }
            }
        }

        // 🧹 Closes the request channel only after every received body byte is drained.
        if ss.req_stream_finished {
            ss.req_body_tx = None;
            if ss.fin_sent {
                ss.dead = true;
            }
        }
    }

    /// 🔁 Resumes every request-body drain that stopped on a full or closed
    /// handler channel.
    ///
    /// Shared by [`Self::process_reads`] (packet wakeups) and
    /// [`Self::process_writes`] (event wakeups) so the retry cannot depend
    /// on the client sending more data — which a flow-control-blocked
    /// upload will not do.
    fn retry_pending_body_drains(&mut self, qconn: &mut tokio_quiche::quic::QuicheConnection) {
        let pending_reads = pending_body_drain_ids(&self.streams);
        for stream_id in pending_reads {
            self.drain_request_body(qconn, stream_id);
        }
    }

    /// Apply one response message from a handler task and try to flush it.
    ///
    /// The write itself waits for `process_writes`, which the worker calls on
    /// every iteration right before it drains packets to the socket.
    fn apply_resp_event(&mut self, ev: RespEvent) {
        {
            let Some(ss) = self.streams.get_mut(&ev.stream_id) else {
                return;
            };
            if ss.dead || ss.handler_cancelled {
                return;
            }
            match ev.msg {
                RespMsg::Headers(headers, fin) => {
                    if ss.headers_sent {
                        return;
                    }
                    ss.pending_headers = Some((headers, fin));
                }
                RespMsg::Body(bytes, fin) => {
                    ss.pending_body_bytes += bytes.len();
                    ss.pending_body.push_back(bytes);
                    if fin {
                        ss.body_fin = true;
                    }
                }
                RespMsg::Trailers(headers) => {
                    ss.pending_trailers = Some(headers);
                }
                RespMsg::HandlerDone => {}
            }
        }
    }

    /// 🧮 Applies handler events up to each stream's body cap.
    ///
    /// Events stay FIFO: the loop stops at the first event whose stream is
    /// over [`BODY_QUEUE_CAP`] (that event becomes `deferred` and everything
    /// behind it stays in the bounded channel), so a later event never
    /// overtakes an earlier one. Returns whether anything was applied, which
    /// the caller uses to avoid sleeping while work is still possible.
    fn apply_available_events(&mut self) -> bool {
        let mut applied = false;
        while let Some(event) = self.take_appliable_event() {
            self.apply_resp_event(event);
            applied = true;
        }
        applied
    }

    /// 🧮 Returns the next response event that can be applied right now.
    ///
    /// The deferred slot is consulted first; when it is empty, exactly one
    /// event is pulled from the channel and either returned or parked in the
    /// slot. Later events stay in the channel, so the channel's bounded
    /// capacity (not an unbounded worker buffer) applies backpressure.
    fn take_appliable_event(&mut self) -> Option<RespEvent> {
        if let Some(event) = self.deferred.take() {
            if Self::event_fits(&self.streams, &event) {
                return Some(event);
            }
            self.deferred = Some(event);
            return None;
        }
        let event = self.resp_rx.try_recv().ok()?;
        if Self::event_fits(&self.streams, &event) {
            Some(event)
        } else {
            self.deferred = Some(event);
            None
        }
    }

    /// 🧮 Whether a response event fits its stream's body-queue cap.
    fn event_fits(streams: &HashMap<u64, StreamState>, event: &RespEvent) -> bool {
        match &event.msg {
            RespMsg::Body(bytes, _) => Self::body_event_fits(streams, event.stream_id, bytes.len()),
            _ => true,
        }
    }

    /// 🧮 Whether a response chunk fits the stream's body-queue cap.
    fn body_event_fits(streams: &HashMap<u64, StreamState>, stream_id: u64, bytes: usize) -> bool {
        streams.get(&stream_id).is_none_or(|ss| {
            // 🌊 An empty queue accepts any single chunk (a handler may
            // legitimately produce one 512 KiB body event); the cap only
            // gates appending more while bytes are already queued.
            ss.pending_body_bytes == 0
                || ss.pending_body_bytes.saturating_add(bytes) <= BODY_QUEUE_CAP
        })
    }

    /// Write as much of a stream's pending response as quiche currently
    /// accepts. Body bytes are always sent with `fin = false`; once the
    /// queue drains and the handler signaled end-of-body, a final empty
    /// `fin = true` write terminates the stream. Retried from the
    /// maintenance pass / writable events whenever flow control opens up.
    fn flush_stream(&mut self, qconn: &mut tokio_quiche::quic::QuicheConnection, stream_id: u64) {
        let Self { h3, streams, .. } = self;
        let conn = qconn;
        let Some(h3) = h3.as_mut() else { return };
        let Some(ss) = streams.get_mut(&stream_id) else {
            return;
        };
        if ss.dead {
            return;
        }

        if !ss.headers_sent {
            let Some((headers, fin)) = ss.pending_headers.take() else {
                return;
            };
            // 🛑 An error response ends the exchange while the client may
            // still be uploading. Tell it to stop sending with H3_NO_ERROR —
            // ngtcp2/curl treat a `RequestRejected` STOP_SENDING as a
            // transport failure (exit 56), while `NoError` lets it conclude
            // the aborted upload cleanly, matching nginx's behavior.
            let is_error_response = headers.iter().any(|header| {
                header.name() == b":status"
                    && (header.value().starts_with(b"4") || header.value().starts_with(b"5"))
            });
            if is_error_response && !ss.req_stream_finished {
                let _ = conn.stream_shutdown(
                    stream_id,
                    quiche::Shutdown::Read,
                    quiche::h3::WireErrorCode::NoError as u64,
                );
            }
            match h3.send_response(conn, stream_id, &headers, fin) {
                Ok(()) => {
                    ss.headers_sent = true;
                    if fin {
                        ss.fin_sent = true;
                    }
                }
                Err(quiche::h3::Error::StreamBlocked) => {
                    ss.pending_headers = Some((headers, fin));
                    return;
                }
                Err(e) => {
                    tracing::debug!(
                        "📤 H3 response headers failed on stream {}: {:?}",
                        stream_id,
                        e
                    );
                    cancel_stream_handler(ss);
                    ss.dead = true;
                    return;
                }
            }
        }

        while ss.pending_body_bytes > 0 {
            let chunk_len = ss.pending_body.front().map_or(0, Vec::len);
            let head = ss.pending_body_head;
            let sent = {
                let Some(chunk) = ss.pending_body.front() else {
                    break;
                };
                h3.send_body(conn, stream_id, &chunk[head..], false)
            };
            match sent {
                Ok(0) => break,
                Ok(n) => {
                    ss.pending_body_bytes -= n;
                    ss.pending_body_head += n;
                    if ss.pending_body_head == chunk_len {
                        ss.pending_body.pop_front();
                        ss.pending_body_head = 0;
                    }
                }
                Err(quiche::h3::Error::Done) => break,
                Err(e) => {
                    tracing::debug!(
                        "🌊 H3 response body failed on stream {}: {:?}",
                        stream_id,
                        e
                    );
                    cancel_stream_handler(ss);
                    ss.dead = true;
                    return;
                }
            }
        }

        if ss.pending_body_bytes == 0
            && !ss.fin_sent
            && let Some(trailers) = ss.pending_trailers.take()
        {
            match h3.send_additional_headers(conn, stream_id, &trailers, true, true) {
                Ok(()) => ss.fin_sent = true,
                Err(quiche::h3::Error::StreamBlocked) => {
                    ss.pending_trailers = Some(trailers);
                    return;
                }
                Err(e) => {
                    tracing::debug!(
                        "🧾 H3 response trailers failed on stream {}: {:?}",
                        stream_id,
                        e
                    );
                    cancel_stream_handler(ss);
                    ss.dead = true;
                    return;
                }
            }
        }

        if ss.body_fin && ss.pending_body_bytes == 0 && !ss.fin_sent {
            match h3.send_body(conn, stream_id, b"", true) {
                Ok(_) => ss.fin_sent = true,
                Err(quiche::h3::Error::Done) => {}
                Err(e) => {
                    tracing::debug!("🏁 H3 response FIN failed on stream {}: {:?}", stream_id, e);
                    cancel_stream_handler(ss);
                    ss.dead = true;
                    return;
                }
            }
        }

        // 🌊 Keeps early-response streams alive until the request body is fully drained.
        if ss.fin_sent && ss.req_stream_finished {
            ss.dead = true;
        }
    }
}

// MARK: - Handler task

/// 🧭 Represents the next transport-neutral action produced by middleware.
enum H3Plan {
    Continue,
    Terminal(H3Terminal),
    Respond(H3ImmediateResponse),
}

/// 🎯 Retains only transport-relevant data after middleware planning completes.
enum H3Terminal {
    Respond {
        status: u16,
        body: Option<String>,
        headers: BTreeMap<String, String>,
    },
    Redirect {
        to: String,
        code: u16,
    },
    Templates {
        root: Option<String>,
    },
    FileServer,
    ReverseProxy,
}

/// ✉️ Describes a local response without coupling policy to a QUIC stream.
struct H3ImmediateResponse {
    status: u16,
    body: String,
    headers: Vec<(String, String)>,
}

/// 🎯 Evaluates one H3 pipeline element's precompiled matcher.
fn h3_element_matcher_matches(
    element_precompile: Option<&MatcherPrecompile>,
    request_header: &RequestHeader,
    effective_uri: &str,
    verified_client_ip: &str,
    request_vars: &mut crate::http_policy::RequestVars,
) -> bool {
    let Some(compiled) = element_precompile.and_then(|node| node.element_matcher.as_ref()) else {
        return true;
    };
    let host = request_header
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(authority_host)
        .unwrap_or("");
    let mut request = MatcherRequest {
        path: effective_uri,
        method: request_header.method.as_str(),
        headers: &request_header.headers,
        host,
        remote_ip: verified_client_ip,
        protocol: "https",
        vars: Some(request_vars.values_mut()),
    };
    evaluate(compiled, &mut request)
}

/// 🧩 Executes non-terminal middleware before selecting an H3 terminal handler.
#[async_recursion::async_recursion]
#[allow(clippy::too_many_arguments)]
async fn plan_h3_handler(
    handler: &HandlerConfig,
    state: &ProxyState,
    route_index: usize,
    request_header: &mut RequestHeader,
    effective_uri: &mut String,
    response_policy: &mut ResponseHeaderPolicy,
    verified_client_ip: &str,
    precompile: Option<&MatcherPrecompile>,
    handling_error: bool,
    request_vars: &mut crate::http_policy::RequestVars,
) -> Result<H3Plan, HandlerError> {
    match handler {
        HandlerConfig::Pipeline { handlers } => {
            let has_proxy = handlers
                .iter()
                .any(|element| crate::server::contains_reverse_proxy(&element.handler));
            for (index, element) in handlers.iter().enumerate() {
                let handler = &element.handler;
                let element_precompile = precompile.and_then(|node| node.children.get(index));
                if !h3_element_matcher_matches(
                    element_precompile,
                    request_header,
                    effective_uri,
                    verified_client_ip,
                    request_vars,
                ) {
                    continue;
                }
                if has_proxy && matches!(handler, HandlerConfig::FileServer { .. }) {
                    continue;
                }
                match plan_h3_handler(
                    handler,
                    state,
                    route_index,
                    request_header,
                    effective_uri,
                    response_policy,
                    verified_client_ip,
                    element_precompile,
                    handling_error,
                    request_vars,
                )
                .await?
                {
                    H3Plan::Continue => {}
                    completed => return Ok(completed),
                }
            }
            Ok(H3Plan::Continue)
        }
        HandlerConfig::Handle { handlers } => {
            let has_proxy = handlers
                .iter()
                .any(|element| crate::server::contains_reverse_proxy(&element.handler));
            for (index, element) in handlers.iter().enumerate() {
                let element_precompile = precompile.and_then(|node| node.children.get(index));
                if !h3_element_matcher_matches(
                    element_precompile,
                    request_header,
                    effective_uri,
                    verified_client_ip,
                    request_vars,
                ) {
                    continue;
                }
                if has_proxy && matches!(&element.handler, HandlerConfig::FileServer { .. }) {
                    continue;
                }
                // 🧭 A `handle` group is mutually exclusive: the first
                // matching element owns the request.
                return plan_h3_handler(
                    &element.handler,
                    state,
                    route_index,
                    request_header,
                    effective_uri,
                    response_policy,
                    verified_client_ip,
                    element_precompile,
                    handling_error,
                    request_vars,
                )
                .await;
            }
            Ok(H3Plan::Continue)
        }
        HandlerConfig::HandlePath { prefix, handlers } => {
            if effective_uri
                .split_once('?')
                .map_or(effective_uri.as_str(), |(path, _)| path)
                .starts_with(prefix.as_str())
            {
                *effective_uri =
                    rewrite_uri(effective_uri, Some(prefix.as_str()), None, None, None, None);
                request_header
                    .set_raw_path(effective_uri.as_bytes())
                    .map_err(|_| (500, "Rewrite Failed"))?;
            }
            let has_proxy = handlers
                .iter()
                .any(|element| crate::server::contains_reverse_proxy(&element.handler));
            for (index, element) in handlers.iter().enumerate() {
                let element_precompile = precompile.and_then(|node| node.children.get(index));
                if !h3_element_matcher_matches(
                    element_precompile,
                    request_header,
                    effective_uri,
                    verified_client_ip,
                    request_vars,
                ) {
                    continue;
                }
                if has_proxy && matches!(&element.handler, HandlerConfig::FileServer { .. }) {
                    continue;
                }
                // 🧭 `handle_path` is a `handle` under another name: the
                // first matching element owns the group.
                return plan_h3_handler(
                    &element.handler,
                    state,
                    route_index,
                    request_header,
                    effective_uri,
                    response_policy,
                    verified_client_ip,
                    element_precompile,
                    handling_error,
                    request_vars,
                )
                .await;
            }
            Ok(H3Plan::Continue)
        }
        HandlerConfig::Headers { set, add, remove } => {
            for (name, value) in set {
                response_policy.set(name, value.clone());
            }
            for (name, value) in add {
                response_policy.add(name, value.clone());
            }
            for name in remove {
                response_policy.remove(name);
            }
            Ok(H3Plan::Continue)
        }
        HandlerConfig::LogSkip => Ok(H3Plan::Continue),
        HandlerConfig::Intercept { .. } => Ok(H3Plan::Continue),
        HandlerConfig::CopyResponse { .. } | HandlerConfig::CopyResponseHeaders { .. } => {
            Ok(H3Plan::Continue)
        }
        // 🔐 `forward_auth` needs an inline upstream round trip that the H3
        // planner does not implement yet; refusing beats silently skipping
        // authentication (tracked in TRIAGE).
        HandlerConfig::ForwardAuth(_) => Ok(H3Plan::Respond(H3ImmediateResponse {
            status: 501,
            body: "forward_auth is not available on HTTP/3 yet".to_string(),
            headers: Vec::new(),
        })),
        HandlerConfig::Vars { values } => {
            // 🧰 Values are templates resolved against the same request, so
            // a value may reference placeholders and earlier vars.
            for (name, template) in values {
                let resolved = resolve_caddy_placeholders(
                    template,
                    request_header,
                    Some(verified_client_ip),
                    "https",
                    request_vars,
                );
                request_vars.set(name.clone(), resolved.into_owned());
            }
            Ok(H3Plan::Continue)
        }
        HandlerConfig::Rewrite {
            strip_prefix,
            strip_suffix,
            replace,
            regex,
            regex_replace,
        } => {
            *effective_uri = state
                .rewrite_request_uri(
                    route_index,
                    effective_uri,
                    strip_prefix.as_deref(),
                    strip_suffix.as_deref(),
                    replace.as_deref(),
                    regex.as_deref(),
                    regex_replace.as_deref(),
                )
                .map_err(|_| (500, "Rewrite Failed"))?;
            request_header
                .set_raw_path(effective_uri.as_bytes())
                .map_err(|_| (500, "Rewrite Failed"))?;
            Ok(H3Plan::Continue)
        }
        HandlerConfig::Cors {
            allowed_origins,
            allowed_methods,
            allowed_headers,
            exposed_headers,
            allow_credentials,
            max_age,
        } => match evaluate_cors(
            &request_header.method,
            &request_header.headers,
            allowed_origins,
            allowed_methods,
            allowed_headers,
            exposed_headers,
            *allow_credentials,
            *max_age,
        ) {
            CorsDecision::PassThrough => Ok(H3Plan::Continue),
            CorsDecision::Continue(policy) => {
                response_policy.merge(policy);
                Ok(H3Plan::Continue)
            }
            CorsDecision::Respond {
                status,
                body,
                headers,
            } => {
                response_policy.merge(headers);
                Ok(H3Plan::Respond(H3ImmediateResponse {
                    status,
                    body: body.to_string(),
                    headers: Vec::new(),
                }))
            }
        },
        HandlerConfig::BasicAuth { realm, credentials } => {
            if pingclair_core::server::verify_basic_auth_async(&request_header.headers, credentials)
                .await
            {
                Ok(H3Plan::Continue)
            } else {
                Ok(H3Plan::Respond(H3ImmediateResponse {
                    status: 401,
                    body: "Unauthorized".to_string(),
                    headers: vec![(
                        "www-authenticate".to_string(),
                        pingclair_core::server::basic_auth_challenge(realm),
                    )],
                }))
            }
        }
        HandlerConfig::AccessControl(_)
        | HandlerConfig::RateLimit { .. }
        | HandlerConfig::HandleErrors { .. } => Ok(H3Plan::Continue),
        HandlerConfig::Respond {
            status,
            body,
            headers,
        } => {
            // 🏷️ The body is a template exactly as it is for H1/H2: `respond
            // "hello {host}"` expands placeholders from the same request.
            // Until 2026-08-07 HTTP/3 wrote the raw text while H1/H2
            // resolved it, so a site served `path={path}` over HTTP/3 and
            // the value over HTTP/1 and HTTP/2.
            let body = body.as_deref().map(|raw| {
                let verified = raw.contains('{').then_some(verified_client_ip);
                resolve_caddy_placeholders(raw, request_header, verified, "https", request_vars)
                    .into_owned()
            });
            Ok(H3Plan::Terminal(H3Terminal::Respond {
                status: *status,
                body,
                headers: headers.clone(),
            }))
        }
        // 🚨 A static error answers with its status and message on HTTP/3
        // exactly as on H1/H2 — same default body, same placeholder rules —
        // but only after the matching error routes have had their say.
        HandlerConfig::Error { status, message } => {
            let raw = message.as_deref().unwrap_or_else(|| {
                http::StatusCode::from_u16(*status)
                    .ok()
                    .and_then(|code| code.canonical_reason())
                    .unwrap_or("")
            });
            let verified = raw.contains('{').then_some(verified_client_ip);
            let body = Some(
                resolve_caddy_placeholders(raw, request_header, verified, "https", request_vars)
                    .into_owned(),
            );
            // 🚫 Inside an error route a second raise responds directly —
            // routing it again is the infinite recursion this guard stops.
            if !handling_error {
                for (index, route) in state.config.error_routes.iter().enumerate() {
                    if !route.matches(*status) {
                        continue;
                    }
                    let precompile = state.compiled_error_route(index);
                    let handlers = HandlerConfig::Pipeline {
                        handlers: route.handlers.clone(),
                    };
                    let plan = plan_h3_handler(
                        &handlers,
                        state,
                        route_index,
                        request_header,
                        effective_uri,
                        response_policy,
                        verified_client_ip,
                        precompile,
                        true,
                        request_vars,
                    )
                    .await?;
                    return Ok(match plan {
                        H3Plan::Continue => H3Plan::Terminal(H3Terminal::Respond {
                            status: *status,
                            body: body.clone(),
                            headers: BTreeMap::new(),
                        }),
                        completed => completed,
                    });
                }
            }
            Ok(H3Plan::Terminal(H3Terminal::Respond {
                status: *status,
                body,
                headers: BTreeMap::new(),
            }))
        }
        // 🧭 Resolved here rather than at send time so H3 and H1/H2 expand the
        // same templates from the same request; a redirect that only works on
        // one transport is the parity gap this crate keeps having to fix.
        HandlerConfig::Redirect { to, code } => Ok(H3Plan::Terminal(H3Terminal::Redirect {
            // 🚀 An HTTP/3 request always arrived over TLS, so the scheme is a
            // constant here rather than something to thread through.
            to: resolve_caddy_placeholders(
                to,
                request_header,
                Some(verified_client_ip),
                "https",
                request_vars,
            )
            .into_owned(),
            code: *code,
        })),
        HandlerConfig::Templates { root } => {
            // 🧭 Only files that actually contain template syntax are
            // intercepted; everything else falls through to FileServer.
            let root = root.clone().unwrap_or_else(|| ".".to_string());
            let relative = effective_uri
                .split('?')
                .next()
                .unwrap_or("/")
                .trim_start_matches('/');
            if relative.split('/').any(|segment| segment == "..") {
                return Ok(H3Plan::Continue);
            }
            let mut file_path = std::path::Path::new(&root).join(relative);
            if file_path.is_dir() {
                file_path = file_path.join("index.html");
            }
            let is_template = std::fs::read_to_string(&file_path)
                .map(|source| source.contains("{{"))
                .unwrap_or(false);
            if is_template {
                Ok(H3Plan::Terminal(H3Terminal::Templates { root: Some(root) }))
            } else {
                Ok(H3Plan::Continue)
            }
        }
        HandlerConfig::FileServer { .. } => Ok(H3Plan::Terminal(H3Terminal::FileServer)),
        HandlerConfig::ReverseProxy(_) => Ok(H3Plan::Terminal(H3Terminal::ReverseProxy)),
        // 🗂️ Parity with H1/H2 comes from sharing the resolver, not from
        // reproducing its rules here. This arm used to answer 501, which was
        // defensible while only JSON could reach the handler and indefensible
        // the moment a Pingclairfile could: the same site would then serve a
        // single-page application over HTTP/2 and refuse it over HTTP/3,
        // depending on nothing the operator wrote.
        HandlerConfig::TryFiles {
            files,
            root,
            fallback,
        } => match crate::http_policy::resolve_try_files(files, root.as_deref(), effective_uri) {
            Some(target) => {
                *effective_uri =
                    rewrite_uri(effective_uri, None, None, Some(target.as_str()), None, None);
                request_header
                    .set_raw_path(effective_uri.as_bytes())
                    .map_err(|_| (500, "Rewrite Failed"))?;
                Ok(H3Plan::Continue)
            }
            None => match fallback {
                Some(fallback) => {
                    let fallback_precompile = precompile.and_then(|node| node.children.first());
                    plan_h3_handler(
                        fallback,
                        state,
                        route_index,
                        request_header,
                        effective_uri,
                        response_policy,
                        verified_client_ip,
                        fallback_precompile,
                        handling_error,
                        request_vars,
                    )
                    .await
                }
                None => Ok(H3Plan::Continue),
            },
        },
        HandlerConfig::Plugin { .. } => Err((501, "Plugin Not Supported Over HTTP/3")),
    }
}

/// 🛑 Waits for an explicit abort while allowing normal sender cleanup to finish.
async fn wait_for_request_cancellation(cancel_rx: &mut watch::Receiver<bool>) {
    loop {
        if *cancel_rx.borrow() {
            return;
        }
        if cancel_rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// 🧩 Runs one handler future until it finishes or its QUIC stream is abandoned.
async fn run_until_request_cancelled<T>(
    cancel_rx: &mut watch::Receiver<bool>,
    future: impl Future<Output = T>,
) -> Option<T> {
    tokio::select! {
        biased;
        _ = wait_for_request_cancellation(cancel_rx) => None,
        result = future => Some(result),
    }
}

/// 🌊 Routes one request and streams its response back to the event loop.
#[allow(clippy::too_many_arguments)]
async fn handle_request(
    proxy: Arc<PingclairProxy>,
    connector: Arc<pingora_core::connectors::http::Connector>,
    req: H3Request,
    remote_ip: IpAddr,
    stream_id: u64,
    mut body_rx: mpsc::Receiver<Vec<u8>>,
    resp_tx: RespSender,
    body_notify: Arc<Notify>,
    mut cancel_rx: watch::Receiver<bool>,
) {
    let request_id = resolve_request_id(
        req.headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-request-id"))
            .map(|(_, value)| value.as_str()),
    );
    let mut error_state = None;
    let mut response_policy = ResponseHeaderPolicy::default();
    let result = run_until_request_cancelled(
        &mut cancel_rx,
        handle_request_inner(
            &proxy,
            &connector,
            &req,
            remote_ip,
            stream_id,
            &mut body_rx,
            &resp_tx,
            &body_notify,
            &request_id,
            &mut error_state,
            &mut response_policy,
        ),
    )
    .await;
    let body_drain_blocked = !body_rx.is_empty();
    drop(body_rx);
    if body_drain_blocked {
        // 🔔 An early response can drop a full body channel before consuming
        // it. Wake the event loop so it observes the closed receiver and
        // resumes discarding bytes instead of leaving the client flow-control
        // blocked forever.
        body_notify.notify_one();
    }
    let Some(Err(e)) = result else {
        return;
    };

    let (status, msg) = e;
    // 🧯 Applies the virtual host error policy only while the client still owns the stream.
    let _ = run_until_request_cancelled(
        &mut cancel_rx,
        send_error_response(
            &resp_tx,
            stream_id,
            status,
            msg,
            error_state.as_deref(),
            &response_policy,
            &request_id,
        ),
    )
    .await;
}

/// 🧯 Carries an HTTP failure to the wrapper before response bytes are queued.
type HandlerError = (u16, &'static str);

#[allow(clippy::too_many_arguments)]
async fn handle_request_inner(
    proxy: &PingclairProxy,
    connector: &pingora_core::connectors::http::Connector,
    req: &H3Request,
    peer_ip: IpAddr,
    stream_id: u64,
    body_rx: &mut mpsc::Receiver<Vec<u8>>,
    resp_tx: &RespSender,
    body_notify: &Arc<Notify>,
    request_id: &str,
    error_state: &mut Option<Arc<ProxyState>>,
    response_policy: &mut ResponseHeaderPolicy,
) -> Result<(), HandlerError> {
    let request_started = Instant::now();
    // 🧭 Builds one Pingora header map for routing and placeholder resolution.
    let method =
        http::Method::from_bytes(req.method.as_bytes()).map_err(|_| (400, "Bad Request"))?;
    let path_only = req.path.split('?').next().unwrap_or("/");

    let mut header = RequestHeader::build(method.clone(), req.path.as_bytes(), None)
        .map_err(|_| (400, "Bad Request"))?;
    for (k, v) in &req.headers {
        header.insert_header(k.clone(), v.as_str()).ok();
    }
    if !req.authority.is_empty() && !header.headers.contains_key("host") {
        header.insert_header("host", &req.authority).ok();
    }

    // 🛡️ QUIC uses the same trusted-proxy identity policy as H1 and H2.
    let peer_address = peer_ip;
    let verified_client_ip = proxy.verified_client_ip(peer_address, &header.headers);
    let verified_client_ip_text = verified_client_ip.to_string();

    let host_bare = authority_host(&req.authority).to_string();

    // 🧭 Routes through the shared matcher used by the H1 and H2 path. The
    // state is resolved by host first so site-level `vars` rules can run
    // before route matching, exactly as they do on H1/H2.
    let mut request_vars = crate::http_policy::RequestVars::default();
    let (state, route_index) = {
        let Some(state) = proxy.get_state(&host_bare) else {
            return Err((404, "No Matching Virtual Host"));
        };
        for (index, rule) in state.config.vars_routes.iter().enumerate() {
            let compiled = state.vars_precompiles.get(index).and_then(Option::as_ref);
            let matches = match compiled {
                Some(compiled) => {
                    let mut request = MatcherRequest {
                        path: path_only,
                        method: req.method.as_str(),
                        headers: &header.headers,
                        host: &host_bare,
                        remote_ip: &verified_client_ip_text,
                        protocol: "https",
                        vars: Some(request_vars.values_mut()),
                    };
                    evaluate(compiled, &mut request)
                }
                None => true,
            };
            if matches {
                for (name, template) in &rule.values {
                    let resolved = resolve_caddy_placeholders(
                        template,
                        &header,
                        Some(&verified_client_ip_text),
                        "https",
                        &request_vars,
                    );
                    request_vars.set(name.clone(), resolved.into_owned());
                }
            }
        }
        let route_index = state
            .router
            .match_normalized_request(
                path_only,
                req.method.as_str(),
                &header.headers,
                &host_bare,
                &verified_client_ip_text,
                "https",
                Some(request_vars.values_mut()),
            )
            .map(|route| route.index);
        (state, route_index)
    };
    let Some(route_index) = route_index else {
        *error_state = Some(state);
        return Err((404, "No Matching Route"));
    };
    *error_state = Some(state.clone());
    let handler = &state
        .config
        .routes
        .get(route_index)
        .ok_or((500, "Missing Route Handler"))?
        .handler;

    // 🧾 Applies the selected virtual host's decoded H3 field bounds.
    let header_count = req.headers.len();
    let header_bytes = req.headers.iter().fold(0usize, |total, (name, value)| {
        total.saturating_add(name.len()).saturating_add(value.len())
    });
    if state
        .config
        .limits
        .max_header_count
        .is_some_and(|limit| header_count > limit)
        || state
            .config
            .limits
            .max_header_bytes
            .is_some_and(|limit| header_bytes > limit)
    {
        return Err((431, "Request Header Fields Too Large"));
    }

    // 🔌 Rejects CONNECT tunnels because the current H3 path is request-response only.
    if method == http::Method::CONNECT || req.protocol.is_some() {
        return Err((501, "CONNECT Not Supported Over HTTP/3"));
    }

    // 🚫 Rejects advertised request trailers before a handler can consume an incomplete message.
    if header.headers.contains_key("trailer") {
        return Err((501, "Request Trailers Not Supported"));
    }

    // 📦 Rejects declared oversized bodies before opening an upstream connection.
    let body_limit = state.config.client_max_body_size;
    if body_limit > 0
        && let Some(content_length) = header
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
        && content_length > body_limit
    {
        return Err((413, "Request Entity Too Large"));
    }

    // 🛡️ HTTP/3 enforces the same compiled access policy before authentication or dispatch.
    if !state.allows_access(route_index, &verified_client_ip_text, &header.headers) {
        return Err((403, "Forbidden"));
    }

    // 🚦 HTTP/3 charges the same exact limiter and identity source as H1 and H2.
    if let Some(limiter) = state
        .rate_limiters
        .get(route_index)
        .and_then(|l| l.as_ref())
    {
        let decision = limiter.check_request(&verified_client_ip_text, &header.headers);
        for (name, value) in decision.info.to_headers() {
            response_policy.set(name, value);
        }
        if decision.reject {
            let mut headers = vec![quiche::h3::Header::new(b":status", b"429")];
            apply_h3_response_policy(&mut headers, response_policy, request_id, Some(&state));
            send_headers(resp_tx, stream_id, headers, true).await;
            return Ok(());
        }
    }

    let mut effective_uri = req.path.clone();
    let route_precompile = state
        .router
        .compiled_route(route_index)
        .map(|route| &route.matcher_precompile);
    let plan = plan_h3_handler(
        handler,
        &state,
        route_index,
        &mut header,
        &mut effective_uri,
        response_policy,
        &verified_client_ip_text,
        route_precompile,
        false,
        &mut request_vars,
    )
    .await?;

    let request_deadline = state
        .config
        .limits
        .request_timeout_ms
        .map(|value| request_started + Duration::from_millis(value));
    let handler = match plan {
        H3Plan::Terminal(handler) => handler,
        H3Plan::Respond(response) => {
            send_immediate_response(
                resp_tx,
                stream_id,
                response,
                response_policy,
                request_id,
                &state,
            )
            .await?;
            return Ok(());
        }
        H3Plan::Continue => return Err((501, "Handler Pipeline Produced No Response")),
    };

    if !matches!(&handler, H3Terminal::ReverseProxy) {
        drain_local_h3_body(
            body_rx,
            body_notify,
            body_limit,
            state.config.limits.body_timeout_ms,
            state.config.limits.upload_bytes_per_sec,
            request_deadline,
        )
        .await?;
    }
    let mut download_pacer = state
        .config
        .limits
        .download_bytes_per_sec
        .map(StreamPacer::new);

    match handler {
        H3Terminal::Respond {
            status,
            body,
            headers,
        } => {
            let body = body.unwrap_or_default();
            let mut hdrs = vec![
                quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
                quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
            ];
            for (k, v) in &headers {
                hdrs.push(quiche::h3::Header::new(k.as_bytes(), v.as_bytes()));
            }
            apply_h3_response_policy(&mut hdrs, response_policy, request_id, Some(&state));
            send_headers(resp_tx, stream_id, hdrs, body.is_empty()).await;
            if !body.is_empty() {
                pace_h3_body(&mut download_pacer, request_deadline, body.len()).await?;
                send_body(resp_tx, stream_id, body.into_bytes(), true).await;
            }
            Ok(())
        }

        H3Terminal::Redirect { to, code } => {
            let mut hdrs = vec![
                quiche::h3::Header::new(b":status", code.to_string().as_bytes()),
                quiche::h3::Header::new(b"location", to.as_bytes()),
            ];
            apply_h3_response_policy(&mut hdrs, response_policy, request_id, Some(&state));
            send_headers(resp_tx, stream_id, hdrs, true).await;
            Ok(())
        }

        H3Terminal::Templates { root } => {
            let root = root.unwrap_or_else(|| ".".to_string());
            let relative = effective_uri
                .split('?')
                .next()
                .unwrap_or("/")
                .trim_start_matches('/');
            let mut file_path = std::path::Path::new(&root).join(relative);
            if file_path.is_dir() {
                file_path = file_path.join("index.html");
            }
            let source = std::fs::read_to_string(&file_path).map_err(|_| (404, "Not Found"))?;
            let body = crate::server::render_template(&source, &root)
                .map_err(|_| (500, "Template Rendering Failed"))?;
            let mut hdrs = vec![
                quiche::h3::Header::new(b":status", b"200"),
                quiche::h3::Header::new(b"content-type", b"text/html; charset=utf-8"),
                quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
            ];
            apply_h3_response_policy(&mut hdrs, response_policy, request_id, Some(&state));
            send_headers(resp_tx, stream_id, hdrs, false).await;
            send_body(resp_tx, stream_id, body.into_bytes(), true).await;
            Ok(())
        }

        H3Terminal::FileServer => {
            let maybe_fs = state.file_servers.get(route_index).and_then(|f| f.clone());
            let Some(fs) = maybe_fs else {
                return Err((503, "File Server Unavailable"));
            };

            let range_header = header.headers.get("range").and_then(|v| v.to_str().ok());
            let accept_encoding = header
                .headers
                .get("accept-encoding")
                .and_then(|v| v.to_str().ok());

            let effective_path = effective_uri.split('?').next().unwrap_or("/");
            match fs
                .serve_auto(effective_path, range_header, accept_encoding)
                .await
            {
                Ok(Some(ServedResponse::Redirect(location))) => {
                    let mut hdrs = vec![quiche::h3::Header::new(b":status", b"308")];
                    hdrs.push(quiche::h3::Header::new(b"location", location.as_bytes()));
                    apply_h3_response_policy(&mut hdrs, response_policy, request_id, Some(&state));
                    send_headers(resp_tx, stream_id, hdrs, true).await;
                    Ok(())
                }
                Ok(Some(ServedResponse::Stream(mut stream))) => {
                    let mut hdrs = vec![
                        quiche::h3::Header::new(b":status", b"200"),
                        quiche::h3::Header::new(b"content-type", stream.content_type.as_bytes()),
                        quiche::h3::Header::new(
                            b"content-length",
                            stream.content_length.as_bytes(),
                        ),
                        quiche::h3::Header::new(b"accept-ranges", b"bytes"),
                    ];
                    if let Some(lm) = &stream.last_modified {
                        hdrs.push(quiche::h3::Header::new(b"last-modified", lm.as_bytes()));
                    }
                    if let Some(etag) = &stream.etag {
                        hdrs.push(quiche::h3::Header::new(b"etag", etag.as_bytes()));
                    }
                    apply_h3_response_policy(&mut hdrs, response_policy, request_id, Some(&state));
                    send_headers(resp_tx, stream_id, hdrs, false).await;

                    // 🌊 Streams file chunks without buffering the complete representation.
                    let mut fin_sent = false;
                    loop {
                        match stream.read_chunk() {
                            Ok(Some(chunk)) => {
                                let last = stream.is_complete();
                                pace_h3_body(&mut download_pacer, request_deadline, chunk.len())
                                    .await?;
                                send_body(resp_tx, stream_id, chunk, last).await;
                                fin_sent = last;
                            }
                            Ok(None) => break,
                            Err(e) => {
                                tracing::error!("❌ H3 file stream error: {}", e);
                                break;
                            }
                        }
                    }
                    if !fin_sent {
                        send_body(resp_tx, stream_id, Vec::new(), true).await;
                    }
                    Ok(())
                }
                Ok(Some(ServedResponse::Buffered(file))) => {
                    let mut hdrs = vec![
                        quiche::h3::Header::new(b":status", file.status.to_string().as_bytes()),
                        quiche::h3::Header::new(b"content-type", file.content_type.as_bytes()),
                        quiche::h3::Header::new(b"content-length", file.content_length.as_bytes()),
                        quiche::h3::Header::new(b"accept-ranges", b"bytes"),
                    ];
                    if let Some(range) = &file.content_range {
                        hdrs.push(quiche::h3::Header::new(b"content-range", range.as_bytes()));
                    }
                    if let Some(lm) = &file.last_modified {
                        hdrs.push(quiche::h3::Header::new(b"last-modified", lm.as_bytes()));
                    }
                    if let Some(etag) = &file.etag {
                        hdrs.push(quiche::h3::Header::new(b"etag", etag.as_bytes()));
                    }
                    if let Some(enc) = &file.content_encoding {
                        hdrs.push(quiche::h3::Header::new(b"content-encoding", enc.as_bytes()));
                    }
                    apply_h3_response_policy(&mut hdrs, response_policy, request_id, Some(&state));
                    send_headers(resp_tx, stream_id, hdrs, file.content.is_empty()).await;
                    if !file.content.is_empty() {
                        pace_h3_body(&mut download_pacer, request_deadline, file.content.len())
                            .await?;
                        send_body(resp_tx, stream_id, file.content, true).await;
                    }
                    Ok(())
                }
                Ok(None) => Err((404, "Not Found")),
                Err(e) => {
                    tracing::error!("❌ H3 FileServer error: {}", e);
                    Err((500, "File Server Error"))
                }
            }
        }

        H3Terminal::ReverseProxy => {
            reverse_proxy_upstream(
                proxy,
                connector,
                &state,
                route_index,
                req,
                &header,
                &effective_uri,
                peer_ip,
                &verified_client_ip_text,
                request_id,
                response_policy,
                body_limit,
                stream_id,
                body_rx,
                resp_tx,
                body_notify,
                request_started,
                &request_vars,
            )
            .await
        }
    }
}

/// Reverse-proxy an HTTP/3 request to an upstream through Pingora's
/// pooled [`Connector`], streaming both bodies.
#[allow(clippy::too_many_arguments)]
async fn reverse_proxy_upstream(
    proxy: &PingclairProxy,
    connector: &pingora_core::connectors::http::Connector,
    state: &crate::server::ProxyState,
    route_index: usize,
    req: &H3Request,
    client_header: &RequestHeader,
    effective_uri: &str,
    peer_ip: IpAddr,
    verified_client_ip: &str,
    request_id: &str,
    response_policy: &ResponseHeaderPolicy,
    body_limit: u64,
    stream_id: u64,
    body_rx: &mut mpsc::Receiver<Vec<u8>>,
    resp_tx: &RespSender,
    body_notify: &Arc<Notify>,
    request_started: Instant,
    request_vars: &crate::http_policy::RequestVars,
) -> Result<(), HandlerError> {
    let _route_admission = match proxy.admit_route(state, route_index).await {
        Ok(admission) => admission,
        Err(crate::overload::AdmissionError::QueueFull) => {
            return Err((429, "Too Many Requests"));
        }
        Err(_) => return Err((503, "Service Unavailable")),
    };
    // ⚖️ Selects the upstream with the verified client IP for IP-hash routing.
    let ip_bytes: Vec<u8> = match verified_client_ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.octets().to_vec(),
        Ok(IpAddr::V6(v6)) => v6.octets().to_vec(),
        Err(_) => Vec::new(),
    };
    let proxy_config = proxy.get_proxy_config(state, route_index);
    let limits = &state.config.limits;
    let immediate_stream = proxy_config
        .as_ref()
        .is_some_and(|config| wants_immediate_flush(config.flush_interval));
    let request_timeout_ms = if immediate_stream {
        limits
            .long_connections
            .request_timeout_ms
            .or(limits.request_timeout_ms)
    } else {
        limits.request_timeout_ms
    };
    let base_request_deadline = request_timeout_ms
        .filter(|value| *value > 0)
        .map(|value| request_started + Duration::from_millis(value));
    let method =
        http::Method::from_bytes(req.method.as_bytes()).map_err(|_| (400, "Bad Request"))?;
    // 📦 Preserves a trusted content length while selecting framing for the upstream protocol.
    let client_content_length: Option<u64> = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<u64>().ok());
    let retry_policy = proxy_config
        .as_ref()
        .map(|config| config.retry.clone())
        .unwrap_or_default();
    let retry_deadline = crate::retry::deadline(request_started, &retry_policy);
    let mut attempts = 0usize;
    let mut excluded = HashSet::new();

    // 🔐 The H3 bridge answers the same routes as the Pingora path, so it
    // enforces the same rule: a route whose upstream TLS material did not load
    // refuses rather than connecting without the trust it was configured with.
    let tls_policy = state.upstream_tls_for(route_index).map_err(|()| {
        tracing::error!(
            route = route_index,
            "🚫 Refusing to dispatch: this route's upstream TLS material did not load"
        );
        (500, "Upstream TLS Configuration Error")
    })?;

    // 🧭 Replaceable dial templates get the same per-request treatment as on
    // H1/H2: expand against the request variables, resolve through the shared
    // bounded cache, and reuse that peer for every retry attempt.
    let mut dynamic_upstream = None;
    if let Some(dial_plan) = state
        .dynamic_dials
        .get(route_index)
        .and_then(|plan| plan.as_ref())
    {
        let Some(spec) = dial_plan.resolve(client_header, Some(verified_client_ip), request_vars)
        else {
            return Err((502, "Dynamic Upstream Not Resolved"));
        };
        dynamic_upstream = Some(
            crate::upstream::resolve_dynamic_dial(spec)
                .await
                .ok_or((502, "Dynamic Upstream Not Resolved"))?,
        );
    }

    // 🧭 The reverse_proxy `method`/`rewrite` subdirectives change the
    // upstream request, mirroring the H1/H2 path; the downstream request
    // object stays untouched.
    let mut upstream_method = method.clone();
    let mut upstream_uri = effective_uri.to_string();
    if let Some(proxy_config) = proxy_config.as_ref() {
        if let Some(rewritten) = &proxy_config.rewrite_method
            && let Ok(rewritten) = http::Method::from_bytes(rewritten.as_bytes())
        {
            upstream_method = rewritten;
        }
        if let Some(template) = &proxy_config.rewrite_uri {
            let resolved = crate::server::resolve_caddy_placeholders(
                template,
                client_header,
                Some(verified_client_ip),
                "http",
                request_vars,
            );
            upstream_uri = resolved.into_owned();
        }
    }

    let (mut session, peer, mut request_deadline, _upstream_admission) = loop {
        if attempts > 0 {
            let delay = crate::retry::backoff(&retry_policy);
            if !delay.is_zero() {
                tracing::debug!(
                    route = route_index,
                    attempt = attempts + 1,
                    backoff_ms = delay.as_millis(),
                    "💤 Waiting before the next H3 upstream attempt"
                );
                tokio::time::sleep(delay).await;
            }
        }
        if retry_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err((504, "Upstream Retry Timeout"));
        }

        let (upstream, mut admission) = if let Some(upstream) = &dynamic_upstream {
            (upstream.clone(), None)
        } else {
            let mut selected =
                proxy.select_admitted_upstream(state, route_index, Some(&ip_bytes), &excluded);
            if matches!(
                selected,
                Err(crate::server::UpstreamSelectionError::NoUpstream)
            ) && !excluded.is_empty()
            {
                // ♻️ A status policy may revisit a backend after every candidate was tried once.
                excluded.clear();
                selected =
                    proxy.select_admitted_upstream(state, route_index, Some(&ip_bytes), &excluded);
            }
            selected.map_err(|error| match error {
                crate::server::UpstreamSelectionError::NoUpstream => (502, "No Upstream Available"),
                crate::server::UpstreamSelectionError::Unavailable => (503, "Upstream Overloaded"),
            })?
        };
        attempts += 1;

        let request_budget = base_request_deadline
            .and_then(|deadline| deadline.checked_duration_since(Instant::now()));
        if request_timeout_ms.is_some() && request_budget.is_none() {
            return Err((408, "Request Timeout"));
        }
        let retry_budget =
            retry_deadline.and_then(|deadline| deadline.checked_duration_since(Instant::now()));
        let attempt_budget = match (request_budget, retry_budget) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(value), None) | (None, Some(value)) => Some(value),
            (None, None) => None,
        };
        let mut peer = PingclairProxy::build_http_peer(
            &upstream,
            proxy_config.as_ref(),
            attempt_budget,
            attempt_budget,
            tls_policy,
        )
        .map_err(|_| (500, "Upstream Peer Configuration Error"))?;
        // ⌛ The retry total bounds response-header wait even when phase timers are longer.
        peer.options.read_timeout = match (peer.options.read_timeout, retry_budget) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(value), None) | (None, Some(value)) => Some(value),
            (None, None) => None,
        };

        let (mut session, _reused) = match connector.get_http_session(&peer).await {
            Ok(result) => result,
            Err(error) => {
                if let Some(admission) = &mut admission {
                    admission.report_failure();
                }
                tracing::warn!(
                    attempt = attempts,
                    error = %error,
                    "🔌 H3 upstream connection attempt failed"
                );
                if let pingora_core::protocols::l4::socket::SocketAddr::Inet(address) =
                    &upstream.addr
                {
                    excluded.insert(*address);
                    proxy.mark_upstream_unhealthy(state, route_index, address);
                    tracing::warn!(
                        "🔻 Marking H3 upstream {} down after connect failure (cooldown {:?})",
                        address,
                        crate::FAIL_COOLDOWN
                    );
                }
                if crate::retry::permits_another_attempt(&retry_policy, attempts, retry_deadline) {
                    continue;
                }
                return Err((502, "Upstream Connect Failed"));
            }
        };
        let upstream_is_h2 = matches!(&session, HttpSession::H2(_));
        if crate::server::peer_requires_h2_alpn(&peer) && !upstream_is_h2 {
            if let Some(admission) = &mut admission {
                admission.report_failure();
            }
            tracing::error!("🔒 H3 bridge rejected a TLS upstream without h2 ALPN");
            session.shutdown().await;
            if let pingora_core::protocols::l4::socket::SocketAddr::Inet(address) = &upstream.addr {
                excluded.insert(*address);
                proxy.mark_upstream_unhealthy(state, route_index, address);
            }
            if crate::retry::permits_another_attempt(&retry_policy, attempts, retry_deadline) {
                continue;
            }
            return Err((502, "TLS H2 Upstream Negotiation Failed"));
        }

        // 📤 Builds the upstream request with every middleware rewrite already applied.
        let mut up_req =
            RequestHeader::build(upstream_method.clone(), upstream_uri.as_bytes(), None)
                .map_err(|_| (400, "Bad Request"))?;

        // 🏷️ Uses the selected upstream's authority instead of the downstream host.
        up_req
            .insert_header("Host", peer.sni.clone())
            .map_err(|_| (502, "Upstream Request Error"))?;

        // 🧹 Forwards end-to-end headers while stripping hop-by-hop framing metadata.
        for (key, value) in &req.headers {
            let name = key.to_ascii_lowercase();
            if name == "te" {
                if upstream_is_h2
                    && value
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("trailers"))
                {
                    up_req.insert_header("te", "trailers").ok();
                }
                continue;
            }
            if matches!(
                name.as_str(),
                "host"
                    | "connection"
                    | "keep-alive"
                    | "transfer-encoding"
                    | "trailer"
                    | "upgrade"
                    | "content-length"
            ) {
                continue;
            }
            up_req.insert_header(key.clone(), value.as_str()).ok();
        }

        match client_content_length {
            Some(content_length) => {
                up_req
                    .insert_header("Content-Length", content_length.to_string())
                    .ok();
            }
            None if !upstream_is_h2
                && matches!(req.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") =>
            {
                up_req.insert_header("Transfer-Encoding", "chunked").ok();
            }
            None => {}
        }

        // 🧩 Resolves configured upstream header placeholders for each selected peer.
        if let Some(config) = &proxy_config {
            for (key, template) in &config.headers_up {
                let resolved = resolve_caddy_placeholders(
                    template,
                    client_header,
                    Some(verified_client_ip),
                    "https",
                    request_vars,
                );
                up_req.insert_header(key.clone(), resolved.as_ref()).ok();
            }
        }

        let has_header_up = |name: &str| {
            proxy_config
                .as_ref()
                .map(|config| {
                    config
                        .headers_up
                        .keys()
                        .any(|key| key.eq_ignore_ascii_case(name))
                })
                .unwrap_or(false)
        };

        if !has_header_up("X-Forwarded-Proto") {
            up_req.insert_header("X-Forwarded-Proto", "https").ok();
        }
        if !has_header_up("X-Forwarded-Host") {
            up_req
                .insert_header("X-Forwarded-Host", req.authority.as_str())
                .ok();
        }
        if !has_header_up("X-Forwarded-For") {
            up_req
                .insert_header(
                    "X-Forwarded-For",
                    proxy
                        .forwarded_for(peer_ip, &client_header.headers)
                        .as_str(),
                )
                .ok();
        }
        if !has_header_up("X-Real-IP") {
            up_req.insert_header("X-Real-IP", verified_client_ip).ok();
        }
        if !has_header_up("X-Request-Id") {
            up_req.insert_header("X-Request-Id", request_id).ok();
        }
        // 🔀 RFC 9110 §7.6.3 uses the downstream HTTP/3 version for this received-by hop.
        if !response_policy.suppresses_via() {
            up_req
                .append_header("via", crate::http_policy::via_value(http::Version::HTTP_3))
                .ok();
        }

        session
            .write_request_header(Box::new(up_req))
            .await
            .map_err(|error| {
                tracing::error!("❌ H3 upstream write header failed: {}", error);
                (502, "Upstream Write Failed")
            })?;

        // 🌊 Streams request chunks after the upstream has accepted the headers.
        let mut counted = 0u64;
        let mut upload_pacer = limits.upload_bytes_per_sec.map(StreamPacer::new);
        loop {
            let next = match limits.body_timeout_ms {
                Some(timeout_ms) => {
                    tokio::time::timeout(Duration::from_millis(timeout_ms), body_rx.recv())
                        .await
                        .map_err(|_| (408, "Request Body Timeout"))?
                }
                None => body_rx.recv().await,
            };
            let Some(chunk) = next else { break };
            // 🔔 Wakes the event loop after freeing request-channel capacity.
            body_notify.notify_one();

            counted += chunk.len() as u64;
            if body_limit > 0 && counted > body_limit {
                // 🛑 Aborts the upstream exchange before returning the body-limit response.
                session.shutdown().await;
                return Err((413, "Request Entity Too Large"));
            }
            if let Some(delay) = upload_pacer
                .as_mut()
                .and_then(|pacer| pacer.delay_for(chunk.len()))
            {
                if base_request_deadline.is_some_and(|deadline| Instant::now() + delay >= deadline)
                {
                    session.shutdown().await;
                    return Err((408, "Request Timeout"));
                }
                tokio::time::sleep(delay).await;
            }
            if let Err(error) = session.write_request_body(Bytes::from(chunk), false).await {
                tracing::error!("❌ H3 upstream write body failed: {}", error);
                session.shutdown().await;
                return Err((502, "Upstream Write Failed"));
            }
        }
        // 📏 Rejects a body length mismatch before it can poison a reused connection.
        if let Some(content_length) = client_content_length
            && counted != content_length
        {
            tracing::warn!(
                "⚠️ H3 request body length mismatch (content-length {}, streamed {})",
                content_length,
                counted
            );
            session.shutdown().await;
            return Err((400, "Bad Request"));
        }

        if let Err(error) = session.finish_request_body().await {
            tracing::error!("❌ H3 upstream finish body failed: {}", error);
            session.shutdown().await;
            return Err((502, "Upstream Write Failed"));
        }

        // 📥 Reads upstream response metadata before committing an H3 response.
        if let Err(error) = session.read_response_header().await {
            tracing::error!("❌ H3 upstream read response header failed: {}", error);
            session.shutdown().await;
            if retry_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err((504, "Upstream Retry Timeout"));
            }
            return Err((502, "Upstream Read Failed"));
        }

        let upstream_status = session
            .response_header()
            .map(|response| response.status.as_u16())
            .unwrap_or(502);
        if let Some(admission) = &mut admission {
            admission.report_status(upstream_status);
        }
        if crate::retry::permits_status_retry(
            &retry_policy,
            &method,
            counted == 0,
            effective_uri.split('?').next().unwrap_or(effective_uri),
            upstream_status,
            attempts,
            retry_deadline,
        ) {
            tracing::warn!(
                status = upstream_status,
                method = %method,
                attempt = attempts,
                max_attempts = retry_policy.max_attempts,
                "🔁 Redispatching a bodyless H3 request after an upstream status"
            );
            session.shutdown().await;
            if let pingora_core::protocols::l4::socket::SocketAddr::Inet(address) = &upstream.addr {
                excluded.insert(*address);
            }
            continue;
        }

        break (session, peer, base_request_deadline, admission);
    };

    let response_streaming = session
        .response_header()
        .and_then(|response| response.headers.get("content-type"))
        .and_then(|value| value.to_str().ok())
        .is_some_and(is_streaming_content_type);
    if response_streaming && let Some(request_ms) = limits.long_connections.request_timeout_ms {
        request_deadline =
            (request_ms > 0).then(|| request_started + Duration::from_millis(request_ms));
    }
    let between_reads_ms = if response_streaming || immediate_stream {
        limits
            .long_connections
            .idle_timeout_ms
            .filter(|value| *value > 0)
            .map(|value| value as i64)
            .or_else(|| {
                proxy_config
                    .as_ref()
                    .and_then(|config| config.between_reads_timeout.or(config.read_timeout))
            })
    } else {
        proxy_config
            .as_ref()
            .and_then(|config| config.between_reads_timeout.or(config.read_timeout))
    };
    let between_reads = between_reads_ms
        .filter(|value| *value > 0)
        .map(|value| Duration::from_millis(value as u64));
    let request_remaining =
        request_deadline.and_then(|deadline| deadline.checked_duration_since(Instant::now()));
    if request_deadline.is_some() && request_remaining.is_none() {
        session.shutdown().await;
        return Err((408, "Request Timeout"));
    }
    let retry_remaining =
        retry_deadline.and_then(|deadline| deadline.checked_duration_since(Instant::now()));
    if retry_deadline.is_some() && retry_remaining.is_none() {
        session.shutdown().await;
        return Err((504, "Upstream Retry Timeout"));
    }
    let remaining = match (request_remaining, retry_remaining) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    };
    request_deadline = match (request_deadline, retry_deadline) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    };
    session.set_read_timeout(match (between_reads, remaining) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    });

    let upstream_status = session
        .response_header()
        .map(|response| response.status.as_u16())
        .unwrap_or(502);

    // 🧭 `handle_response` evaluates from the response header alone — status
    // and headers, never the body — so the H3 path stays streaming-safe just
    // like the H1/H2 response_filter.
    let mut intercept_remove: Vec<String> = Vec::new();
    let mut intercept_set: Vec<(String, String)> = Vec::new();
    let mut intercept_status: Option<u16> = None;
    let mut intercept_replacement: Option<crate::http_policy::InterceptedResponse> = None;
    {
        let handlers = state
            .config
            .routes
            .get(route_index)
            .and_then(|route| crate::server::find_reverse_proxy_config(&route.handler))
            .map(|config| config.handle_response.as_slice())
            .filter(|handlers| !handlers.is_empty())
            .unwrap_or(&[]);
        if !handlers.is_empty()
            && let Some(resp) = session.response_header()
        {
            let mut eval_vars = request_vars.clone();
            if let Some(outcome) = crate::http_policy::evaluate_response_handlers(
                handlers,
                resp.status.as_u16(),
                &resp.headers,
                &mut eval_vars,
            ) {
                intercept_remove = outcome.header_remove;
                intercept_set = outcome.header_set;
                intercept_status = outcome.passthrough_status;
                intercept_replacement = outcome.replacement;
            }
        }
    }
    let effective_status = intercept_status.unwrap_or(upstream_status);
    if intercept_replacement.is_none() && state.intercepts_error_status(effective_status) {
        session.shutdown().await;
        return Err((effective_status, error_reason(effective_status)));
    }

    if intercept_replacement.is_none()
        && session
            .response_header()
            .is_some_and(|response| response.headers.contains_key("trailer"))
    {
        tracing::warn!(
            "🚫 Rejecting an H3 upstream response that requires unsupported trailer forwarding"
        );
        session.shutdown().await;
        return Err((502, "Upstream Response Trailers Not Supported"));
    }

    let mut hdrs = Vec::new();
    if let Some(resp) = session.response_header() {
        if let Some(replacement) = &intercept_replacement {
            hdrs.push(quiche::h3::Header::new(
                b":status",
                replacement.status.to_string().as_bytes(),
            ));
            for (name, value) in &replacement.headers {
                hdrs.push(quiche::h3::Header::new(
                    name.to_ascii_lowercase().as_bytes(),
                    value.as_bytes(),
                ));
            }
            hdrs.push(quiche::h3::Header::new(
                b"content-length",
                replacement.body.len().to_string().as_bytes(),
            ));
        } else {
            hdrs.push(quiche::h3::Header::new(
                b":status",
                effective_status.to_string().as_bytes(),
            ));
            for (name, value) in resp.headers.iter() {
                let lower = name.as_str().to_ascii_lowercase();
                if matches!(
                    lower.as_str(),
                    "connection"
                        | "keep-alive"
                        | "transfer-encoding"
                        | "te"
                        | "trailer"
                        | "upgrade"
                ) || intercept_remove
                    .iter()
                    .any(|removed| removed.eq_ignore_ascii_case(&lower))
                {
                    continue;
                }
                hdrs.push(quiche::h3::Header::new(lower.as_bytes(), value.as_bytes()));
            }
            for (name, value) in &intercept_set {
                let resolved = crate::server::resolve_caddy_placeholders(
                    value,
                    client_header,
                    Some(verified_client_ip),
                    "https",
                    request_vars,
                )
                .into_owned();
                hdrs.push(quiche::h3::Header::new(
                    name.to_ascii_lowercase().as_bytes(),
                    resolved.as_bytes(),
                ));
            }
        }
    } else {
        hdrs.push(quiche::h3::Header::new(b":status", b"502"));
    }

    // 🧩 Proxy-owned replacements fill gaps without overriding outer middleware.
    let mut effective_policy = response_policy.clone();
    if let Some(cfg) = &proxy_config {
        effective_policy.merge_proxy_set(&cfg.headers_down);
    }
    // 🔀 Only the proxied path gets a `Via`: the other H3 responses are
    // produced by this server, so there is no hop to record. Appended after
    // the upstream's own value, and describing the version we received the
    // response over rather than the H3 we are about to answer with.
    if !effective_policy.suppresses_via()
        && let Some(resp) = session.response_header()
    {
        hdrs.push(quiche::h3::Header::new(
            b"via",
            crate::http_policy::via_value(resp.version).as_bytes(),
        ));
    }
    apply_h3_response_policy(&mut hdrs, &effective_policy, request_id, Some(state));

    send_headers(resp_tx, stream_id, hdrs, false).await;

    // 🌊 Streams the upstream response without committing the final H3 frame early.
    let mut clean = true;
    let mut download_pacer = limits.download_bytes_per_sec.map(StreamPacer::new);
    let mut replacement_sent = false;
    loop {
        match session.read_response_body().await {
            Ok(Some(bytes)) => {
                if let Some(replacement) = &intercept_replacement {
                    // 🧭 The static replacement is emitted once; upstream
                    // chunks are drained and discarded so memory stays
                    // bounded by the replacement, not the upstream body.
                    if !replacement_sent {
                        replacement_sent = true;
                        send_body(resp_tx, stream_id, replacement.body.clone(), false).await;
                    }
                    continue;
                }
                if let Some(delay) = download_pacer
                    .as_mut()
                    .and_then(|pacer| pacer.delay_for(bytes.len()))
                {
                    if request_deadline.is_some_and(|deadline| Instant::now() + delay >= deadline) {
                        tracing::warn!("⏱️ H3 whole-request timeout reached during response body");
                        clean = false;
                        break;
                    }
                    tokio::time::sleep(delay).await;
                }
                send_body(resp_tx, stream_id, bytes.to_vec(), false).await;
            }
            Ok(None) => {
                if let Some(replacement) = &intercept_replacement
                    && !replacement_sent
                {
                    send_body(resp_tx, stream_id, replacement.body.clone(), false).await;
                }
                break;
            }
            Err(e) => {
                tracing::error!("❌ H3 upstream read body failed: {}", e);
                clean = false;
                break;
            }
        }
    }

    let mut response_trailers = None;
    if clean
        && intercept_replacement.is_none()
        && let HttpSession::H2(h2) = &mut session
    {
        match h2.read_trailers().await {
            Ok(Some(headers)) => {
                let mut trailers = Vec::with_capacity(headers.len());
                for (name, value) in headers.iter() {
                    let lower = name.as_str().to_ascii_lowercase();
                    if matches!(
                        lower.as_str(),
                        "connection"
                            | "keep-alive"
                            | "transfer-encoding"
                            | "te"
                            | "trailer"
                            | "upgrade"
                    ) {
                        continue;
                    }
                    trailers.push(quiche::h3::Header::new(lower.as_bytes(), value.as_bytes()));
                }
                response_trailers = Some(trailers);
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!("❌ H3 upstream response trailer read failed: {}", e);
                clean = false;
            }
        }
    }

    if let Some(trailers) = response_trailers.filter(|trailers| !trailers.is_empty()) {
        send_trailers(resp_tx, stream_id, trailers).await;
    } else {
        send_body(resp_tx, stream_id, Vec::new(), true).await;
    }

    if clean {
        // ♻️ Returns a fully consumed session to the keepalive pool.
        connector.release_http_session(session, &peer, None).await;
    } else {
        session.shutdown().await;
    }

    Ok(())
}

// MARK: - Response channel helpers

/// 🧩 Replaces one H3 response header while preserving unrelated values.
fn set_h3_header(headers: &mut Vec<quiche::h3::Header>, name: &str, value: &str) {
    let normalized = name.to_ascii_lowercase();
    headers.retain(|header| !header.name().eq_ignore_ascii_case(normalized.as_bytes()));
    headers.push(quiche::h3::Header::new(
        normalized.as_bytes(),
        value.as_bytes(),
    ));
}

/// 🛡️ Applies transport-neutral middleware and vhost security headers to H3.
fn apply_h3_response_policy(
    headers: &mut Vec<quiche::h3::Header>,
    policy: &ResponseHeaderPolicy,
    request_id: &str,
    state: Option<&ProxyState>,
) {
    for (name, value) in policy.set_headers() {
        set_h3_header(headers, name, value);
    }
    for (name, value) in policy.add_headers() {
        headers.push(quiche::h3::Header::new(name.as_bytes(), value.as_bytes()));
    }
    for name in policy.removed_headers() {
        headers.retain(|header| !header.name().eq_ignore_ascii_case(name.as_bytes()));
    }
    if policy.suppresses_server() {
        headers.retain(|header| !header.name().eq_ignore_ascii_case(b"server"));
    } else {
        set_h3_header(headers, "server", "Pingclair");
    }
    set_h3_header(headers, "x-request-id", request_id);

    let Some(state) = state.filter(|state| state.config.security.enabled) else {
        return;
    };
    let security = &state.config.security;
    set_h3_header(
        headers,
        "x-content-type-options",
        &security.x_content_type_options,
    );
    set_h3_header(headers, "x-frame-options", &security.x_frame_options);
    set_h3_header(headers, "x-xss-protection", &security.x_xss_protection);
    set_h3_header(
        headers,
        "x-permitted-cross-domain-policies",
        &security.x_permitted_cross_domain,
    );
    set_h3_header(headers, "referrer-policy", &security.referrer_policy);
    set_h3_header(headers, "permissions-policy", &security.permissions_policy);
    if state
        .config
        .tls
        .as_ref()
        .is_some_and(|tls| tls.auto || tls.cert.is_some())
        && let Some(hsts) = &security.hsts
    {
        let value = format!(
            "max-age={};{}{}",
            hsts.max_age,
            if hsts.include_subdomains {
                " includeSubDomains;"
            } else {
                ""
            },
            if hsts.preload { " preload" } else { "" }
        );
        set_h3_header(headers, "strict-transport-security", &value);
    }
    if let Some(csp) = &security.csp {
        set_h3_header(headers, "content-security-policy", csp);
    }
}

/// 📤 Sends one middleware-generated H3 response with the shared header policy.
async fn send_immediate_response(
    resp_tx: &RespSender,
    stream_id: u64,
    response: H3ImmediateResponse,
    policy: &ResponseHeaderPolicy,
    request_id: &str,
    state: &ProxyState,
) -> Result<(), HandlerError> {
    let body = response.body.into_bytes();
    let mut pacer = state
        .config
        .limits
        .download_bytes_per_sec
        .map(StreamPacer::new);
    let has_content_type = response
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-type"));
    let mut headers = vec![
        quiche::h3::Header::new(b":status", response.status.to_string().as_bytes()),
        quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
    ];
    if !body.is_empty() && !has_content_type {
        headers.push(quiche::h3::Header::new(b"content-type", b"text/plain"));
    }
    for (name, value) in response.headers {
        headers.push(quiche::h3::Header::new(name.as_bytes(), value.as_bytes()));
    }
    apply_h3_response_policy(&mut headers, policy, request_id, Some(state));
    send_headers(resp_tx, stream_id, headers, body.is_empty()).await;
    if !body.is_empty() {
        let request_deadline = state
            .config
            .limits
            .request_timeout_ms
            .map(|value| Instant::now() + Duration::from_millis(value));
        pace_h3_body(&mut pacer, request_deadline, body.len()).await?;
        send_body(resp_tx, stream_id, body, true).await;
    }
    Ok(())
}

async fn send_headers(
    resp_tx: &RespSender,
    stream_id: u64,
    headers: Vec<quiche::h3::Header>,
    fin: bool,
) {
    let _ = resp_tx
        .send(RespEvent {
            stream_id,
            msg: RespMsg::Headers(headers, fin),
        })
        .await;
}

async fn send_body(resp_tx: &RespSender, stream_id: u64, bytes: Vec<u8>, fin: bool) {
    let _ = resp_tx
        .send(RespEvent {
            stream_id,
            msg: RespMsg::Body(bytes, fin),
        })
        .await;
}

/// 🧾 Queues H3 response trailers after every response body chunk.
async fn send_trailers(resp_tx: &RespSender, stream_id: u64, headers: Vec<quiche::h3::Header>) {
    let _ = resp_tx
        .send(RespEvent {
            stream_id,
            msg: RespMsg::Trailers(headers),
        })
        .await;
}

/// 🧯 Sends a custom or built-in error response before an H3 stream is committed.
#[allow(clippy::too_many_arguments)]
async fn send_error_response(
    resp_tx: &RespSender,
    stream_id: u64,
    status: u16,
    msg: &str,
    state: Option<&ProxyState>,
    policy: &ResponseHeaderPolicy,
    request_id: &str,
) {
    let (body, content_type) = state
        .and_then(|state| state.read_error_page(status))
        .unwrap_or_else(|| (msg.as_bytes().to_vec(), "text/plain"));
    let mut headers = vec![
        quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
        quiche::h3::Header::new(b"content-type", content_type.as_bytes()),
        quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
    ];
    apply_h3_response_policy(&mut headers, policy, request_id, state);
    send_headers(resp_tx, stream_id, headers, body.is_empty()).await;
    if !body.is_empty() {
        send_body(resp_tx, stream_id, body, true).await;
    }
}

// MARK: - Tests

#[cfg(test)]
mod tests {
    use super::*;
    use pingclair_core::config::{
        BasicAuthCredential, HandlerElement, Matcher, RetryConfig, ReverseProxyConfig, RouteConfig,
        ServerConfig,
    };

    fn proxy_state(handler: HandlerConfig) -> ProxyState {
        ProxyState::new(ServerConfig {
            routes: vec![RouteConfig {
                path: "/*".to_string(),
                handler,
                methods: None,
                matcher: None,
            }],
            ..Default::default()
        })
    }

    /// Generate a self-signed PEM cert+key for the given names.
    fn self_signed_pem(names: &[&str]) -> (String, String) {
        let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(
            names.iter().map(|s| s.to_string()).collect::<Vec<String>>(),
        )
        .unwrap();
        (cert.pem(), signing_key.serialize_pem())
    }

    #[test]
    fn cert_table_exact_lookup() {
        let table = CertTable::new();
        let (cert, key) = self_signed_pem(&["example.com"]);
        table.upsert_pem("example.com", &cert, &key).unwrap();

        assert!(table.lookup("example.com").is_some());
        // Unknown name falls back to the default (first inserted) entry.
        assert!(table.lookup("other.test").is_some());
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn cert_table_wildcard_lookup() {
        let table = CertTable::new();
        let (cert, key) = self_signed_pem(&["*.example.com"]);
        table.upsert_pem("*.example.com", &cert, &key).unwrap();

        assert!(table.lookup("foo.example.com").is_some());
    }

    #[test]
    fn cert_table_prefers_exact_over_default() {
        let table = CertTable::new();
        let (cert_a, key_a) = self_signed_pem(&["a.example.com"]);
        let (cert_b, key_b) = self_signed_pem(&["b.example.com"]);
        table.upsert_pem("a.example.com", &cert_a, &key_a).unwrap();
        table.upsert_pem("b.example.com", &cert_b, &key_b).unwrap();

        let entry = table.lookup("b.example.com").unwrap();
        let expected = boring::x509::X509::from_pem(cert_b.as_bytes())
            .unwrap()
            .to_der()
            .unwrap();
        assert_eq!(entry.chain[0].to_der().unwrap(), expected);
    }

    #[test]
    fn cert_table_miss_without_default() {
        // Empty table: nothing to serve, lookup must fail so the handshake
        // is rejected instead of silently serving the wrong certificate.
        let table = CertTable::new();
        assert!(table.lookup("example.com").is_none());
        assert!(table.is_empty());
    }

    #[test]
    fn cert_table_rejects_bad_pem() {
        let table = CertTable::new();
        assert!(
            table
                .upsert_pem("bad", "not a pem", "also not a pem")
                .is_err()
        );
        assert!(table.is_empty());
    }

    #[test]
    fn cert_table_replacement_updates_lookup() {
        // Simulates an ACME renewal: same name, new material. The lookup
        // must return the replacement.
        let table = CertTable::new();
        let (cert1, key1) = self_signed_pem(&["example.com"]);
        table.upsert_pem("example.com", &cert1, &key1).unwrap();
        let first = table.lookup("example.com").unwrap();

        let (cert2, key2) = self_signed_pem(&["example.com"]);
        table.upsert_pem("example.com", &cert2, &key2).unwrap();
        let second = table.lookup("example.com").unwrap();

        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn parse_h3_request_extracts_pseudo_headers() {
        let list = vec![
            quiche::h3::Header::new(b":method", b"POST"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"example.com:443"),
            quiche::h3::Header::new(b":path", b"/upload?x=1"),
            quiche::h3::Header::new(b"content-type", b"text/plain"),
        ];
        let req = parse_h3_request(&list).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/upload?x=1");
        assert_eq!(req.authority, "example.com:443");
        assert_eq!(
            req.headers,
            vec![("content-type".to_string(), "text/plain".to_string())]
        );
    }

    #[test]
    fn parse_h3_request_falls_back_to_host_header() {
        let list = vec![
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b":path", b"/"),
            quiche::h3::Header::new(b"host", b"fallback.example.com"),
        ];
        let req = parse_h3_request(&list).unwrap();
        assert_eq!(req.authority, "fallback.example.com");
    }

    #[test]
    fn parse_h3_request_preserves_extended_connect_protocol() {
        let list = vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", b"websocket"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"example.com"),
            quiche::h3::Header::new(b":path", b"/socket"),
        ];

        let req = parse_h3_request(&list).unwrap();

        assert_eq!(req.protocol.as_deref(), Some("websocket"));
    }

    #[test]
    fn parse_h3_request_rejects_missing_pseudo_headers() {
        let list = vec![quiche::h3::Header::new(b":method", b"GET")];
        assert!(parse_h3_request(&list).is_none());
    }

    #[test]
    fn h3_request_trailers_cancel_handler_and_queue_clear_error() {
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let mut stream = StreamState {
            cancel_tx: Some(cancel_tx),
            req_body_tx: Some(mpsc::channel(1).0),
            pending_body: VecDeque::from([b"stale".to_vec()]),
            pending_body_bytes: 5,
            ..Default::default()
        };

        assert_eq!(
            reject_request_trailers(&mut stream),
            TrailerRejection::ResponseQueued
        );
        assert!(*cancel_rx.borrow());
        assert!(stream.handler_cancelled);
        assert!(stream.req_stream_finished);
        assert!(stream.req_body_tx.is_none());
        assert_eq!(
            stream
                .pending_body
                .iter()
                .flatten()
                .copied()
                .collect::<Vec<_>>(),
            b"Request Trailers Not Supported"
        );
        assert_eq!(
            stream.pending_body_bytes,
            b"Request Trailers Not Supported".len()
        );
        let (headers, fin) = stream.pending_headers.as_ref().unwrap();
        assert!(!fin);
        assert!(
            headers
                .iter()
                .any(|header| header.name() == b":status" && header.value() == b"501")
        );
    }

    #[test]
    fn full_closed_body_channel_switches_to_discard_mode() {
        // 🧠 Regression: a handler that answered 413 for an oversized body can
        // leave its request-body channel full with its receiver dropped. The
        // drain loop must detect the closed channel and clear it even when
        // `capacity() == 0`, or the deferred drain never resumes and the
        // client's upload hangs forever on closed QUIC flow control.
        let (tx, rx) = mpsc::channel::<Vec<u8>>(1);
        tx.try_send(vec![0x42]).unwrap();
        drop(rx);

        let mut stream = StreamState {
            req_body_tx: Some(tx),
            body_read_pending: true,
            ..Default::default()
        };

        assert!(drop_closed_handler_channel(&mut stream.req_body_tx));
        assert!(stream.req_body_tx.is_none());
        assert!(stream.body_read_pending, "cleared by the next drain pass");
    }

    #[test]
    fn alive_full_body_channel_is_not_dropped() {
        // 🧠 A live handler may still be draining: dropping its channel now
        // would discard bytes the handler still needs. Only a closed
        // receiver may be cleared.
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(1);
        tx.try_send(vec![0x42]).unwrap();

        let mut stream = StreamState {
            req_body_tx: Some(tx),
            ..Default::default()
        };

        assert!(!drop_closed_handler_channel(&mut stream.req_body_tx));
        assert!(stream.req_body_tx.is_some());
    }

    #[test]
    fn pending_drain_ids_only_include_deferred_streams() {
        // 🧠 The retry pass must resume exactly the streams whose drain
        // stopped on a full channel, leaving healthy streams untouched.
        let mut streams = HashMap::new();
        streams.insert(0, StreamState::default());
        streams.insert(
            4,
            StreamState {
                body_read_pending: true,
                ..Default::default()
            },
        );
        streams.insert(
            8,
            StreamState {
                body_read_pending: true,
                req_stream_finished: true,
                ..Default::default()
            },
        );

        let mut pending = pending_body_drain_ids(&streams);
        pending.sort_unstable();
        assert_eq!(pending, vec![4, 8]);
    }

    #[test]
    fn body_event_fits_respects_the_per_stream_cap() {
        // 🧠 The backlog must defer body chunks that would push a stream over
        // `BODY_QUEUE_CAP`; unknown streams are treated as fitting so their
        // events drain to a harmless no-op. An empty queue always fits so a
        // single oversized chunk (e.g. one 512 KiB handler body) cannot be
        // stranded in the backlog forever.
        let mut streams = HashMap::new();
        streams.insert(
            0,
            StreamState {
                pending_body_bytes: BODY_QUEUE_CAP,
                ..Default::default()
            },
        );
        streams.insert(
            4,
            StreamState {
                pending_body_bytes: BODY_QUEUE_CAP - 1,
                ..Default::default()
            },
        );
        streams.insert(12, StreamState::default());

        assert!(!H3App::body_event_fits(&streams, 0, 1));
        assert!(H3App::body_event_fits(&streams, 4, 1));
        assert!(!H3App::body_event_fits(&streams, 4, BODY_QUEUE_CAP));
        assert!(H3App::body_event_fits(&streams, 8, usize::MAX / 2));
        assert!(H3App::body_event_fits(&streams, 12, BODY_QUEUE_CAP * 4));
    }

    #[test]
    fn h3_request_trailers_reset_a_committed_response() {
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let mut stream = StreamState {
            headers_sent: true,
            cancel_tx: Some(cancel_tx),
            ..Default::default()
        };

        assert_eq!(
            reject_request_trailers(&mut stream),
            TrailerRejection::ResetRequired
        );
        assert!(*cancel_rx.borrow());
        assert!(stream.dead);
    }

    #[tokio::test]
    async fn h3_request_cancellation_preempts_handler_work() {
        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        cancel_tx.send(true).unwrap();

        let result = run_until_request_cancelled(&mut cancel_rx, async { 7 }).await;

        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn h3_normal_stream_cleanup_does_not_cancel_completed_work() {
        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        drop(cancel_tx);

        let result = run_until_request_cancelled(&mut cancel_rx, async { 7 }).await;

        assert_eq!(result, Some(7));
    }

    #[tokio::test]
    async fn h3_bridge_retries_a_configured_bodyless_status() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            for attempt in 1..=2 {
                let (mut stream, _) = upstream.accept().await.unwrap();
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = stream.read(&mut chunk).await.unwrap();
                    assert!(read > 0, "H3 bridge request closed before its headers");
                    request.extend_from_slice(&chunk[..read]);
                }
                let (status, body) = if attempt == 1 {
                    ("503 Service Unavailable", "retry")
                } else {
                    ("200 OK", "ok")
                };
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        });

        let state = proxy_state(HandlerConfig::ReverseProxy(Box::new(ReverseProxyConfig {
            upstreams: vec![format!("http://{upstream_address}")],
            retry: Box::new(RetryConfig {
                max_attempts: 2,
                status_codes: vec![503],
                methods: vec!["GET".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        })));
        let proxy = PingclairProxy::new();
        let connector = pingora_core::connectors::http::Connector::new(Some(
            pingora_core::connectors::ConnectorOptions::new(16),
        ));
        let request = H3Request {
            method: "GET".to_string(),
            protocol: None,
            path: "/retry".to_string(),
            authority: "example.test".to_string(),
            headers: Vec::new(),
        };
        let client_header = RequestHeader::build(http::Method::GET, b"/retry", None).unwrap();
        let (body_tx, mut body_rx) = mpsc::channel(1);
        drop(body_tx);
        let (resp_tx, mut resp_rx) = mpsc::channel(8);
        let body_notify = Arc::new(Notify::new());

        reverse_proxy_upstream(
            &proxy,
            &connector,
            &state,
            0,
            &request,
            &client_header,
            &request.path,
            "127.0.0.1".parse().unwrap(),
            "127.0.0.1",
            "retry-request-id",
            &ResponseHeaderPolicy::default(),
            0,
            0,
            &mut body_rx,
            &resp_tx,
            &body_notify,
            Instant::now(),
            &crate::http_policy::RequestVars::default(),
        )
        .await
        .unwrap();

        let response = resp_rx.recv().await.unwrap();
        let RespMsg::Headers(headers, false) = response.msg else {
            panic!("expected H3 response headers");
        };
        assert!(
            headers
                .iter()
                .any(|header| header.name() == b":status" && header.value() == b"200")
        );
        let body = resp_rx.recv().await.unwrap();
        assert!(matches!(
            body.msg,
            RespMsg::Body(ref bytes, false) if bytes == b"ok"
        ));
        upstream_task.await.unwrap();
    }

    #[tokio::test]
    async fn h3_bridge_respects_an_open_upstream_circuit() {
        use pingclair_core::config::CircuitBreakerConfig;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read > 0, "H3 bridge request closed before its headers");
                request.extend_from_slice(&chunk[..read]);
            }
            stream
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 6\r\nConnection: close\r\n\r\nfailed",
                )
                .await
                .unwrap();
        });

        let state = proxy_state(HandlerConfig::ReverseProxy(Box::new(ReverseProxyConfig {
            upstreams: vec![format!("http://{upstream_address}")],
            retry: Box::new(RetryConfig {
                max_attempts: 1,
                ..Default::default()
            }),
            circuit_breaker: Box::new(CircuitBreakerConfig {
                consecutive_failures: Some(1),
                open_duration_ms: 30_000,
                ..Default::default()
            }),
            ..Default::default()
        })));
        let proxy = PingclairProxy::new();
        let connector = pingora_core::connectors::http::Connector::new(Some(
            pingora_core::connectors::ConnectorOptions::new(16),
        ));
        let request = H3Request {
            method: "GET".to_string(),
            protocol: None,
            path: "/circuit".to_string(),
            authority: "example.test".to_string(),
            headers: Vec::new(),
        };
        let client_header = RequestHeader::build(http::Method::GET, b"/circuit", None).unwrap();

        let (body_tx, mut body_rx) = mpsc::channel(1);
        drop(body_tx);
        let (resp_tx, _resp_rx) = mpsc::channel(8);
        reverse_proxy_upstream(
            &proxy,
            &connector,
            &state,
            0,
            &request,
            &client_header,
            &request.path,
            "127.0.0.1".parse().unwrap(),
            "127.0.0.1",
            "circuit-request-id",
            &ResponseHeaderPolicy::default(),
            0,
            0,
            &mut body_rx,
            &resp_tx,
            &Arc::new(Notify::new()),
            Instant::now(),
            &crate::http_policy::RequestVars::default(),
        )
        .await
        .unwrap();
        upstream_task.await.unwrap();

        let (body_tx, mut body_rx) = mpsc::channel(1);
        drop(body_tx);
        let (resp_tx, _resp_rx) = mpsc::channel(8);
        let result = reverse_proxy_upstream(
            &proxy,
            &connector,
            &state,
            0,
            &request,
            &client_header,
            &request.path,
            "127.0.0.1".parse().unwrap(),
            "127.0.0.1",
            "circuit-request-id",
            &ResponseHeaderPolicy::default(),
            0,
            4,
            &mut body_rx,
            &resp_tx,
            &Arc::new(Notify::new()),
            Instant::now(),
            &crate::http_policy::RequestVars::default(),
        )
        .await;
        assert_eq!(result, Err((503, "Upstream Overloaded")));
    }

    #[tokio::test]
    async fn h3_bridge_preserves_h2c_grpc_response_trailers() {
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let (response_read_tx, response_read_rx) = tokio::sync::oneshot::channel();
        let upstream_task = tokio::spawn(async move {
            let (stream, _) = upstream.accept().await.unwrap();
            let mut connection = h2::server::handshake(stream).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(
                request.headers().get("te").unwrap(),
                http::HeaderValue::from_static("trailers")
            );

            let response = http::Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, "application/grpc")
                .body(())
                .unwrap();
            let mut body = respond.send_response(response, false).unwrap();
            body.send_data(Bytes::from_static(b"\0\0\0\0\0"), false)
                .unwrap();
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
            trailers.insert("grpc-message", http::HeaderValue::from_static("healthy"));
            body.send_trailers(trailers).unwrap();

            tokio::select! {
                _ = async {
                    while connection.accept().await.is_some() {}
                } => {}
                _ = response_read_rx => {}
            }
        });

        let state = proxy_state(HandlerConfig::ReverseProxy(Box::new(ReverseProxyConfig {
            upstreams: vec![format!("h2c://{upstream_address}")],
            ..Default::default()
        })));
        let proxy = PingclairProxy::new();
        let connector = pingora_core::connectors::http::Connector::new(Some(
            pingora_core::connectors::ConnectorOptions::new(16),
        ));
        let request = H3Request {
            method: "POST".to_string(),
            protocol: None,
            path: "/grpc.health.v1.Health/Check".to_string(),
            authority: "example.test".to_string(),
            headers: vec![
                ("content-type".to_string(), "application/grpc".to_string()),
                ("te".to_string(), "trailers".to_string()),
            ],
        };
        let mut client_header =
            RequestHeader::build(http::Method::POST, b"/grpc.health.v1.Health/Check", None)
                .unwrap();
        client_header
            .insert_header(http::header::CONTENT_TYPE, "application/grpc")
            .unwrap();
        let (body_tx, mut body_rx) = mpsc::channel(1);
        drop(body_tx);
        let (resp_tx, mut resp_rx) = mpsc::channel(8);
        let body_notify = Arc::new(Notify::new());

        reverse_proxy_upstream(
            &proxy,
            &connector,
            &state,
            0,
            &request,
            &client_header,
            &request.path,
            "127.0.0.1".parse().unwrap(),
            "127.0.0.1",
            "test-request-id",
            &ResponseHeaderPolicy::default(),
            0,
            0,
            &mut body_rx,
            &resp_tx,
            &body_notify,
            Instant::now(),
            &crate::http_policy::RequestVars::default(),
        )
        .await
        .unwrap();

        let headers = resp_rx.recv().await.unwrap();
        assert!(matches!(headers.msg, RespMsg::Headers(_, false)));
        let body = resp_rx.recv().await.unwrap();
        assert!(matches!(
            body.msg,
            RespMsg::Body(ref bytes, false) if bytes == b"\0\0\0\0\0"
        ));
        let trailers = resp_rx.recv().await.unwrap();
        let RespMsg::Trailers(trailers) = trailers.msg else {
            panic!("expected H3 response trailers");
        };
        assert!(
            trailers
                .iter()
                .any(|header| header.name() == b"grpc-status" && header.value() == b"0")
        );
        assert!(
            trailers
                .iter()
                .any(|header| header.name() == b"grpc-message" && header.value() == b"healthy")
        );

        response_read_tx.send(()).unwrap();
        upstream_task.await.unwrap();
    }

    #[tokio::test]
    async fn h3_pipeline_applies_cors_regex_rewrite_and_terminal_response() {
        let handler = HandlerConfig::Pipeline {
            handlers: vec![
                HandlerElement::plain(HandlerConfig::Cors {
                    allowed_origins: vec!["https://app.example".to_string()],
                    allowed_methods: vec!["GET".to_string()],
                    allowed_headers: vec!["content-type".to_string()],
                    exposed_headers: vec!["x-request-id".to_string()],
                    allow_credentials: true,
                    max_age: 600,
                }),
                HandlerElement::plain(HandlerConfig::Rewrite {
                    strip_prefix: None,
                    strip_suffix: None,
                    replace: None,
                    regex: Some(r"^/old/(.*)$".to_string()),
                    regex_replace: Some("/new/$1".to_string()),
                }),
                HandlerElement::plain(HandlerConfig::Respond {
                    status: 200,
                    body: Some("ok".to_string()),
                    headers: BTreeMap::new(),
                }),
            ],
        };
        let state = proxy_state(handler.clone());
        let mut request = RequestHeader::build(http::Method::GET, b"/old/item?q=1", None).unwrap();
        request
            .insert_header("origin", "https://app.example")
            .unwrap();
        let mut uri = "/old/item?q=1".to_string();
        let mut policy = ResponseHeaderPolicy::default();

        let plan = plan_h3_handler(
            &handler,
            &state,
            0,
            &mut request,
            &mut uri,
            &mut policy,
            "203.0.113.7",
            None,
            false,
            &mut crate::http_policy::RequestVars::default(),
        )
        .await
        .unwrap();

        assert!(matches!(
            plan,
            H3Plan::Terminal(H3Terminal::Respond { status: 200, .. })
        ));
        assert_eq!(uri, "/new/item?q=1");
        assert_eq!(
            request.uri.path_and_query().unwrap().as_str(),
            "/new/item?q=1"
        );
        assert!(policy.set_headers().any(|(name, value)| {
            name == "access-control-allow-origin" && value == "https://app.example"
        }));
    }

    #[tokio::test]
    async fn h3_preflight_rejects_before_terminal_handler() {
        let handler = HandlerConfig::Pipeline {
            handlers: vec![
                HandlerElement::plain(HandlerConfig::Cors {
                    allowed_origins: vec!["https://app.example".to_string()],
                    allowed_methods: vec!["GET".to_string()],
                    allowed_headers: vec!["content-type".to_string()],
                    exposed_headers: Vec::new(),
                    allow_credentials: false,
                    max_age: 600,
                }),
                HandlerElement::plain(HandlerConfig::Respond {
                    status: 200,
                    body: Some("must not run".to_string()),
                    headers: BTreeMap::new(),
                }),
            ],
        };
        let state = proxy_state(handler.clone());
        let mut request = RequestHeader::build(http::Method::OPTIONS, b"/resource", None).unwrap();
        request
            .insert_header("origin", "https://app.example")
            .unwrap();
        request
            .insert_header("access-control-request-method", "DELETE")
            .unwrap();
        let mut uri = "/resource".to_string();
        let mut policy = ResponseHeaderPolicy::default();

        let plan = plan_h3_handler(
            &handler,
            &state,
            0,
            &mut request,
            &mut uri,
            &mut policy,
            "203.0.113.7",
            None,
            false,
            &mut crate::http_policy::RequestVars::default(),
        )
        .await
        .unwrap();

        assert!(matches!(
            plan,
            H3Plan::Respond(H3ImmediateResponse { status: 403, .. })
        ));
    }

    #[tokio::test]
    async fn h3_vars_set_values_visible_to_later_placeholders() {
        let handler = HandlerConfig::Pipeline {
            handlers: vec![
                HandlerElement::plain(HandlerConfig::Vars {
                    values: BTreeMap::from([("who".to_string(), "h3".to_string())]),
                }),
                HandlerElement::plain(HandlerConfig::Respond {
                    status: 200,
                    body: Some("{http.vars.who}".to_string()),
                    headers: BTreeMap::new(),
                }),
            ],
        };
        let state = proxy_state(handler.clone());
        let mut request = RequestHeader::build(http::Method::GET, b"/", None).unwrap();
        let mut uri = "/".to_string();
        let mut policy = ResponseHeaderPolicy::default();

        let plan = plan_h3_handler(
            &handler,
            &state,
            0,
            &mut request,
            &mut uri,
            &mut policy,
            "203.0.113.7",
            None,
            false,
            &mut crate::http_policy::RequestVars::default(),
        )
        .await
        .unwrap();
        assert!(matches!(
            plan,
            H3Plan::Terminal(H3Terminal::Respond {
                body: Some(ref body),
                ..
            }) if body == "h3"
        ));
    }

    #[tokio::test]
    async fn h3_header_policy_survives_basic_auth_rejection() {
        let handler = HandlerConfig::Pipeline {
            handlers: vec![
                HandlerElement::plain(HandlerConfig::Headers {
                    set: BTreeMap::from([("x-policy".to_string(), "active".to_string())]),
                    add: BTreeMap::new(),
                    remove: Vec::new(),
                }),
                HandlerElement::plain(HandlerConfig::BasicAuth {
                    realm: "Restricted".to_string(),
                    credentials: vec![BasicAuthCredential {
                        username: "alice".to_string(),
                        password: "$2y$04$BjuNmKvAV.mEi7.yFrazX.S6w6OO7H0BzQfyVVFZBq/qbVXCVNX4W"
                            .to_string(),
                        algorithm: pingclair_core::config::BasicAuthAlgorithm::Bcrypt,
                    }],
                }),
            ],
        };
        let state = proxy_state(handler.clone());
        let mut request = RequestHeader::build(http::Method::GET, b"/private", None).unwrap();
        let mut uri = "/private".to_string();
        let mut policy = ResponseHeaderPolicy::default();

        let plan = plan_h3_handler(
            &handler,
            &state,
            0,
            &mut request,
            &mut uri,
            &mut policy,
            "203.0.113.7",
            None,
            false,
            &mut crate::http_policy::RequestVars::default(),
        )
        .await
        .unwrap();

        assert!(matches!(
            plan,
            H3Plan::Respond(H3ImmediateResponse { status: 401, .. })
        ));
        assert!(
            policy
                .set_headers()
                .any(|(name, value)| name == "x-policy" && value == "active")
        );
    }

    #[tokio::test]
    async fn h3_handle_path_rewrites_the_terminal_uri() {
        let handler = HandlerConfig::HandlePath {
            prefix: "/api".to_string(),
            handlers: vec![HandlerElement::plain(HandlerConfig::ReverseProxy(
                Default::default(),
            ))],
        };
        let state = proxy_state(handler.clone());
        let mut request = RequestHeader::build(http::Method::GET, b"/api/users?q=1", None).unwrap();
        let mut uri = "/api/users?q=1".to_string();
        let mut policy = ResponseHeaderPolicy::default();

        let plan = plan_h3_handler(
            &handler,
            &state,
            0,
            &mut request,
            &mut uri,
            &mut policy,
            "203.0.113.7",
            None,
            false,
            &mut crate::http_policy::RequestVars::default(),
        )
        .await
        .unwrap();

        assert!(matches!(plan, H3Plan::Terminal(H3Terminal::ReverseProxy)));
        assert_eq!(uri, "/users?q=1");
    }

    #[tokio::test]
    async fn h3_respond_expands_placeholders_like_h1_h2() {
        let handler = HandlerConfig::Respond {
            status: 200,
            body: Some("path={path} scheme={scheme} host={host} remote={remote_ip}".to_string()),
            headers: BTreeMap::new(),
        };
        let state = proxy_state(handler.clone());
        let mut request = RequestHeader::build(http::Method::GET, b"/probe?q=1", None).unwrap();
        request.insert_header("host", "probe.example").unwrap();
        let mut uri = "/probe?q=1".to_string();
        let mut policy = ResponseHeaderPolicy::default();

        let plan = plan_h3_handler(
            &handler,
            &state,
            0,
            &mut request,
            &mut uri,
            &mut policy,
            "203.0.113.7",
            None,
            false,
            &mut crate::http_policy::RequestVars::default(),
        )
        .await
        .unwrap();

        match plan {
            H3Plan::Terminal(H3Terminal::Respond { body, .. }) => {
                assert_eq!(
                    body.as_deref(),
                    Some("path=/probe scheme=https host=probe.example remote=203.0.113.7")
                );
            }
            _ => panic!("expected a respond terminal"),
        }
    }

    #[tokio::test]
    async fn h3_redirect_expands_the_verified_remote_ip() {
        let handler = HandlerConfig::Redirect {
            to: "https://{host}/from/{remote_host}".to_string(),
            code: 302,
        };
        let state = proxy_state(handler.clone());
        let mut request = RequestHeader::build(http::Method::GET, b"/probe", None).unwrap();
        request.insert_header("host", "probe.example").unwrap();
        let mut uri = "/probe".to_string();
        let mut policy = ResponseHeaderPolicy::default();

        let plan = plan_h3_handler(
            &handler,
            &state,
            0,
            &mut request,
            &mut uri,
            &mut policy,
            "203.0.113.9",
            None,
            false,
            &mut crate::http_policy::RequestVars::default(),
        )
        .await
        .unwrap();

        match plan {
            H3Plan::Terminal(H3Terminal::Redirect { to, .. }) => {
                assert_eq!(to, "https://probe.example/from/203.0.113.9");
            }
            _ => panic!("expected a redirect terminal"),
        }
    }

    #[tokio::test]
    async fn h3_pipeline_elements_respect_their_own_matchers() {
        let handler = HandlerConfig::Pipeline {
            handlers: vec![
                HandlerElement::with_matcher(
                    Matcher::Path {
                        patterns: vec!["/admin/*".to_string()],
                    },
                    HandlerConfig::Respond {
                        status: 200,
                        body: Some("SECRET".to_string()),
                        headers: BTreeMap::new(),
                    },
                ),
                HandlerElement::plain(HandlerConfig::Respond {
                    status: 200,
                    body: Some("public".to_string()),
                    headers: BTreeMap::new(),
                }),
            ],
        };
        let state = proxy_state(handler.clone());
        let precompile = state
            .router
            .compiled_route(0)
            .map(|route| &route.matcher_precompile);

        let mut request = RequestHeader::build(http::Method::GET, b"/admin/secrets", None).unwrap();
        let mut uri = "/admin/secrets".to_string();
        let mut policy = ResponseHeaderPolicy::default();
        let plan = plan_h3_handler(
            &handler,
            &state,
            0,
            &mut request,
            &mut uri,
            &mut policy,
            "203.0.113.7",
            precompile,
            false,
            &mut crate::http_policy::RequestVars::default(),
        )
        .await
        .unwrap();
        let H3Plan::Terminal(H3Terminal::Respond { body, .. }) = plan else {
            panic!("expected a respond terminal");
        };
        assert_eq!(body.as_deref(), Some("SECRET"));

        let mut request = RequestHeader::build(http::Method::GET, b"/public", None).unwrap();
        let mut uri = "/public".to_string();
        let mut policy = ResponseHeaderPolicy::default();
        let plan = plan_h3_handler(
            &handler,
            &state,
            0,
            &mut request,
            &mut uri,
            &mut policy,
            "203.0.113.7",
            precompile,
            false,
            &mut crate::http_policy::RequestVars::default(),
        )
        .await
        .unwrap();
        let H3Plan::Terminal(H3Terminal::Respond { body, .. }) = plan else {
            panic!("expected the second respond terminal");
        };
        assert_eq!(body.as_deref(), Some("public"));
    }

    #[test]
    fn h3_response_policy_replaces_removes_and_appends_headers() {
        let mut headers = vec![
            quiche::h3::Header::new(b":status", b"200"),
            quiche::h3::Header::new(b"x-old", b"remove-me"),
            quiche::h3::Header::new(b"x-set", b"old"),
        ];
        let mut policy = ResponseHeaderPolicy::default();
        policy.set("x-set", "new");
        policy.add("vary", "Origin");
        policy.remove("x-old");
        apply_h3_response_policy(&mut headers, &policy, "request-123", None);

        assert!(!headers.iter().any(|header| header.name() == b"x-old"));
        assert!(
            headers
                .iter()
                .any(|header| header.name() == b"x-set" && header.value() == b"new")
        );
        assert!(
            headers
                .iter()
                .any(|header| header.name() == b"vary" && header.value() == b"Origin")
        );
        assert!(headers.iter().any(|header| {
            header.name() == b"x-request-id" && header.value() == b"request-123"
        }));
    }

    // MARK: - Cross-transport policy parity

    /// 🔀 Renders a policy the way the HTTP/1.1 and HTTP/2 path renders it.
    ///
    /// `via_hop` is `None` on purpose: H3 appends `Via` at its own call sites
    /// rather than inside [`apply_h3_response_policy`], so including it here
    /// would compare two things that were never meant to line up. Everything
    /// else in the shared policy — replacements, appends, removals, the
    /// `Server` decision and the request id — is common ground.
    fn rendered_by_pingora(policy: &ResponseHeaderPolicy) -> Vec<(String, String)> {
        let mut response = pingora_http::ResponseHeader::build(200, None).unwrap();
        policy
            .apply_pingora(
                &mut response,
                &http::HeaderValue::from_static("request-123"),
                None,
            )
            .expect("the policy must apply cleanly");
        let mut rendered: Vec<(String, String)> = response
            .headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_ascii_lowercase(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        rendered.sort();
        rendered
    }

    /// 🔀 Renders the same policy the way the HTTP/3 path renders it.
    fn rendered_by_h3(policy: &ResponseHeaderPolicy) -> Vec<(String, String)> {
        let mut headers = vec![quiche::h3::Header::new(b":status", b"200")];
        apply_h3_response_policy(&mut headers, policy, "request-123", None);
        let mut rendered: Vec<(String, String)> = headers
            .iter()
            // 🚫 `:status` has no HeaderMap counterpart; it is framing, not a field.
            .filter(|header| !header.name().starts_with(b":"))
            .map(|header| {
                (
                    String::from_utf8_lossy(header.name()).to_ascii_lowercase(),
                    String::from_utf8_lossy(header.value()).into_owned(),
                )
            })
            .collect();
        rendered.sort();
        rendered
    }

    /// 🛡️ The shared policy layer must mean the same thing on both transports.
    ///
    /// This exists because it keeps not being true. The most recent instance:
    /// `apply_pingora` looked an appended header's precomputed value up by
    /// name instead of by position, so a route with `header +Vary
    /// Accept-Encoding` merged with CORS emitted `Vary: Accept-Encoding`
    /// twice and dropped `Vary: Origin` — while H3, which reads the pairs
    /// directly, stayed correct. Both transports had their own passing tests;
    /// nothing compared them to each other.
    ///
    /// Comparison is over the sorted multiset rather than the sequence,
    /// because `set` is a `HashMap` and its iteration order is not stable.
    /// A multiset still distinguishes the failure above: emitting one value
    /// twice is not the same bag as emitting two different values once each.
    #[test]
    fn both_transports_render_the_same_policy_identically() {
        let cases: Vec<(&str, ResponseHeaderPolicy)> = vec![
            ("empty", ResponseHeaderPolicy::default()),
            ("one replacement", {
                let mut policy = ResponseHeaderPolicy::default();
                policy.set("x-set", "value");
                policy
            }),
            ("one append", {
                let mut policy = ResponseHeaderPolicy::default();
                policy.add("vary", "Origin");
                policy
            }),
            // 🚨 The regression that motivated this test.
            ("the same name appended twice", {
                let mut policy = ResponseHeaderPolicy::default();
                policy.add("vary", "Accept-Encoding");
                policy.add("vary", "Origin");
                policy
            }),
            ("the same name appended three times", {
                let mut policy = ResponseHeaderPolicy::default();
                policy.add("link", "</a.css>; rel=preload");
                policy.add("link", "</b.js>; rel=preload");
                policy.add("link", "</c.png>; rel=preload");
                policy
            }),
            // 🔗 The reachable shape: a route policy merged with a CORS decision.
            ("a merged route and CORS policy", {
                let mut route = ResponseHeaderPolicy::default();
                route.add("vary", "Accept-Encoding");
                route.set("cache-control", "public, max-age=60");
                let mut cors = ResponseHeaderPolicy::default();
                cors.add("vary", "Origin");
                cors.set("access-control-allow-origin", "https://example.test");
                route.merge(cors);
                route
            }),
            ("a replacement that is also removed", {
                let mut policy = ResponseHeaderPolicy::default();
                policy.set("x-temp", "value");
                policy.remove("x-temp");
                policy
            }),
            ("a suppressed Server header", {
                let mut policy = ResponseHeaderPolicy::default();
                policy.remove("server");
                policy
            }),
            ("appends and removals of unrelated names", {
                let mut policy = ResponseHeaderPolicy::default();
                policy.add("x-keep", "one");
                policy.add("x-keep", "two");
                policy.remove("x-gone");
                policy.set("x-set", "final");
                policy
            }),
        ];

        for (description, policy) in cases {
            assert_eq!(
                rendered_by_pingora(&policy),
                rendered_by_h3(&policy),
                "H1/H2 and H3 disagreed on the policy for: {description}"
            );
        }
    }
}
