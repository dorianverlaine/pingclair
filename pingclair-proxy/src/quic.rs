//! HTTP/3 (QUIC) server built on Cloudflare's quiche (BoringSSL).
//!
//! 🏗️ ARCHITECTURE
//!
//! - One UDP socket and one tokio task per HTTPS listen port
//!   ([`QuicServer::run`]). The task single-threads the whole QUIC state:
//!   a `HashMap<ConnectionId, ConnState>` with no locks on the hot path.
//! - The datagram/timeout loop follows the structure of quiche's
//!   `examples/http3-server.rs`, adapted to tokio (`UdpSocket` +
//!   `tokio::select!` + `tokio::time::sleep` for `conn.timeout()`).
//! - SNI multi-certificate support uses BoringSSL's
//!   `select_certificate_callback` backed by an [`ArcSwap`]-published
//!   [`CertTable`], so ACME renewals are picked up by new handshakes
//!   without restarting the listener.
//! - Every HTTP/3 request is dispatched to a tokio task that reuses
//!   [`PingclairProxy::match_route`] (the same routing entry point as the
//!   H1/H2 path). Response bytes flow back to the event loop over a
//!   channel and are written through quiche with real flow control
//!   (pending buffers + writable-stream events), so large static files
//!   and upstream responses are streamed, never buffered whole.
//! - Reverse-proxying goes through Pingora's [`Connector`], i.e. the same
//!   keepalive connection pool, TLS-to-upstream support and timeout
//!   semantics as the H1/H2 path.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc};

use pingclair_core::config::HandlerConfig;
use pingclair_static::ServedResponse;
use pingora_http::RequestHeader;
use quiche::h3::NameValue;

use crate::connection_filter::PingclairConnectionFilter;
use crate::server::{PingclairProxy, find_basic_auth_config, resolve_caddy_placeholders};

/// Maximum UDP payload we ask quiche to send (standard Ethernet MTU-safe).
const MAX_DATAGRAM_SIZE: usize = 1350;

/// Bound for the per-stream request-body channel between the event loop
/// and a handler task. When full, the event loop stops draining quiche so
/// QUIC flow control pushes back on the client.
const REQ_BODY_CHANNEL_CAPACITY: usize = 16;

/// Bound for the global response channel shared by all handler tasks.
const RESP_CHANNEL_CAPACITY: usize = 256;

/// Read size for draining request bodies out of quiche.
const BODY_CHUNK_SIZE: usize = 16 * 1024;

/// Idle fallback for the event loop when no connection has an active timer.
const NO_TIMER_SLEEP: Duration = Duration::from_secs(3600);

/// Length of the authentication tag appended to stateless-retry tokens.
const TOKEN_TAG_LEN: usize = 16;

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

/// Build the quiche configuration with an SNI-aware BoringSSL context.
fn build_quiche_config(certs: Arc<CertTable>) -> Result<quiche::Config, QuicError> {
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

    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder)
        .map_err(|e| QuicError::Tls(format!("failed to build quiche config: {e}")))?;

    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|e| QuicError::Tls(format!("failed to set ALPN: {e}")))?;

    config.set_max_idle_timeout(30_000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.enable_early_data();

    Ok(config)
}

// MARK: - Stateless retry tokens

/// Compute the authentication tag for a retry token.
///
/// BoringSSL's Rust bindings don't expose a bare HMAC, so we use PBKDF2
/// with a single iteration: its PRF is HMAC-SHA256 keyed by `key`, which
/// makes this a strong keyed PRF of the token body.
fn token_tag(key: &[u8; 32], body: &[u8]) -> [u8; TOKEN_TAG_LEN] {
    let mut tag = [0u8; TOKEN_TAG_LEN];
    // Infallible in practice (all buffers are small); a failure would just
    // yield a tag that never validates, which fails closed.
    let _ = boring::pkcs5::pbkdf2_hmac(
        key,
        body,
        1,
        boring::hash::MessageDigest::sha256(),
        &mut tag,
    );
    tag
}

/// Mint a stateless retry token binding the client IP to the original
/// destination connection ID it chose.
fn mint_token(key: &[u8; 32], dcid: &[u8], src: &SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();
    match src.ip() {
        IpAddr::V4(a) => {
            token.push(4u8);
            token.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            token.push(6u8);
            token.extend_from_slice(&a.octets());
        }
    }
    token.extend_from_slice(dcid);
    let tag = token_tag(key, &token);
    token.extend_from_slice(&tag);
    token
}

/// Validate a retry token; on success returns the original destination
/// connection ID to pass to `quiche::accept`.
fn validate_token<'a>(
    key: &[u8; 32],
    src: &SocketAddr,
    token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
    let (family, rest) = token.split_first()?;
    let ip_len = match family {
        4 => 4usize,
        6 => 16usize,
        _ => return None,
    };
    if rest.len() < ip_len + TOKEN_TAG_LEN + 1 {
        return None;
    }

    let (ip_bytes, rest) = rest.split_at(ip_len);
    let matches_ip = match (src.ip(), family) {
        (IpAddr::V4(a), 4) => a.octets() == ip_bytes,
        (IpAddr::V6(a), 6) => a.octets() == ip_bytes,
        _ => false,
    };
    if !matches_ip {
        return None;
    }

    let (odcid, tag) = rest.split_at(rest.len() - TOKEN_TAG_LEN);
    let body_len = 1 + ip_len + odcid.len();
    let expected = token_tag(key, &token[..body_len]);
    if !boring::memcmp::eq(&expected, tag) {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(odcid))
}

// MARK: - Request/response plumbing

/// One parsed HTTP/3 request, handed to a handler task.
struct H3Request {
    method: String,
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
    let mut path = None;
    let mut authority = None;
    let mut headers = Vec::new();

    for h in list {
        let value = String::from_utf8_lossy(h.value()).into_owned();
        match h.name() {
            b":method" => method = Some(value),
            b":path" => path = Some(value),
            b":authority" => authority = Some(value),
            b":scheme" | b":protocol" => {}
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
        path: path?,
        authority: authority?,
        headers,
    })
}

/// Messages from handler tasks back to the event loop.
enum RespMsg {
    /// Response headers; bool = fin (no body follows).
    Headers(Vec<quiche::h3::Header>, bool),
    /// Body chunk; bool = fin.
    Body(Vec<u8>, bool),
}

struct RespEvent {
    cid: quiche::ConnectionId<'static>,
    stream_id: u64,
    msg: RespMsg,
}

type RespSender = mpsc::Sender<RespEvent>;

type ConnMap = HashMap<quiche::ConnectionId<'static>, ConnState>;

// MARK: - Connection / stream state

/// Per-stream state owned by the event loop.
#[derive(Default)]
struct StreamState {
    /// Response headers not yet written (e.g. stream was blocked).
    pending_headers: Option<(Vec<quiche::h3::Header>, bool)>,
    headers_sent: bool,
    /// Response body bytes accepted from the handler but not yet by quiche.
    pending_body: VecDeque<u8>,
    /// The handler signaled end-of-body.
    body_fin: bool,
    /// FIN was successfully written to the QUIC stream.
    fin_sent: bool,
    /// Channel feeding request-body chunks to the handler task. Dropped
    /// once the request stream finished AND all buffered body bytes were
    /// drained out of quiche, which ends the handler's receive loop.
    req_body_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// quiche reported `Event::Finished` for the request stream. Body bytes
    /// may still be buffered inside quiche at this point, so the handler
    /// channel is only closed after [`QuicServer::drain_request_body`] has
    /// pumped them all out (otherwise a large POST would be truncated and
    /// the upstream exchange would deadlock on Content-Length).
    req_stream_finished: bool,
    /// Set when the handler's channel was full at the last drain attempt;
    /// the drain is retried on later loop iterations (woken early by the
    /// shared `Notify` once the handler frees capacity).
    body_read_pending: bool,
    /// Response terminated (reset or fully sent); ignore further messages.
    dead: bool,
}

struct ConnState {
    conn: quiche::Connection,
    h3: Option<quiche::h3::Connection>,
    remote_addr: SocketAddr,
    streams: HashMap<u64, StreamState>,
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

    /// Run the event loop forever (or until the task is aborted).
    pub async fn run(self) -> Result<(), QuicError> {
        let mut config = build_quiche_config(self.certs.clone())?;
        let h3_config = quiche::h3::Config::new().map_err(|e| QuicError::H3(e.to_string()))?;

        let socket = UdpSocket::bind(self.listen).await?;
        let local_addr = socket.local_addr()?;
        tracing::info!(
            "🚀 HTTP/3 (quiche) server listening on {} (UDP)",
            local_addr
        );

        let mut token_key = [0u8; 32];
        boring::rand::rand_bytes(&mut token_key)
            .map_err(|e| QuicError::Tls(format!("failed to generate retry token key: {e}")))?;

        let mut conns: ConnMap = HashMap::new();
        let (resp_tx, mut resp_rx) = mpsc::channel::<RespEvent>(RESP_CHANNEL_CAPACITY);
        let body_notify = Arc::new(Notify::new());

        let mut buf = vec![0u8; 65535];
        let mut out = vec![0u8; MAX_DATAGRAM_SIZE];

        loop {
            // Earliest timer across all connections.
            let timeout = conns.values().filter_map(|c| c.conn.timeout()).min();

            tokio::select! {
                res = socket.recv_from(&mut buf) => {
                    match res {
                        Ok((len, from)) => {
                            self.handle_packet(
                                &socket,
                                local_addr,
                                &mut config,
                                &mut conns,
                                &h3_config,
                                &resp_tx,
                                &body_notify,
                                &token_key,
                                &mut buf[..len],
                                from,
                                &mut out,
                            ).await;
                        }
                        Err(e) => {
                            tracing::error!("H3: UDP recv failed: {}", e);
                        }
                    }
                }
                Some(ev) = resp_rx.recv() => {
                    Self::apply_resp_event(&mut conns, ev);
                }
                _ = body_notify.notified() => {
                    // A handler freed request-body channel capacity; the
                    // deferred drains are retried in the maintenance pass.
                }
                _ = tokio::time::sleep(timeout.unwrap_or(NO_TIMER_SLEEP)) => {
                    for c in conns.values_mut() {
                        c.conn.on_timeout();
                    }
                }
            }

            // Maintenance pass: retry deferred request-body drains, pump any
            // HTTP/3 events those drains queued inside quiche (e.g. the
            // Finished event that ends a request body), flush streams that
            // have something to send, push out QUIC packets, and
            // garbage-collect.
            for (cid, cs) in conns.iter_mut() {
                let pending_reads: Vec<u64> = cs
                    .streams
                    .iter()
                    .filter(|(_, s)| s.body_read_pending)
                    .map(|(id, _)| *id)
                    .collect();
                for stream_id in pending_reads {
                    Self::drain_request_body(cs, stream_id);
                }

                if cs.h3.is_some() {
                    self.pump_h3_events(cs, cid, &resp_tx, &body_notify);
                }

                let dirty: Vec<u64> = cs
                    .streams
                    .iter()
                    .filter(|(_, s)| {
                        !s.dead
                            && (s.pending_headers.is_some()
                                || !s.pending_body.is_empty()
                                || (s.body_fin && !s.fin_sent))
                    })
                    .map(|(id, _)| *id)
                    .collect();
                for stream_id in dirty {
                    Self::flush_stream(cs, stream_id);
                }

                let writable: Vec<u64> = cs.conn.writable().collect();
                for stream_id in writable {
                    Self::flush_stream(cs, stream_id);
                }

                loop {
                    match cs.conn.send(&mut out) {
                        Ok((written, send_info)) => {
                            if let Err(e) = socket.send_to(&out[..written], send_info.to).await {
                                tracing::error!("H3: UDP send failed: {}", e);
                                break;
                            }
                        }
                        Err(quiche::Error::Done) => break,
                        Err(e) => {
                            tracing::error!("{} send failed: {:?}", cs.conn.trace_id(), e);
                            cs.conn.close(false, 0x1, b"fail").ok();
                            break;
                        }
                    }
                }

                cs.streams.retain(|_, s| !s.dead);
            }

            conns.retain(|_, cs| !cs.conn.is_closed());
        }
    }

    /// Handle one incoming UDP datagram: route it to an existing connection
    /// or run the new-connection handshake (version negotiation, stateless
    /// retry, `quiche::accept`), then pump HTTP/3 events.
    #[allow(clippy::too_many_arguments)]
    async fn handle_packet(
        &self,
        socket: &UdpSocket,
        local_addr: SocketAddr,
        config: &mut quiche::Config,
        conns: &mut ConnMap,
        h3_config: &quiche::h3::Config,
        resp_tx: &RespSender,
        body_notify: &Arc<Notify>,
        token_key: &[u8; 32],
        pkt: &mut [u8],
        from: SocketAddr,
        out: &mut [u8],
    ) {
        let hdr = match quiche::Header::from_slice(pkt, quiche::MAX_CONN_ID_LEN) {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!("H3: parsing packet header failed: {:?}", e);
                return;
            }
        };

        // L4 blocklist, same semantics as the TCP connection filter.
        if !self.filter.allows(&from) {
            return;
        }

        let cid: quiche::ConnectionId<'static> = hdr.dcid.as_ref().to_vec().into();

        if !conns.contains_key(&cid) {
            if hdr.ty != quiche::Type::Initial {
                tracing::trace!("H3: packet for unknown connection is not Initial");
                return;
            }

            if !quiche::version_is_supported(hdr.version) {
                tracing::debug!("H3: doing version negotiation");
                match quiche::negotiate_version(&hdr.scid, &hdr.dcid, out) {
                    Ok(len) => {
                        if let Err(e) = socket.send_to(&out[..len], from).await {
                            tracing::error!("H3: failed to send version negotiation: {}", e);
                        }
                    }
                    Err(e) => tracing::error!("H3: version negotiation failed: {:?}", e),
                }
                return;
            }

            // Token is always present in Initial packets.
            let token = hdr.token.as_deref().unwrap_or(&[]);

            // Do stateless retry if the client didn't send a token.
            if token.is_empty() {
                let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
                if boring::rand::rand_bytes(&mut scid_bytes).is_err() {
                    tracing::error!("H3: failed to generate connection ID");
                    return;
                }
                let scid = quiche::ConnectionId::from_ref(&scid_bytes);
                let new_token = mint_token(token_key, &hdr.dcid, &from);

                match quiche::retry(&hdr.scid, &hdr.dcid, &scid, &new_token, hdr.version, out) {
                    Ok(len) => {
                        if let Err(e) = socket.send_to(&out[..len], from).await {
                            tracing::error!("H3: failed to send retry: {}", e);
                        }
                    }
                    Err(e) => tracing::error!("H3: retry failed: {:?}", e),
                }
                return;
            }

            let Some(odcid) = validate_token(token_key, &from, token) else {
                tracing::warn!("H3: invalid address validation token from {}", from);
                return;
            };

            if hdr.dcid.len() != quiche::MAX_CONN_ID_LEN {
                tracing::warn!("H3: invalid destination connection ID length");
                return;
            }

            // Reuse the source connection ID we sent in the Retry packet,
            // instead of changing it again.
            let scid = hdr.dcid.clone();

            let conn = match quiche::accept(&scid, Some(&odcid), local_addr, from, config) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("H3: accept failed: {:?}", e);
                    return;
                }
            };

            tracing::debug!("H3: new connection from {}", from);
            conns.insert(
                cid.clone(),
                ConnState {
                    conn,
                    h3: None,
                    remote_addr: from,
                    streams: HashMap::new(),
                },
            );
        }

        let Some(cs) = conns.get_mut(&cid) else {
            return;
        };

        let recv_info = quiche::RecvInfo {
            to: local_addr,
            from,
        };
        if let Err(e) = cs.conn.recv(pkt, recv_info) {
            tracing::debug!("{} recv failed: {:?}", cs.conn.trace_id(), e);
            return;
        }

        // Create the HTTP/3 connection as soon as the QUIC handshake is
        // complete (or early data is available).
        if (cs.conn.is_established() || cs.conn.is_in_early_data()) && cs.h3.is_none() {
            match quiche::h3::Connection::with_transport(&mut cs.conn, h3_config) {
                Ok(h3) => cs.h3 = Some(h3),
                Err(e) => {
                    tracing::error!("H3: failed to create HTTP/3 connection: {}", e);
                    return;
                }
            }
        }

        if cs.h3.is_some() {
            self.pump_h3_events(cs, &cid, resp_tx, body_notify);
        }
    }

    /// Pump queued HTTP/3 events until quiche reports `Error::Done`.
    ///
    /// Must be called after every `conn.recv` AND from the event loop's
    /// maintenance pass: `h3::Connection::recv_body` queues the `Finished`
    /// event internally once the final body bytes are consumed, so a drain
    /// triggered by the maintenance pass (request-body backpressure retry)
    /// can produce events even when no new packet arrived. Without the
    /// maintenance-pass pump a large request body would deadlock: the
    /// handler waits for end-of-body that never gets signaled.
    fn pump_h3_events(
        &self,
        cs: &mut ConnState,
        cid: &quiche::ConnectionId<'static>,
        resp_tx: &RespSender,
        body_notify: &Arc<Notify>,
    ) {
        loop {
            let poll_result = {
                let h3 = cs.h3.as_mut().expect("checked above");
                h3.poll(&mut cs.conn)
            };

            match poll_result {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    self.handle_h3_headers(cs, cid, stream_id, list, resp_tx, body_notify);
                }
                Ok((stream_id, quiche::h3::Event::Data)) => {
                    Self::drain_request_body(cs, stream_id);
                }
                Ok((stream_id, quiche::h3::Event::Finished)) => {
                    // Request stream ended. Body bytes may still be
                    // buffered in quiche, so drain first; the handler's
                    // body channel is closed by drain_request_body once
                    // nothing is left to read.
                    if let Some(ss) = cs.streams.get_mut(&stream_id) {
                        ss.req_stream_finished = true;
                    }
                    Self::drain_request_body(cs, stream_id);
                }
                Ok((stream_id, quiche::h3::Event::Reset(_))) => {
                    if let Some(ss) = cs.streams.get_mut(&stream_id) {
                        ss.req_body_tx = None;
                        ss.dead = true;
                    }
                }
                Ok((_, quiche::h3::Event::PriorityUpdate)) => (),
                Ok((_, quiche::h3::Event::GoAway)) => (),
                Err(quiche::h3::Error::Done) => break,
                Err(e) => {
                    tracing::error!("{} HTTP/3 error {:?}", cs.conn.trace_id(), e);
                    break;
                }
            }
        }
    }

    /// Handle a request HEADERS event: parse the request, register stream
    /// state, and spawn the handler task.
    fn handle_h3_headers(
        &self,
        cs: &mut ConnState,
        cid: &quiche::ConnectionId<'static>,
        stream_id: u64,
        list: Vec<quiche::h3::Header>,
        resp_tx: &RespSender,
        body_notify: &Arc<Notify>,
    ) {
        // Only client-initiated bidirectional streams carry requests.
        if !stream_id.is_multiple_of(4) {
            return;
        }

        // A second HEADERS frame on a tracked stream is a trailers block;
        // we don't use trailers, so ignore it.
        if cs.streams.contains_key(&stream_id) {
            return;
        }

        let Some(req) = parse_h3_request(&list) else {
            Self::queue_simple_response(cs, stream_id, 400, "Bad Request");
            return;
        };

        let (req_body_tx, req_body_rx) = mpsc::channel::<Vec<u8>>(REQ_BODY_CHANNEL_CAPACITY);
        cs.streams.insert(
            stream_id,
            StreamState {
                req_body_tx: Some(req_body_tx),
                ..Default::default()
            },
        );

        let proxy = self.proxy.clone();
        let connector = self.connector.clone();
        let resp_tx = resp_tx.clone();
        let notify = body_notify.clone();
        let remote_ip = cs.remote_addr.ip().to_string();
        let cid = cid.clone();

        tokio::spawn(async move {
            handle_request(
                proxy,
                connector,
                req,
                remote_ip,
                cid,
                stream_id,
                req_body_rx,
                resp_tx,
                notify,
            )
            .await;
        });
    }

    /// Queue a plain-text response without spawning a handler task
    /// (used for early errors like malformed requests).
    fn queue_simple_response(cs: &mut ConnState, stream_id: u64, status: u16, body: &str) {
        let headers = vec![
            quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
            quiche::h3::Header::new(b"content-type", b"text/plain"),
            quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
            quiche::h3::Header::new(b"server", b"Pingclair"),
        ];
        cs.streams.insert(
            stream_id,
            StreamState {
                pending_headers: Some((headers, false)),
                pending_body: body.as_bytes().iter().copied().collect(),
                body_fin: true,
                ..Default::default()
            },
        );
        Self::flush_stream(cs, stream_id);
    }

    /// Drain request-body bytes out of quiche into the handler's channel.
    ///
    /// When the channel is full we stop draining and let QUIC flow control
    /// push back on the client; the drain is retried from the maintenance
    /// pass once the handler frees capacity.
    fn drain_request_body(cs: &mut ConnState, stream_id: u64) {
        let ConnState {
            conn, h3, streams, ..
        } = cs;
        let Some(h3) = h3.as_mut() else { return };
        let Some(ss) = streams.get_mut(&stream_id) else {
            return;
        };

        ss.body_read_pending = false;
        let mut tmp = [0u8; BODY_CHUNK_SIZE];

        loop {
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

        // The request stream finished and everything it carried is now in
        // the handler's channel: close the channel so the handler's receive
        // loop terminates.
        if ss.req_stream_finished {
            ss.req_body_tx = None;
        }
    }

    /// Apply one response message from a handler task and try to flush it.
    fn apply_resp_event(conns: &mut ConnMap, ev: RespEvent) {
        let Some(cs) = conns.get_mut(&ev.cid) else {
            return;
        };
        {
            let Some(ss) = cs.streams.get_mut(&ev.stream_id) else {
                return;
            };
            if ss.dead {
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
                    ss.pending_body.extend(bytes);
                    if fin {
                        ss.body_fin = true;
                    }
                }
            }
        }
        Self::flush_stream(cs, ev.stream_id);
    }

    /// Write as much of a stream's pending response as quiche currently
    /// accepts. Body bytes are always sent with `fin = false`; once the
    /// queue drains and the handler signaled end-of-body, a final empty
    /// `fin = true` write terminates the stream. Retried from the
    /// maintenance pass / writable events whenever flow control opens up.
    fn flush_stream(cs: &mut ConnState, stream_id: u64) {
        let ConnState {
            conn, h3, streams, ..
        } = cs;
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
                    tracing::debug!("H3: send_response failed on stream {}: {:?}", stream_id, e);
                    ss.dead = true;
                    return;
                }
            }
        }

        while !ss.pending_body.is_empty() {
            let (front, _) = ss.pending_body.as_slices();
            match h3.send_body(conn, stream_id, front, false) {
                Ok(0) => break,
                Ok(n) => {
                    ss.pending_body.drain(..n);
                }
                Err(quiche::h3::Error::Done) => break,
                Err(e) => {
                    tracing::debug!("H3: send_body failed on stream {}: {:?}", stream_id, e);
                    ss.dead = true;
                    return;
                }
            }
        }

        if ss.body_fin && ss.pending_body.is_empty() && !ss.fin_sent {
            match h3.send_body(conn, stream_id, b"", true) {
                Ok(_) => ss.fin_sent = true,
                Err(quiche::h3::Error::Done) => {}
                Err(e) => {
                    tracing::debug!("H3: fin write failed on stream {}: {:?}", stream_id, e);
                    ss.dead = true;
                    return;
                }
            }
        }

        if ss.fin_sent {
            ss.dead = true;
        }
    }
}

// MARK: - Handler task

/// Per-request handler task: routes via the shared proxy logic and streams
/// the response back to the event loop.
#[allow(clippy::too_many_arguments)]
async fn handle_request(
    proxy: Arc<PingclairProxy>,
    connector: Arc<pingora_core::connectors::http::Connector>,
    req: H3Request,
    remote_ip: String,
    cid: quiche::ConnectionId<'static>,
    stream_id: u64,
    body_rx: mpsc::Receiver<Vec<u8>>,
    resp_tx: RespSender,
    body_notify: Arc<Notify>,
) {
    if let Err(e) = handle_request_inner(
        &proxy,
        &connector,
        &req,
        &remote_ip,
        &cid,
        stream_id,
        body_rx,
        &resp_tx,
        &body_notify,
    )
    .await
    {
        // No response has been sent yet — answer with a plain-text error.
        let (status, msg) = e;
        send_simple(&resp_tx, &cid, stream_id, status, msg).await;
    }
}

/// Error shorthand: (HTTP status, message). Returning `Err` before any
/// response bytes were queued lets `handle_request` emit a plain-text
/// error response.
type HandlerError = (u16, &'static str);

#[allow(clippy::too_many_arguments)]
async fn handle_request_inner(
    proxy: &PingclairProxy,
    connector: &pingora_core::connectors::http::Connector,
    req: &H3Request,
    peer_ip: &str,
    cid: &quiche::ConnectionId<'static>,
    stream_id: u64,
    mut body_rx: mpsc::Receiver<Vec<u8>>,
    resp_tx: &RespSender,
    body_notify: &Arc<Notify>,
) -> Result<(), HandlerError> {
    // Build a pingora RequestHeader for routing and placeholder resolution.
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
    let peer_address = peer_ip
        .parse::<IpAddr>()
        .map_err(|_| (400, "Invalid Peer Address"))?;
    let verified_client_ip = proxy.verified_client_ip(peer_address, &header.headers);
    let verified_client_ip_text = verified_client_ip.to_string();

    let host_bare = req.authority.split(':').next().unwrap_or("").to_string();

    // Route via the shared logic (same entry point as the H1/H2 path).
    let (state, route_index, handler) = match proxy.match_route(
        &host_bare,
        path_only,
        req.method.as_str(),
        &header,
        &verified_client_ip_text,
    ) {
        Some((s, Some(idx), Some(h))) => (s, idx, h),
        Some(_) => return Err((404, "No Matching Route")),
        None => return Err((404, "No Matching Virtual Host")),
    };

    // Request body size limit (Content-Length precheck; the streaming
    // counter in the reverse-proxy path enforces it for chunked bodies).
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

    // 🛡️ Rate limiting uses the same verified client identity as H1 and H2.
    if let Some(limiter) = state
        .rate_limiters
        .get(route_index)
        .and_then(|l| l.as_ref())
    {
        let key = if limiter.config.by_ip {
            Some(verified_client_ip_text.as_str())
        } else {
            None
        };
        if let Err(info) = limiter.check(key) {
            let mut headers = vec![
                quiche::h3::Header::new(b":status", b"429"),
                quiche::h3::Header::new(b"server", b"Pingclair"),
            ];
            for (k, v) in info.to_headers() {
                headers.push(quiche::h3::Header::new(k.as_bytes(), v.as_bytes()));
            }
            send_headers(resp_tx, cid, stream_id, headers, true).await;
            return Ok(());
        }
    }

    // 🔐 The HTTP/3 gate shares the asynchronous verifier with H1 and H2.
    if let Some((realm, credentials)) = find_basic_auth_config(&handler)
        && !pingclair_core::server::verify_basic_auth_async(&header.headers, credentials).await
    {
        let challenge = pingclair_core::server::basic_auth_challenge(realm);
        let hdrs = vec![
            quiche::h3::Header::new(b":status", b"401"),
            quiche::h3::Header::new(b"www-authenticate", challenge.as_bytes()),
            quiche::h3::Header::new(b"server", b"Pingclair"),
        ];
        send_headers(resp_tx, cid, stream_id, hdrs, true).await;
        return Ok(());
    }

    match handler {
        HandlerConfig::Respond {
            status,
            body,
            headers,
        } => {
            let body = body.unwrap_or_default();
            let mut hdrs = vec![
                quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
                quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
                quiche::h3::Header::new(b"server", b"Pingclair"),
            ];
            for (k, v) in &headers {
                hdrs.push(quiche::h3::Header::new(k.as_bytes(), v.as_bytes()));
            }
            send_headers(resp_tx, cid, stream_id, hdrs, body.is_empty()).await;
            if !body.is_empty() {
                send_body(resp_tx, cid, stream_id, body.into_bytes(), true).await;
            }
            Ok(())
        }

        HandlerConfig::Redirect { to, code } => {
            let hdrs = vec![
                quiche::h3::Header::new(b":status", code.to_string().as_bytes()),
                quiche::h3::Header::new(b"location", to.as_bytes()),
                quiche::h3::Header::new(b"server", b"Pingclair"),
            ];
            send_headers(resp_tx, cid, stream_id, hdrs, true).await;
            Ok(())
        }

        HandlerConfig::FileServer { .. } => {
            let maybe_fs = state.file_servers.get(route_index).and_then(|f| f.clone());
            let Some(fs) = maybe_fs else {
                return Err((503, "File Server Unavailable"));
            };

            let range_header = header.headers.get("range").and_then(|v| v.to_str().ok());
            let accept_encoding = header
                .headers
                .get("accept-encoding")
                .and_then(|v| v.to_str().ok());

            match fs
                .serve_auto(path_only, range_header, accept_encoding)
                .await
            {
                Ok(Some(ServedResponse::Stream(mut stream))) => {
                    let mut hdrs = vec![
                        quiche::h3::Header::new(b":status", b"200"),
                        quiche::h3::Header::new(b"content-type", stream.mime_type.as_bytes()),
                        quiche::h3::Header::new(
                            b"content-length",
                            stream.file_size.to_string().as_bytes(),
                        ),
                        quiche::h3::Header::new(b"accept-ranges", b"bytes"),
                        quiche::h3::Header::new(b"server", b"Pingclair"),
                    ];
                    if let Some(lm) = &stream.last_modified {
                        hdrs.push(quiche::h3::Header::new(b"last-modified", lm.as_bytes()));
                    }
                    if let Some(etag) = &stream.etag {
                        hdrs.push(quiche::h3::Header::new(b"etag", etag.as_bytes()));
                    }
                    send_headers(resp_tx, cid, stream_id, hdrs, false).await;

                    // Stream the file in chunks — never buffered whole.
                    let mut fin_sent = false;
                    loop {
                        match stream.read_chunk() {
                            Ok(Some(chunk)) => {
                                let last = stream.is_complete();
                                send_body(resp_tx, cid, stream_id, chunk, last).await;
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
                        send_body(resp_tx, cid, stream_id, Vec::new(), true).await;
                    }
                    Ok(())
                }
                Ok(Some(ServedResponse::Buffered(file))) => {
                    let mut hdrs = vec![
                        quiche::h3::Header::new(b":status", file.status.to_string().as_bytes()),
                        quiche::h3::Header::new(b"content-type", file.mime_type.as_bytes()),
                        quiche::h3::Header::new(
                            b"content-length",
                            file.content.len().to_string().as_bytes(),
                        ),
                        quiche::h3::Header::new(b"accept-ranges", b"bytes"),
                        quiche::h3::Header::new(b"server", b"Pingclair"),
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
                    send_headers(resp_tx, cid, stream_id, hdrs, file.content.is_empty()).await;
                    if !file.content.is_empty() {
                        send_body(resp_tx, cid, stream_id, file.content, true).await;
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

        HandlerConfig::ReverseProxy(_) => {
            reverse_proxy_upstream(
                proxy,
                connector,
                &state,
                route_index,
                req,
                &header,
                peer_ip,
                &verified_client_ip_text,
                body_limit,
                cid,
                stream_id,
                &mut body_rx,
                resp_tx,
                body_notify,
            )
            .await
        }

        // All other handlers are not applicable over the H3 in-process path.
        _ => Err((501, "Handler Not Supported Over HTTP/3")),
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
    peer_ip: &str,
    verified_client_ip: &str,
    body_limit: u64,
    cid: &quiche::ConnectionId<'static>,
    stream_id: u64,
    body_rx: &mut mpsc::Receiver<Vec<u8>>,
    resp_tx: &RespSender,
    body_notify: &Arc<Notify>,
) -> Result<(), HandlerError> {
    // ⚖️ Selects the upstream with the verified client IP for IP-hash routing.
    let ip_bytes: Vec<u8> = match verified_client_ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.octets().to_vec(),
        Ok(IpAddr::V6(v6)) => v6.octets().to_vec(),
        Err(_) => Vec::new(),
    };
    let upstream = proxy
        .select_upstream(state, route_index, Some(&ip_bytes))
        .ok_or((502, "No Upstream Available"))?;

    let proxy_config = proxy.get_proxy_config(state, route_index);
    let (read_timeout, write_timeout) = proxy_config
        .as_ref()
        .map(|c| (c.read_timeout, c.write_timeout))
        .unwrap_or((None, None));

    let peer = PingclairProxy::build_http_peer(&upstream, read_timeout, write_timeout);

    let (mut session, _reused) = connector.get_http_session(&peer).await.map_err(|e| {
        tracing::error!("❌ H3 upstream connect failed: {}", e);
        (502, "Upstream Connect Failed")
    })?;

    // Build the upstream request.
    let method =
        http::Method::from_bytes(req.method.as_bytes()).map_err(|_| (400, "Bad Request"))?;
    let mut up_req = RequestHeader::build(method, req.path.as_bytes(), None)
        .map_err(|_| (400, "Bad Request"))?;

    // Host: the upstream's, not the downstream client's.
    up_req
        .insert_header("Host", peer.sni.clone())
        .map_err(|_| (502, "Upstream Request Error"))?;

    // The request body framing for the upstream. HTTP/3 carries no framing
    // headers, but Pingora's HTTP/1 upstream session picks its body-writer
    // mode (content-length vs chunked) from the request headers, so we must
    // supply one: the client's content-length when it sent one, chunked
    // otherwise for methods that may carry a body.
    let client_content_length: Option<u64> = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<u64>().ok());

    // Forward client headers, skipping hop-by-hop and framing headers.
    for (k, v) in &req.headers {
        let name = k.to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "host"
                | "connection"
                | "keep-alive"
                | "transfer-encoding"
                | "te"
                | "trailer"
                | "upgrade"
                | "content-length"
        ) {
            continue;
        }
        up_req.insert_header(k.clone(), v.as_str()).ok();
    }

    match client_content_length {
        Some(cl) => {
            up_req.insert_header("Content-Length", cl.to_string()).ok();
        }
        None if matches!(req.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") => {
            up_req.insert_header("Transfer-Encoding", "chunked").ok();
        }
        None => {}
    }

    // Configured headers_up with Caddy placeholder resolution.
    if let Some(cfg) = &proxy_config {
        for (key, template) in &cfg.headers_up {
            let resolved =
                resolve_caddy_placeholders(template, client_header, Some(verified_client_ip));
            up_req.insert_header(key.clone(), resolved.as_str()).ok();
        }
    }

    let has_header_up = |name: &str| {
        proxy_config
            .as_ref()
            .map(|c| c.headers_up.keys().any(|k| k.eq_ignore_ascii_case(name)))
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
    if !has_header_up("X-Forwarded-For")
        && let Ok(peer_address) = peer_ip.parse::<IpAddr>()
    {
        up_req
            .insert_header(
                "X-Forwarded-For",
                proxy
                    .forwarded_for(peer_address, &client_header.headers)
                    .as_str(),
            )
            .ok();
    }
    if !has_header_up("X-Real-IP") {
        up_req.insert_header("X-Real-IP", verified_client_ip).ok();
    }

    session
        .write_request_header(Box::new(up_req))
        .await
        .map_err(|e| {
            tracing::error!("❌ H3 upstream write header failed: {}", e);
            (502, "Upstream Write Failed")
        })?;

    // Stream the request body: headers went out first, body follows
    // chunk-by-chunk as it arrives from the client.
    let mut counted = 0u64;
    while let Some(chunk) = body_rx.recv().await {
        // A slot in the channel just freed up — wake the event loop so it
        // retries deferred drains.
        body_notify.notify_one();

        counted += chunk.len() as u64;
        if body_limit > 0 && counted > body_limit {
            // Abort the upstream exchange; the client gets a 413.
            session.shutdown().await;
            return Err((413, "Request Entity Too Large"));
        }
        if let Err(e) = session.write_request_body(Bytes::from(chunk), false).await {
            tracing::error!("❌ H3 upstream write body failed: {}", e);
            session.shutdown().await;
            return Err((502, "Upstream Write Failed"));
        }
    }
    // A declared content-length must match what was actually streamed;
    // otherwise the upstream would wait for bytes that never come (or the
    // extra bytes would poison the reused connection).
    if let Some(cl) = client_content_length
        && counted != cl
    {
        tracing::warn!(
            "H3: request body length mismatch (content-length {}, streamed {})",
            cl,
            counted
        );
        session.shutdown().await;
        return Err((400, "Bad Request"));
    }

    if let Err(e) = session.finish_request_body().await {
        tracing::error!("❌ H3 upstream finish body failed: {}", e);
        session.shutdown().await;
        return Err((502, "Upstream Write Failed"));
    }

    // Read the upstream response headers.
    if let Err(e) = session.read_response_header().await {
        tracing::error!("❌ H3 upstream read response header failed: {}", e);
        session.shutdown().await;
        return Err((502, "Upstream Read Failed"));
    }

    let mut hdrs = Vec::new();
    if let Some(resp) = session.response_header() {
        hdrs.push(quiche::h3::Header::new(
            b":status",
            resp.status.as_u16().to_string().as_bytes(),
        ));
        for (name, value) in resp.headers.iter() {
            let lower = name.as_str().to_ascii_lowercase();
            if matches!(
                lower.as_str(),
                "connection" | "keep-alive" | "transfer-encoding" | "te" | "trailer" | "upgrade"
            ) {
                continue;
            }
            hdrs.push(quiche::h3::Header::new(lower.as_bytes(), value.as_bytes()));
        }
    } else {
        hdrs.push(quiche::h3::Header::new(b":status", b"502"));
    }

    // Configured headers_down (set semantics, like the Pingora path).
    if let Some(cfg) = &proxy_config {
        for (k, v) in &cfg.headers_down {
            let lower = k.to_ascii_lowercase();
            hdrs.retain(|h| h.name() != lower.as_bytes());
            hdrs.push(quiche::h3::Header::new(lower.as_bytes(), v.as_bytes()));
        }
    }
    hdrs.retain(|h| h.name() != b"server");
    hdrs.push(quiche::h3::Header::new(b"server", b"Pingclair"));

    send_headers(resp_tx, cid, stream_id, hdrs, false).await;

    // Stream the response body back to the client.
    let mut clean = true;
    loop {
        match session.read_response_body().await {
            Ok(Some(bytes)) => {
                send_body(resp_tx, cid, stream_id, bytes.to_vec(), false).await;
            }
            Ok(None) => break,
            Err(e) => {
                tracing::error!("❌ H3 upstream read body failed: {}", e);
                clean = false;
                break;
            }
        }
    }
    send_body(resp_tx, cid, stream_id, Vec::new(), true).await;

    if clean {
        // Return the session to the keepalive pool.
        connector.release_http_session(session, &peer, None).await;
    } else {
        session.shutdown().await;
    }

    Ok(())
}

// MARK: - Response channel helpers

async fn send_headers(
    resp_tx: &RespSender,
    cid: &quiche::ConnectionId<'static>,
    stream_id: u64,
    headers: Vec<quiche::h3::Header>,
    fin: bool,
) {
    let _ = resp_tx
        .send(RespEvent {
            cid: cid.clone(),
            stream_id,
            msg: RespMsg::Headers(headers, fin),
        })
        .await;
}

async fn send_body(
    resp_tx: &RespSender,
    cid: &quiche::ConnectionId<'static>,
    stream_id: u64,
    bytes: Vec<u8>,
    fin: bool,
) {
    let _ = resp_tx
        .send(RespEvent {
            cid: cid.clone(),
            stream_id,
            msg: RespMsg::Body(bytes, fin),
        })
        .await;
}

/// Send a plain-text error response from a handler task.
async fn send_simple(
    resp_tx: &RespSender,
    cid: &quiche::ConnectionId<'static>,
    stream_id: u64,
    status: u16,
    msg: &str,
) {
    let headers = vec![
        quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
        quiche::h3::Header::new(b"content-type", b"text/plain"),
        quiche::h3::Header::new(b"content-length", msg.len().to_string().as_bytes()),
        quiche::h3::Header::new(b"server", b"Pingclair"),
    ];
    send_headers(resp_tx, cid, stream_id, headers, msg.is_empty()).await;
    if !msg.is_empty() {
        send_body(resp_tx, cid, stream_id, msg.as_bytes().to_vec(), true).await;
    }
}

// MARK: - Tests

#[cfg(test)]
mod tests {
    use super::*;

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
    fn retry_token_roundtrip() {
        let key = [7u8; 32];
        let src: SocketAddr = "192.0.2.10:55555".parse().unwrap();
        let dcid = quiche::ConnectionId::from_ref(&[1, 2, 3, 4, 5, 6, 7, 8]);

        let token = mint_token(&key, &dcid, &src);
        let odcid = validate_token(&key, &src, &token).expect("token should validate");
        assert_eq!(odcid.as_ref(), dcid.as_ref());
    }

    #[test]
    fn retry_token_roundtrip_ipv6() {
        let key = [9u8; 32];
        let src: SocketAddr = "[2001:db8::1]:4433".parse().unwrap();
        let dcid = quiche::ConnectionId::from_ref(&[42; 20]);

        let token = mint_token(&key, &dcid, &src);
        let odcid = validate_token(&key, &src, &token).expect("v6 token should validate");
        assert_eq!(odcid.as_ref(), dcid.as_ref());
    }

    #[test]
    fn retry_token_rejects_wrong_ip_and_tampering() {
        let key = [7u8; 32];
        let src: SocketAddr = "192.0.2.10:55555".parse().unwrap();
        let dcid = quiche::ConnectionId::from_ref(&[9, 9, 9, 9]);

        let token = mint_token(&key, &dcid, &src);

        // Different source IP must not validate (anti-spoofing).
        let other: SocketAddr = "198.51.100.20:4444".parse().unwrap();
        assert!(validate_token(&key, &other, &token).is_none());

        // Tampered token must not validate.
        let mut tampered = token.clone();
        let n = tampered.len();
        tampered[n - 1] ^= 0xFF;
        assert!(validate_token(&key, &src, &tampered).is_none());

        // Garbage must not validate.
        assert!(validate_token(&key, &src, b"garbage").is_none());
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
    fn parse_h3_request_rejects_missing_pseudo_headers() {
        let list = vec![quiche::h3::Header::new(b":method", b"GET")];
        assert!(parse_h3_request(&list).is_none());
    }
}
