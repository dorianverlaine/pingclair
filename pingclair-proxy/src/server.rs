// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Pingclair HTTP Proxy implementation using Pingora
//!
//! 🌐 This module implements the core reverse proxy using Pingora's ProxyHttp trait.

use pingclair_core::config::{
    AccessControlConfig, HandlerConfig, ResourceLimitsConfig, ReverseProxyConfig, ServerConfig,
};
use pingclair_core::server::Router;

use async_trait::async_trait;
use pingora_core::Result as PingoraResult;
use pingora_core::upstreams::peer::{HttpPeer, Peer};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};

use arc_swap::ArcSwap;
use async_recursion::async_recursion;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::encoding::{ResponseEncoder, negotiate, stream_chunk};
use crate::http_policy::{
    CorsDecision, ResponseHeaderPolicy, authority_host, evaluate_cors, generate_request_id,
    rewrite_uri, sanitize_request_id, via_value,
};
use crate::metrics;
use crate::overload::{AdmissionError, RouteAdmission, RouteProtection, UpstreamAdmission};
use crate::upstream::{HostName, Scheme, UpstreamSpec};
use crate::{HealthChecker, LoadBalancer, Strategy, Upstream, UpstreamEntry};
use bytes::Bytes;
use ipnet::IpNet;
use pingclair_core::config::Encoding;
use regex::Regex;

// MARK: - Context

/// Context for each request
pub struct RequestContext {
    /// Matched server state
    pub state: Option<ProxyState>,
    /// Matched route index
    pub route_index: Option<usize>,
    /// Selected upstream (kept for connection tracking)
    pub upstream: Option<Upstream>,
    /// Extra headers to add upstream
    pub headers_upstream: HashMap<String, String>,
    /// 🧭 Transport-neutral downstream response header mutations.
    pub(crate) response_headers: ResponseHeaderPolicy,
    /// 🗜️ Coding agreed between this client's `Accept-Encoding` and the
    /// server's `encode` list, or `None` for an identity response. Decided
    /// once per request, before the upstream response exists.
    pub negotiated_encoding: Option<Encoding>,
    /// Whether the matched route requested immediate per-chunk flushing
    /// (`flush_interval: -1`). When true, body chunks flow downstream as
    /// they arrive from upstream and response compression is disabled so
    /// SSE / LLM-style streaming endpoints work through the proxy.
    pub streaming_response: bool,
    /// Streaming encoder for the response body, created in `response_filter`
    /// once the upstream content type proves the body is worth compressing.
    pub response_encoder: Option<ResponseEncoder>,
    /// Request method (for access log)
    pub request_method: String,
    /// Request path (for access log)
    pub request_path: String,
    /// Request host (for access log)
    pub request_host: String,
    /// 🛡️ Client IP resolved through the trusted-proxy policy.
    pub verified_client_ip: Option<IpAddr>,
    /// 🌐 Verified downstream request scheme forwarded to the upstream.
    pub request_scheme: String,
    /// Upstream response status (for access log)
    pub response_status: u16,
    /// Response body bytes written (for access log)
    pub response_bytes: u64,
    /// Unique request ID
    pub request_id: String,
    /// Start time for logging
    pub start_time: std::time::Instant,
    /// ⏱️ When the first response byte was handed downstream, for TTFB.
    /// `None` when the response failed before producing any byte.
    pub first_byte_at: Option<std::time::Instant>,
    /// Path produced by the most recent rewrite handler. Pipelines consume
    /// this before invoking the next local handler.
    pub rewritten_path: Option<String>,
    /// 📦 Request-body bytes observed incrementally by the streaming filter.
    pub request_body_bytes: u64,
    /// ⌛ Active whole-request deadline after applying long-connection policy.
    pub request_deadline: Option<std::time::Instant>,
    /// 🌊 Whether this request uses the separately configured long-connection policy.
    pub long_connection: bool,
    /// 📥 Streaming upload-rate pacer with constant memory use.
    upload_pacer: Option<BandwidthPacer>,
    /// 📤 Streaming download-rate pacer with constant memory use.
    download_pacer: Option<BandwidthPacer>,
    /// ⏱️ Whether the last exhausted upstream failed specifically by connect timeout.
    upstream_connect_timed_out: bool,
    /// 🔢 Number of upstream attempts already started for this request.
    retry_attempts: usize,
    /// ⌛ Request-local deadline shared by retry attempts and backoff.
    retry_deadline: Option<std::time::Instant>,
    /// 💤 Whether the next upstream selection must apply retry backoff.
    retry_pending: bool,
    /// 🔁 Backends already attempted during the current redispatch cycle.
    retry_excluded: HashSet<SocketAddr>,
    /// 🚦 Route execution slot retained until this request context is dropped.
    route_admission: Option<RouteAdmission>,
    /// 🔌 Selected backend capacity and circuit admission for the active attempt.
    upstream_admission: Option<UpstreamAdmission>,
    /// 🚦 The first attempt's admitted backend, chosen in `proxy_upstream_filter`
    /// and handed to the first `upstream_peer` call so admission still runs once.
    preadmitted_upstream: Option<(Upstream, Option<UpstreamAdmission>)>,
}

impl Default for RequestContext {
    fn default() -> Self {
        Self {
            state: None,
            route_index: None,
            upstream: None,
            headers_upstream: HashMap::new(),
            response_headers: ResponseHeaderPolicy::default(),
            negotiated_encoding: None,
            streaming_response: false,
            response_encoder: None,
            request_method: String::new(),
            request_path: String::new(),
            request_host: String::new(),
            verified_client_ip: None,
            request_scheme: "http".to_string(),
            response_status: 0,
            response_bytes: 0,
            request_id: generate_request_id(),
            start_time: std::time::Instant::now(),
            first_byte_at: None,
            rewritten_path: None,
            request_body_bytes: 0,
            request_deadline: None,
            long_connection: false,
            upload_pacer: None,
            download_pacer: None,
            upstream_connect_timed_out: false,
            retry_attempts: 0,
            retry_deadline: None,
            retry_pending: false,
            retry_excluded: HashSet::new(),
            route_admission: None,
            upstream_admission: None,
            preadmitted_upstream: None,
        }
    }
}

/// 🚦 Paces a byte stream against one cumulative, allocation-free rate budget.
struct BandwidthPacer {
    rate: u64,
    bytes: u64,
    started: std::time::Instant,
}

impl BandwidthPacer {
    fn new(rate: u64) -> Self {
        Self {
            rate,
            bytes: 0,
            started: std::time::Instant::now(),
        }
    }

    fn delay_for(&mut self, bytes: usize) -> Option<Duration> {
        self.bytes = self.bytes.saturating_add(bytes as u64);
        let target = Duration::from_secs_f64(self.bytes as f64 / self.rate as f64);
        target.checked_sub(self.started.elapsed())
    }
}

/// 🧱 Maximum accepted hops in an inbound `X-Forwarded-For` chain.
const MAX_FORWARDED_HOPS: usize = 32;

/// 🧩 Bits of [`HttpPeer::group_key`] reserved for the upstream protocol.
///
/// A peer's group key isolates connection reuse. Pingclair packs two
/// independent reasons to isolate into it: the negotiated protocol in the low
/// bits, and the TLS trust identity above them. Keeping the protocol in a
/// fixed field means [`peer_protocol_group`] can still recover it after the
/// TLS half is mixed in.
const PROTOCOL_GROUP_BITS: u32 = 8;

/// 🌐 Cleartext HTTP/1.1.
const PROTOCOL_GROUP_HTTP: u64 = 1;
/// 🔒 TLS with HTTP/1.1 or HTTP/2 by ALPN.
const PROTOCOL_GROUP_HTTPS: u64 = 2;
/// 🔓 Cleartext HTTP/2 with prior knowledge.
const PROTOCOL_GROUP_H2C: u64 = 3;
/// 🔐 TLS that must negotiate HTTP/2.
const PROTOCOL_GROUP_H2: u64 = 4;

/// 🧩 Recovers the protocol a peer was built for from its packed group key.
pub(crate) fn peer_protocol_group(peer: &HttpPeer) -> u64 {
    peer.group_key & ((1 << PROTOCOL_GROUP_BITS) - 1)
}

/// 🔐 Reports whether this peer must negotiate `h2` or be rejected.
pub(crate) fn peer_requires_h2_alpn(peer: &HttpPeer) -> bool {
    peer_protocol_group(peer) == PROTOCOL_GROUP_H2
}

/// 🚫 Distinguishes an empty load-balancer pool from policy rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamSelectionError {
    NoUpstream,
    Unavailable,
}

/// 🧱 Keeps the smallest configured listener-wide bound across virtual hosts.
fn merge_listener_limit<T: Ord + Copy>(target: &mut Option<T>, candidate: Option<T>) {
    if let Some(candidate) = candidate {
        *target = Some(target.map_or(candidate, |current| current.min(candidate)));
    }
}

/// ⏱️ Selects the stricter of two optional time budgets.
fn shortest_duration(left: Option<Duration>, right: Option<Duration>) -> Option<Duration> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

/// 🧹 Fields that never cross a hop, whatever the client says.
///
/// `Transfer-Encoding` is deliberately absent: HTTP/1 framing belongs to
/// Pingora, which re-frames the body for the upstream, and removing the field
/// underneath it would describe a body that is not what gets sent.
const ALWAYS_HOP_BY_HOP: &[&str] = &[
    "proxy-connection",
    "keep-alive",
    "te",
    // 🔑 RFC 9110 §11.7.1: consumed by the first inbound proxy. Relaying it is
    // only correct when proxies cooperatively authenticate, which is not a
    // thing this server does, so the safe default is to consume it.
    "proxy-authorization",
    "proxy-authenticate",
];

/// 🧹 Removes connection-scoped fields from a request about to be forwarded.
///
/// RFC 9110 §7.6.1 requires removing `Connection`, every field it names, and
/// the connection-specific fields. The one exception is a genuine protocol
/// upgrade: Pingora detects a WebSocket tunnel by seeing `Connection: upgrade`
/// together with `Upgrade`, so stripping those would not harden anything — it
/// would simply break WebSocket.
fn strip_hop_by_hop_headers(
    session: &Session,
    upstream_request: &mut RequestHeader,
) -> pingora_core::Result<()> {
    let downstream = session.req_header();
    let upgrading = is_websocket_upgrade(&downstream.headers);

    // 🎯 Collected before anything is removed, since the list lives in the very
    // field being removed.
    let named: Vec<String> = downstream
        .headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect();

    for name in &named {
        // `close` and `keep-alive` describe the connection, not a field, and
        // `upgrade` is handled by the exception below.
        if matches!(name.as_str(), "close" | "keep-alive" | "upgrade") {
            continue;
        }
        upstream_request.remove_header(name.as_str());
    }

    for name in ALWAYS_HOP_BY_HOP {
        if upgrading && *name == "te" {
            // A tunnelling client may legitimately negotiate transfer codings.
            continue;
        }
        upstream_request.remove_header(*name);
    }

    if upgrading {
        return Ok(());
    }
    upstream_request.remove_header("connection");
    upstream_request.remove_header("upgrade");
    Ok(())
}

/// 🔌 Detects an HTTP/1 WebSocket upgrade before the response enters tunnel mode.
fn is_websocket_upgrade(headers: &http::HeaderMap) -> bool {
    headers
        .get("upgrade")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        && headers
            .get("connection")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
}

/// 🔐 Records the protocol selected by an upstream TLS handshake.
#[derive(Debug)]
struct NegotiatedUpstreamAlpn(Vec<u8>);

/// 🛡️ Pre-parsed proxy networks allowed to assert downstream client identity.
#[derive(Debug)]
struct TrustedProxyPolicy {
    networks: Vec<IpNet>,
}

impl TrustedProxyPolicy {
    fn from_rules(rules: &[String]) -> Self {
        let networks = rules
            .iter()
            .filter_map(|rule| {
                rule.parse::<IpNet>()
                    .or_else(|_| rule.parse::<IpAddr>().map(IpNet::from))
                    .map_err(|error| {
                        tracing::error!(
                            rule,
                            %error,
                            "❌ Invalid trusted proxy IP/CIDR; the rule is ignored"
                        );
                    })
                    .ok()
            })
            .collect();
        Self { networks }
    }

    fn contains(&self, address: IpAddr) -> bool {
        self.networks
            .iter()
            .any(|network| network.contains(&address))
    }

    fn verified_client_ip(&self, peer: IpAddr, headers: &http::HeaderMap) -> IpAddr {
        self.verified_client_ip_with_fallback(peer, peer, headers)
    }

    fn verified_client_ip_with_fallback(
        &self,
        transport_peer: IpAddr,
        fallback: IpAddr,
        headers: &http::HeaderMap,
    ) -> IpAddr {
        if !self.contains(transport_peer) {
            return fallback;
        }

        // ☁️ `CF-Connecting-IP` wins when the immediate peer is trusted.
        //
        // Cloudflare defines it as the single original visitor address, so it
        // needs no chain walking and cannot be ambiguous the way a multi-hop
        // `X-Forwarded-For` can. This is the header that matters for the
        // `Cloudflare Tunnel → pingclair` deployment.
        //
        // It is read *only* inside the `self.contains(peer)` branch above, so
        // an untrusted client sending `CF-Connecting-IP: 1.2.3.4` is ignored
        // and its socket peer is used instead — spoofing it requires already
        // being a trusted proxy.
        if let Some(cf_ip) = headers
            .get("cf-connecting-ip")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_forwarded_ip)
        {
            return cf_ip;
        }

        let xff = parse_forwarded_chain(headers);
        let forwarded = parse_rfc_forwarded_chain(headers);
        let client_from = |chain: &[IpAddr]| {
            chain
                .iter()
                .rev()
                .copied()
                .find(|candidate| !self.contains(*candidate))
                .unwrap_or(chain[0])
        };
        match (xff, forwarded) {
            (Ok(Some(xff)), Ok(Some(forwarded))) => {
                let xff_client = client_from(&xff);
                let forwarded_client = client_from(&forwarded);
                if xff_client == forwarded_client {
                    xff_client
                } else {
                    tracing::warn!(
                        xff = %xff_client,
                        forwarded = %forwarded_client,
                        "🚫 Conflicting forwarding identity headers failed closed"
                    );
                    fallback
                }
            }
            (Ok(Some(chain)), Ok(None)) | (Ok(None), Ok(Some(chain))) => client_from(&chain),
            (Ok(None), Ok(None)) => headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .and_then(parse_forwarded_ip)
                .unwrap_or(fallback),
            _ => fallback,
        }
    }

    fn forwarded_for_with_fallback(
        &self,
        transport_peer: IpAddr,
        fallback: IpAddr,
        headers: &http::HeaderMap,
    ) -> String {
        if !self.contains(transport_peer) {
            return fallback.to_string();
        }

        let Ok(Some(mut chain)) = parse_forwarded_chain(headers) else {
            let client = self.verified_client_ip_with_fallback(transport_peer, fallback, headers);
            return if client == transport_peer {
                transport_peer.to_string()
            } else {
                format!("{client}, {transport_peer}")
            };
        };
        if chain.last().copied() != Some(transport_peer) {
            chain.push(transport_peer);
        }
        chain
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// 🔎 Parses every `X-Forwarded-For` field into one bounded, normalized chain.
fn parse_forwarded_chain(headers: &http::HeaderMap) -> Result<Option<Vec<IpAddr>>, ()> {
    let values = headers.get_all("x-forwarded-for");
    if values.iter().next().is_none() {
        return Ok(None);
    }

    let mut chain = Vec::new();
    for value in values.iter() {
        let value = value.to_str().map_err(|_| ())?;
        for item in value.split(',') {
            if chain.len() >= MAX_FORWARDED_HOPS {
                return Err(());
            }
            chain.push(parse_forwarded_ip(item).ok_or(())?);
        }
    }
    if chain.is_empty() {
        Err(())
    } else {
        Ok(Some(chain))
    }
}

/// 🧭 Parses RFC 7239 `Forwarded` elements into one bounded `for` chain.
fn parse_rfc_forwarded_chain(headers: &http::HeaderMap) -> Result<Option<Vec<IpAddr>>, ()> {
    let values = headers.get_all("forwarded");
    if values.iter().next().is_none() {
        return Ok(None);
    }

    let mut chain = Vec::new();
    let mut total_bytes = 0usize;
    for value in values.iter() {
        let value = value.to_str().map_err(|_| ())?;
        total_bytes = total_bytes.checked_add(value.len()).ok_or(())?;
        if total_bytes > 8_192 {
            return Err(());
        }
        for element in split_quoted(value, ',')? {
            if chain.len() >= MAX_FORWARDED_HOPS {
                return Err(());
            }
            let mut forwarded_for = None;
            for parameter in split_quoted(&element, ';')? {
                let (name, raw_value) = parameter.split_once('=').ok_or(())?;
                if !name.trim().eq_ignore_ascii_case("for") {
                    continue;
                }
                if forwarded_for.is_some() {
                    return Err(());
                }
                let decoded = decode_forwarded_value(raw_value.trim())?;
                forwarded_for = parse_forwarded_ip(&decoded);
            }
            chain.push(forwarded_for.ok_or(())?);
        }
    }
    if chain.is_empty() {
        Err(())
    } else {
        Ok(Some(chain))
    }
}

fn split_quoted(value: &str, delimiter: char) -> Result<Vec<String>, ()> {
    let mut values = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if quoted && character == '\\' {
            current.push(character);
            escaped = true;
            continue;
        }
        if character == '"' {
            quoted = !quoted;
            current.push(character);
            continue;
        }
        if character == delimiter && !quoted {
            if current.trim().is_empty() {
                return Err(());
            }
            values.push(current.trim().to_string());
            current.clear();
        } else {
            current.push(character);
        }
    }
    if quoted || escaped || current.trim().is_empty() {
        return Err(());
    }
    values.push(current.trim().to_string());
    Ok(values)
}

fn decode_forwarded_value(value: &str) -> Result<String, ()> {
    if !value.starts_with('"') {
        if value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(());
        }
        return Ok(value.to_string());
    }
    let inner = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(())?;
    let mut decoded = String::new();
    let mut escaped = false;
    for character in inner.chars() {
        if escaped {
            decoded.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            decoded.push(character);
        }
    }
    if escaped || decoded.bytes().any(|byte| byte.is_ascii_control()) {
        Err(())
    } else {
        Ok(decoded)
    }
}

/// 🌐 Parses a forwarded IP with optional quotes, brackets, or a port.
fn parse_forwarded_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|unquoted| unquoted.strip_suffix('"'))
        .unwrap_or(value);
    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| {
            value
                .parse::<std::net::SocketAddr>()
                .ok()
                .map(|addr| addr.ip())
        })
        .or_else(|| {
            value
                .strip_prefix('[')
                .and_then(|bracketed| bracketed.strip_suffix(']'))
                .and_then(|ip| ip.parse::<IpAddr>().ok())
        })
}

// MARK: - Proxy State

/// Whether a route's `flush_interval` means "forward each chunk downstream
/// as soon as it arrives from upstream" (configured as `-1`).
///
/// Positive `flush_interval` values are deliberately not implemented as a
/// timer: Pingora 0.8 has no timed downstream flush mechanism (the
/// `Option<Duration>` returned by its body filters is a *delay* before
/// forwarding, not a flush schedule), and its transport layer already
/// flushes every chunk for unknown-length bodies (see the buffering note in
/// pingora-core `v1/body.rs`: buffering is only allowed when the body size
/// is known ahead). Immediate mode therefore only needs to disable anything
/// on our side that would hold chunks back — today that is response gzip.
pub fn wants_immediate_flush(flush_interval: Option<i64>) -> bool {
    flush_interval == Some(-1)
}

/// Whether the response content type is a real-time streaming format that
/// must never be compressed, regardless of route configuration.
///
/// Server-Sent Events (`text/event-stream`) clients expect an identity
/// body delivered incrementally; wrapping it in `Content-Encoding: gzip`
/// breaks event delivery for clients that do not decode gzip.
pub fn is_streaming_content_type(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .map(|mime| mime.trim().eq_ignore_ascii_case("text/event-stream"))
        .unwrap_or(false)
}

/// 🗜️ Matches a response MIME type against configured gzip patterns.
pub fn is_compressible_content_type(content_type: &str, configured_types: &[String]) -> bool {
    let mime = content_type.split(';').next().map(str::trim).unwrap_or("");
    if mime.is_empty() {
        return false;
    }

    if configured_types.is_empty() {
        return pingclair_core::config::DEFAULT_GZIP_TYPES
            .iter()
            .any(|pattern| gzip_type_matches(mime, pattern));
    }
    configured_types
        .iter()
        .any(|pattern| gzip_type_matches(mime, pattern))
}

/// 🎯 Matches exact, subtype-wildcard, and structured-suffix MIME patterns.
fn gzip_type_matches(mime: &str, pattern: &str) -> bool {
    let pattern = pattern.trim();
    if pattern == "*/*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return mime
            .get(..prefix.len())
            .is_some_and(|value| value.eq_ignore_ascii_case(prefix))
            && mime.as_bytes().get(prefix.len()) == Some(&b'/');
    }
    if let Some((prefix, suffix)) = pattern.split_once('*') {
        return mime
            .get(..prefix.len())
            .is_some_and(|value| value.eq_ignore_ascii_case(prefix))
            && mime
                .get(mime.len().saturating_sub(suffix.len())..)
                .is_some_and(|value| value.eq_ignore_ascii_case(suffix));
    }
    mime.eq_ignore_ascii_case(pattern)
}

/// Mutable state for hot reloading
#[derive(Clone)]
pub struct ProxyState {
    /// Server configuration
    pub config: Arc<ServerConfig>,
    /// Route matcher
    pub router: Arc<Router>,
    /// Load balancers per route
    pub load_balancers: Vec<Option<Arc<LoadBalancer>>>,
    /// Health checkers per route
    pub health_checkers: Vec<Option<Arc<HealthChecker>>>,
    /// File servers per route
    pub file_servers: Vec<Option<Arc<pingclair_static::FileServer>>>,
    /// Rate limiters per route
    pub rate_limiters: Vec<Option<Arc<crate::rate_limit::RateLimiter>>>,
    /// 🚦 Admission and circuit state per reverse-proxy route.
    pub(crate) route_protections: Vec<Option<Arc<RouteProtection>>>,
    /// 🔐 Compiled upstream TLS trust and identity per reverse-proxy route.
    pub(crate) upstream_tls: Vec<RouteUpstreamTls>,
    /// Pre-compiled per-route access policies.
    access_controls: Vec<Option<Arc<RouteAccessControl>>>,
    /// Pre-compiled regular expressions used by route rewrite handlers.
    rewrite_regexes: Vec<HashMap<String, Arc<Regex>>>,
    /// 📝 Per-server access logger built from this server's `log` block.
    /// `None` keeps the previous process-wide `tracing` output.
    access_logger: Option<Arc<crate::access_log::AccessLogger>>,
}

/// 🔐 A route's upstream TLS posture, resolved once per configuration load.
#[derive(Clone)]
pub(crate) enum RouteUpstreamTls {
    /// 🌐 No `transport http` TLS directives: Pingora's system-trust default
    /// applies, which already verifies the chain and the hostname.
    Default,
    /// 🎫 Trust roots, client identity, or an SNI override are in force.
    Compiled(Arc<crate::upstream_tls::UpstreamTls>),
    /// 🚫 The route asked for TLS material that could not be loaded.
    ///
    /// This deliberately has no fallback. A route configured to pin a private
    /// CA or present a client certificate, whose material is missing, must not
    /// quietly connect using system trust and no identity — that is precisely
    /// the connection the operator wrote the block to forbid.
    Broken,
}

/// 🔐 Compiles one route's upstream TLS block, logging what an operator needs.
///
/// Certificate problems are reported here, at load time, with the offending
/// path — not at the first request, where a handshake alert looks like every
/// other upstream failure. A failure marks the route [`RouteUpstreamTls::Broken`]
/// rather than aborting the process: one misconfigured route should not take
/// down the server's other routes, but it must not serve either.
fn compile_route_upstream_tls(
    route_path: &str,
    config: &pingclair_core::config::UpstreamTlsConfig,
) -> RouteUpstreamTls {
    match crate::upstream_tls::UpstreamTls::compile(config) {
        Ok(None) => RouteUpstreamTls::Default,
        Ok(Some(policy)) => {
            if !policy.verifies() {
                // ⚠️ Logged at every load, not once: an operator who inherits
                // this configuration must see it without reading the file.
                tracing::warn!(
                    route = route_path,
                    "⚠️ Upstream certificate verification is DISABLED for this route; \
                     anything answering on the upstream address will be trusted"
                );
            }
            tracing::info!(
                route = route_path,
                policy = %policy.summary(),
                "🔐 Upstream TLS policy loaded"
            );
            RouteUpstreamTls::Compiled(policy)
        }
        Err(error) => {
            tracing::error!(
                route = route_path,
                %error,
                "🚫 Upstream TLS material failed to load; this route will refuse requests \
                 instead of connecting without the trust it was configured to require"
            );
            RouteUpstreamTls::Broken
        }
    }
}

/// Pre-compiled request access rules. Parsing and regex compilation happen
/// only on configuration load/hot reload, never on the request path.
struct RouteAccessControl {
    allowed_ips: Vec<IpNet>,
    denied_ips: Vec<IpNet>,
    allowed_referers: Vec<String>,
    denied_referers: Vec<String>,
    allowed_user_agents: Vec<Regex>,
    denied_user_agents: Vec<Regex>,
    invalid: bool,
}

impl RouteAccessControl {
    fn from_config(config: &AccessControlConfig) -> Self {
        let mut invalid = false;
        let parse_ips = |rules: &[String], invalid: &mut bool| {
            rules
                .iter()
                .filter_map(|rule| {
                    match rule
                        .parse::<IpNet>()
                        .or_else(|_| rule.parse::<IpAddr>().map(IpNet::from))
                    {
                        Ok(network) => Some(network),
                        Err(error) => {
                            tracing::error!(
                                rule,
                                %error,
                                "Invalid access-control IP/CIDR rule"
                            );
                            *invalid = true;
                            None
                        }
                    }
                })
                .collect()
        };
        let parse_regexes = |rules: &[String], invalid: &mut bool| {
            rules
                .iter()
                .filter_map(|rule| match Regex::new(rule) {
                    Ok(regex) => Some(regex),
                    Err(error) => {
                        tracing::error!(
                            rule,
                            %error,
                            "Invalid access-control User-Agent regex"
                        );
                        *invalid = true;
                        None
                    }
                })
                .collect()
        };
        Self {
            allowed_ips: parse_ips(&config.allowed_ips, &mut invalid),
            denied_ips: parse_ips(&config.denied_ips, &mut invalid),
            allowed_referers: config
                .allowed_referers
                .iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            denied_referers: config
                .denied_referers
                .iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            allowed_user_agents: parse_regexes(&config.allowed_user_agents, &mut invalid),
            denied_user_agents: parse_regexes(&config.denied_user_agents, &mut invalid),
            invalid,
        }
    }

    fn allows(&self, remote_ip: &str, headers: &http::HeaderMap) -> bool {
        if self.invalid {
            return false;
        }
        let ip = remote_ip.parse::<IpAddr>().ok();
        if self
            .denied_ips
            .iter()
            .any(|network| ip.is_some_and(|ip| network.contains(&ip)))
        {
            return false;
        }
        if !self.allowed_ips.is_empty()
            && !self
                .allowed_ips
                .iter()
                .any(|network| ip.is_some_and(|ip| network.contains(&ip)))
        {
            return false;
        }

        let referer = headers
            .get(http::header::REFERER)
            .and_then(|value| value.to_str().ok())
            .and_then(referer_host);
        if self
            .denied_referers
            .iter()
            .any(|rule| referer.is_some_and(|host| host_matches_rule(host, rule)))
        {
            return false;
        }
        if !self.allowed_referers.is_empty()
            && !self
                .allowed_referers
                .iter()
                .any(|rule| referer.is_some_and(|host| host_matches_rule(host, rule)))
        {
            return false;
        }

        let user_agent = headers
            .get(http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        if self
            .denied_user_agents
            .iter()
            .any(|regex| regex.is_match(user_agent))
        {
            return false;
        }
        self.allowed_user_agents.is_empty()
            || self
                .allowed_user_agents
                .iter()
                .any(|regex| regex.is_match(user_agent))
    }
}

fn referer_host(referer: &str) -> Option<&str> {
    let authority = referer.split_once("://")?.1.split('/').next()?;
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if let Some(bracketed) = host.strip_prefix('[') {
        return bracketed.split_once(']').map(|(host, _)| host);
    }
    Some(host.split(':').next().unwrap_or(host))
}

fn request_authority(request: &RequestHeader) -> &str {
    // 🌐 HTTP/2 carries the virtual host in `:authority`, which Pingora stores in the URI.
    request
        .uri
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| {
            request
                .headers
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
        })
        .unwrap_or("")
}

/// 🌐 Extracts the immediate network peer without consulting request headers.
fn session_peer_ip(session: &Session) -> IpAddr {
    session
        .client_addr()
        .map(|addr| match addr {
            pingora_core::protocols::l4::socket::SocketAddr::Inet(inet) => inet.ip(),
            pingora_core::protocols::l4::socket::SocketAddr::Unix(_) => {
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            }
        })
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
}

fn session_inet_addresses(session: &Session) -> Option<(SocketAddr, SocketAddr)> {
    let peer = match session.client_addr()? {
        pingora_core::protocols::l4::socket::SocketAddr::Inet(address) => *address,
        pingora_core::protocols::l4::socket::SocketAddr::Unix(_) => return None,
    };
    let listener = match session.server_addr()? {
        pingora_core::protocols::l4::socket::SocketAddr::Inet(address) => *address,
        pingora_core::protocols::l4::socket::SocketAddr::Unix(_) => return None,
    };
    Some((peer, listener))
}

fn authority_port(authority: &str) -> Option<u16> {
    authority
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
}

fn host_matches_rule(host: &str, rule: &str) -> bool {
    let host = host.to_ascii_lowercase();
    if let Some(suffix) = rule.strip_prefix("*.") {
        host.ends_with(suffix) && host.len() > suffix.len()
    } else {
        host == rule
    }
}

/// 🧭 Groups one rewrite handler's immutable matching and replacement rules.
struct RewriteRule<'a> {
    strip_prefix: Option<&'a str>,
    strip_suffix: Option<&'a str>,
    replace: Option<&'a str>,
    regex: Option<&'a str>,
    regex_replace: Option<&'a str>,
}

impl ProxyState {
    /// Creates a new `ProxyState` from a server configuration.
    ///
    /// Initializes all necessary components (Load Balancers, File Servers, Rate Limiters)
    /// based on the provided configuration.
    ///
    /// - Parameter config: The server configuration to load.
    /// - Returns: A fully initialized `ProxyState`.
    pub fn new(config: ServerConfig) -> Self {
        Self::new_with_previous(config, None)
    }

    /// ♻️ Rebuilds configuration while retaining compatible breaker state.
    fn new_with_previous(config: ServerConfig, previous: Option<&ProxyState>) -> Self {
        let router = Router::new(config.routes.clone());
        let host_label = config.name.clone().unwrap_or_else(|| "_".to_string());

        // 🧩 Initializes index-aligned components for each route.
        let mut load_balancers = Vec::new();
        let mut health_checkers = Vec::new();
        let mut file_servers = Vec::new();
        let mut rate_limiters = Vec::new();
        let mut route_protections = Vec::new();
        let mut upstream_tls = Vec::new();
        let mut access_controls = Vec::new();
        let mut rewrite_regexes = Vec::new();

        for (route_index, route) in config.routes.iter().enumerate() {
            // Each per-route slot is resolved independently by walking the
            // route's handler tree. A `reverse_proxy`/`file_server`/
            // `rate_limit` may sit at the top level *or* be nested inside a
            // `handle {}` / `route {}` block (which the adapter represents as
            // a Pipeline); the finders recurse so both cases are set up
            // identically. Previously only top-level ReverseProxy/FileServer
            // handlers were recognised, so anything inside a `handle` block
            // got no load balancer / no file-server instance and failed at
            // runtime with ConnectNoRoute — even though rate limiting inside
            // the same block already worked. Every slot is pushed exactly
            // once per route, keeping the four vecs index-aligned.

            // Load balancer (possibly nested inside a handle/route block)
            if let Some(proxy_config) = find_reverse_proxy_config(&route.handler) {
                let (primary, backup) = build_weighted_upstreams(proxy_config);

                if primary.is_empty() && backup.is_empty() {
                    tracing::warn!("⚠️ No valid upstreams found for route {}", route.path);
                }
                let primary_is_empty = primary.is_empty();

                let strategy = match proxy_config.load_balance.strategy.as_str() {
                    "random" => Strategy::Random,
                    "least_conn" => Strategy::LeastConn,
                    "ip_hash" => Strategy::IpHash,
                    "first" => Strategy::RoundRobin,
                    _ => Strategy::RoundRobin,
                };

                let load_balancer = Arc::new(if primary_is_empty {
                    // A backup-only configuration is still useful for a
                    // deliberately standby-only route; there is no primary
                    // pool to wait on in that case.
                    LoadBalancer::from_entries(backup, vec![], strategy)
                } else {
                    LoadBalancer::from_entries(primary, backup, strategy)
                });

                // 🔐 Compile the route policy before its probe peer so health and
                // ordinary traffic use identical trust roots, client identity, and SNI.
                let route_tls = compile_route_upstream_tls(&route.path, &proxy_config.upstream_tls);
                if let Some(hc_config) = &proxy_config.health_check {
                    let tls_policy = match &route_tls {
                        RouteUpstreamTls::Default => Some(None),
                        RouteUpstreamTls::Compiled(policy) => Some(Some(policy)),
                        RouteUpstreamTls::Broken => None,
                    };
                    if let (Some(upstream), Some(tls_policy)) =
                        (load_balancer.first_backend(), tls_policy)
                    {
                        let timeout = Duration::from_secs(hc_config.timeout);
                        let peer_template = PingclairProxy::build_http_peer(
                            &upstream,
                            Some(proxy_config),
                            Some(timeout),
                            Some(timeout),
                            tls_policy,
                        );
                        let host = hc_config.host.clone().unwrap_or_else(|| {
                            upstream
                                .ext
                                .get::<HostName>()
                                .map(|host| host.0.clone())
                                .unwrap_or_else(|| upstream.addr.to_string())
                        });
                        load_balancer.set_health_check(
                            crate::health_check::HealthCheckConfig {
                                path: hc_config.path.clone(),
                                timeout,
                                positive_threshold: hc_config.consecutive_success as usize,
                                negative_threshold: hc_config
                                    .consecutive_failure
                                    .unwrap_or(hc_config.threshold)
                                    as usize,
                                expected_statuses: hc_config.expected_statuses.clone(),
                                expected_body: hc_config.expected_body.clone(),
                                method: hc_config.method.clone(),
                                host,
                                host_override: hc_config.host.clone(),
                                sni_override: tls_policy
                                    .and_then(|policy| policy.server_name())
                                    .map(str::to_string),
                                headers: hc_config.headers.clone(),
                                port_override: hc_config.port,
                                reuse_connection: hc_config.reuse_connection,
                                max_response_body_bytes: hc_config.max_response_body_bytes,
                                slow_start: Duration::from_millis(hc_config.slow_start_ms),
                            },
                            peer_template,
                        );
                        load_balancer
                            .set_health_check_frequency(Duration::from_secs(hc_config.interval));
                        crate::health_check::register(&load_balancer);
                    } else {
                        tracing::error!(
                            route = %route.path,
                            "🚫 Active health checking did not start because no valid TLS probe peer exists"
                        );
                    }
                }

                // Hostname upstreams are re-resolved by the shared refresher;
                // pools of IP literals are ignored by `register`.
                crate::dns::register(&load_balancer);

                load_balancers.push(Some(load_balancer));
                tracing::info!(
                    "⚖️ Initialized load balancer for route {} with strategy {:?}",
                    route.path,
                    strategy
                );

                let retained = previous
                    .and_then(|state| state.config.routes.get(route_index).map(|old| (state, old)))
                    .filter(|(_, old)| old.path == route.path)
                    .and_then(|(state, _)| state.route_protections.get(route_index))
                    .and_then(|protection| protection.as_ref())
                    .filter(|protection| {
                        protection.compatible(
                            &proxy_config.overload,
                            &proxy_config.circuit_breaker,
                            &host_label,
                            &route.path,
                            &proxy_config.upstreams,
                        )
                    })
                    .cloned();
                route_protections.push(Some(retained.unwrap_or_else(|| {
                    Arc::new(RouteProtection::new(
                        (*proxy_config.overload).clone(),
                        (*proxy_config.circuit_breaker).clone(),
                        host_label.clone(),
                        route.path.clone(),
                        proxy_config.upstreams.clone(),
                    ))
                })));

                upstream_tls.push(route_tls);
            } else {
                load_balancers.push(None);
                route_protections.push(None);
                upstream_tls.push(RouteUpstreamTls::Default);
            }

            // Health checker is stored inside the LB object; this slot is a
            // tombstone kept only for index alignment with load_balancers.
            health_checkers.push(None);

            // File server (possibly nested inside a handle/route block)
            if let Some(HandlerConfig::FileServer {
                root,
                index,
                browse,
                compress,
            }) = find_file_server_config(&route.handler)
            {
                let fs_config = pingclair_static::FileServerConfig {
                    root: std::path::PathBuf::from(root),
                    index: if index.is_empty() {
                        vec!["index.html".to_string()]
                    } else {
                        index.clone()
                    },
                    browse: *browse,
                    compress: *compress,
                    precompressed: true, // Enable pre-compressed file detection by default
                };

                file_servers.push(Some(Arc::new(pingclair_static::FileServer::new(fs_config))));
                tracing::info!("📁 Initialized file server for route {}", route.path);
            } else {
                file_servers.push(None);
            }

            // Check for rate limit config
            if let Some(rl_config) = find_rate_limit_config(&route.handler, &route.path) {
                use crate::rate_limit::RateLimiter;
                rate_limiters.push(Some(RateLimiter::new(rl_config)));
                tracing::info!("🚦 Initialized rate limiter for route {}", route.path);
            } else {
                rate_limiters.push(None);
            }

            access_controls.push(
                find_access_control_config(&route.handler)
                    .map(|config| Arc::new(RouteAccessControl::from_config(config))),
            );

            let mut route_regexes = HashMap::new();
            collect_rewrite_regexes(&route.handler, &mut route_regexes);
            rewrite_regexes.push(route_regexes);
        }

        // A misconfigured log sink must not take the whole server down at
        // boot: fall back to tracing and say so loudly.
        let access_logger = match crate::access_log::AccessLogger::from_config(config.log.as_ref())
        {
            Ok(logger) => logger.map(Arc::new),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    server = config.name.as_deref().unwrap_or("<default>"),
                    "❌ Could not open configured access log; falling back to tracing output"
                );
                None
            }
        };

        Self {
            config: Arc::new(config),
            router: Arc::new(router),
            load_balancers,
            health_checkers,
            file_servers,
            rate_limiters,
            route_protections,
            upstream_tls,
            access_controls,
            rewrite_regexes,
            access_logger,
        }
    }

    /// 🔐 Returns the compiled TLS policy for a route, or `None` for the default.
    ///
    /// `Err(())` means the route's TLS material failed to load and the request
    /// must be refused rather than downgraded.
    pub(crate) fn upstream_tls_for(
        &self,
        route_index: usize,
    ) -> Result<Option<&Arc<crate::upstream_tls::UpstreamTls>>, ()> {
        match self.upstream_tls.get(route_index) {
            Some(RouteUpstreamTls::Compiled(policy)) => Ok(Some(policy)),
            Some(RouteUpstreamTls::Broken) => Err(()),
            // 🧩 A missing slot can only mean an index-alignment bug; treating
            // it as the default keeps behaviour identical to before this field
            // existed rather than inventing a new failure mode.
            Some(RouteUpstreamTls::Default) | None => Ok(None),
        }
    }

    /// 🛡️ Applies the route's compiled access policy to a verified client.
    pub(crate) fn allows_access(
        &self,
        route_index: usize,
        remote_ip: &str,
        headers: &http::HeaderMap,
    ) -> bool {
        self.access_controls
            .get(route_index)
            .and_then(|policy| policy.as_ref())
            .is_none_or(|policy| policy.allows(remote_ip, headers))
    }

    /// 🧭 Applies one precompiled route rewrite without transport-specific state.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn rewrite_request_uri(
        &self,
        route_index: usize,
        current: &str,
        strip_prefix: Option<&str>,
        strip_suffix: Option<&str>,
        replace: Option<&str>,
        regex_pattern: Option<&str>,
        regex_replace: Option<&str>,
    ) -> Result<String, &'static str> {
        let compiled = if let Some(pattern) = regex_pattern {
            Some(
                self.rewrite_regexes
                    .get(route_index)
                    .and_then(|regexes| regexes.get(pattern).map(AsRef::as_ref))
                    .ok_or("invalid rewrite regex in active configuration")?,
            )
        } else {
            None
        };
        Ok(rewrite_uri(
            current,
            strip_prefix,
            strip_suffix,
            replace,
            compiled,
            regex_replace,
        ))
    }

    /// 🧯 Reads one configured custom error page on the cold error path.
    pub(crate) fn read_error_page(&self, status: u16) -> Option<(Vec<u8>, &'static str)> {
        let path = self.config.error_pages.get(&status)?;
        let content = std::fs::read(path).ok()?;
        let content_type = if path.ends_with(".htm") || path.ends_with(".html") {
            "text/html"
        } else {
            "text/plain"
        };
        Some((content, content_type))
    }

    /// 🧯 Reports whether an upstream status is configured for interception.
    pub(crate) fn intercepts_error_status(&self, status: u16) -> bool {
        self.config.error_pages.contains_key(&status)
    }
}

/// 🧯 Maps common HTTP failures to stable built-in reason phrases.
pub(crate) fn error_reason(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Request Entity Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}

// MARK: - Server Implementation

/// Pingclair reverse proxy
///
/// `hosts`/`default` use `ArcSwap` rather than `RwLock` because they sit on
/// the per-request hot path (`get_state` is called for every single
/// request) while writes only happen on hot-reload — an operation measured
/// in reloads-per-hour, not requests-per-second. `ArcSwap::load()` is a
/// lock-free, wait-free read, so concurrent requests never contend with
/// each other or with a config reload.
#[derive(Clone)]
pub struct PingclairProxy {
    /// Map of hostname -> server state
    pub hosts: Arc<ArcSwap<HashMap<String, ProxyState>>>,
    /// Default server state (catch-all)
    pub default: Arc<ArcSwap<Option<ProxyState>>>,
    /// TLS Manager for certificate resolution
    pub tls_manager: Option<Arc<pingclair_tls::manager::TlsManager>>,
    /// Alt-Svc value advertised on this listener's responses when HTTP/3 is
    /// enabled (`None` = do not advertise, e.g. plain-HTTP listeners).
    /// Stored behind `ArcSwap` so it can be flipped without restarting the
    /// Pingora service.
    pub alt_svc: Arc<ArcSwap<Option<String>>>,
    /// 🛡️ Immutable policy used by every protocol to resolve client identity.
    trusted_proxies: Arc<TrustedProxyPolicy>,
    /// 🧭 Trusted transport claims keyed by the private ingress tunnel sockets.
    proxy_protocol_registry: Arc<crate::proxy_protocol::ProxyProtocolRegistry>,
    /// 🚫 Rejects TCP requests that bypass the required external PROXY ingress.
    proxy_protocol_required: bool,
}

impl Default for PingclairProxy {
    fn default() -> Self {
        Self {
            hosts: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            default: Arc::new(ArcSwap::from_pointee(None)),
            tls_manager: None,
            alt_svc: Arc::new(ArcSwap::from_pointee(None)),
            trusted_proxies: Arc::new(TrustedProxyPolicy::from_rules(&[])),
            proxy_protocol_registry: Arc::new(
                crate::proxy_protocol::ProxyProtocolRegistry::default(),
            ),
            proxy_protocol_required: false,
        }
    }
}

impl PingclairProxy {
    /// Create a new proxy
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new proxy with TLS manager
    pub fn with_tls(tls_manager: Arc<pingclair_tls::manager::TlsManager>) -> Self {
        Self {
            hosts: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            default: Arc::new(ArcSwap::from_pointee(None)),
            tls_manager: Some(tls_manager),
            alt_svc: Arc::new(ArcSwap::from_pointee(None)),
            trusted_proxies: Arc::new(TrustedProxyPolicy::from_rules(&[])),
            proxy_protocol_registry: Arc::new(
                crate::proxy_protocol::ProxyProtocolRegistry::default(),
            ),
            proxy_protocol_required: false,
        }
    }

    /// 🛡️ Creates a TLS proxy with a pre-parsed trusted-proxy policy.
    pub fn with_tls_and_trusted_proxies(
        tls_manager: Arc<pingclair_tls::manager::TlsManager>,
        trusted_proxies: &[String],
        proxy_protocol_required: bool,
    ) -> Self {
        Self {
            hosts: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            default: Arc::new(ArcSwap::from_pointee(None)),
            tls_manager: Some(tls_manager),
            alt_svc: Arc::new(ArcSwap::from_pointee(None)),
            trusted_proxies: Arc::new(TrustedProxyPolicy::from_rules(trusted_proxies)),
            proxy_protocol_registry: Arc::new(
                crate::proxy_protocol::ProxyProtocolRegistry::default(),
            ),
            proxy_protocol_required,
        }
    }

    /// 🧪 Creates a non-TLS proxy with a trusted-proxy policy.
    #[cfg(test)]
    fn with_trusted_proxies(trusted_proxies: &[String]) -> Self {
        Self {
            trusted_proxies: Arc::new(TrustedProxyPolicy::from_rules(trusted_proxies)),
            ..Self::default()
        }
    }

    /// 🛡️ Resolves the verified client address shared by all request policies.
    pub(crate) fn verified_client_ip(&self, peer: IpAddr, headers: &http::HeaderMap) -> IpAddr {
        self.trusted_proxies.verified_client_ip(peer, headers)
    }

    fn downstream_identity(
        &self,
        session: &Session,
        headers: &http::HeaderMap,
    ) -> (IpAddr, IpAddr, IpAddr) {
        if let Some(identity) = self.proxy_protocol_identity(session) {
            let client = self.trusted_proxies.verified_client_ip_with_fallback(
                identity.transport_peer.ip(),
                identity.client.ip(),
                headers,
            );
            return (identity.transport_peer.ip(), identity.client.ip(), client);
        }
        let peer = session_peer_ip(session);
        (
            peer,
            peer,
            self.trusted_proxies.verified_client_ip(peer, headers),
        )
    }

    fn proxy_protocol_identity(
        &self,
        session: &Session,
    ) -> Option<crate::proxy_protocol::ProxyProtocolIdentity> {
        let (peer, listener) = session_inet_addresses(session)?;
        self.proxy_protocol_registry.resolve(peer, listener)
    }

    /// 🧭 Exposes the per-listener tunnel registry to the startup ingress.
    pub fn proxy_protocol_registry(&self) -> Arc<crate::proxy_protocol::ProxyProtocolRegistry> {
        self.proxy_protocol_registry.clone()
    }

    /// 🔒 Reports whether the immediate peer may assert proxy headers.
    pub(crate) fn is_trusted_proxy(&self, peer: IpAddr) -> bool {
        self.trusted_proxies.contains(peer)
    }

    /// 📤 Builds a sanitized upstream `X-Forwarded-For` value.
    pub(crate) fn forwarded_for(&self, peer: IpAddr, headers: &http::HeaderMap) -> String {
        self.trusted_proxies
            .forwarded_for_with_fallback(peer, peer, headers)
    }

    /// Advertise HTTP/3 availability for this listener via the `Alt-Svc`
    /// response header (added by the downstream module registered in
    /// `init_downstream_modules`).
    pub fn set_alt_svc(&self, port: u16) {
        self.alt_svc
            .store(Arc::new(Some(crate::alt_svc::alt_svc_value(port))));
    }

    /// Add a server configuration to this proxy
    pub fn add_server(&self, config: ServerConfig) {
        if let Some(domain) = &config.name {
            if domain == "_" || domain == "*" || domain.starts_with(':') {
                let current = self.default.load();
                let state =
                    ProxyState::new_with_previous(config.clone(), current.as_ref().as_ref());
                self.default.store(Arc::new(Some(state)));
            } else {
                let current = self.hosts.load();
                let state = ProxyState::new_with_previous(config.clone(), current.get(domain));
                // Read-Copy-Update: clone the current map, insert into the
                // copy, then publish it atomically. add_server is a rare,
                // low-frequency admin operation, so an O(n) copy here is a
                // fair trade for wait-free reads on the request hot path.
                self.hosts.rcu(|current| {
                    let mut next = (**current).clone();
                    next.insert(domain.clone(), state.clone());
                    next
                });
            }
        } else {
            let current = self.default.load();
            let state = ProxyState::new_with_previous(config.clone(), current.as_ref().as_ref());
            self.default.store(Arc::new(Some(state)));
        }
    }

    /// 🧱 Returns the strictest pre-routing limits shared by a listener's virtual hosts.
    pub fn listener_limits(&self) -> ResourceLimitsConfig {
        let mut limits = ResourceLimitsConfig::default();
        let hosts = self.hosts.load();
        for state in hosts.values().chain(self.default.load().iter()) {
            merge_listener_limit(
                &mut limits.header_timeout_ms,
                state.config.limits.header_timeout_ms,
            );
            merge_listener_limit(
                &mut limits.max_header_count,
                state.config.limits.max_header_count,
            );
            merge_listener_limit(
                &mut limits.max_header_bytes,
                state.config.limits.max_header_bytes,
            );
            merge_listener_limit(
                &mut limits.max_connections,
                state.config.limits.max_connections,
            );
            merge_listener_limit(
                &mut limits.idle_timeout_ms,
                state.config.limits.idle_timeout_ms,
            );
            merge_listener_limit(
                &mut limits.long_connections.idle_timeout_ms,
                state.config.limits.long_connections.idle_timeout_ms,
            );
        }
        limits
    }

    /// Replace all server configurations with a new list
    pub fn update_config(&self, servers: Vec<ServerConfig>) {
        let mut new_hosts = HashMap::new();
        let mut new_default = None;
        let old_hosts = self.hosts.load();
        let old_default = self.default.load();

        for config in servers {
            if let Some(domain) = &config.name {
                if domain == "_" || domain == "*" || domain.starts_with(':') {
                    let state = ProxyState::new_with_previous(
                        config.clone(),
                        old_default.as_ref().as_ref(),
                    );
                    new_default = Some(state);
                } else {
                    let state =
                        ProxyState::new_with_previous(config.clone(), old_hosts.get(domain));
                    new_hosts.insert(domain.clone(), state);
                }
            } else {
                let state =
                    ProxyState::new_with_previous(config.clone(), old_default.as_ref().as_ref());
                new_default = Some(state);
            }
        }

        // Single atomic publish: in-flight requests keep using the Arc they
        // already loaded; new requests see the new map. No lock is ever
        // held, so a reload can never block or be blocked by traffic.
        self.hosts.store(Arc::new(new_hosts));
        self.default.store(Arc::new(new_default));

        tracing::info!("♻️ Configuration reloaded successfully");
    }

    /// Resolve a request to a handler state
    /// Used by HTTP/3 server to reuse routing logic
    pub fn match_route(
        &self,
        host: &str,
        path: &str,
        method: &str,
        headers: &pingora_http::RequestHeader,
        remote_ip: &str,
    ) -> Option<(ProxyState, Option<usize>, Option<HandlerConfig>)> {
        self.match_route_index(host, path, method, headers, remote_ip)
            .map(|(state, route_index)| {
                let handler = route_index
                    .and_then(|index| state.config.routes.get(index))
                    .map(|route| route.handler.clone());
                (state, route_index, handler)
            })
    }

    /// 🧭 Resolves a route without cloning its complete handler tree.
    pub(crate) fn match_route_index(
        &self,
        host: &str,
        path: &str,
        method: &str,
        headers: &pingora_http::RequestHeader,
        remote_ip: &str,
    ) -> Option<(ProxyState, Option<usize>)> {
        // 🏠 Resolves the immutable state published for this virtual host.
        let state = self.get_state(host)?;

        // 🔐 Matches the HTTPS transport used by the in-process H3 adapter.
        let protocol = "https";

        let route_index = state
            .router
            .match_request(path, method, &headers.headers, host, remote_ip, protocol)
            .map(|route| route.index);
        Some((state, route_index))
    }

    // MARK: - Internal Helpers

    /// Get the state for a specific host.
    ///
    /// Resolution order (matches Caddy semantics):
    /// 1. Exact hostname match (`api.example.com`)
    /// 2. Wildcard match (`*.example.com`) — checks all registered wildcard hosts
    /// 3. Default catch-all server
    fn get_state(&self, host: &str) -> Option<ProxyState> {
        let hosts = self.hosts.load();

        // 1. Exact match (fast path)
        if let Some(state) = hosts.get(host) {
            return Some(state.clone());
        }

        // 2. ⚡ OPTIMIZATION: Wildcard match — iterate registered patterns like *.example.com
        // Only hosts whose registered key starts with "*." are wildcard entries.
        // For a request to "foo.example.com" we check if "*.example.com" is registered.
        for (pattern, state) in hosts.iter() {
            if let Some(wildcard_suffix) = pattern.strip_prefix("*.") {
                // The request host must end with ".{suffix}" to match *.{suffix}
                if host.ends_with(&format!(".{wildcard_suffix}")) {
                    return Some(state.clone());
                }
            }
        }

        // 3. Default catch-all
        // Explicit double-deref: `Guard` and `Arc` both implement `Clone`
        // themselves, so a bare `.load().clone()` would clone the guard
        // (cheap, but the wrong type) instead of the `Option<ProxyState>`
        // it points to.
        (**self.default.load()).clone()
    }

    /// 🔁 Selects a healthy backend outside the current request's attempted set.
    pub(crate) fn select_upstream_excluding(
        &self,
        state: &ProxyState,
        route_index: usize,
        remote_addr: Option<&[u8]>,
        excluded: &HashSet<SocketAddr>,
    ) -> Option<Upstream> {
        state
            .load_balancers
            .get(route_index)
            .and_then(|load_balancer| load_balancer.as_ref())
            .and_then(|load_balancer| load_balancer.select_excluding(remote_addr, excluded))
    }

    /// 🚦 Acquires the selected route's bounded execution slot.
    pub(crate) async fn admit_route(
        &self,
        state: &ProxyState,
        route_index: usize,
    ) -> Result<RouteAdmission, AdmissionError> {
        match state
            .route_protections
            .get(route_index)
            .and_then(|protection| protection.as_ref())
        {
            Some(protection) => protection.admit_route().await,
            None => Err(AdmissionError::QueueFull),
        }
    }

    /// ⚖️ Returns the identity IP-hash balancing uses, matching request policy.
    fn balancing_identity(&self, session: &mut Session, ctx: &RequestContext) -> Option<Vec<u8>> {
        ctx.verified_client_ip
            .or_else(|| {
                Some(
                    self.downstream_identity(session, &session.req_header().headers)
                        .2,
                )
            })
            .map(|address| match address {
                IpAddr::V4(ip) => ip.octets().to_vec(),
                IpAddr::V6(ip) => ip.octets().to_vec(),
            })
    }

    /// 🔌 Selects a backend that has both load-balancer and protection capacity.
    pub(crate) fn select_admitted_upstream(
        &self,
        state: &ProxyState,
        route_index: usize,
        remote_addr: Option<&[u8]>,
        excluded: &HashSet<SocketAddr>,
    ) -> Result<(Upstream, Option<UpstreamAdmission>), UpstreamSelectionError> {
        let protection = state
            .route_protections
            .get(route_index)
            .and_then(|protection| protection.as_ref());

        // ♻️ Drop protection state for backends that have left the pool. The
        // load balancer bumps a generation on every republish, so this is one
        // atomic comparison unless a DNS refresh actually moved something —
        // without it, an upstream that changes address leaves a dead circuit
        // and a dead semaphore behind on every move, forever.
        if let (Some(protection), Some(Some(balancer))) =
            (protection, state.load_balancers.get(route_index))
        {
            protection.reconcile_backends(balancer.generation(), || balancer.backend_addresses());
        }

        let mut local_excluded = excluded.clone();
        let mut rejected = false;
        loop {
            let Some(upstream) =
                self.select_upstream_excluding(state, route_index, remote_addr, &local_excluded)
            else {
                return Err(if rejected {
                    UpstreamSelectionError::Unavailable
                } else {
                    UpstreamSelectionError::NoUpstream
                });
            };
            let pingora_core::protocols::l4::socket::SocketAddr::Inet(address) = &upstream.addr
            else {
                return Ok((upstream, None));
            };
            let Some(protection) = protection else {
                return Ok((upstream, None));
            };
            match protection.admit_upstream(*address) {
                Ok(admission) => return Ok((upstream, Some(admission))),
                Err(error @ (AdmissionError::UpstreamCapacity | AdmissionError::CircuitOpen)) => {
                    rejected = true;
                    local_excluded.insert(*address);
                    protection.reject(error);
                }
                Err(_) => return Err(UpstreamSelectionError::Unavailable),
            }
        }
    }

    /// 🔻 Applies the existing passive-health cooldown to one route backend.
    pub(crate) fn mark_upstream_unhealthy(
        &self,
        state: &ProxyState,
        route_index: usize,
        address: &SocketAddr,
    ) {
        if let Some(load_balancer) = state
            .load_balancers
            .get(route_index)
            .and_then(|load_balancer| load_balancer.as_ref())
        {
            load_balancer.mark_unhealthy(address);
        }
    }

    /// 🌐 Parses an upstream URL into its host, port, and TLS requirement.
    pub fn parse_upstream(upstream: &str) -> Option<(String, u16, bool)> {
        let upstream = upstream.trim();

        let (scheme, rest) = if let Some(stripped) = upstream.strip_prefix("h2c://") {
            (false, stripped)
        } else if let Some(stripped) = upstream.strip_prefix("h2://") {
            (true, stripped)
        } else if let Some(stripped) = upstream.strip_prefix("https://") {
            (true, stripped)
        } else if let Some(stripped) = upstream.strip_prefix("http://") {
            (false, stripped)
        } else {
            (false, upstream)
        };

        let (host, port) = if let Some(colon_idx) = rest.rfind(':') {
            let host = &rest[..colon_idx];
            let port_str = &rest[colon_idx + 1..];
            let port = port_str.parse::<u16>().ok()?;
            (host.to_string(), port)
        } else {
            (rest.to_string(), if scheme { 443 } else { 80 })
        };

        Some((host, port, scheme))
    }

    /// Get proxy config for a route
    pub(crate) fn get_proxy_config(
        &self,
        state: &ProxyState,
        route_index: usize,
    ) -> Option<ReverseProxyConfig> {
        let route = state.config.routes.get(route_index)?;
        // Recurse into handle/route blocks so a nested reverse_proxy's
        // headers/timeouts are picked up, matching how ProxyState::new sets
        // up its load balancer.
        find_reverse_proxy_config(&route.handler).cloned()
    }

    /// 🌐 Builds an [`HttpPeer`] with the selected upstream protocol and timeouts.
    ///
    /// 🤝 This shared builder keeps protocol, timeout, and SNI semantics identical
    /// between the Pingora and HTTP/3 paths.
    pub(crate) fn build_http_peer(
        upstream: &Upstream,
        config: Option<&ReverseProxyConfig>,
        request_budget: Option<Duration>,
        read_budget: Option<Duration>,
        tls_policy: Option<&Arc<crate::upstream_tls::UpstreamTls>>,
    ) -> HttpPeer {
        let addr = upstream.addr.clone();
        let scheme = upstream.ext.get::<Scheme>().unwrap_or(&Scheme::Http);
        let host = upstream
            .ext
            .get::<HostName>()
            .map(|h| h.0.clone())
            .unwrap_or_else(|| match &addr {
                pingora_core::protocols::l4::socket::SocketAddr::Inet(inet) => {
                    inet.ip().to_string()
                }
                pingora_core::protocols::l4::socket::SocketAddr::Unix(u) => u
                    .as_pathname()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or("unix_socket".to_string()),
            });
        let (mut tls, max_http_version, min_http_version, mut protocol_group) = match scheme {
            Scheme::Http => (false, 1, 1, PROTOCOL_GROUP_HTTP),
            Scheme::Https => (true, 2, 1, PROTOCOL_GROUP_HTTPS),
            Scheme::H2c => (false, 2, 2, PROTOCOL_GROUP_H2C),
            Scheme::H2 => (true, 2, 2, PROTOCOL_GROUP_H2),
        };
        // 🔒 A bare `tls` directive upgrades a scheme-less upstream, matching
        // Caddy. It adds encryption and nothing else — the offered ALPN stays
        // HTTP/1.1. Quietly widening it to h2 would let the same directive
        // change which protocol the upstream speaks, so `h2://`/`https://`
        // remain the only ways to ask for that. `h2c://` is likewise left
        // alone: prior-knowledge h2 has no TLS form to be upgraded into.
        if !tls && matches!(scheme, Scheme::Http) && tls_policy.is_some_and(|p| p.forces_tls()) {
            tls = true;
            protocol_group = PROTOCOL_GROUP_HTTPS;
        }

        let mut peer = HttpPeer::new(addr, tls, host);
        peer.options
            .set_http_version(max_http_version, min_http_version);
        if max_http_version == 2 {
            // 🚀 Allows one pooled H2 connection to multiplex independent request streams.
            peer.options.max_h2_streams = 100;
        }
        if matches!(scheme, Scheme::H2) {
            // 🔐 Captures ALPN so the proxy can reject a silent HTTP/1.1 fallback.
            peer.options.upstream_tls_handshake_complete_hook = Some(Arc::new(|tls| {
                Some(Arc::new(NegotiatedUpstreamAlpn(
                    tls.selected_alpn_protocol()
                        .map_or_else(Vec::new, ToOwned::to_owned),
                )))
            }));
        }
        // 🧩 Prevents differently negotiated protocols from sharing a connection pool.
        // 🔐 The TLS identity rides in the upper bits: Pingora hashes a peer's
        // client certificate and verify flags when deciding on connection
        // reuse, but never its CA bundle, so two routes with different trust
        // roots would otherwise share a session verified under whichever
        // roots happened to open it first.
        peer.group_key = protocol_group
            | (tls_policy.map_or(0, |policy| policy.pool_key()) << PROTOCOL_GROUP_BITS);
        if let Some(policy) = tls_policy {
            policy.apply(&mut peer);
        }

        let legacy_read = config
            .and_then(|config| config.read_timeout)
            .filter(|value| *value > 0)
            .map(|value| Duration::from_millis(value as u64));
        let first_byte = config
            .and_then(|config| config.first_byte_timeout)
            .filter(|value| *value > 0)
            .map(|value| Duration::from_millis(value as u64))
            .or(legacy_read);
        let between_reads = config
            .and_then(|config| config.between_reads_timeout)
            .filter(|value| *value > 0)
            .map(|value| Duration::from_millis(value as u64))
            .or(legacy_read);
        // ⏱️ Pingora 0.8 exposes one upstream read timer for both H1/H2 phases.
        // 🌊 Preserve explicit phase timers so a response can become SSE after its header.
        let phase_read_timeout = shortest_duration(first_byte, between_reads);
        peer.options.read_timeout = phase_read_timeout.or(read_budget);
        peer.options.write_timeout = shortest_duration(
            config
                .and_then(|config| config.write_timeout)
                .filter(|value| *value > 0)
                .map(|value| Duration::from_millis(value as u64)),
            request_budget,
        );
        let connect_timeout = config
            .and_then(|config| config.connect_timeout)
            .filter(|value| *value > 0)
            .map(|value| Duration::from_millis(value as u64))
            .unwrap_or(Duration::from_secs(10));
        peer.options.connection_timeout = shortest_duration(Some(connect_timeout), request_budget);
        peer.options.total_connection_timeout = peer.options.connection_timeout;

        peer
    }

    /// 🧱 Applies one virtual host's request deadlines without buffering body data.
    fn initialize_request_limits(
        session: &mut Session,
        ctx: &mut RequestContext,
        state: &ProxyState,
    ) {
        let limits = &state.config.limits;
        ctx.request_deadline = limits
            .request_timeout_ms
            .map(Duration::from_millis)
            .map(|duration| ctx.start_time + duration);
        ctx.upload_pacer = limits.upload_bytes_per_sec.map(BandwidthPacer::new);
        ctx.download_pacer = limits.download_bytes_per_sec.map(BandwidthPacer::new);

        let read_timeout = shortest_duration(
            limits.body_timeout_ms.map(Duration::from_millis),
            limits.idle_timeout_ms.map(Duration::from_millis),
        );
        session.as_mut().set_read_timeout(read_timeout);
        session
            .as_mut()
            .set_write_timeout(limits.idle_timeout_ms.map(Duration::from_millis));
        session.as_mut().set_total_drain_timeout(read_timeout);
        session.as_mut().set_keepalive(Some(
            limits
                .idle_timeout_ms
                .map_or(60, |idle_ms| idle_ms.div_ceil(1_000)),
        ));
    }

    /// 🌊 Replaces ordinary deadlines for an intentional streaming response or tunnel.
    fn activate_long_connection(
        session: &mut Session,
        ctx: &mut RequestContext,
        state: &ProxyState,
    ) {
        if ctx.long_connection {
            return;
        }
        ctx.long_connection = true;
        let long = &state.config.limits.long_connections;
        if let Some(request_ms) = long.request_timeout_ms {
            ctx.request_deadline =
                (request_ms > 0).then(|| ctx.start_time + Duration::from_millis(request_ms));
        }
        if let Some(idle_ms) = long.idle_timeout_ms {
            let timeout = (idle_ms > 0).then(|| Duration::from_millis(idle_ms));
            session.as_mut().set_read_timeout(timeout);
            session.as_mut().set_write_timeout(timeout);
            session.as_mut().set_total_drain_timeout(timeout);
            session
                .as_mut()
                .set_keepalive((idle_ms > 0).then(|| idle_ms.div_ceil(1_000)));
        }
    }

    /// ⌛ Returns a fail-closed timeout error when the whole-request budget expired.
    fn enforce_request_deadline(ctx: &RequestContext) -> pingora_core::Result<()> {
        if ctx
            .request_deadline
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
        {
            return pingora_core::Error::e_explain(
                pingora_core::ErrorType::HTTPStatus(408),
                "whole-request timeout exceeded",
            );
        }
        Ok(())
    }

    /// 🔁 Returns a gateway timeout when the route's total retry budget expired.
    fn enforce_retry_deadline(ctx: &RequestContext) -> pingora_core::Result<()> {
        if ctx
            .retry_deadline
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
        {
            return pingora_core::Error::e_explain(
                pingora_core::ErrorType::HTTPStatus(504),
                "upstream retry timeout exceeded",
            );
        }
        Ok(())
    }

    /// 📥 Enforces one streamed request-body chunk without retaining it.
    async fn enforce_request_body_chunk(
        session: &mut Session,
        ctx: &mut RequestContext,
        bytes: usize,
    ) -> pingora_core::Result<()> {
        Self::enforce_request_deadline(ctx)?;
        Self::enforce_retry_deadline(ctx)?;
        ctx.request_body_bytes = ctx.request_body_bytes.saturating_add(bytes as u64);
        if ctx.state.as_ref().is_some_and(|state| {
            let limit = state.config.client_max_body_size;
            limit > 0 && ctx.request_body_bytes > limit
        }) {
            session.as_mut().set_keepalive(None);
            return pingora_core::Error::e_explain(
                pingora_core::ErrorType::HTTPStatus(413),
                "streamed request body exceeds configured limit",
            );
        }
        if let Some(delay) = ctx
            .upload_pacer
            .as_mut()
            .and_then(|pacer| pacer.delay_for(bytes))
        {
            if ctx
                .request_deadline
                .is_some_and(|deadline| std::time::Instant::now() + delay >= deadline)
            {
                return pingora_core::Error::e_explain(
                    pingora_core::ErrorType::HTTPStatus(408),
                    "upload rate budget exceeds whole-request deadline",
                );
            }
            tokio::time::sleep(delay).await;
        }
        Ok(())
    }

    /// 📥 Drains a local handler's body through the same streaming limits as a proxy.
    async fn drain_local_request_body(
        session: &mut Session,
        ctx: &mut RequestContext,
    ) -> pingora_core::Result<()> {
        while let Some(bytes) = session.read_request_body().await? {
            Self::enforce_request_body_chunk(session, ctx, bytes.len()).await?;
        }
        Ok(())
    }

    /// 📤 Writes one local response chunk through the configured streaming budget.
    async fn write_local_body(
        session: &mut Session,
        ctx: &mut RequestContext,
        body: Bytes,
        end_of_stream: bool,
    ) -> PingoraResult<()> {
        Self::enforce_request_deadline(ctx)?;
        if let Some(delay) = ctx
            .download_pacer
            .as_mut()
            .and_then(|pacer| pacer.delay_for(body.len()))
        {
            if ctx
                .request_deadline
                .is_some_and(|deadline| std::time::Instant::now() + delay >= deadline)
            {
                return pingora_core::Error::e_explain(
                    pingora_core::ErrorType::HTTPStatus(408),
                    "download rate budget exceeds whole-request deadline",
                );
            }
            tokio::time::sleep(delay).await;
        }
        ctx.response_bytes += body.len() as u64;
        session.write_response_body(Some(body), end_of_stream).await
    }

    /// Write a minimal plain-text response and end the request.
    /// Used for early, handler-less answers such as 404s.
    async fn write_simple_response(
        session: &mut Session,
        // Takes &mut so the access log can count the body bytes it writes.
        ctx: &mut RequestContext,
        status: u16,
        body: &str,
    ) -> PingoraResult<()> {
        let mut response = ResponseHeader::build(status, Some(3)).unwrap();
        response
            .insert_header("Content-Type", "text/plain")
            .unwrap();
        response
            .insert_header("Content-Length", body.len().to_string())
            .unwrap();
        Self::apply_local_response_headers(&mut response, ctx)?;
        session
            .write_response_header(Box::new(response), false)
            .await?;
        Self::write_local_body(session, ctx, Bytes::copy_from_slice(body.as_bytes()), true).await?;
        Ok(())
    }

    /// Apply response directives accumulated by handlers such as `header`
    /// and `cors` to locally generated responses. Upstream responses receive
    /// the same treatment in `response_filter`.
    fn apply_local_response_headers(
        response: &mut ResponseHeader,
        ctx: &RequestContext,
    ) -> PingoraResult<()> {
        ctx.response_headers
            .apply_pingora(response, &ctx.request_id, None)?;
        if let Some(state) = &ctx.state {
            Self::apply_security_response_headers(response, state)?;
        }
        Ok(())
    }

    /// 🛡️ Applies the vhost security policy consistently to local and upstream responses.
    fn apply_security_response_headers(
        response: &mut ResponseHeader,
        state: &ProxyState,
    ) -> PingoraResult<()> {
        if !state.config.security.enabled {
            return Ok(());
        }
        response.insert_header(
            "X-Content-Type-Options",
            &state.config.security.x_content_type_options,
        )?;
        response.insert_header("X-Frame-Options", &state.config.security.x_frame_options)?;
        response.insert_header("X-XSS-Protection", &state.config.security.x_xss_protection)?;
        response.insert_header(
            "X-Permitted-Cross-Domain-Policies",
            &state.config.security.x_permitted_cross_domain,
        )?;
        response.insert_header("Referrer-Policy", &state.config.security.referrer_policy)?;
        response.insert_header(
            "Permissions-Policy",
            &state.config.security.permissions_policy,
        )?;
        if state
            .config
            .tls
            .as_ref()
            .is_some_and(|tls| tls.auto || tls.cert.is_some())
            && let Some(hsts_config) = &state.config.security.hsts
        {
            let hsts_value = format!(
                "max-age={};{}{}",
                hsts_config.max_age,
                if hsts_config.include_subdomains {
                    " includeSubDomains;"
                } else {
                    ""
                },
                if hsts_config.preload { " preload" } else { "" }
            );
            response.insert_header("Strict-Transport-Security", &hsts_value)?;
        }
        if let Some(csp) = &state.config.security.csp {
            response.insert_header("Content-Security-Policy", csp)?;
        }
        Ok(())
    }

    /// Apply an internal rewrite to the downstream request before Pingora
    /// clones it for the upstream connection. Existing query parameters are
    /// preserved unless the replacement supplies its own query string.
    fn apply_rewrite(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        route_index: usize,
        rule: RewriteRule<'_>,
    ) -> PingoraResult<()> {
        let current = session
            .req_header()
            .uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");
        let new_uri = ctx
            .state
            .as_ref()
            .ok_or_else(|| {
                pingora_core::Error::explain(
                    pingora_core::ErrorType::InternalError,
                    "missing route state for rewrite",
                )
            })?
            .rewrite_request_uri(
                route_index,
                current,
                rule.strip_prefix,
                rule.strip_suffix,
                rule.replace,
                rule.regex,
                rule.regex_replace,
            )
            .map_err(|message| {
                pingora_core::Error::explain(pingora_core::ErrorType::InternalError, message)
            })?;
        session.req_header_mut().set_raw_path(new_uri.as_bytes())?;
        ctx.rewritten_path = Some(
            new_uri
                .split_once('?')
                .map_or(new_uri.clone(), |(path, _)| path.to_string()),
        );
        Ok(())
    }

    /// Serve the vhost's configured custom error page for `status`
    /// (`error_page` directive), falling back to the built-in plain-text
    /// response when no page is mapped or the file cannot be read.
    /// Error paths are cold, so a synchronous file read here is fine.
    async fn serve_error_page(
        &self,
        session: &mut Session,
        // &mut so body bytes can be counted for the access log.
        ctx: &mut RequestContext,
        status: u16,
    ) -> PingoraResult<()> {
        if let Some((content, content_type)) = ctx
            .state
            .as_ref()
            .and_then(|state| state.read_error_page(status))
        {
            let mut response = ResponseHeader::build(status, Some(4)).unwrap();
            response
                .insert_header("Content-Type", content_type)
                .unwrap();
            response
                .insert_header("Content-Length", content.len().to_string())
                .unwrap();
            Self::apply_local_response_headers(&mut response, ctx)?;
            session
                .write_response_header(Box::new(response), false)
                .await?;
            Self::write_local_body(session, ctx, Bytes::from(content), true).await?;
            return Ok(());
        }
        let reason = error_reason(status);
        Self::write_simple_response(session, ctx, status, &format!("{status} {reason}")).await
    }

    /// Handle a specific handler configuration
    #[async_recursion]
    async fn handle_config(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        handler: &HandlerConfig,
        path: &str,
        route_index: usize,
    ) -> PingoraResult<bool> {
        match handler {
            HandlerConfig::Respond {
                status,
                body,
                headers,
            } => {
                let mut response = ResponseHeader::build(*status, Some(3)).unwrap();
                for (k, v) in headers {
                    if let (Ok(name), Ok(value)) = (
                        http::header::HeaderName::from_bytes(k.as_bytes()),
                        http::header::HeaderValue::from_str(v.as_str()),
                    ) {
                        response.insert_header(name, value).unwrap();
                    }
                }
                let body_bytes = body.as_deref().unwrap_or("").as_bytes();
                response
                    .insert_header("Content-Length", body_bytes.len().to_string())
                    .unwrap();
                Self::apply_local_response_headers(&mut response, ctx)?;
                session
                    .write_response_header(Box::new(response), false)
                    .await?;
                Self::write_local_body(session, ctx, Bytes::copy_from_slice(body_bytes), true)
                    .await?;
                Ok(true)
            }
            HandlerConfig::Redirect { to, code } => {
                let mut response = ResponseHeader::build(*code, Some(3)).unwrap();
                response.insert_header("Location", to.as_str()).unwrap();
                Self::apply_local_response_headers(&mut response, ctx)?;
                session
                    .write_response_header(Box::new(response), true)
                    .await?;
                Ok(true)
            }
            HandlerConfig::FileServer { .. } => {
                let maybe_file_server = {
                    ctx.state.as_ref().and_then(|state| {
                        state.file_servers.get(route_index).and_then(|f| f.clone())
                    })
                };

                if let Some(file_server) = maybe_file_server {
                    let range_header = session
                        .req_header()
                        .headers
                        .get("Range")
                        .and_then(|v| v.to_str().ok());
                    let accept_encoding = session
                        .req_header()
                        .headers
                        .get("Accept-Encoding")
                        .and_then(|v| v.to_str().ok());

                    // serve_auto makes the buffered-vs-streaming call in one
                    // pass (single resolve + stat per request): large,
                    // complete, uncompressed responses stream in 64KB chunks
                    // instead of being buffered whole in memory.
                    match file_server
                        .serve_auto(path, range_header, accept_encoding)
                        .await
                    {
                        Ok(Some(pingclair_static::ServedResponse::Stream(mut stream))) => {
                            let mut header = ResponseHeader::build(200, Some(3)).unwrap();
                            header
                                .insert_header("Content-Type", stream.mime_type.as_str())
                                .unwrap();
                            header
                                .insert_header("Content-Length", stream.file_size.to_string())
                                .unwrap();
                            if let Some(lm) = &stream.last_modified {
                                header.insert_header("Last-Modified", lm.as_str()).unwrap();
                            }
                            if let Some(etag) = &stream.etag {
                                header.insert_header("ETag", etag.as_str()).unwrap();
                            }
                            header.insert_header("Accept-Ranges", "bytes").unwrap();
                            Self::apply_local_response_headers(&mut header, ctx)?;

                            session
                                .write_response_header(Box::new(header), false)
                                .await?;
                            // Synchronous chunk reads (see StreamingFile):
                            // only the socket writes are async here.
                            while let Some(chunk) = stream.read_chunk().map_err(|e| {
                                pingora_core::Error::because(
                                    pingora_core::ErrorType::ReadError,
                                    "streaming file body",
                                    e,
                                )
                            })? {
                                let last = stream.is_complete();
                                Self::write_local_body(session, ctx, Bytes::from(chunk), last)
                                    .await?;
                            }
                            return Ok(true);
                        }
                        Ok(Some(pingclair_static::ServedResponse::Buffered(file))) => {
                            let mut header = ResponseHeader::build(file.status, Some(3)).unwrap();
                            header
                                .insert_header("Content-Type", file.mime_type.as_str())
                                .unwrap();
                            header
                                .insert_header("Content-Length", file.content.len().to_string())
                                .unwrap();

                            if let Some(range) = file.content_range {
                                header
                                    .insert_header("Content-Range", range.as_str())
                                    .unwrap();
                            }
                            if let Some(lm) = file.last_modified {
                                header.insert_header("Last-Modified", lm.as_str()).unwrap();
                            }
                            if let Some(etag) = file.etag {
                                header.insert_header("ETag", etag.as_str()).unwrap();
                            }
                            if let Some(encoding) = file.content_encoding {
                                header
                                    .insert_header("Content-Encoding", encoding.as_str())
                                    .unwrap();
                            }
                            header.insert_header("Accept-Ranges", "bytes").unwrap();
                            Self::apply_local_response_headers(&mut header, ctx)?;

                            session
                                .write_response_header(Box::new(header), false)
                                .await?;
                            Self::write_local_body(session, ctx, Bytes::from(file.content), true)
                                .await?;
                            return Ok(true);
                        }
                        // Missing file (or read error): a file_server route
                        // has no upstream to fall back to, so answer 404
                        // here instead of falling through to upstream_peer,
                        // which would surface a 500 (ConnectNoRoute).
                        _ => {
                            self.serve_error_page(session, ctx, 404).await?;
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            }
            HandlerConfig::Pipeline { handlers } => {
                let mut current_path = path.to_string();
                for h in handlers {
                    if self
                        .handle_config(session, ctx, h, &current_path, route_index)
                        .await?
                    {
                        return Ok(true);
                    }
                    current_path = ctx
                        .rewritten_path
                        .take()
                        .unwrap_or_else(|| session.req_header().uri.path().to_string());
                }
                Ok(false)
            }
            HandlerConfig::Handle { handlers } => {
                let mut current_path = path.to_string();
                for h in handlers {
                    if self
                        .handle_config(session, ctx, h, &current_path, route_index)
                        .await?
                    {
                        return Ok(true);
                    }
                    current_path = ctx
                        .rewritten_path
                        .take()
                        .unwrap_or_else(|| session.req_header().uri.path().to_string());
                }
                Ok(false)
            }
            HandlerConfig::HandlePath { prefix, handlers } => {
                let current = session
                    .req_header()
                    .uri
                    .path_and_query()
                    .map(|value| value.as_str())
                    .unwrap_or(path);
                let rewritten = if path.starts_with(prefix) {
                    rewrite_uri(current, Some(prefix), None, None, None, None)
                } else {
                    current.to_string()
                };
                session
                    .req_header_mut()
                    .set_raw_path(rewritten.as_bytes())?;
                let new_path = rewritten
                    .split_once('?')
                    .map_or(rewritten.as_str(), |(rewritten_path, _)| rewritten_path);
                ctx.rewritten_path = Some(new_path.to_string());

                for handler in handlers {
                    if self
                        .handle_config(session, ctx, handler, new_path, route_index)
                        .await?
                    {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            HandlerConfig::HandleErrors { .. } => {
                // Error handlers are configured separately or handled by middleware.
                // This config node is a placeholder for attached error handlers.
                Ok(false)
            }
            HandlerConfig::RateLimit { .. } => {
                // Enforcement happens in `request_filter`, which holds one
                // pre-built limiter per route (see `rate_limiters`); reaching
                // this arm means the request passed, so just fall through.
                Ok(false)
            }
            HandlerConfig::BasicAuth { realm, credentials } => {
                // 🔐 Authentication runs before later handlers in the chain.
                if pingclair_core::server::verify_basic_auth_async(
                    &session.req_header().headers,
                    credentials,
                )
                .await
                {
                    Ok(false)
                } else {
                    let body = "Unauthorized";
                    let challenge = pingclair_core::server::basic_auth_challenge(realm);
                    let mut response = ResponseHeader::build(401, Some(3)).unwrap();
                    response
                        .insert_header("WWW-Authenticate", challenge.as_str())
                        .unwrap();
                    response
                        .insert_header("Content-Length", body.len().to_string())
                        .unwrap();
                    Self::apply_local_response_headers(&mut response, ctx)?;
                    session
                        .write_response_header(Box::new(response), false)
                        .await?;
                    Self::write_local_body(
                        session,
                        ctx,
                        Bytes::copy_from_slice(body.as_bytes()),
                        true,
                    )
                    .await?;
                    Ok(true)
                }
            }
            HandlerConfig::Headers { set, add, remove } => {
                for (k, v) in set {
                    ctx.response_headers.set(k, v.clone());
                }
                for (k, v) in add {
                    ctx.response_headers.add(k, v.clone());
                }
                for name in remove {
                    ctx.response_headers.remove(name);
                }
                Ok(false)
            }
            HandlerConfig::Rewrite {
                strip_prefix,
                strip_suffix,
                replace,
                regex,
                regex_replace,
            } => {
                self.apply_rewrite(
                    session,
                    ctx,
                    route_index,
                    RewriteRule {
                        strip_prefix: strip_prefix.as_deref(),
                        strip_suffix: strip_suffix.as_deref(),
                        replace: replace.as_deref(),
                        regex: regex.as_deref(),
                        regex_replace: regex_replace.as_deref(),
                    },
                )?;
                Ok(false)
            }
            HandlerConfig::AccessControl(_) => {
                // The compiled policy runs before handler dispatch in
                // request_filter, making it consistently apply to static,
                // proxied, and locally generated responses.
                Ok(false)
            }
            HandlerConfig::Cors {
                allowed_origins,
                allowed_methods,
                allowed_headers,
                exposed_headers,
                allow_credentials,
                max_age,
            } => {
                let decision = evaluate_cors(
                    &session.req_header().method,
                    &session.req_header().headers,
                    allowed_origins,
                    allowed_methods,
                    allowed_headers,
                    exposed_headers,
                    *allow_credentials,
                    *max_age,
                );
                match decision {
                    CorsDecision::PassThrough => Ok(false),
                    CorsDecision::Continue(policy) => {
                        ctx.response_headers.merge(policy);
                        Ok(false)
                    }
                    CorsDecision::Respond {
                        status,
                        body,
                        headers,
                    } => {
                        ctx.response_headers.merge(headers);
                        let mut response = ResponseHeader::build(status, Some(8)).unwrap();
                        if !body.is_empty() {
                            response
                                .insert_header("content-type", "text/plain")
                                .unwrap();
                        }
                        response
                            .insert_header("content-length", body.len().to_string())
                            .unwrap();
                        Self::apply_local_response_headers(&mut response, ctx)?;
                        session
                            .write_response_header(Box::new(response), body.is_empty())
                            .await?;
                        if !body.is_empty() {
                            Self::write_local_body(
                                session,
                                ctx,
                                Bytes::copy_from_slice(body.as_bytes()),
                                true,
                            )
                            .await?;
                        }
                        Ok(true)
                    }
                }
            }
            HandlerConfig::TryFiles { files, fallback } => {
                // 🏗️ ARCHITECTURE: try_files checks each file path in order.
                // If a file exists, serve it via FileServer. If none match,
                // execute the fallback handler (or 404).
                for file_path in files {
                    // Resolve {path} variable
                    let resolved = file_path.replace("{path}", path);
                    // Check if file exists (delegate to static server)
                    let full_path = std::path::Path::new(&resolved);
                    if full_path.exists() && full_path.is_file() {
                        // Serve via FileServer handler
                        let parent = full_path
                            .parent()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_else(|| ".".to_string());
                        let file_handler = HandlerConfig::FileServer {
                            root: parent,
                            index: vec![],
                            browse: false,
                            compress: true,
                        };
                        return self
                            .handle_config(session, ctx, &file_handler, &resolved, route_index)
                            .await;
                    }
                }
                // No file found — execute fallback
                if let Some(fb) = fallback {
                    return self
                        .handle_config(session, ctx, fb, path, route_index)
                        .await;
                }
                Ok(false)
            }
            _ => Ok(false),
        }
    }
}

// MARK: - Caddy Placeholder Resolution

/// Resolve Caddy-style `{placeholder}` variables in a header value string
/// using the actual downstream request headers.
///
/// Supported placeholders:
/// - `{http.request.header.Header-Name}` → value of the named request header
/// - `{host}`                            → request Host header
/// - 🛡️ `{remote_ip}`                    → verified client IP
/// - `{http.request.method}`             → HTTP method
/// - `{http.request.uri}`                → full URI
/// - `{http.request.uri.path}`           → URI path only
///
/// If a placeholder references a header that doesn't exist, it resolves to
/// an empty string (matching Caddy's behavior).
pub(crate) fn resolve_caddy_placeholders(
    template: &str,
    req: &RequestHeader,
    verified_client_ip: Option<&str>,
) -> String {
    if !template.contains('{') {
        // ⚡ OPTIMIZATION: Fast path — no placeholders, return as-is.
        return template.to_string();
    }

    let mut result = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '{' {
            // Collect placeholder name until '}'
            let mut placeholder = String::new();
            while let Some(&pc) = chars.peek() {
                if pc == '}' {
                    chars.next(); // consume '}'
                    break;
                }
                placeholder.push(chars.next().unwrap());
            }

            // Resolve the placeholder
            let resolved = resolve_single_placeholder(&placeholder, req, verified_client_ip);
            result.push_str(&resolved);
        } else {
            result.push(c);
        }
    }

    result
}

/// Resolve a single Caddy placeholder name to its value.
fn resolve_single_placeholder(
    name: &str,
    req: &RequestHeader,
    verified_client_ip: Option<&str>,
) -> String {
    // {http.request.header.Header-Name}
    if let Some(header_name) = name.strip_prefix("http.request.header.") {
        return req
            .headers
            .get(header_name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
    }

    // Common shortcuts
    match name {
        "host" => req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string(),
        "http.request.host" => req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string(),
        "remote_ip" | "http.request.remote.host" => verified_client_ip.unwrap_or("").to_string(),
        "http.request.method" => req.method.as_str().to_string(),
        "http.request.uri" => req.uri.to_string(),
        "http.request.uri.path" => req.uri.path().to_string(),
        _ => {
            tracing::debug!("⚠️ Unresolved Caddy placeholder: {{{}}}", name);
            String::new()
        }
    }
}

// MARK: - ProxyHttp Trait

#[async_trait]
impl ProxyHttp for PingclairProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext::default()
    }

    /// Register downstream modules that run on every response written
    /// through this proxy (both locally generated and upstream-proxied),
    /// which is exactly the property Alt-Svc advertisement needs.
    fn init_downstream_modules(&self, modules: &mut pingora_core::modules::http::HttpModules) {
        modules.add_module(Box::new(crate::alt_svc::AltSvcModuleBuilder::new(
            self.alt_svc.clone(),
        )));
    }

    /// 🧾 Rejects decoded headers that exceed the selected virtual host's explicit bounds.
    async fn early_request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()> {
        let request = session.req_header();
        let host = authority_host(request_authority(request));
        let Some(state) = self.get_state(host) else {
            return Ok(());
        };
        let limits = &state.config.limits;
        let header_count = request.headers.len();
        let header_bytes = request.headers.iter().fold(0usize, |total, (name, value)| {
            total
                .saturating_add(name.as_str().len())
                .saturating_add(value.as_bytes().len())
        });
        if limits
            .max_header_count
            .is_some_and(|limit| header_count > limit)
            || limits
                .max_header_bytes
                .is_some_and(|limit| header_bytes > limit)
        {
            session.as_mut().set_keepalive(None);
            return pingora_core::Error::e_explain(
                pingora_core::ErrorType::HTTPStatus(431),
                "request headers exceed configured limits",
            );
        }
        Ok(())
    }

    /*
    // Removed in Pingora 0.6: TLS resolution is handled by listeners, not the proxy trait.
    /// Resolve TLS certificate for SNI
     */

    /// Request filter (Handle static files and early return)
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<bool> {
        if self.proxy_protocol_required && self.proxy_protocol_identity(session).is_none() {
            tracing::warn!("🚫 Rejected a TCP request that bypassed the PROXY protocol ingress");
            session.as_mut().set_keepalive(None);
            Self::write_simple_response(session, ctx, 400, "PROXY Protocol Required").await?;
            return Ok(true);
        }

        // 🛡️ Framing is settled before anything else reads the request, because
        // a message whose length two parsers can read differently must not be
        // routed, logged as a normal request, or forwarded at all.
        {
            let request_header = session.req_header();

            // 🚫 A path that still carries `.` or `..` would match one route
            // here and resolve to a different resource at the origin.
            if crate::http_policy::path_escapes_its_route(request_header.uri.path()) {
                tracing::warn!(
                    "🚫 Rejected a request whose path escapes the route it matched: {}",
                    request_header.uri.path()
                );
                Self::write_simple_response(session, ctx, 400, "Unnormalized Request Path").await?;
                return Ok(true);
            }

            if let Err(rejection) = crate::http_policy::check_request_framing(
                request_header.version,
                &request_header.headers,
            ) {
                tracing::warn!(
                    "🚫 Rejected a request with untrustworthy message framing: {}",
                    rejection.reason()
                );
                // 🔌 The connection is no longer safe to reuse: we and the client
                // may already disagree about where this request body ends.
                session.as_mut().set_keepalive(None);
                Self::write_simple_response(session, ctx, 400, rejection.reason()).await?;
                return Ok(true);
            }
        }

        // Handle ACME Challenges (HTTP-01)
        let request_header = session.req_header();
        let path = request_header.uri.path();

        if path.starts_with("/.well-known/acme-challenge/")
            && let Some(manager) = &self.tls_manager
        {
            // Extract token
            let token = path.trim_start_matches("/.well-known/acme-challenge/");

            // Lookup token in challenge handler
            let handler = manager.challenge_handler();
            if let Some(key_auth) = handler.get_token(token) {
                tracing::info!("🔐 Serving ACME challenge for token: {}", token);

                let mut header = pingora_http::ResponseHeader::build(200, Some(2)).unwrap();
                header
                    .insert_header("Content-Type", "application/octet-stream")
                    .unwrap();
                header
                    .insert_header("Content-Length", key_auth.len().to_string())
                    .unwrap();
                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                ctx.response_bytes += key_auth.len() as u64;
                session
                    .write_response_body(Some(Bytes::from(key_auth)), true)
                    .await?;
                return Ok(true);
            } else {
                tracing::warn!("⚠️ ACME challenge token not found: {}", token);
            }
        }

        // Match route in a scope to release borrow of session
        let (
            path_str,
            route_index,
            handler,
            remote_ip,
            request_host,
            request_method,
            request_scheme,
        ) = {
            let request_header = session.req_header();
            let path = request_header.uri.path();
            let method = request_header.method.as_str();

            // 🌐 Prefer URI authority so HTTP/2 virtual hosts match the HTTP/1.1 Host path.
            let authority = request_authority(request_header);
            let host = authority_host(authority);

            // Get state for this host
            let state = match self.get_state(host) {
                Some(s) => s,
                None => {
                    // Unknown virtual host: nothing could ever proxy this
                    // request, so answer 404 now. Returning Ok(false) here
                    // would land in upstream_peer with no state and surface
                    // as a 500 (ConnectNoRoute).
                    Self::write_simple_response(session, ctx, 404, "404 Not Found").await?;
                    return Ok(true);
                }
            };
            ctx.state = Some(state.clone());

            // 🛡️ Resolve proxy headers only when the immediate peer is trusted.
            let (transport_peer_ip, _transport_client_ip, verified_client_ip) =
                self.downstream_identity(session, &request_header.headers);
            let remote_ip = verified_client_ip.to_string();

            // ⚡ OPTIMIZATION: Identify protocol via URI scheme, forwarding header, or port.
            // Pingora 0.6 removed the per-request TLS flag; we detect HTTPS by:
            //   (a) checking the HTTP/2 `:scheme` mapped into the URI,
            //   (b) checking X-Forwarded-Proto, or
            //   (c) checking whether the authority uses port 443 / 8443.
            let protocol = {
                let via_header = if self.is_trusted_proxy(transport_peer_ip) {
                    request_header
                        .headers
                        .get("x-forwarded-proto")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                } else {
                    ""
                };
                if request_header.uri.scheme_str() == Some("https") || via_header == "https" {
                    "https"
                } else {
                    let port_in_host = authority_port(authority).unwrap_or(80);
                    if port_in_host == 443 || port_in_host == 8443 {
                        "https"
                    } else {
                        "http"
                    }
                }
            };

            if let Some(route) = state.router.match_request(
                path,
                method,
                &request_header.headers,
                host,
                &remote_ip,
                protocol,
            ) {
                let index = route.index;
                let handler = state.config.routes.get(index).map(|r| r.handler.clone());
                (
                    path.to_string(),
                    Some(index),
                    handler,
                    remote_ip,
                    host.to_string(),
                    method.to_string(),
                    protocol.to_string(),
                )
            } else {
                (
                    path.to_string(),
                    None,
                    None,
                    remote_ip,
                    host.to_string(),
                    method.to_string(),
                    protocol.to_string(),
                )
            }
        };

        // Capture request metadata for access log
        ctx.request_path = path_str.clone();
        ctx.request_host = request_host;
        ctx.request_method = request_method;
        ctx.verified_client_ip = remote_ip.parse().ok();
        ctx.request_scheme = request_scheme;

        if let Some(state) = ctx.state.clone() {
            Self::initialize_request_limits(session, ctx, &state);
        }

        // Honor a client-supplied request ID so traces can be correlated
        // across chained proxies; fall back to the generated one when the
        // header is absent or malformed.
        if let Some(client_id) = session
            .req_header()
            .headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .and_then(sanitize_request_id)
        {
            ctx.request_id = client_id;
        }

        // 🗜️ Negotiate the response coding against this server's `encode`
        // list. Done here, not in `response_filter`, so the decision is made
        // from the request alone — `response_filter` then only has to check
        // properties of the upstream response (content type, size, whether it
        // is already encoded).
        if let Some(state) = &ctx.state {
            let accept_encoding = session
                .req_header()
                .headers
                .get("accept-encoding")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            ctx.negotiated_encoding = negotiate(accept_encoding, &state.config.encodings);
        }

        // Check request body size (Content-Length)
        if let Some(state) = &ctx.state {
            let limit = state.config.client_max_body_size;
            if limit > 0
                && let Some(content_length) = session
                    .req_header()
                    .headers
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                && content_length > limit
            {
                let mut header = pingora_http::ResponseHeader::build(413, Some(4)).unwrap();
                header.insert_header("Connection", "close").unwrap();
                Self::apply_local_response_headers(&mut header, ctx)?;
                session
                    .write_response_header(Box::new(header), true)
                    .await?;
                return Ok(true);
            }
        }

        if let Some(index) = route_index {
            ctx.route_index = Some(index);

            if let Some(state) = ctx.state.clone() {
                let immediate_flush = self
                    .get_proxy_config(&state, index)
                    .is_some_and(|config| wants_immediate_flush(config.flush_interval));
                if immediate_flush || is_websocket_upgrade(&session.req_header().headers) {
                    Self::activate_long_connection(session, ctx, &state);
                }
            }

            // Access rules run before authentication, static-file lookup, or
            // an upstream connection. This keeps denied traffic out of every
            // later request path and makes the policy apply uniformly to all
            // terminal handler types.
            if let Some(state) = &ctx.state
                && !state.allows_access(index, &remote_ip, &session.req_header().headers)
            {
                Self::write_simple_response(session, ctx, 403, "Forbidden").await?;
                return Ok(true);
            }

            // 🚫 Rejects declared request trailers because Pingora currently discards H1 trailers.
            if session.req_header().headers.contains_key("trailer") {
                tracing::debug!("🚫 Rejecting request trailers before handler dispatch");
                session.as_mut().set_keepalive(None);
                self.serve_error_page(session, ctx, 501).await?;
                return Ok(true);
            }

            // 🚦 Charges the configured exact token bucket before handler dispatch.
            if let Some(state) = &ctx.state
                && let Some(limiter) = state.rate_limiters.get(index).and_then(|l| l.as_ref())
            {
                let decision =
                    limiter.check_request(remote_ip.as_str(), &session.req_header().headers);
                for (name, value) in decision.info.to_headers() {
                    ctx.response_headers.set(name, value);
                }
                if decision.reject {
                    let mut header = pingora_http::ResponseHeader::build(429, Some(8)).unwrap();
                    Self::apply_local_response_headers(&mut header, ctx)?;
                    session
                        .write_response_header(Box::new(header), true)
                        .await?;
                    return Ok(true);
                }
            }

            if handler
                .as_ref()
                .is_some_and(|handler| find_reverse_proxy_config(handler).is_some())
                && let Some(state) = ctx.state.clone()
            {
                match self.admit_route(&state, index).await {
                    Ok(admission) => ctx.route_admission = Some(admission),
                    Err(AdmissionError::QueueFull) => {
                        Self::write_simple_response(session, ctx, 429, "Too Many Requests").await?;
                        return Ok(true);
                    }
                    Err(AdmissionError::QueueTimeout) => {
                        Self::write_simple_response(session, ctx, 503, "Service Unavailable")
                            .await?;
                        return Ok(true);
                    }
                    Err(_) => {
                        Self::write_simple_response(session, ctx, 503, "Service Unavailable")
                            .await?;
                        return Ok(true);
                    }
                }
            }

            if let Some(h) = handler {
                if find_reverse_proxy_config(&h).is_none() {
                    Self::drain_local_request_body(session, ctx).await?;
                }
                if self
                    .handle_config(session, ctx, &h, &path_str, index)
                    .await?
                {
                    // ⏱️ A locally produced response never reaches `response_filter`.
                    // ⏱️ Record its TTFB immediately after the synchronous write.
                    ctx.first_byte_at
                        .get_or_insert_with(std::time::Instant::now);
                    return Ok(true);
                }
            }
        }

        // A vhost matched but no route did: there is no handler and no
        // upstream for this request, so answer 404. (Ok(false) would reach
        // upstream_peer, which has nothing to proxy to and fails with a
        // 500 ConnectNoRoute.) When a route *did* match, Ok(false) remains
        // the normal "proxy this to the route's upstream" signal.
        if route_index.is_none() {
            self.serve_error_page(session, ctx, 404).await?;
            return Ok(true);
        }

        Ok(false)
    }

    /// 📦 Enforces streamed body size, timeout, and upload rate without replay buffering.
    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let Some(bytes) = body.as_ref() else {
            return Ok(());
        };
        Self::enforce_request_body_chunk(session, ctx, bytes.len()).await
    }

    /// 🚦 Decides the first attempt's admission before the request is committed
    /// to an upstream, so a fail-fast rejection stays a locally served response.
    ///
    /// The overload rejections (circuit open, upstream capacity) used to surface
    /// as an `Err` out of `upstream_peer`. That error reaches `fail_to_proxy` on
    /// pingora-proxy's `process_request` path, which logs `error_code` but hands
    /// its own `server_reuse` flag — always `false` after a failed upstream
    /// selection — to `finish()`, and `finish()` is what decides whether the
    /// *downstream* connection is reused. `can_reuse_downstream` is only honoured
    /// on the `handle_error` paths, so a fail-fast 503 always closed the client's
    /// connection while the response itself advertised `Connection: keep-alive`.
    ///
    /// Declining here instead returns `Ok(false)`, the one signal pingora-proxy
    /// documents as "a response was written, keep the session reusable". The
    /// admission decision is not repeated: a successful selection is stashed for
    /// the first `upstream_peer` call to consume, and later retry attempts admit
    /// inside `upstream_peer` as they always did.
    async fn proxy_upstream_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        let (Some(state), Some(route_index)) = (ctx.state.clone(), ctx.route_index) else {
            return Ok(true);
        };

        let client_ip = self.balancing_identity(session, ctx);
        match self.select_admitted_upstream(
            &state,
            route_index,
            client_ip.as_deref(),
            &ctx.retry_excluded,
        ) {
            Ok(selected) => {
                ctx.preadmitted_upstream = Some(selected);
                Ok(true)
            }
            Err(UpstreamSelectionError::Unavailable) => {
                tracing::warn!(
                    route = route_index,
                    "⚠️ Failing fast: every backend for this route was rejected by overload protection"
                );
                self.serve_error_page(session, ctx, 503).await?;
                Ok(false)
            }
            // 🛤️ A route with no reachable backend at all is not an overload
            // rejection. Leave it to `upstream_peer`, which owns the 502/504
            // distinction and the redispatch-cycle exclusion reset. This is also
            // the answer for a route that has no load balancer to select from,
            // which is why no separate handler-type guard is needed here: reaching
            // this hook at all means `request_filter` declined to serve locally,
            // and `NoUpstream` is reported before any backend is charged.
            Err(UpstreamSelectionError::NoUpstream) => Ok(true),
        }
    }

    /// 🔁 Selects one upstream while enforcing request-local retry bounds.
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Box<HttpPeer>>
    where
        Self::CTX: Send + Sync,
    {
        let route_index = if let Some(index) = ctx.route_index {
            index
        } else {
            return Err(pingora_core::Error::new(
                pingora_core::ErrorType::ConnectNoRoute,
            ));
        };

        // 🛑 A matched route must retain its immutable state across redispatch attempts.
        let state = match ctx.state.clone() {
            Some(state) => state,
            None => {
                tracing::warn!(
                    "⚠️ upstream_peer called with no state in context — no virtual host matched"
                );
                return Err(pingora_core::Error::new(
                    pingora_core::ErrorType::ConnectNoRoute,
                ));
            }
        };

        let proxy_config = self.get_proxy_config(&state, route_index);
        let retry_policy = proxy_config
            .as_ref()
            .map(|config| config.retry.clone())
            .unwrap_or_default();
        if ctx.retry_attempts == 0 {
            ctx.retry_deadline = crate::retry::deadline(ctx.start_time, &retry_policy);
        }
        if ctx.retry_pending {
            let delay = crate::retry::backoff(&retry_policy);
            if !delay.is_zero() {
                tracing::debug!(
                    route = route_index,
                    attempt = ctx.retry_attempts + 1,
                    backoff_ms = delay.as_millis(),
                    "💤 Waiting before the next upstream attempt"
                );
                tokio::time::sleep(delay).await;
            }
            ctx.retry_pending = false;
        }
        if ctx
            .retry_deadline
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
        {
            return pingora_core::Error::e_explain(
                pingora_core::ErrorType::HTTPStatus(504),
                "upstream retry deadline exceeded",
            );
        }

        // 🔐 Checked before a backend is chosen: a route whose TLS material
        // failed to load must not connect at all, so there is nothing to gain
        // from selecting, admitting, and then dropping an upstream.
        let Ok(tls_policy) = state.upstream_tls_for(route_index) else {
            tracing::error!(
                route = route_index,
                "🚫 Refusing to dispatch: this route's upstream TLS material did not load"
            );
            return pingora_core::Error::e_explain(
                pingora_core::ErrorType::HTTPStatus(500),
                "upstream TLS configuration failed to load",
            );
        };

        // 🚦 `proxy_upstream_filter` already admitted the first attempt; taking
        // its result keeps a backend slot and a circuit probe charged exactly
        // once per attempt, and spares the common path a second identity lookup.
        // Retry attempts find the slot empty and admit here as they always did.
        let mut client_ip = None;
        let mut selected = match ctx.preadmitted_upstream.take() {
            Some(preadmitted) => Ok(preadmitted),
            None => {
                client_ip = self.balancing_identity(session, ctx);
                self.select_admitted_upstream(
                    &state,
                    route_index,
                    client_ip.as_deref(),
                    &ctx.retry_excluded,
                )
            }
        };
        if matches!(selected, Err(UpstreamSelectionError::NoUpstream))
            && !ctx.retry_excluded.is_empty()
        {
            // ♻️ A status policy may revisit a backend after every candidate was tried once.
            ctx.retry_excluded.clear();
            selected = self.select_admitted_upstream(
                &state,
                route_index,
                client_ip.as_deref(),
                &ctx.retry_excluded,
            );
        }

        if let Ok((upstream, admission)) = selected {
            ctx.retry_attempts += 1;
            ctx.upstream = Some(upstream.clone());
            ctx.upstream_admission = admission;

            Self::enforce_request_deadline(ctx)?;
            if let Some(proxy_config) = &proxy_config {
                ctx.headers_upstream = proxy_config.headers_up.clone();
                ctx.response_headers
                    .merge_proxy_set(&proxy_config.headers_down);
                ctx.streaming_response = wants_immediate_flush(proxy_config.flush_interval);
            }
            let request_budget = ctx
                .request_deadline
                .and_then(|deadline| deadline.checked_duration_since(std::time::Instant::now()));
            let retry_budget = ctx
                .retry_deadline
                .and_then(|deadline| deadline.checked_duration_since(std::time::Instant::now()));
            let attempt_budget = shortest_duration(request_budget, retry_budget);
            let read_budget = match state.config.limits.long_connections.idle_timeout_ms {
                Some(0) => None,
                Some(value) => Some(Duration::from_millis(value)),
                None => attempt_budget,
            };

            // 🌐 Builds the peer through the transport-neutral timeout policy.
            let mut peer = Self::build_http_peer(
                &upstream,
                proxy_config.as_ref(),
                attempt_budget,
                read_budget,
                tls_policy,
            );
            // ⌛ A configured retry total is a hard bound, even when phase timers are longer.
            peer.options.read_timeout = shortest_duration(peer.options.read_timeout, retry_budget);
            return Ok(Box::new(peer));
        }

        // ⏱️ Preserves timeout and overload status when selection exhausts the pool.
        let status = if matches!(selected, Err(UpstreamSelectionError::Unavailable)) {
            503
        } else if ctx.upstream_connect_timed_out {
            504
        } else {
            502
        };
        tracing::warn!(
            route = route_index,
            "⚠️ No upstream available for the matched route"
        );
        pingora_core::Error::e_explain(
            pingora_core::ErrorType::HTTPStatus(status),
            "no upstream available",
        )
    }

    /// 🔒 Rejects `h2://` peers that did not negotiate HTTP/2 over TLS.
    async fn connected_to_upstream(
        &self,
        _session: &mut Session,
        _reused: bool,
        peer: &HttpPeer,
        #[cfg(unix)] _fd: std::os::unix::io::RawFd,
        #[cfg(windows)] _sock: std::os::windows::io::RawSocket,
        digest: Option<&pingora_core::protocols::Digest>,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()>
    where
        Self::CTX: Send + Sync,
    {
        if !peer_requires_h2_alpn(peer) {
            return Ok(());
        }

        let negotiated_h2 = digest
            .and_then(|digest| digest.ssl_digest.as_deref())
            .and_then(|digest| digest.extension.get::<NegotiatedUpstreamAlpn>())
            .is_some_and(|alpn| alpn.0.as_slice() == b"h2");
        if negotiated_h2 {
            return Ok(());
        }

        tracing::error!(
            peer = %peer,
            "🔒 TLS H2 upstream did not negotiate the required h2 ALPN"
        );
        if let Some(mut admission) = ctx.upstream_admission.take() {
            admission.report_failure();
        }
        pingora_core::Error::e_explain(
            pingora_core::ErrorType::HTTPStatus(502),
            "TLS H2 upstream did not negotiate h2",
        )
    }

    /// Called before sending request to upstream
    ///
    /// 🏗️ ARCHITECTURE: Resolve Caddy-style `{http.request.header.X}` placeholders
    /// in `headers_up` values by reading from the actual downstream request at runtime.
    /// This enables configs like:
    ///   `header_up X-Forwarded-For {http.request.header.CF-Connecting-IP}`
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // 🧹 Hop-by-hop fields stop here, before anything of ours is added.
        //
        // Doing this first matters twice over: a client naming our own fields in
        // `Connection` cannot strip headers we are about to set, and the fields
        // it does name are gone before the origin can see either them or the
        // instruction. Pingora removes these only on the HTTP/2 upstream path,
        // where the h2 crate insists; the HTTP/1 path forwarded them verbatim,
        // including `Proxy-Authorization` — a credential addressed to this
        // proxy, handed to the origin.
        strip_hop_by_hop_headers(session, upstream_request)?;

        let downstream_headers = session.req_header();
        let has_header_up = |name: &str| {
            ctx.headers_upstream
                .keys()
                .any(|key| key.eq_ignore_ascii_case(name))
        };

        // Add configured upstream headers with variable resolution
        let verified_client_ip = ctx.verified_client_ip.map(|ip| ip.to_string());
        for (key, value_template) in &ctx.headers_upstream {
            let resolved = resolve_caddy_placeholders(
                value_template,
                downstream_headers,
                verified_client_ip.as_deref(),
            );
            upstream_request.insert_header(key.clone(), resolved.as_str())?;
        }

        // Add standard proxy headers (only if not already configured by user)
        if !has_header_up("X-Forwarded-Proto") {
            upstream_request.insert_header("X-Forwarded-Proto", &ctx.request_scheme)?;
        }
        if !has_header_up("X-Forwarded-Host") {
            upstream_request
                .insert_header("X-Forwarded-Host", request_authority(downstream_headers))?;
        }

        // 🛡️ Untrusted peers cannot smuggle a forged forwarding chain upstream.
        let (transport_peer_ip, transport_client_ip, resolved_client_ip) =
            self.downstream_identity(session, &downstream_headers.headers);
        let client_ip = ctx.verified_client_ip.unwrap_or(resolved_client_ip);
        if !has_header_up("X-Forwarded-For") {
            upstream_request.insert_header(
                "X-Forwarded-For",
                self.trusted_proxies.forwarded_for_with_fallback(
                    transport_peer_ip,
                    transport_client_ip,
                    &downstream_headers.headers,
                ),
            )?;
        }
        if !has_header_up("X-Real-IP") {
            upstream_request.insert_header("X-Real-IP", client_ip.to_string())?;
        }
        if !has_header_up("Forwarded") {
            let value = match client_ip {
                IpAddr::V4(address) => format!("for={address}"),
                IpAddr::V6(address) => format!("for=\"[{address}]\""),
            };
            upstream_request.insert_header("Forwarded", value)?;
        }

        // Forward the request ID so upstream services can correlate their
        // logs with ours; a user-configured `header_up X-Request-Id` wins.
        if !has_header_up("X-Request-Id") {
            upstream_request.insert_header("X-Request-Id", &ctx.request_id)?;
        }

        // 🔀 RFC 9110 §7.6.3: a gateway MUST announce itself in `Via` on every
        // request it forwards. Appended rather than inserted — the header is a
        // record of the whole chain, and `upstream_request` already carries
        // whatever the client (or Cloudflare, or another proxy) put there.
        // The version token is the one we *received* on, not the one we are
        // about to speak upstream.
        if !ctx.response_headers.suppresses_via() {
            upstream_request.append_header("via", via_value(downstream_headers.version))?;
        }

        Ok(())
    }

    /// 🔁 Redispatches configured status responses before committing downstream headers.
    async fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        Self::enforce_retry_deadline(ctx)?;
        if upstream_response.headers.contains_key("trailer") {
            tracing::warn!(
                "🚫 Rejecting an upstream response that requires unsupported trailer forwarding"
            );
            return pingora_core::Error::e_explain(
                pingora_core::ErrorType::HTTPStatus(502),
                "Upstream response trailers are unsupported",
            );
        }

        let retry_policy = ctx
            .state
            .as_ref()
            .zip(ctx.route_index)
            .and_then(|(state, route_index)| self.get_proxy_config(state, route_index))
            .map(|config| config.retry)
            .unwrap_or_default();
        let method = session.req_header().method.clone();
        let body_is_empty = session.as_mut().is_body_empty();
        let status = upstream_response.status.as_u16();
        if let Some(admission) = &mut ctx.upstream_admission {
            admission.report_status(status);
        }
        if crate::retry::permits_status_retry(
            &retry_policy,
            &method,
            body_is_empty,
            status,
            ctx.retry_attempts,
            ctx.retry_deadline,
        ) {
            if let Some(upstream) = ctx.upstream.as_ref()
                && let pingora_core::protocols::l4::socket::SocketAddr::Inet(address) =
                    &upstream.addr
            {
                ctx.retry_excluded.insert(*address);
            }
            ctx.upstream_admission.take();
            ctx.retry_pending = true;
            tracing::warn!(
                status,
                method = %method,
                attempt = ctx.retry_attempts,
                max_attempts = retry_policy.max_attempts,
                "🔁 Redispatching a bodyless request after an upstream status"
            );
            let mut error = pingora_core::Error::explain(
                pingora_core::ErrorType::HTTPStatus(status),
                "configured upstream status retry",
            );
            error.retry = true.into();
            return Err(error);
        }
        Ok(())
    }

    /// Called before sending response to client
    ///
    /// 🏗️ ARCHITECTURE: Full response header processing pipeline:
    ///   1. Set downstream headers (from header directive)
    ///   2. Add downstream headers (append, from header +Key directive)
    ///   3. Remove headers (from header -Key directive)
    ///   4. Conditionally suppress Server header
    ///   5. Apply security headers
    ///   6. Setup gzip compression if client supports it
    ///   7. Add request ID header
    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        Self::enforce_request_deadline(ctx)?;
        if upstream_response
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(is_streaming_content_type)
            && let Some(state) = ctx.state.clone()
        {
            Self::activate_long_connection(session, ctx, &state);
        }

        // Capture response status for access log
        ctx.response_status = upstream_response.status.as_u16();

        // ⏱️ TTFB is measured at the response header, which is the first byte
        // the client can actually observe. Recorded once — a retry or an
        // interceptor running this filter again must not reset it.
        ctx.first_byte_at
            .get_or_insert_with(std::time::Instant::now);

        ctx.response_headers.apply_pingora(
            upstream_response,
            &ctx.request_id,
            Some(upstream_response.version),
        )?;

        // 🛡️ Applies the same security policy used by locally generated responses.
        if let Some(state) = &ctx.state {
            Self::apply_security_response_headers(upstream_response, state)?;
        }

        // 7. Set up response compression if applicable.
        // Only compress if:
        //   - A coding was negotiated (client accepts one this server offers)
        //   - Route did not request immediate flushing (`flush_interval: -1`)
        //   - Response is not a real-time stream (e.g. text/event-stream)
        //   - Response is not already compressed
        //   - Content type is compressible (text/*, application/json, etc.)
        //   - Body is not too small (> 256 bytes via Content-Length)
        if let Some(encoding) = ctx.negotiated_encoding
            && !ctx.streaming_response
        {
            let already_encoded = upstream_response.headers.get("content-encoding").is_some();
            let content_type = upstream_response
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let gzip_types = ctx
                .state
                .as_ref()
                .map(|state| state.config.gzip_types.as_slice())
                .unwrap_or_default();
            let is_compressible = is_compressible_content_type(content_type, gzip_types);
            let content_length = upstream_response
                .headers
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok());
            let too_small = content_length.is_some_and(|len| len < 256);

            if !already_encoded
                && is_compressible
                && !is_streaming_content_type(content_type)
                && !too_small
            {
                match ResponseEncoder::new(encoding) {
                    Ok(encoder) => {
                        // Headers are only rewritten once the encoder exists.
                        // Announcing a coding we then failed to construct
                        // would hand the client a body it cannot decode.
                        upstream_response.insert_header("Content-Encoding", encoder.token())?;
                        ctx.response_encoder = Some(encoder);
                        let _ = upstream_response.remove_header("Content-Length");
                        // Transfer-Encoding: chunked will be set by Pingora automatically
                        upstream_response.insert_header("Vary", "Accept-Encoding")?;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "⚠️ Could not initialize {} encoder, serving identity: {}",
                            encoding.token(),
                            e
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Filter upstream response body chunks through the negotiated coding.
    ///
    /// 🏗️ ARCHITECTURE: Streaming, never full-body buffering — see
    /// [`crate::encoding::stream_chunk`]. Every chunk is written in,
    /// sync-flushed and drained immediately, so memory use is bounded by one
    /// chunk's worth of compressed output rather than by response size.
    /// `end_of_stream` finalizes the encoder (trailer + final flush).
    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Option<Duration>> {
        Self::enforce_request_deadline(ctx)?;
        Self::enforce_retry_deadline(ctx)?;
        // Track response bytes for access log
        if let Some(b) = body.as_ref() {
            ctx.response_bytes += b.len() as u64;
        }

        stream_chunk(&mut ctx.response_encoder, body, end_of_stream);

        let delay = body.as_ref().and_then(|bytes| {
            ctx.download_pacer
                .as_mut()
                .and_then(|pacer| pacer.delay_for(bytes.len()))
        });
        if delay.is_some_and(|delay| {
            ctx.request_deadline
                .is_some_and(|deadline| std::time::Instant::now() + delay >= deadline)
        }) {
            return pingora_core::Error::e_explain(
                pingora_core::ErrorType::HTTPStatus(408),
                "download rate budget exceeds whole-request deadline",
            );
        }
        if delay.is_some_and(|delay| {
            ctx.retry_deadline
                .is_some_and(|deadline| std::time::Instant::now() + delay >= deadline)
        }) {
            return pingora_core::Error::e_explain(
                pingora_core::ErrorType::HTTPStatus(504),
                "download rate budget exceeds upstream retry deadline",
            );
        }
        Ok(delay)
    }

    /// 🔌 Handles a connection failure before any request bytes reach an upstream.
    ///
    /// 🔁 Passive health removes the failed backend from selection, while the
    /// route policy bounds whether Pingora may make another safe attempt.
    fn fail_to_connect(
        &self,
        _session: &mut Session,
        peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<pingora_core::Error>,
    ) -> Box<pingora_core::Error> {
        if let Some(mut admission) = ctx.upstream_admission.take() {
            admission.report_failure();
        }
        ctx.upstream_connect_timed_out = matches!(
            e.etype(),
            pingora_core::ErrorType::ConnectTimedout
                | pingora_core::ErrorType::TLSHandshakeTimedout
        );
        if let pingora_core::protocols::l4::socket::SocketAddr::Inet(address) = peer.address() {
            ctx.retry_excluded.insert(*address);
            if let (Some(state), Some(route_index)) = (ctx.state.as_ref(), ctx.route_index) {
                tracing::warn!(
                    "🔻 Marking upstream {} down after connect failure (cooldown {:?})",
                    address,
                    crate::FAIL_COOLDOWN
                );
                self.mark_upstream_unhealthy(state, route_index, address);
            }
        }

        let retry_policy = ctx
            .state
            .as_ref()
            .zip(ctx.route_index)
            .and_then(|(state, route_index)| self.get_proxy_config(state, route_index))
            .map(|config| config.retry)
            .unwrap_or_default();
        let retry = crate::retry::permits_another_attempt(
            &retry_policy,
            ctx.retry_attempts,
            ctx.retry_deadline,
        );
        ctx.retry_pending = retry;
        e.retry = retry.into();
        e
    }

    /// Called on errors
    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        _session: &mut Session,
        e: Box<pingora_core::Error>,
        ctx: &mut Self::CTX,
        _client_reused: bool,
    ) -> Box<pingora_core::Error> {
        if let Some(mut admission) = ctx.upstream_admission.take() {
            admission.report_failure();
        }
        let elapsed = ctx.start_time.elapsed();
        tracing::error!(
            peer = %peer,
            elapsed_ms = elapsed.as_millis(),
            error = %e,
            "❌ Proxy error"
        );
        e
    }

    /// Structured access log — emitted after each request completes.
    ///
    /// 🏗️ ARCHITECTURE: Produces JSON-structured log lines compatible
    /// with the Caddy JSON log format. Fields:
    ///   - ts, duration, request (method, host, uri), status, size, request_id
    ///   - Per-server log level/file is configured but we use tracing for now
    /// Called when proxying to upstream fails. Serves the vhost's custom
    /// error page (when configured) instead of Pingora's built-in error.
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora_core::Error,
        ctx: &mut Self::CTX,
    ) -> pingora_proxy::FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        use pingora_core::{ErrorSource, ErrorType};
        // 🧾 A response already on the wire means the error page cannot own the
        // framing, so the connection is no longer in a state anyone can reuse.
        let already_responded = session.response_written().is_some();
        let code = if ctx
            .request_deadline
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
        {
            408
        } else {
            match e.etype() {
                ErrorType::HTTPStatus(code) => *code,
                _ => match e.esource() {
                    ErrorSource::Upstream => match e.etype() {
                        ErrorType::ConnectTimedout
                        | ErrorType::TLSHandshakeTimedout
                        | ErrorType::ReadTimedout
                        | ErrorType::WriteTimedout => 504,
                        _ => 502,
                    },
                    ErrorSource::Downstream => match e.etype() {
                        ErrorType::WriteError
                        | ErrorType::ReadError
                        | ErrorType::ConnectionClosed => 0,
                        ErrorType::ReadTimedout | ErrorType::WriteTimedout => 408,
                        _ => 400,
                    },
                    ErrorSource::Internal | ErrorSource::Unset => 500,
                },
            }
        };
        let served = code > 0 && self.serve_error_page(session, ctx, code).await.is_ok();

        // 🔁 A fail-fast rejection is a complete, locally generated response, so
        // the keep-alive connection it was written on is still perfectly good.
        // Refusing reuse here made every circuit-open or capacity 503 tear down
        // the client's connection while the response itself still advertised
        // `Connection: keep-alive` — a reconnect storm provoked at precisely the
        // moment the server is already shedding load, and a reset that races
        // whatever the client had already pipelined onto that socket.
        //
        // Reuse is claimed only for a response this hop wrote in full, on a
        // connection the downstream transport has not already implicated:
        // a downstream read/write error, a malformed request, or a response that
        // was partly streamed before the failure all leave framing we cannot
        // vouch for. Pingora's own `reuse()` remains the second gate — it honours
        // every `set_keepalive(None)` on the request path (413, 431, 501, PROXY
        // protocol), drains the request body, and refuses a connection that
        // overread a pipelined request.
        let can_reuse_downstream =
            served && !already_responded && !matches!(e.esource(), ErrorSource::Downstream);

        pingora_proxy::FailToProxy {
            error_code: code,
            can_reuse_downstream,
        }
    }

    async fn logging(
        &self,
        session: &mut Session,
        e: Option<&pingora_core::Error>,
        ctx: &mut Self::CTX,
    ) {
        let response_code = session
            .response_written()
            .map(|resp| resp.status.as_u16())
            .unwrap_or(ctx.response_status);

        let req_header = session.req_header();
        let method = req_header.method.as_str();
        let host = match request_authority(req_header) {
            "" => "-",
            authority => authority,
        };
        let user_agent = req_header
            .headers
            .get("User-Agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");
        let referer = req_header
            .headers
            .get("Referer")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");
        let remote_ip = ctx
            .verified_client_ip
            .unwrap_or_else(|| session_peer_ip(session))
            .to_string();
        let elapsed = ctx.start_time.elapsed();

        // Update Prometheus metrics
        metrics::REQUESTS_TOTAL
            .with_label_values(&[method, &response_code.to_string(), host])
            .inc();

        metrics::REQUEST_DURATION_SECONDS
            .with_label_values(&[method, &response_code.to_string(), host])
            .observe(elapsed.as_secs_f64());

        // 📝 Prefer this server's configured access logger. Only when the
        // server has no `log` block do we fall back to the process-wide
        // tracing output, so existing configs keep their current behavior.
        let configured_logger = ctx
            .state
            .as_ref()
            .and_then(|state| state.access_logger.clone());

        if let Some(logger) = configured_logger {
            let upstream_addr = ctx.upstream.as_ref().map(|u| u.addr.to_string());
            let route = ctx.state.as_ref().and_then(|state| {
                ctx.route_index
                    .and_then(|index| state.config.routes.get(index))
                    .map(|route| route.path.as_str())
            });
            let error_text = e.map(|err| err.to_string());

            // 🙈 Log the full request target, but redact secret-looking query
            // parameters first. Operators need the query to debug; a logged
            // `?api_key=...` is a leaked credential.
            let logged_path = match req_header.uri.path_and_query() {
                Some(pq) => crate::redaction::redact_target(pq.as_str()),
                None => req_header.uri.path().to_string(),
            };
            // Referer carries the *previous* page's URL, so it can leak a
            // token this request never contained.
            let redacted_referer = crate::redaction::redact_referer(referer);

            logger.log(&crate::access_log::AccessEntry {
                request_id: &ctx.request_id,
                method,
                host,
                path: &logged_path,
                status: response_code,
                // Body bytes only, matching nginx's $body_bytes_sent.
                //
                // Deliberately NOT pingora's Session::body_bytes_sent(). On
                // the H1 path that counter also adds the serialized response
                // header (pingora-core 0.8.1, v1/server.rs:603), so a 21-byte
                // body reports 281. H2 counts only in write_body, so the same
                // response reports 21 there — the value changes meaning with
                // the client's protocol.
                //
                // Fixed upstream in cloudflare/pingora e7de90a but not in the
                // 0.8.1 release; see
                // https://github.com/cloudflare/pingora/issues/846
                // Keep our own counter even after upgrading — it is the
                // body-only number an access log should report.
                bytes: ctx.response_bytes,
                duration_ms: elapsed.as_millis(),
                ttfb_ms: ctx
                    .first_byte_at
                    .map(|at| at.duration_since(ctx.start_time).as_millis()),
                client_ip: &remote_ip,
                route,
                upstream: upstream_addr.as_deref(),
                user_agent,
                referer: &redacted_referer,
                protocol: match session.req_header().version {
                    http::Version::HTTP_09 => "HTTP/0.9",
                    http::Version::HTTP_10 => "HTTP/1.0",
                    http::Version::HTTP_11 => "HTTP/1.1",
                    http::Version::HTTP_2 => "HTTP/2",
                    http::Version::HTTP_3 => "HTTP/3",
                    _ => "-",
                },
                error: error_text.as_deref(),
            });
            return;
        }

        // Structured access log
        if let Some(err) = e {
            tracing::error!(
                request_id = %ctx.request_id,
                method = method,
                host = host,
                path = req_header.uri.path(),
                status = response_code,
                bytes = ctx.response_bytes,
                duration_ms = elapsed.as_millis(),
                remote_ip = %remote_ip,
                user_agent = user_agent,
                error = %err,
                "❌ Access"
            );
        } else {
            tracing::info!(
                request_id = %ctx.request_id,
                method = method,
                host = host,
                path = req_header.uri.path(),
                status = response_code,
                bytes = ctx.response_bytes,
                duration_ms = elapsed.as_millis(),
                remote_ip = %remote_ip,
                user_agent = user_agent,
                referer = referer,
                upstream = ?ctx.upstream.as_ref().map(|u| &u.addr),
                "📝 Access"
            );
        }
    }
}

// MARK: - Helper Functions

/// Recursively find a rate limit config in a handler tree
/// Find the first `ReverseProxy` config in a handler tree, recursing
/// through `Pipeline`/`Handle`/`HandlePath` wrappers.
///
/// A `handle /api/* { reverse_proxy ... }` block is compiled to a route
/// whose handler is a `Pipeline([ReverseProxy])`, not a bare `ReverseProxy`.
/// Without this recursion the reverse proxy nested in that pipeline would
/// get no load balancer and every request to it would fail with
/// ConnectNoRoute. Mirrors [`find_rate_limit_config`].
fn find_reverse_proxy_config(handler: &HandlerConfig) -> Option<&ReverseProxyConfig> {
    match handler {
        HandlerConfig::ReverseProxy(config) => Some(config),
        HandlerConfig::Pipeline { handlers }
        | HandlerConfig::Handle { handlers }
        | HandlerConfig::HandlePath { handlers, .. } => {
            handlers.iter().find_map(|h| find_reverse_proxy_config(h))
        }
        _ => None,
    }
}

/// ⚖️ Apply each upstream weight to Pingora's native weighted backend.
///
/// Repeating an identical backend is incorrect because Pingora stores its
/// backend set by value and deduplicates those entries before selection.
/// A defensive cap keeps every selector's internal weighted table bounded.
///
/// Addresses are *not* resolved here: the load balancer keeps the parsed
/// specs so a hostname can be re-resolved later, and an upstream that is not
/// answering DNS yet stays in the list instead of being dropped for good.
fn build_weighted_upstreams(
    config: &ReverseProxyConfig,
) -> (Vec<UpstreamEntry>, Vec<UpstreamEntry>) {
    let options: Vec<_> = if config.upstream_options.is_empty() {
        config
            .upstreams
            .iter()
            .map(|address| pingclair_core::config::ProxyUpstream {
                address: address.clone(),
                weight: 1,
                backup: false,
            })
            .collect()
    } else {
        config.upstream_options.clone()
    };

    let mut primary = Vec::new();
    let mut backup = Vec::new();
    for option in options {
        let weight = option.weight.clamp(1, 100);
        let target = if option.backup {
            &mut backup
        } else {
            &mut primary
        };
        match UpstreamSpec::parse(&option.address) {
            Some(spec) => target.push(UpstreamEntry {
                spec,
                weight: weight as usize,
            }),
            None => tracing::warn!(upstream = %option.address, "Ignoring invalid upstream address"),
        }
    }
    (primary, backup)
}

fn find_access_control_config(handler: &HandlerConfig) -> Option<&AccessControlConfig> {
    match handler {
        HandlerConfig::AccessControl(config) => Some(config),
        HandlerConfig::Pipeline { handlers }
        | HandlerConfig::Handle { handlers }
        | HandlerConfig::HandlePath { handlers, .. } => {
            handlers.iter().find_map(find_access_control_config)
        }
        _ => None,
    }
}

fn collect_rewrite_regexes(handler: &HandlerConfig, regexes: &mut HashMap<String, Arc<Regex>>) {
    match handler {
        HandlerConfig::Rewrite {
            regex: Some(pattern),
            ..
        } => match Regex::new(pattern) {
            Ok(regex) => {
                regexes.insert(pattern.clone(), Arc::new(regex));
            }
            Err(error) => tracing::error!(pattern, %error, "Invalid rewrite regex"),
        },
        HandlerConfig::Pipeline { handlers }
        | HandlerConfig::Handle { handlers }
        | HandlerConfig::HandlePath { handlers, .. } => {
            for handler in handlers {
                collect_rewrite_regexes(handler, regexes);
            }
        }
        _ => {}
    }
}

/// Find the first `FileServer` config in a handler tree, recursing through
/// `Pipeline`/`Handle`/`HandlePath` wrappers. Returns the `FileServer`
/// handler node itself so the caller can destructure its fields.
fn find_file_server_config(handler: &HandlerConfig) -> Option<&HandlerConfig> {
    match handler {
        HandlerConfig::FileServer { .. } => Some(handler),
        HandlerConfig::Pipeline { handlers }
        | HandlerConfig::Handle { handlers }
        | HandlerConfig::HandlePath { handlers, .. } => {
            handlers.iter().find_map(|h| find_file_server_config(h))
        }
        _ => None,
    }
}

fn find_rate_limit_config(
    handler: &HandlerConfig,
    route: &str,
) -> Option<crate::rate_limit::RateLimitConfig> {
    match handler {
        HandlerConfig::RateLimit {
            requests,
            window_secs,
            by_ip,
            burst,
            key,
            dry_run,
        } => Some(crate::rate_limit::RateLimitConfig {
            requests_per_window: *requests,
            window: std::time::Duration::from_secs(*window_secs),
            key: key.clone().unwrap_or(if *by_ip {
                pingclair_core::config::RateLimitKey::Ip
            } else {
                pingclair_core::config::RateLimitKey::Global
            }),
            burst: *burst,
            dry_run: *dry_run,
            route: route.to_string(),
        }),
        HandlerConfig::Pipeline { handlers }
        | HandlerConfig::Handle { handlers }
        | HandlerConfig::HandlePath { handlers, .. } => {
            for h in handlers {
                if let Some(config) = find_rate_limit_config(h, route) {
                    return Some(config);
                }
            }
            None
        }
        _ => None,
    }
}

// MARK: - P0 Regression Tests
//
// Targeted tests for the 4 P0 issues fixed per docs/AUDIT_NGINX_PARITY.md:
// gzip OOM risk, request ID syscall overhead, hosts lock contention, and
// upstream connection pool sizing.
#[cfg(test)]
mod forwarded_headers_tests {
    use super::*;

    #[test]
    fn untrusted_peer_cannot_spoof_forwarded_identity() {
        let proxy = PingclairProxy::new();
        let peer = "198.51.100.4".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
        headers.insert("x-real-ip", "203.0.113.8".parse().unwrap());

        assert_eq!(proxy.verified_client_ip(peer, &headers), peer);
        assert_eq!(proxy.forwarded_for(peer, &headers), "198.51.100.4");
    }

    #[test]
    fn untrusted_peer_cannot_spoof_rfc_forwarded_identity() {
        let proxy = PingclairProxy::new();
        let peer = "198.51.100.4".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("forwarded", "for=203.0.113.7;proto=https".parse().unwrap());

        assert_eq!(proxy.verified_client_ip(peer, &headers), peer);
    }

    #[test]
    fn conflicting_xff_and_rfc_forwarded_fail_closed_to_peer() {
        let proxy = PingclairProxy::with_trusted_proxies(&["10.0.0.0/8".to_string()]);
        let peer = "10.0.0.5".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
        headers.insert("forwarded", "for=198.51.100.9".parse().unwrap());

        assert_eq!(proxy.verified_client_ip(peer, &headers), peer);
    }

    #[test]
    fn trusted_rfc_forwarded_chain_supports_quoted_ipv6_and_ports() {
        let proxy = PingclairProxy::with_trusted_proxies(&[
            "10.0.0.0/8".to_string(),
            "2001:db8:ffff::/48".to_string(),
        ]);
        let peer = "10.0.0.5".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "forwarded",
            "for=\"[2001:db8::7]:4567\";proto=https, for=\"[2001:db8:ffff::1]\""
                .parse()
                .unwrap(),
        );

        assert_eq!(
            proxy.verified_client_ip(peer, &headers),
            "2001:db8::7".parse::<IpAddr>().unwrap()
        );
    }

    // ---- CF-Connecting-IP (Cloudflare Tunnel deployments) ----

    /// The security boundary: an untrusted client sending CF-Connecting-IP
    /// must be ignored entirely. If this ever regresses, any client on the
    /// internet can forge its own identity for access control, rate limits
    /// and logs.
    #[test]
    fn untrusted_peer_cannot_spoof_cf_connecting_ip() {
        let proxy = PingclairProxy::new();
        let peer: IpAddr = "198.51.100.4".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("cf-connecting-ip", "203.0.113.7".parse().unwrap());

        assert_eq!(
            proxy.verified_client_ip(peer, &headers),
            peer,
            "untrusted CF-Connecting-IP must be ignored"
        );
    }

    #[test]
    fn trusted_peer_cf_connecting_ip_is_honored() {
        let proxy = PingclairProxy::with_trusted_proxies(&["10.0.0.0/8".to_string()]);
        let peer: IpAddr = "10.0.0.5".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("cf-connecting-ip", "203.0.113.7".parse().unwrap());

        assert_eq!(
            proxy.verified_client_ip(peer, &headers),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
    }

    /// Cloudflare sends both headers. CF-Connecting-IP is the unambiguous
    /// single original-visitor value, so it wins over chain walking.
    #[test]
    fn cf_connecting_ip_takes_precedence_over_forwarded_chain() {
        let proxy = PingclairProxy::with_trusted_proxies(&["10.0.0.0/8".to_string()]);
        let peer: IpAddr = "10.0.0.5".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("cf-connecting-ip", "203.0.113.7".parse().unwrap());
        headers.insert("x-forwarded-for", "198.51.100.9, 10.1.2.3".parse().unwrap());
        headers.insert("x-real-ip", "198.51.100.10".parse().unwrap());

        assert_eq!(
            proxy.verified_client_ip(peer, &headers),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
    }

    /// A malformed CF-Connecting-IP must not silently fall through to a
    /// value an attacker also controls — it falls back to the normal chain.
    #[test]
    fn malformed_cf_connecting_ip_falls_back_to_the_chain() {
        let proxy = PingclairProxy::with_trusted_proxies(&["10.0.0.0/8".to_string()]);
        let peer: IpAddr = "10.0.0.5".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("cf-connecting-ip", "not-an-ip".parse().unwrap());
        headers.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());

        assert_eq!(
            proxy.verified_client_ip(peer, &headers),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn cf_connecting_ip_supports_ipv6() {
        let proxy = PingclairProxy::with_trusted_proxies(&["10.0.0.0/8".to_string()]);
        let peer: IpAddr = "10.0.0.5".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("cf-connecting-ip", "2001:db8::1".parse().unwrap());

        assert_eq!(
            proxy.verified_client_ip(peer, &headers),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn trusted_peer_walks_the_chain_from_right_to_left() {
        let proxy = PingclairProxy::with_trusted_proxies(&["10.0.0.0/8".to_string()]);
        let peer = "10.0.0.5".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.7, 10.1.2.3".parse().unwrap());

        assert_eq!(
            proxy.verified_client_ip(peer, &headers),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            proxy.forwarded_for(peer, &headers),
            "203.0.113.7, 10.1.2.3, 10.0.0.5"
        );
    }

    #[test]
    fn trusted_peer_uses_x_real_ip_only_when_xff_is_absent() {
        let proxy = PingclairProxy::with_trusted_proxies(&["127.0.0.1".to_string()]);
        let peer = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let mut headers = http::HeaderMap::new();
        headers.insert("x-real-ip", "203.0.113.9".parse().unwrap());

        assert_eq!(
            proxy.verified_client_ip(peer, &headers),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            proxy.forwarded_for(peer, &headers),
            "203.0.113.9, 127.0.0.1"
        );
    }

    #[test]
    fn malformed_or_oversized_chain_fails_closed_to_peer() {
        let proxy = PingclairProxy::with_trusted_proxies(&["127.0.0.1".to_string()]);
        let peer = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let mut malformed = http::HeaderMap::new();
        malformed.insert(
            "x-forwarded-for",
            "203.0.113.7, definitely-not-an-ip".parse().unwrap(),
        );
        assert_eq!(proxy.verified_client_ip(peer, &malformed), peer);
        assert_eq!(proxy.forwarded_for(peer, &malformed), "127.0.0.1");

        let mut oversized = http::HeaderMap::new();
        oversized.insert(
            "x-forwarded-for",
            std::iter::repeat_n("203.0.113.7", MAX_FORWARDED_HOPS + 1)
                .collect::<Vec<_>>()
                .join(", ")
                .parse()
                .unwrap(),
        );
        assert_eq!(proxy.verified_client_ip(peer, &oversized), peer);
    }
}

#[cfg(test)]
mod p0_regression_tests {
    use super::*;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn protected_server(max_in_flight: usize) -> ServerConfig {
        let proxy = ReverseProxyConfig {
            upstreams: vec!["127.0.0.1:9000".to_string()],
            overload: Box::new(pingclair_core::config::OverloadConfig {
                max_in_flight: Some(max_in_flight),
                ..Default::default()
            }),
            circuit_breaker: Box::new(pingclair_core::config::CircuitBreakerConfig {
                consecutive_failures: Some(2),
                ..Default::default()
            }),
            ..Default::default()
        };
        ServerConfig {
            name: Some("reload.example".to_string()),
            routes: vec![pingclair_core::config::RouteConfig {
                path: "/api/*".to_string(),
                handler: HandlerConfig::ReverseProxy(proxy),
                methods: None,
                matcher: None,
            }],
            ..ServerConfig::default()
        }
    }

    #[test]
    fn hot_reload_retains_only_compatible_route_protection_state() {
        let proxy = PingclairProxy::new();
        proxy.add_server(protected_server(2));
        let before = proxy.get_state("reload.example").unwrap().route_protections[0]
            .as_ref()
            .unwrap()
            .clone();

        proxy.update_config(vec![protected_server(2)]);
        let retained = proxy.get_state("reload.example").unwrap().route_protections[0]
            .as_ref()
            .unwrap()
            .clone();
        assert!(Arc::ptr_eq(&before, &retained));

        proxy.update_config(vec![protected_server(3)]);
        let replaced = proxy.get_state("reload.example").unwrap().route_protections[0]
            .as_ref()
            .unwrap()
            .clone();
        assert!(!Arc::ptr_eq(&retained, &replaced));
    }

    #[test]
    fn request_authority_supports_http1_host_and_http2_authority() {
        let mut h1 = RequestHeader::build("GET", b"/ready", None).unwrap();
        h1.insert_header(http::header::HOST, "api.example.com:8443")
            .unwrap();
        assert_eq!(request_authority(&h1), "api.example.com:8443");
        assert_eq!(authority_host(request_authority(&h1)), "api.example.com");
        assert_eq!(authority_port(request_authority(&h1)), Some(8443));

        let mut h2 = RequestHeader::build_no_case("GET", b"/ready", None).unwrap();
        h2.uri = "https://h2.example.com:443/ready".parse().unwrap();
        h2.insert_header(http::header::HOST, "conflicting.example.com")
            .unwrap();
        assert_eq!(request_authority(&h2), "h2.example.com:443");
        assert_eq!(authority_host(request_authority(&h2)), "h2.example.com");
        assert_eq!(authority_port(request_authority(&h2)), Some(443));
    }

    #[test]
    fn authority_host_supports_bracketed_ipv6() {
        assert_eq!(authority_host("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(authority_port("[2001:db8::1]:443"), Some(443));
    }

    // ---- Fix 1: streaming compression stays bounded regardless of body size
    //
    // The regression tests for this moved to `crate::encoding` when the
    // encoder became multi-coding; they now assert the same bound for gzip
    // *and* zstd. See `encoding::tests::memory_stays_bounded_by_chunk_size_
    // not_body_size`.

    // ---- Fix 2: request ID generation is syscall-free per request ----

    #[test]
    fn request_ids_are_unique_across_many_sequential_calls() {
        let mut ids = std::collections::HashSet::new();
        for _ in 0..100_000 {
            assert!(
                ids.insert(generate_request_id()),
                "duplicate request ID generated"
            );
        }
    }

    #[test]
    fn request_ids_are_unique_under_concurrent_generation() {
        // The counter is a shared static AtomicU64; this is the test that
        // would catch a race in the fix (e.g. non-atomic increment).
        let thread_count = 16;
        let per_thread = 5_000;
        let barrier = Arc::new(Barrier::new(thread_count));

        let handles: Vec<_> = (0..thread_count)
            .map(|_| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    (0..per_thread)
                        .map(|_| generate_request_id())
                        .collect::<Vec<_>>()
                })
            })
            .collect();

        let mut all_ids = std::collections::HashSet::new();
        for h in handles {
            for id in h.join().unwrap() {
                assert!(all_ids.insert(id), "duplicate request ID across threads");
            }
        }
        assert_eq!(all_ids.len(), thread_count * per_thread);
    }

    #[test]
    fn request_id_format_is_stable_and_sortable_within_epoch() {
        let a = generate_request_id();
        let b = generate_request_id();
        assert!(a.contains('-'), "expected `<epoch>-<seq>` format, got {a}");
        let (epoch_a, seq_a) = a.split_once('-').unwrap();
        let (epoch_b, seq_b) = b.split_once('-').unwrap();
        // Same process epoch for two calls made back-to-back.
        assert_eq!(epoch_a, epoch_b);
        let seq_a = u64::from_str_radix(seq_a, 16).unwrap();
        let seq_b = u64::from_str_radix(seq_b, 16).unwrap();
        assert!(seq_b > seq_a, "sequence should be monotonically increasing");
    }

    #[test]
    fn sanitize_request_id_accepts_typical_values() {
        assert_eq!(
            sanitize_request_id("abc-123_DEF.456"),
            Some("abc-123_DEF.456".to_string())
        );
        assert_eq!(
            sanitize_request_id("  padded  "),
            Some("padded".to_string())
        );
    }

    #[test]
    fn sanitize_request_id_rejects_unsafe_values() {
        // Empty / whitespace-only
        assert_eq!(sanitize_request_id(""), None);
        assert_eq!(sanitize_request_id("   "), None);
        // CR/LF header-smuggling attempts
        assert_eq!(sanitize_request_id("ok\r\nX-Injected: evil"), None);
        assert_eq!(sanitize_request_id("ok\nbad"), None);
        // Non-ASCII
        assert_eq!(sanitize_request_id("要求-123"), None);
        // Overlong
        assert_eq!(sanitize_request_id(&"a".repeat(129)), None);
        assert!(sanitize_request_id(&"a".repeat(128)).is_some());
    }

    // ---- Fix 3: hosts/default reads never contend with reloads ----

    fn minimal_server_config(name: &str) -> ServerConfig {
        ServerConfig {
            name: Some(name.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn get_state_resolves_exact_host_after_add_server() {
        let proxy = PingclairProxy::new();
        assert!(proxy.get_state("api.example.com").is_none());

        proxy.add_server(minimal_server_config("api.example.com"));
        assert!(proxy.get_state("api.example.com").is_some());
        assert!(proxy.get_state("other.example.com").is_none());
    }

    #[test]
    fn get_state_falls_back_to_wildcard_then_default() {
        let proxy = PingclairProxy::new();
        proxy.add_server(minimal_server_config("*.example.com"));
        assert!(proxy.get_state("foo.example.com").is_some());
        assert!(proxy.get_state("example.com").is_none()); // wildcard doesn't match bare domain

        proxy.add_server(minimal_server_config("_")); // catch-all
        assert!(proxy.get_state("totally-unrelated.test").is_some());
    }

    #[test]
    fn update_config_atomically_replaces_the_whole_host_map() {
        let proxy = PingclairProxy::new();
        proxy.add_server(minimal_server_config("a.example.com"));
        proxy.add_server(minimal_server_config("b.example.com"));
        assert!(proxy.get_state("a.example.com").is_some());
        assert!(proxy.get_state("b.example.com").is_some());

        // Replace entirely with just one host — "a" should disappear.
        proxy.update_config(vec![minimal_server_config("b.example.com")]);
        assert!(proxy.get_state("a.example.com").is_none());
        assert!(proxy.get_state("b.example.com").is_some());
    }

    #[test]
    fn listener_limits_include_the_default_virtual_host() {
        let proxy = PingclairProxy::new();
        let mut config = minimal_server_config("_");
        config.limits.header_timeout_ms = Some(200);
        config.limits.max_connections = Some(1);
        proxy.add_server(config);
        let limits = proxy.listener_limits();
        assert_eq!(limits.header_timeout_ms, Some(200));
        assert_eq!(limits.max_connections, Some(1));
    }

    #[test]
    fn concurrent_add_server_calls_never_lose_entries() {
        // This is the test a naive `hosts.write(); *hosts = ...` swap (or a
        // non-retrying read-modify-write) would fail: under contention,
        // ArcSwap::rcu must retry rather than silently drop a racing
        // writer's insert.
        let proxy = Arc::new(PingclairProxy::new());
        let thread_count = 32;
        let barrier = Arc::new(Barrier::new(thread_count));

        let handles: Vec<_> = (0..thread_count)
            .map(|i| {
                let proxy = proxy.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    proxy.add_server(minimal_server_config(&format!("host-{i}.example.com")));
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        for i in 0..thread_count {
            assert!(
                proxy.get_state(&format!("host-{i}.example.com")).is_some(),
                "host-{i}.example.com was lost under concurrent add_server calls"
            );
        }
    }

    #[test]
    fn concurrent_reads_never_observe_a_torn_or_panicking_state_during_reload() {
        // Readers must never block on, or be corrupted by, a concurrent
        // hot-reload. Hammer get_state from many threads while another
        // thread repeatedly calls update_config, and assert nothing panics
        // and every read is a fully-formed ProxyState or None.
        let proxy = Arc::new(PingclairProxy::new());
        proxy.add_server(minimal_server_config("stable.example.com"));

        let stop = Arc::new(AtomicUsize::new(0));
        let reload_count = 200;

        let writer = {
            let proxy = proxy.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                for i in 0..reload_count {
                    proxy.update_config(vec![
                        minimal_server_config("stable.example.com"),
                        minimal_server_config(&format!("churn-{i}.example.com")),
                    ]);
                }
                stop.store(1, Ordering::Relaxed);
            })
        };

        let readers: Vec<_> = (0..8)
            .map(|_| {
                let proxy = proxy.clone();
                let stop = stop.clone();
                std::thread::spawn(move || {
                    let mut observed_none_for_stable = false;
                    while stop.load(Ordering::Relaxed) == 0 {
                        match proxy.get_state("stable.example.com") {
                            Some(state) => {
                                // A fully-formed ProxyState must have a
                                // router; this is what would look "torn"
                                // if we ever read across two different
                                // in-progress writes.
                                let _ = &state.router;
                            }
                            None => observed_none_for_stable = true,
                        }
                    }
                    observed_none_for_stable
                })
            })
            .collect();

        writer.join().unwrap();
        for r in readers {
            let saw_none = r.join().unwrap();
            // "stable.example.com" is present in every single update_config
            // call, so a correct implementation must never report it
            // missing to a reader.
            assert!(
                !saw_none,
                "reader observed stable host missing during reload — reload is not atomic per-map"
            );
        }

        assert!(proxy.get_state("stable.example.com").is_some());
    }

    // ---- Fix 4: upstream connection pool size is explicit, not implicit ----

    #[test]
    fn global_config_pool_size_defaults_to_none_and_round_trips() {
        use pingclair_core::config::GlobalConfig;

        let default_cfg = GlobalConfig::default();
        assert_eq!(
            default_cfg.upstream_keepalive_pool_size, None,
            "default must be None so main.rs falls back to Pingora's own default explicitly, \
             rather than us silently guessing a number"
        );

        let json = r#"{"email":null,"auto_https":"on","blocked_ips":[],"upstream_keepalive_pool_size":256}"#;
        let parsed: GlobalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.upstream_keepalive_pool_size, Some(256));

        // Old configs saved before this field existed must still parse.
        let legacy_json = r#"{"email":null,"auto_https":"on","blocked_ips":[]}"#;
        let parsed_legacy: GlobalConfig = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(parsed_legacy.upstream_keepalive_pool_size, None);
    }
}

#[cfg(test)]
mod streaming_flush_tests {
    use super::*;

    #[test]
    fn immediate_flush_only_for_negative_one() {
        assert!(wants_immediate_flush(Some(-1)));
        assert!(!wants_immediate_flush(None));
        assert!(!wants_immediate_flush(Some(0)));
        assert!(!wants_immediate_flush(Some(1)));
        assert!(!wants_immediate_flush(Some(100)));
        assert!(!wants_immediate_flush(Some(-2)));
    }

    #[test]
    fn event_stream_content_type_is_detected_as_streaming() {
        assert!(is_streaming_content_type("text/event-stream"));
        assert!(is_streaming_content_type(
            "text/event-stream; charset=utf-8"
        ));
        assert!(is_streaming_content_type("Text/Event-Stream"));
        assert!(is_streaming_content_type(
            " text/event-stream ; charset=utf-8"
        ));
    }

    #[test]
    fn non_streaming_content_types_are_not_flagged() {
        assert!(!is_streaming_content_type("text/plain"));
        assert!(!is_streaming_content_type("text/html; charset=utf-8"));
        assert!(!is_streaming_content_type("application/json"));
        assert!(!is_streaming_content_type("application/x-ndjson"));
        assert!(!is_streaming_content_type(""));
    }

    #[test]
    fn streaming_response_defaults_to_off() {
        let ctx = RequestContext::default();
        assert!(!ctx.streaming_response);
    }

    #[test]
    fn streaming_route_disables_compression_gate() {
        // The compression branch in `response_filter` requires
        // `ctx.negotiated_encoding.is_some() && !ctx.streaming_response`.
        // A route with `flush_interval: -1` sets streaming_response, which
        // must keep the gate closed even when a coding was negotiated.
        let mut ctx = RequestContext {
            negotiated_encoding: Some(Encoding::Zstd),
            ..Default::default()
        };
        ctx.streaming_response = wants_immediate_flush(Some(-1));
        let gate_opens = ctx.negotiated_encoding.is_some() && !ctx.streaming_response;
        assert!(
            !gate_opens,
            "flush_interval: -1 must disable response compression"
        );

        // Sanity: without the streaming flag the same request would compress.
        ctx.streaming_response = wants_immediate_flush(None);
        let gate_opens = ctx.negotiated_encoding.is_some() && !ctx.streaming_response;
        assert!(gate_opens);
    }

    /// A server with `encode off` compiles to an empty offer list, and no
    /// `Accept-Encoding` value may talk it into compressing anyway.
    #[test]
    fn encode_off_wins_over_any_accept_encoding() {
        for accept in ["gzip", "zstd", "gzip, zstd, br", "*"] {
            assert_eq!(
                negotiate(accept, &[]),
                None,
                "`encode off` must not compress for Accept-Encoding: {accept}"
            );
        }
    }
}

#[cfg(test)]
mod gzip_type_tests {
    use super::*;

    #[test]
    fn default_types_cover_text_json_xml_javascript_and_svg() {
        assert!(is_compressible_content_type(
            "text/html; charset=utf-8",
            &[]
        ));
        assert!(is_compressible_content_type("application/json", &[]));
        assert!(is_compressible_content_type(
            "application/problem+json",
            &[]
        ));
        assert!(is_compressible_content_type("application/rss+xml", &[]));
        assert!(is_compressible_content_type("application/javascript", &[]));
        assert!(is_compressible_content_type("image/svg+xml", &[]));
        assert!(!is_compressible_content_type("image/png", &[]));
    }

    #[test]
    fn configured_types_replace_defaults_and_ignore_case() {
        let configured = vec!["application/wasm".to_string(), "FONT/*".to_string()];
        assert!(is_compressible_content_type(
            "application/wasm",
            &configured
        ));
        assert!(is_compressible_content_type(
            "font/ttf; charset=binary",
            &configured
        ));
        assert!(!is_compressible_content_type("text/plain", &configured));
    }

    #[test]
    fn all_types_wildcard_matches_any_nonempty_mime() {
        let configured = vec!["*/*".to_string()];
        assert!(is_compressible_content_type(
            "application/octet-stream",
            &configured
        ));
        assert!(!is_compressible_content_type("", &configured));
    }
}

#[cfg(test)]
mod caddy_parity_tests {
    use super::*;
    use crate::upstream::create_upstream;

    #[test]
    fn access_control_enforces_cidr_referer_and_user_agent_rules() {
        let policy = RouteAccessControl::from_config(&AccessControlConfig {
            allowed_ips: vec!["10.0.0.0/8".into()],
            denied_ips: vec!["10.1.2.3".into()],
            allowed_referers: vec!["*.trusted.example".into()],
            denied_referers: vec!["evil.trusted.example".into()],
            allowed_user_agents: vec!["^PingclairClient/".into()],
            denied_user_agents: vec!["(?i)bot".into()],
        });
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::REFERER,
            "https://app.trusted.example/page".parse().unwrap(),
        );
        headers.insert(
            http::header::USER_AGENT,
            "PingclairClient/1.0".parse().unwrap(),
        );
        assert!(policy.allowed_ips[0].contains(&"10.2.3.4".parse::<IpAddr>().unwrap()));
        assert_eq!(
            referer_host("https://app.trusted.example/page"),
            Some("app.trusted.example")
        );
        assert!(host_matches_rule(
            "app.trusted.example",
            "*.trusted.example"
        ));
        assert!(policy.allowed_user_agents[0].is_match("PingclairClient/1.0"));
        let ip: IpAddr = "10.2.3.4".parse().unwrap();
        assert!(
            !policy
                .denied_ips
                .iter()
                .any(|network| network.contains(&ip))
        );
        assert!(
            policy
                .allowed_ips
                .iter()
                .any(|network| network.contains(&ip))
        );
        assert!(
            !policy
                .denied_referers
                .iter()
                .any(|rule| host_matches_rule("app.trusted.example", rule))
        );
        assert!(
            policy
                .allowed_referers
                .iter()
                .any(|rule| host_matches_rule("app.trusted.example", rule))
        );
        assert!(
            !policy
                .denied_user_agents
                .iter()
                .any(|regex| regex.is_match("PingclairClient/1.0"))
        );
        assert!(policy.allows("10.2.3.4", &headers));

        assert!(!policy.allows("192.168.1.1", &headers));
        assert!(!policy.allows("10.1.2.3", &headers));
        headers.insert(
            http::header::REFERER,
            "https://evil.trusted.example/".parse().unwrap(),
        );
        assert!(!policy.allows("10.2.3.4", &headers));
        headers.insert(
            http::header::REFERER,
            "https://app.trusted.example/".parse().unwrap(),
        );
        headers.insert(
            http::header::USER_AGENT,
            "PingclairBot/1.0".parse().unwrap(),
        );
        assert!(!policy.allows("10.2.3.4", &headers));
    }

    #[test]
    fn proxy_state_exposes_the_same_compiled_access_gate_to_every_protocol() {
        let access = AccessControlConfig {
            allowed_ips: vec!["10.0.0.0/8".into()],
            denied_ips: Vec::new(),
            allowed_referers: Vec::new(),
            denied_referers: Vec::new(),
            allowed_user_agents: Vec::new(),
            denied_user_agents: vec!["(?i)blockedbot".into()],
        };
        let state = ProxyState::new(ServerConfig {
            routes: vec![pingclair_core::config::RouteConfig {
                path: "/*".into(),
                handler: HandlerConfig::Pipeline {
                    handlers: vec![
                        HandlerConfig::AccessControl(access),
                        HandlerConfig::Respond {
                            status: 200,
                            body: Some("ok".into()),
                            headers: HashMap::new(),
                        },
                    ],
                },
                methods: None,
                matcher: None,
            }],
            ..Default::default()
        });
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::USER_AGENT, "Browser/1.0".parse().unwrap());

        assert!(state.allows_access(0, "10.2.3.4", &headers));
        assert!(!state.allows_access(0, "192.0.2.1", &headers));
        headers.insert(http::header::USER_AGENT, "BlockedBot/1.0".parse().unwrap());
        assert!(!state.allows_access(0, "10.2.3.4", &headers));
        assert!(state.allows_access(99, "192.0.2.1", &headers));
    }

    #[test]
    fn weighted_upstreams_set_native_weights_and_isolate_backups() {
        let config = ReverseProxyConfig {
            upstream_options: vec![
                pingclair_core::config::ProxyUpstream {
                    address: "127.0.0.1:8301".into(),
                    weight: 3,
                    backup: false,
                },
                pingclair_core::config::ProxyUpstream {
                    address: "127.0.0.1:8302".into(),
                    weight: 2,
                    backup: true,
                },
            ],
            ..Default::default()
        };
        let (primary, backup) = build_weighted_upstreams(&config);
        assert_eq!(primary.len(), 1);
        assert_eq!(primary[0].spec.authority(), "127.0.0.1:8301");
        assert_eq!(primary[0].weight, 3);
        assert_eq!(backup.len(), 1);
        assert_eq!(backup[0].spec.authority(), "127.0.0.1:8302");
        assert_eq!(backup[0].weight, 2);

        // The weights must survive all the way into the built pool.
        let load_balancer = LoadBalancer::from_entries(primary, backup, Strategy::RoundRobin);
        let selected = load_balancer.select(None).unwrap();
        assert_eq!(selected.addr.to_string(), "127.0.0.1:8301");
        assert_eq!(selected.weight, 3);
    }

    #[test]
    fn upstream_schemes_select_tls_and_http_versions() {
        for (address, tls, min_version, max_version, group_key) in [
            ("http://127.0.0.1:8301", false, 1, 1, 1),
            ("https://127.0.0.1:8302", true, 1, 2, 2),
            ("h2c://127.0.0.1:8303", false, 2, 2, 3),
            ("h2://127.0.0.1:8304", true, 2, 2, 4),
        ] {
            let upstream = create_upstream(address).unwrap();
            let peer = PingclairProxy::build_http_peer(&upstream, None, None, None, None);

            assert_eq!(peer.is_tls(), tls);
            assert_eq!(
                peer.options.alpn.get_min_http_version(),
                min_version,
                "{address}"
            );
            assert_eq!(
                peer.options.alpn.get_max_http_version(),
                max_version,
                "{address}"
            );
            assert_eq!(peer.group_key, group_key);
            assert_eq!(
                peer_protocol_group(&peer),
                group_key,
                "a peer without a TLS policy must leave the group key unpacked: {address}"
            );
            assert_eq!(
                peer.options.upstream_tls_handshake_complete_hook.is_some(),
                group_key == 4,
                "{address}"
            );
        }
    }

    /// 🧪 Compiles a TLS policy from an in-memory configuration.
    fn compile_tls(
        config: pingclair_core::config::UpstreamTlsConfig,
    ) -> Arc<crate::upstream_tls::UpstreamTls> {
        crate::upstream_tls::UpstreamTls::compile(&config)
            .expect("policy compiles")
            .expect("policy is a customisation")
    }

    #[test]
    fn a_tls_policy_reaches_the_peer_without_disturbing_the_protocol_group() {
        // Setup scenarios
        let policy = compile_tls(pingclair_core::config::UpstreamTlsConfig {
            server_name: Some("internal.example".into()),
            ..Default::default()
        });
        let upstream = create_upstream("https://10.0.0.7:8443").unwrap();

        // Verification
        let peer =
            PingclairProxy::build_http_peer(&upstream, None, None, None, Some(&policy)).clone();
        assert_eq!(peer.sni, "internal.example");
        assert_eq!(
            peer_protocol_group(&peer),
            PROTOCOL_GROUP_HTTPS,
            "packing the TLS identity must not change which protocol the peer speaks"
        );
        assert_ne!(
            peer.group_key, PROTOCOL_GROUP_HTTPS,
            "the TLS identity must actually be present in the group key"
        );
    }

    #[test]
    fn different_trust_domains_do_not_share_a_connection_pool() {
        // Setup scenarios
        // Two routes reaching the same address with the same SNI, differing
        // only in the name they will accept. Pingora's own peer hash ignores
        // the CA bundle, so without the packed group key these would reuse
        // each other's connections.
        let upstream = create_upstream("https://10.0.0.7:8443").unwrap();
        let strict = compile_tls(pingclair_core::config::UpstreamTlsConfig {
            server_name: Some("strict.internal".into()),
            ..Default::default()
        });
        let other = compile_tls(pingclair_core::config::UpstreamTlsConfig {
            server_name: Some("other.internal".into()),
            ..Default::default()
        });

        // Verification
        let left = PingclairProxy::build_http_peer(&upstream, None, None, None, Some(&strict));
        let right = PingclairProxy::build_http_peer(&upstream, None, None, None, Some(&other));
        assert_ne!(left.group_key, right.group_key);
        assert_eq!(peer_protocol_group(&left), peer_protocol_group(&right));
    }

    #[test]
    fn skipping_verification_reaches_both_peer_flags() {
        // Setup scenarios
        let policy = compile_tls(pingclair_core::config::UpstreamTlsConfig {
            insecure_skip_verify: true,
            ..Default::default()
        });
        let upstream = create_upstream("https://127.0.0.1:8443").unwrap();

        // Verification
        let peer = PingclairProxy::build_http_peer(&upstream, None, None, None, Some(&policy));
        assert!(!peer.options.verify_cert);
        assert!(!peer.options.verify_hostname);
    }

    #[test]
    fn a_bare_tls_directive_adds_encryption_without_widening_alpn() {
        // Setup scenarios
        let policy = compile_tls(pingclair_core::config::UpstreamTlsConfig {
            enable: true,
            ..Default::default()
        });
        let plain = create_upstream("127.0.0.1:8443").unwrap();
        let prior_knowledge_h2 = create_upstream("h2c://127.0.0.1:8443").unwrap();

        // Verification
        let upgraded = PingclairProxy::build_http_peer(&plain, None, None, None, Some(&policy));
        assert!(
            upgraded.is_tls(),
            "`tls` must upgrade a scheme-less upstream"
        );
        assert_eq!(
            upgraded.options.alpn.get_max_http_version(),
            1,
            "`tls` must not silently start offering h2 to an HTTP/1.1 upstream"
        );
        assert_eq!(peer_protocol_group(&upgraded), PROTOCOL_GROUP_HTTPS);

        let untouched =
            PingclairProxy::build_http_peer(&prior_knowledge_h2, None, None, None, Some(&policy));
        assert!(
            !untouched.is_tls(),
            "prior-knowledge h2c has no TLS form to be upgraded into"
        );
    }

    /// 🧪 Builds a one-route reverse-proxy server around a TLS block.
    fn state_with_upstream_tls(tls: pingclair_core::config::UpstreamTlsConfig) -> ProxyState {
        ProxyState::new(ServerConfig {
            routes: vec![pingclair_core::config::RouteConfig {
                path: "/*".into(),
                handler: HandlerConfig::ReverseProxy(ReverseProxyConfig {
                    upstreams: vec!["https://127.0.0.1:8443".into()],
                    upstream_tls: Box::new(tls),
                    ..Default::default()
                }),
                methods: None,
                matcher: None,
            }],
            ..Default::default()
        })
    }

    #[test]
    fn a_route_whose_trust_material_is_missing_refuses_instead_of_downgrading() {
        // Setup scenarios
        let state = state_with_upstream_tls(pingclair_core::config::UpstreamTlsConfig {
            trusted_ca_certs: vec!["/nonexistent/pingclair-day11-ca.pem".into()],
            ..Default::default()
        });

        // Verification
        assert!(
            state.upstream_tls_for(0).is_err(),
            "a route that could not load its trust roots must not fall back to system trust"
        );
    }

    #[test]
    fn a_route_with_no_tls_block_keeps_the_shared_default() {
        // Setup scenarios
        let state = state_with_upstream_tls(pingclair_core::config::UpstreamTlsConfig::default());

        // Verification
        assert!(
            matches!(state.upstream_tls_for(0), Ok(None)),
            "an untouched route must not allocate per-route TLS state"
        );
    }

    #[test]
    fn a_route_that_asked_for_an_sni_override_compiles_it() {
        // Setup scenarios
        let state = state_with_upstream_tls(pingclair_core::config::UpstreamTlsConfig {
            server_name: Some("origin.internal".into()),
            ..Default::default()
        });

        // Verification
        let policy = state
            .upstream_tls_for(0)
            .expect("policy loads")
            .expect("policy is a customisation");
        assert_eq!(policy.server_name(), Some("origin.internal"));
        assert!(policy.verifies());
    }

    #[test]
    fn regex_rewrite_preserves_the_query_and_expands_captures() {
        let regex = Regex::new(r"^/api/(.*)$").unwrap();
        assert_eq!(
            rewrite_uri(
                "/api/users/42?verbose=1",
                None,
                None,
                None,
                Some(&regex),
                Some("/v1/$1"),
            ),
            "/v1/users/42?verbose=1",
        );
    }

    #[test]
    fn upstream_timeout_policy_preserves_streaming_read_phases() {
        let spec = UpstreamSpec::parse("127.0.0.1:9000").unwrap();
        let upstream = spec.backend("127.0.0.1:9000".parse().unwrap(), 1).unwrap();
        let config = ReverseProxyConfig {
            connect_timeout: Some(100),
            first_byte_timeout: Some(200),
            between_reads_timeout: Some(300),
            write_timeout: Some(400),
            ..Default::default()
        };
        let peer = PingclairProxy::build_http_peer(
            &upstream,
            Some(&config),
            Some(Duration::from_millis(50)),
            Some(Duration::from_millis(60)),
            None,
        );
        assert_eq!(
            peer.options.connection_timeout,
            Some(Duration::from_millis(50))
        );
        assert_eq!(
            peer.options.total_connection_timeout,
            Some(Duration::from_millis(50))
        );
        assert_eq!(peer.options.read_timeout, Some(Duration::from_millis(200)));
        assert_eq!(peer.options.write_timeout, Some(Duration::from_millis(50)));
    }

    #[test]
    fn bandwidth_pacer_retains_only_counters() {
        let mut pacer = BandwidthPacer::new(1_000);
        let first = pacer.delay_for(500).expect("first chunk should be paced");
        assert!(first <= Duration::from_millis(500));
        pacer.started -= Duration::from_secs(2);
        assert_eq!(pacer.delay_for(500), None);
        assert_eq!(pacer.bytes, 1_000);
    }
}
