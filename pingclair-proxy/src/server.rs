// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Pingclair HTTP Proxy implementation using Pingora
//!
//! 🌐 This module implements the core reverse proxy using Pingora's ProxyHttp trait.

use pingclair_core::config::{
    AccessControlConfig, CacheConfig, HandlerConfig, ResourceLimitsConfig, RetryConfig,
    ReverseProxyConfig, ServerConfig,
};
use pingclair_core::server::{
    CompiledMatcher, MatcherPrecompile, MatcherRequest, MatcherVerdict, RequestAddresses, Router,
    evaluate, evaluate_verdict,
};

use async_trait::async_trait;
use pingora_core::Result as PingoraResult;
use pingora_core::upstreams::peer::{HttpPeer, Peer};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};

// 🗄️ Response caching. Already linked through pingora-proxy; named directly so
// the storage and metadata types are reachable.
use pingora_cache::cache_control::CacheControl;
use pingora_cache::key::{CacheKey, HashBinary};

use crate::cache_budget::CACHE_EVICTION;
use pingora_cache::eviction::EvictionManager;
#[cfg(test)]
use pingora_cache::eviction::simple_lru;
use pingora_cache::lock::{CacheKeyLockImpl, CacheLock};
use pingora_cache::predictor::Predictor;
use pingora_cache::{CacheMeta, MemCache, NoCacheReason, RespCacheable, filters};

use arc_swap::ArcSwap;
use async_recursion::async_recursion;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use crate::cache_policy::{
    OriginFreshness, cache_defaults, heuristic_lifetime, origin_freshness,
    uncacheable_response_reason,
};
use crate::encoding::{ResponseEncoder, negotiate};
use crate::http_policy::{
    CorsDecision, ResponseContent, ResponseHeaderPolicy, evaluate_cors, generate_request_id,
    is_websocket_upgrade, rewrite_uri, sanitize_request_id, strip_path_prefix, via_value,
};
use crate::listener_generation::RouteTable;
use crate::metrics;
use crate::overload::{AdmissionError, RouteAdmission, RouteProtection, UpstreamAdmission};
use crate::upstream::{DynamicDialPlan, HostName, Scheme, UpstreamSpec};
use crate::{HealthChecker, LoadBalancer, Strategy, Upstream, UpstreamEntry};
use bytes::{Bytes, BytesMut};
use ipnet::IpNet;
use pingclair_core::config::Encoding;
use regex::Regex;

// 🛡️ Which forwarding headers name the client, and when to believe them.
mod trusted_proxy;
use trusted_proxy::TrustedProxyPolicy;

/// 🚦 Why a prepared control-plane transaction could not be published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigApplyErrorKind {
    /// 🚫 The document or its external trust material is invalid.
    Invalid,
    /// 🔁 A listener/process setting cannot safely change without rebuilding sockets.
    RestartRequired,
    /// 🔐 The request authenticated against an Admin policy that has since changed.
    StaleAuthorization,
    /// 💥 The runtime publisher needed by this process is unavailable.
    Unavailable,
}

/// 🚫 A fail-closed control-plane publication error.
#[derive(Debug, Clone)]
pub struct ConfigApplyError {
    /// 🧭 Stable category used by the Admin API to choose an HTTP status.
    pub kind: ConfigApplyErrorKind,
    /// 📝 Operator-facing reason naming the setting that did not apply.
    pub message: String,
}

impl ConfigApplyError {
    /// 🚫 Creates an invalid-policy rejection.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            kind: ConfigApplyErrorKind::Invalid,
            message: message.into(),
        }
    }

    /// 🔁 Creates an explicit restart-required rejection.
    pub fn restart_required(message: impl Into<String>) -> Self {
        Self {
            kind: ConfigApplyErrorKind::RestartRequired,
            message: message.into(),
        }
    }

    /// 🔐 Creates a stale-authorization rejection.
    pub fn stale_authorization(message: impl Into<String>) -> Self {
        Self {
            kind: ConfigApplyErrorKind::StaleAuthorization,
            message: message.into(),
        }
    }

    /// 💥 Creates a rejection when no complete runtime publisher is available.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            kind: ConfigApplyErrorKind::Unavailable,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ConfigApplyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ConfigApplyError {}

/// 📣 The one publication path used by Admin and signal reloads.
pub trait ConfigPublisher: Send + Sync {
    /// 🧪 Prepares the complete document, then publishes every listener and Admin
    /// policy or none. `expected_admin_revision` binds a mutation to the policy
    /// that authenticated it, preventing an old key's queued request from
    /// landing after key rotation.
    /// 📄 Admin writes retain their raw document, including traversal metadata;
    /// signal reloads pass no document and publish the canonical serialization.
    fn publish_config(
        &self,
        config: &pingclair_core::config::PingclairConfig,
        expected_admin_revision: Option<u64>,
        document: Option<&serde_json::Value>,
    ) -> Result<usize, ConfigApplyError>;
}

// MARK: - Context

/// Context for each request
pub struct RequestContext {
    /// Matched server state
    pub state: Option<Arc<ProxyState>>,
    /// 📦 The one listener generation this request reads routes and client-auth
    /// policy from, loaded at its first phase so a reload mid-request cannot
    /// hand it one half of each.
    pub(crate) generation: Option<Arc<crate::listener_generation::ListenerGeneration>>,
    /// Matched route index
    pub route_index: Option<usize>,
    /// Selected upstream (kept for connection tracking)
    pub upstream: Option<Upstream>,
    /// Extra headers to add upstream
    pub headers_upstream: BTreeMap<String, String>,
    /// 🚫 Header names to take off the upstream request, from `header_up -Name`.
    pub headers_upstream_remove: Vec<String>,
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
    /// 🛡️ Client IP resolved through the trusted-proxy policy.
    pub verified_client_ip: Option<IpAddr>,
    /// 🔌 The connection's own peer, never taken from a forwarded header; what
    /// the `remote_ip` matcher compares. A PROXY-protocol source counts as the
    /// peer, because that header replaces the connection's address.
    pub remote_ip: Option<IpAddr>,
    /// 🌐 Verified downstream request scheme forwarded to the upstream.
    pub request_scheme: &'static str,
    /// Upstream response status (for access log)
    pub response_status: u16,
    /// Response body bytes written (for access log)
    pub response_bytes: u64,
    /// 🗄️ Freshness lifetime for this route, set only when caching is enabled.
    ///
    /// Carried on the context because `response_cache_filter` runs long after
    /// the route was matched and has no other way back to its configuration.
    pub cache_ttl_secs: Option<u64>,
    /// 🔑 The matched route's cache scope, copied out of `ProxyState` when
    /// caching is enabled so `cache_key_callback` can key the entry by route.
    pub(crate) cache_scope: Option<crate::cache_key::CacheScope>,
    /// 🧭 The upstream a placeholder dial resolved to, as a digest, for a
    /// caching route whose dial has placeholders. `cache_vary_filter` makes it
    /// part of the variant, so each upstream's copy is stored apart.
    pub(crate) cache_upstream: Option<pingora_cache::key::HashBinary>,

    /// 📏 Whether this request's cache has a per-response ceiling that still
    /// needs body chunks fed to it. Cleared once the limit is exceeded, so the
    /// rest of the body streams without touching the tracker again.
    pub cache_size_tracked: bool,
    /// 🪪 Request ID stored once in the representation used by both header
    /// inserts and logging. `HeaderValue::try_from(String)` takes ownership of
    /// generated bytes, avoiding a second allocation and copy per request.
    pub request_id_value: http::HeaderValue,
    /// Start time for logging
    pub start_time: std::time::Instant,
    /// ⏳ The upstream attempt starts before connection setup, for RFC 9111 response delay.
    cache_request_started: Option<std::time::Instant>,
    /// 🔁 Raw 304 clock fields survive Pingora's selective merge into the stored response.
    cache_revalidation_headers: Option<crate::cache_age::RevalidationHeaders>,
    /// ⏱️ When the first response byte was handed downstream, for TTFB.
    /// `None` when the response failed before producing any byte.
    pub first_byte_at: Option<std::time::Instant>,
    /// 📊 Resolved active-request gauge retained so completion needs no label lookup.
    active_connection_metric: Option<prometheus::IntGauge>,
    /// 🚰 Keeps shutdown waiting until this request is finished; see [`crate::drain`].
    _in_flight: Option<crate::drain::InFlight>,
    /// Path produced by the most recent rewrite handler. Pipelines consume
    /// this before invoking the next local handler.
    pub rewritten_path: Option<String>,
    /// 📦 Request-body bytes observed incrementally by the streaming filter.
    pub request_body_bytes: u64,
    /// 🧱 `request_buffers` state for this request, created only when the
    /// matched route configured a ceiling. `None` is the streaming default,
    /// and it is the cheap case: no allocation, one `Option` test per chunk.
    request_buffer: Option<crate::body_buffer::BufferedBody>,
    /// 🧱 `response_buffers` state, on the upstream-to-client half.
    response_buffer: Option<crate::body_buffer::BufferedBody>,
    /// 🚨 Status raised by an `error` handler, awaiting error-route dispatch.
    pub error_status: Option<u16>,
    /// 💬 Message carried with the raised error status.
    pub error_message: Option<String>,
    /// 🔎 What exactly went wrong, appended to the built-in error body when no
    /// `error_page` is configured — for a 431, which field was too large.
    /// Unlike `error_message` it never replaces the operator's page.
    pub error_detail: Option<std::borrow::Cow<'static, str>>,
    /// 🚫 This request was refused before any route could run.
    ///
    /// `handle_errors` routes and `error_page` files exist so a site can answer
    /// for its handlers; a request refused before routing never reached one,
    /// and its refusal carries the detail that says what was wrong (#288).
    /// HTTP/3 already answers these directly, so this is also the shape all
    /// three transports share.
    pub refused_before_routing: bool,
    /// 🏷️ Why the latest upstream attempt failed. Recorded by
    /// `fail_to_connect` and `error_while_proxy`, cleared once an attempt
    /// connects, and settled by `fail_to_proxy`; only the error page that
    /// hook writes consumes it, so `Proxy-Status` never lands on an ordinary
    /// local response.
    pub(crate) proxy_error: Option<crate::proxy_status::ProxyError>,
    /// 🧰 Request-scoped variables set by `vars` handlers.
    pub request_vars: crate::http_policy::RequestVars,
    /// 🧭 Response handlers registered by an `intercept` handler for this
    /// request; the proxy's own `handle_response` takes precedence.
    pub intercept_handlers: Vec<pingclair_core::config::ResponseHandlerConfig>,
    /// 🧭 Replacement response decided by `handle_response`, emitted once.
    pub intercepted_response: Option<crate::http_policy::InterceptedResponse>,
    /// 📂 Response-subroute `file_server` stream, emitted chunk by chunk
    /// while the upstream body is drained and discarded.
    pub intercepted_file: Option<pingclair_static::StreamingFile>,
    /// 🚩 Whether the replacement body has already been handed downstream.
    pub intercepted_body_emitted: bool,
    /// 🚨 Status raised while a response subroute evaluates its terminal handler.
    pub response_decision_error: Option<u16>,
    /// 🌊 Whether response interception fully wrote and framed the downstream body.
    pub response_takeover_complete: bool,
    /// 🔌 Whether Pingora's upstream loop has started, so a failure from here on
    /// ends with Pingora closing the client connection whatever
    /// `fail_to_proxy` asks for.
    pub upstream_attempted: bool,
    /// 🧭 The request URI before any rewrite, for `{http.request.orig_uri.*}`.
    pub orig_uri: http::Uri,
    /// 🚫 Whether the request is already inside an error route; a second
    /// raised error then responds directly instead of recursing forever.
    pub handling_error: bool,
    /// 🚨 The error route running and the status it answers, while one runs.
    /// A `file_server` reads it to serve the route's own page with that status.
    pub(crate) error_scope: Option<crate::error_routes::ErrorScope>,
    /// 🚫 Whether a `log_skip` middleware excluded this request from access
    /// logging.
    pub log_skip: bool,
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
    /// ⌛ The moment after which no further upstream attempt may start
    /// (`lb_try_duration`). Never a deadline on the attempt already running.
    retry_deadline: Option<std::time::Instant>,
    /// 💤 Whether the next upstream selection must apply retry backoff.
    retry_pending: bool,
    /// 🔁 Backends already attempted during the current redispatch cycle.
    retry_excluded: HashSet<SocketAddr>,
    /// 📥 Per-route override of the site's `client_max_body_size`, set by the
    /// `request_body` handler. `None` means the site's limit still applies.
    request_body_limit: Option<u64>,
    /// 🧾 Replacement body from `request_body { set … }`, already resolved for
    /// this request. While this is `Some`, the client's own bytes are discarded
    /// as they arrive and this string is what the upstream receives: the
    /// replacement is what the configuration wrote, so nothing in this path
    /// grows with the size of the upload being replaced.
    request_body_set: Option<Bytes>,
    /// ⏱️ Per-route `request_body` deadlines in milliseconds, seeded from the
    /// route's declaration before the first byte is read and overwritten with
    /// the exact value when the handler runs.
    request_body_read_timeout_ms: Option<u64>,
    request_body_write_timeout_ms: Option<u64>,
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
        let request_id_value = http::HeaderValue::try_from(generate_request_id())
            .expect("generated request id is valid header bytes");
        Self {
            state: None,
            generation: None,
            route_index: None,
            cache_ttl_secs: None,
            cache_scope: None,
            cache_upstream: None,
            cache_size_tracked: false,
            upstream: None,
            headers_upstream: BTreeMap::new(),
            headers_upstream_remove: Vec::new(),
            response_headers: ResponseHeaderPolicy::default(),
            negotiated_encoding: None,
            streaming_response: false,
            verified_client_ip: None,
            remote_ip: None,
            request_scheme: "http",
            response_status: 0,
            response_bytes: 0,
            request_id_value,
            start_time: std::time::Instant::now(),
            cache_request_started: None,
            cache_revalidation_headers: None,
            first_byte_at: None,
            active_connection_metric: None,
            _in_flight: None,
            rewritten_path: None,
            request_body_bytes: 0,
            request_buffer: None,
            response_buffer: None,
            error_status: None,
            error_message: None,
            error_detail: None,
            refused_before_routing: false,
            proxy_error: None,
            request_vars: crate::http_policy::RequestVars::default(),
            intercept_handlers: Vec::new(),
            intercepted_response: None,
            intercepted_file: None,
            intercepted_body_emitted: false,
            response_decision_error: None,
            response_takeover_complete: false,
            upstream_attempted: false,
            orig_uri: http::Uri::default(),
            handling_error: false,
            error_scope: None,
            log_skip: false,
            request_deadline: None,
            long_connection: false,
            upload_pacer: None,
            download_pacer: None,
            upstream_connect_timed_out: false,
            retry_attempts: 0,
            retry_deadline: None,
            retry_pending: false,
            retry_excluded: HashSet::new(),
            request_body_limit: None,
            request_body_set: None,
            request_body_read_timeout_ms: None,
            request_body_write_timeout_ms: None,
            route_admission: None,
            upstream_admission: None,
            preadmitted_upstream: None,
        }
    }
}

impl RequestContext {
    /// 🪪 Borrows the validated request ID without materialising another string.
    fn request_id(&self) -> &str {
        self.request_id_value
            .to_str()
            .expect("request IDs are validated visible ASCII")
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

/// 🧱 Derives the transport-captured ceiling from a set of virtual hosts.
fn merged_listener_limits<'a>(
    configured: impl Iterator<Item = &'a ResourceLimitsConfig>,
) -> ResourceLimitsConfig {
    let mut limits = ResourceLimitsConfig::default();
    for candidate in configured {
        merge_listener_limit(&mut limits.header_timeout_ms, candidate.header_timeout_ms);
        merge_listener_limit(&mut limits.max_header_count, candidate.max_header_count);
        merge_listener_limit(&mut limits.max_header_bytes, candidate.max_header_bytes);
        merge_listener_limit(&mut limits.max_connections, candidate.max_connections);
        merge_listener_limit(&mut limits.idle_timeout_ms, candidate.idle_timeout_ms);
        merge_listener_limit(
            &mut limits.long_connections.idle_timeout_ms,
            candidate.long_connections.idle_timeout_ms,
        );
    }
    limits
}

/// ⏱️ Selects the stricter of two optional time budgets.
fn shortest_duration(left: Option<Duration>, right: Option<Duration>) -> Option<Duration> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

/// 🧹 Removes everything a client must not hand to the origin.
///
/// The list itself lives in `http_policy::OutboundRequestFilter`, shared with
/// HTTP/3, inline subrequests and the FastCGI environment — four sinks that each
/// used to carry their own copy and each disagreed with the others.
///
/// This is the removing variant: Pingora has already cloned the client's request
/// into `upstream_request`, so the work is deletion rather than selection. The
/// `Connection`-named fields are removed by walking the tokens, because the list
/// of what to delete lives in the very field being deleted.
///
/// 📌 `Transfer-Encoding` is deliberately left alone here: HTTP/1 framing belongs
/// to Pingora, which re-frames the body for the upstream, and removing the field
/// underneath it would describe a body that is not what gets sent.
fn strip_hop_by_hop_headers(
    session: &Session,
    upstream_request: &mut RequestHeader,
) -> pingora_core::Result<()> {
    let downstream = session.req_header();
    let filter = crate::http_policy::OutboundRequestFilter::for_client(&downstream.headers);

    // 🎯 Collected before anything is removed, since the names live in the very
    // field about to be removed. This is the one place an allocation is
    // unavoidable: the borrow of `downstream` has to end before
    // `upstream_request` is mutated, and both alias the same session.
    let named: Vec<Box<str>> = filter.connection_tokens().map(Box::from).collect();
    let upgrading = filter.is_upgrading();

    for name in &named {
        upstream_request.remove_header(name.as_ref());
    }

    for name in crate::http_policy::NEVER_FORWARDED_TO_ORIGIN {
        upstream_request.remove_header(*name);
    }

    if upgrading {
        // 🔌 A tunnelling client may legitimately negotiate transfer codings,
        // and needs `Connection`/`Upgrade` to reach the origin at all.
        return Ok(());
    }
    upstream_request.remove_header("te");
    upstream_request.remove_header("connection");
    upstream_request.remove_header("upgrade");
    Ok(())
}

/// 🔐 Records the protocol selected by an upstream TLS handshake.
#[derive(Debug)]
struct NegotiatedUpstreamAlpn(Vec<u8>);

// MARK: - Proxy State

/// Whether a route's `flush_interval` means "forward each chunk downstream
/// as soon as it arrives from upstream" (configured as `-1`).
///
/// Positive `flush_interval` values are deliberately not implemented as a
/// timer: Pingora 0.9.0 has no timed downstream flush mechanism (the
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

/// 🗜️ Both response paths use the same MIME policy.
pub fn is_compressible_content_type(content_type: &str, configured_types: &[String]) -> bool {
    pingclair_core::encoding::is_compressible_content_type(content_type, configured_types)
}

/// Mutable state for hot reloading
#[derive(Clone)]
pub struct ProxyState {
    /// 🎯 Immutable response patterns are compiled at site load time.
    pub(crate) encode_policy: pingclair_core::encoding::EncodePolicy,
    /// Server configuration
    pub config: Arc<ServerConfig>,
    /// Route matcher
    pub router: Arc<Router>,
    /// 🚨 Each error route's pipeline, matchers and file server, parallel to
    /// `config.error_routes`.
    pub(crate) error_routes: Arc<[crate::error_routes::PreparedErrorRoute]>,
    /// 🧰 Precompiled matchers for site-level `vars` rules, parallel to
    /// `config.vars_routes`; `None` means the rule has no matcher.
    pub vars_precompiles: Vec<Option<CompiledMatcher>>,
    /// Load balancers per route
    pub load_balancers: Vec<Option<Arc<LoadBalancer>>>,
    /// 🧭 Per-route dial templates with request placeholders, parallel to
    /// `load_balancers`; `None` means the route dials only static peers.
    pub dynamic_dials: Vec<Option<Arc<DynamicDialPlan>>>,
    /// 🔁 Parsed inline subrequest targets for each route's handler tree.
    pub(crate) subrequests: Vec<Vec<Arc<crate::subrequest::PreparedSubrequest>>>,
    /// Health checkers per route
    pub health_checkers: Vec<Option<Arc<HealthChecker>>>,
    /// File servers per route
    pub file_servers: Vec<Option<Arc<pingclair_static::FileServer>>>,
    /// 📂 File servers for `handle_response { file_server }`, built once per
    /// distinct configuration rather than once per response.
    ///
    /// 🤡 Each response used to build its own and throw it away. `FileServer::new`
    /// is cheap, but the caches it carries are not: they started empty every
    /// time, so a custom error page recomputed its content type, `ETag` and
    /// `Last-Modified` on every single response — and, with `compress` on,
    /// deflated the same file again for each one. Avoiding exactly that is the
    /// only reason those caches exist.
    ///
    /// 🔒 A `Mutex` rather than `ArcSwap`: this is reached only when a
    /// `handle_response` entry matched, which is an error path rather than the
    /// request path, and the lock covers one map lookup and never spans an
    /// `await`. Entries are bounded by the configuration — a root that comes
    /// from `{http.vars.root}` is deliberately not cached, because that value
    /// can be built from the request and an unbounded key is how a cache
    /// becomes a memory-growth vector.
    pub(crate) response_file_servers: Arc<
        std::sync::Mutex<
            std::collections::HashMap<
                crate::http_policy::ResponseFileServer,
                Arc<pingclair_static::FileServer>,
            >,
        >,
    >,
    /// Rate limiters per route
    pub rate_limiters: Vec<Option<Arc<crate::rate_limit::RateLimiter>>>,
    /// 🚦 Admission and circuit state per reverse-proxy route.
    pub(crate) route_protections: Vec<Option<Arc<RouteProtection>>>,

    /// 🔑 Per-route consistent-hash key source, parallel to `load_balancers`.
    /// `None` means the route hashes the client address, or does not hash.
    pub(crate) hash_key_sources: Vec<Option<HashKeySource>>,
    /// 🔐 Compiled upstream TLS trust and identity per reverse-proxy route.
    pub(crate) upstream_tls: Vec<RouteUpstreamTls>,
    /// Pre-compiled per-route access policies.
    access_controls: Vec<Option<Arc<RouteAccessControl>>>,
    /// Pre-compiled regular expressions used by route rewrite handlers.
    route_regexes: Vec<HashMap<String, Arc<Regex>>>,
    /// 📥 Per route, the widest `request_body` limit it could grant.
    route_body_ceilings: Vec<Option<u64>>,
    /// ⏱️ Per route, the longest `request_body` read and write deadlines it
    /// declares. Resolved once here for the same reason as the ceiling above:
    /// the local body drain runs before the handler that would set them.
    route_body_timeouts: Vec<RouteBodyTimeouts>,
    /// 🧱 Per route, how many body bytes `request_buffers`/`response_buffers`
    /// hold before the rest streams. Resolved once here because the answer
    /// cannot differ between two requests on the same route, and because the
    /// body filters run per chunk — the one place a per-request `min()` would
    /// be paid a hundred thousand times a second.
    pub(crate) route_buffering: Vec<RouteBuffering>,
    /// 🔑 Per route, the scope that keeps its cache entries apart from every
    /// other route's; `None` for a route that does not cache.
    pub(crate) cache_scopes: Arc<crate::cache_key::RouteScopes>,
    /// 🌊 Cache admission reads this before upstream selection can set response flags.
    route_streaming: Vec<bool>,
    /// 🧭 Whether configured runtime text can observe original-URI variables.
    /// Most sites cannot, so their requests never build those owned map entries.
    needs_original_uri_vars: bool,
    /// 🪵 Every access-log destination this server can reach, already narrowed
    /// by each logger's `hostnames`.
    ///
    /// The server's own `log` block, its global channels and its named loggers
    /// used to be three separate fields that the request path fanned out to
    /// unconditionally. They are one list now because the question a request
    /// asks is not "which kind of logger is this" but "does this host belong
    /// here", and that is answered once, at configuration time.
    log_targets: pingclair_runtime::access_log::LogTargets,
    /// 🔐 The built-in `Strict-Transport-Security` value, rendered once.
    pub(crate) strict_transport: crate::http_policy::StrictTransport,
}

impl ProxyState {
    /// 🪵 The access-log destinations this server can reach, for the HTTP/3
    /// path, which builds its record outside this module.
    pub(crate) fn log_targets(&self) -> &pingclair_runtime::access_log::LogTargets {
        &self.log_targets
    }

    /// 🧱 This route's resolved buffering ceilings, or the streaming default
    /// for a route index that has none.
    pub(crate) fn buffering(&self, route_index: usize) -> RouteBuffering {
        self.route_buffering
            .get(route_index)
            .copied()
            .unwrap_or_default()
    }
}

/// 🧱 One route's buffering answer, resolved at load time.
///
/// `None` on either side means that direction streams, which is both the
/// default and what `0` means in the configuration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RouteBuffering {
    pub(crate) request: Option<usize>,
    pub(crate) response: Option<usize>,
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
pub(crate) fn compile_route_upstream_tls(
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
                                "🧯 Invalid access-control IP/CIDR rule"
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
                            "🧯 Invalid access-control User-Agent regex"
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

/// 🌐 Canonicalises an IPv4-mapped IPv6 address into plain IPv4.
///
/// 🛡️ This is a security fix, not cosmetics. A dual-stack listener — which is
/// what `:8080` becomes — reports an IPv4 client as `::ffff:127.0.0.1`, and an
/// IPv4 CIDR does not contain an IPv6 address. Day 26 measured what that costs:
/// with `@blocked remote_ip 127.0.0.0/8` and `respond @blocked 403`, the
/// correct answer is 403 and we answered **200**. Every deny rule written with
/// an IPv4 range silently did nothing.
///
/// Normalising here, where the address is first read, means the matcher, the
/// access log, `X-Forwarded-For` and `{remote_host}` all see one canonical form
/// instead of each having to remember this.
///
/// `to_ipv4_mapped` is deliberately narrower than `to_ipv4`: the latter also
/// converts deprecated IPv4-compatible addresses (`::127.0.0.1`), which are not
/// the same thing and which no listener produces.
pub(crate) fn canonical_client_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        other => other,
    }
}

/// 🌐 Extracts the immediate network peer without consulting request headers.
fn session_peer_ip(session: &Session) -> IpAddr {
    session
        .client_addr()
        .map(|addr| match addr {
            pingora_core::protocols::l4::socket::SocketAddr::Inet(inet) => {
                canonical_client_ip(inet.ip())
            }
            pingora_core::protocols::l4::socket::SocketAddr::Unix(_) => {
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            }
        })
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
}

#[cfg(test)]
mod canonical_client_ip_tests {
    use super::canonical_client_ip;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// 🛡️ The measured failure: a dual-stack listener reports an IPv4 client as
    /// `::ffff:a.b.c.d`, and an IPv4 CIDR does not contain an IPv6 address, so
    /// `@blocked remote_ip 127.0.0.0/8` matched nothing and a deny rule became a
    /// no-op: the same configuration must answer 403, and we answered 200.
    #[test]
    fn an_ipv4_mapped_address_becomes_plain_ipv4() {
        let mapped = IpAddr::V6("::ffff:127.0.0.1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(
            canonical_client_ip(mapped),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        );
        let mapped = IpAddr::V6("::ffff:10.1.2.3".parse::<Ipv6Addr>().unwrap());
        assert_eq!(
            canonical_client_ip(mapped),
            IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))
        );
    }

    /// 📌 A real IPv6 client must stay IPv6. Rewriting it would break IPv6 CIDRs
    /// in the other direction, which is the same defect with the sign flipped.
    #[test]
    fn a_genuine_ipv6_address_is_untouched() {
        for text in ["2001:db8::1", "::1", "fe80::1"] {
            let ip = IpAddr::V6(text.parse::<Ipv6Addr>().unwrap());
            assert_eq!(canonical_client_ip(ip), ip, "{text} must not be rewritten");
        }
    }

    #[test]
    fn an_ipv4_address_passes_through() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        assert_eq!(canonical_client_ip(ip), ip);
    }

    /// 🚫 IPv4-*compatible* addresses (`::a.b.c.d`) are deprecated and no
    /// listener produces them. Converting them would silently widen what an
    /// IPv4 rule matches, so `to_ipv4_mapped` is used rather than `to_ipv4`.
    #[test]
    fn deprecated_ipv4_compatible_addresses_are_not_converted() {
        let compat = IpAddr::V6("::127.0.0.1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(canonical_client_ip(compat), compat);
    }
}

fn session_inet_addresses(session: &Session) -> Option<(SocketAddr, SocketAddr)> {
    let peer = match session.client_addr()? {
        // 🛡️ Same canonicalisation as `session_peer_ip`: the PROXY-protocol and
        // forwarded-identity logic compares this against configured IPv4
        // networks too.
        pingora_core::protocols::l4::socket::SocketAddr::Inet(address) => {
            SocketAddr::new(canonical_client_ip(address.ip()), address.port())
        }
        pingora_core::protocols::l4::socket::SocketAddr::Unix(_) => return None,
    };
    let listener = match session.server_addr()? {
        pingora_core::protocols::l4::socket::SocketAddr::Inet(address) => *address,
        pingora_core::protocols::l4::socket::SocketAddr::Unix(_) => return None,
    };
    Some((peer, listener))
}

/// 🔐 Narrows a request's host to something safe to put in a `Location`.
///
/// Returns the authority to use — a DNS name as written, an IPv6 literal
/// re-bracketed — or `None` when the value is not a host at all.
///
/// 🚫 Nothing is escaped or percent-encoded on the way through. A `Host`
/// carrying a slash, an `@`, a space or a control character is refused
/// outright, because the alternative is a `Location` whose text means one thing
/// to a browser and another to whoever reads the log line afterwards. Refusing
/// produces no redirect, which is the safe direction: the request falls through
/// to the ordinary 404.
///
/// 📌 `request_host` has already removed the port and the IPv6 brackets by the
/// time this runs, so an IPv6 literal arrives here with its colons bare and has
/// to be put back in brackets to be a valid authority.
fn redirect_authority(host: &str) -> Option<String> {
    if let Ok(address) = host.parse::<std::net::Ipv6Addr>() {
        return Some(format!("[{address}]"));
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(host.to_string());
    }
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    // 🔤 One label rule, applied to every label: letters, digits, `-` and `_`,
    // never empty, never over the DNS length limit. A trailing dot is already
    // gone — `canonical_host` strips exactly one — and a second one would leave
    // an empty label here, which is what rejects `example.com..`.
    let well_formed = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    });
    well_formed.then(|| host.to_string())
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

/// 🌊 One locally generated body whose framing is owned by Pingclair.
enum LocalResponseBody {
    /// 📭 A header-only response ends with the header block.
    Empty,
    /// 📄 A bounded in-memory response is emitted in one write.
    Bytes(Bytes),
    /// 📂 A file response is emitted in fixed-size chunks.
    /// 📂 Boxed: `StreamingFile` carries a file handle and its response
    /// metadata, and the bytes variant should not pay for that in padding.
    File(Box<pingclair_static::StreamingFile>),
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
        // ⚡ Configuration decides whether these request variables can ever be
        // observed. Serialising once at load is deliberately conservative: a
        // literal mention may produce a false positive, while a false negative
        // would change routing or a rewritten response.
        let needs_original_uri_vars = serde_json::to_vec(&config).map_or(true, |encoded| {
            const PREFIX: &[u8] = b"{http.request.orig_uri.";
            encoded.windows(PREFIX.len()).any(|window| window == PREFIX)
        });
        let router = Router::new(config.routes.clone());
        let error_routes = crate::error_routes::prepare(&config);
        let vars_precompiles = config
            .vars_routes
            .iter()
            .map(|rule| rule.matcher.as_ref().map(CompiledMatcher::compile))
            .collect();
        let host_label = config.name.clone().unwrap_or_else(|| "_".to_string());

        // 🧩 Initializes index-aligned components for each route.
        let mut load_balancers = Vec::new();
        let mut dynamic_dials = Vec::new();
        let mut subrequests = Vec::new();
        let mut health_checkers = Vec::new();
        let mut file_servers = Vec::new();
        let mut rate_limiters = Vec::new();
        let mut route_protections = Vec::new();
        let mut hash_key_sources = Vec::new();
        let mut upstream_tls = Vec::new();
        let mut access_controls = Vec::new();
        let mut route_regexes = Vec::new();
        let mut route_body_ceilings = Vec::new();
        let mut route_body_timeouts = Vec::new();
        let mut route_buffering = Vec::new();

        for (route_index, route) in config.routes.iter().enumerate() {
            let mut route_subrequests = Vec::new();
            collect_subrequest_plans(&route.handler, &mut route_subrequests);
            subrequests.push(route_subrequests);
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
                let (primary, backup, dynamic_templates) = build_weighted_upstreams(proxy_config);

                if primary.is_empty()
                    && backup.is_empty()
                    && dynamic_templates.is_empty()
                    && proxy_config.dynamic_upstream.is_none()
                {
                    tracing::warn!("⚠️ No valid upstreams found for route {}", route.path);
                }
                let primary_is_empty = primary.is_empty();

                let strategy = match proxy_config.load_balance.strategy.as_str() {
                    // 🌐 Caddy's documented default, and what an unset policy
                    // compiles to: the adapter writes an empty string when no
                    // `lb_policy` was named, so this arm — not the serde default
                    // on `LoadBalanceConfig` — is the one a Pingclairfile
                    // actually reaches. Both spellings land here so the JSON and
                    // DSL paths cannot disagree.
                    "" | "random" => Strategy::Random,
                    "round_robin" => Strategy::RoundRobin,
                    "least_conn" => Strategy::LeastConn,
                    // 🔑 Every hashing policy uses the same consistent-hash
                    // ring; they differ only in what gets hashed, which the
                    // request path resolves through `hash_key_sources`.
                    "ip_hash" | "header" | "cookie" | "query" => Strategy::IpHash,
                    // 🥇 Caddy's `first`: the first available upstream answers,
                    // and the next one takes over only when it cannot. Used for
                    // a primary/secondary pair, where spreading traffic across
                    // both is the thing the operator asked to avoid.
                    "first" => Strategy::First,
                    // 🚫 Only a hand-written JSON config can reach this, since
                    // the adapter validates the name against the list above.
                    // It means "the schema accepted a policy nobody implements",
                    // and the honest answer to that is the documented default.
                    _ => Strategy::Random,
                };

                let load_balancer = Arc::new(
                    if let Some(dynamic_config) = proxy_config.dynamic_upstream.as_ref() {
                        match crate::dynamic_upstream::dynamic_source(dynamic_config) {
                            Ok(source) => {
                                LoadBalancer::from_dynamic(source, primary, backup, strategy)
                            }
                            Err(error) => {
                                tracing::error!(
                                    route = %route.path,
                                    %error,
                                    "🚫 Dynamic upstream source failed to build"
                                );
                                LoadBalancer::from_entries(vec![], vec![], strategy)
                            }
                        }
                    } else if primary_is_empty {
                        // A backup-only configuration is still useful for a
                        // deliberately standby-only route; there is no primary
                        // pool to wait on in that case.
                        LoadBalancer::from_entries(backup, vec![], strategy)
                    } else {
                        LoadBalancer::from_entries(primary, backup, strategy)
                    },
                );
                // 🧭 Replaceable dial templates are expanded per request; the
                // plan itself is precomputed here so the request path only
                // substitutes values into strings it already owns.
                dynamic_dials.push(if dynamic_templates.is_empty() {
                    None
                } else {
                    Some(Arc::new(DynamicDialPlan::new(dynamic_templates)))
                });
                // 🧱 A ceiling this server will not honour verbatim is said out
                // loud at load, naming the number it will use instead. The
                // format's own implementation warns here too — that unlimited
                // buffering can crash the process out of memory — and the only
                // thing worse than that warning is our version of it being
                // silent about the cap that replaces it.
                for (name, configured) in [
                    ("request_buffers", proxy_config.request_buffer_bytes),
                    ("response_buffers", proxy_config.response_buffer_bytes),
                ] {
                    if let Some(explanation) = crate::body_buffer::describe_clamp(configured) {
                        tracing::warn!(
                            route = %route.path,
                            directive = name,
                            "🧱 {explanation}"
                        );
                    }
                }

                // ⚠️ Accepted, but only partly honoured, so it is said at load.
                let non_idempotent = crate::retry::non_idempotent_methods(&proxy_config.retry);
                if !non_idempotent.is_empty() {
                    tracing::warn!(
                        route = %route.path,
                        methods = ?non_idempotent,
                        "⚠️ lb_retry_match names non-idempotent methods; they are retried \
                         only when connecting fails, never once the upstream has seen the request"
                    );
                }

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
                        match PingclairProxy::build_http_peer(
                            &upstream,
                            Some(proxy_config),
                            Some(timeout),
                            Some(timeout),
                            tls_policy,
                        ) {
                            Ok(peer_template) => {
                                // 🏷️ The probe's Host is the authority it
                                // dialled, port included when it is not the
                                // scheme's default; the operator's explicit
                                // `health_host` still wins.
                                let host = hc_config.host.clone().unwrap_or_else(|| match upstream
                                    .ext
                                    .get::<HostName>()
                                {
                                    Some(name) => crate::upstream::authority(
                                        &name.0,
                                        &upstream.addr,
                                        upstream.ext.get::<Scheme>().copied(),
                                    ),
                                    None => upstream.addr.to_string(),
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
                                load_balancer.set_health_check_frequency(Duration::from_secs(
                                    hc_config.interval,
                                ));
                                crate::health_check::register(&load_balancer);
                            }
                            Err(error) => tracing::error!(
                                route = %route.path,
                                %error,
                                "🚫 Active health checking did not start because no valid probe peer exists"
                            ),
                        }
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
                // 🔑 Resolve the hash-key source once, here, so the request
                // path never re-reads the strategy string. A named field with
                // no strategy that hashes it is dropped rather than kept: the
                // adapter only sets one alongside the other, so reaching this
                // with a mismatch means the two drifted apart.
                hash_key_sources.push(proxy_config.load_balance.hash_key.as_ref().and_then(
                    |field| match proxy_config.load_balance.strategy.as_str() {
                        "header" => Some(HashKeySource::Header(field.clone())),
                        "cookie" => Some(HashKeySource::Cookie(field.clone())),
                        "query" => Some(HashKeySource::Query(field.clone())),
                        _ => None,
                    },
                ));
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
                dynamic_dials.push(None);
                route_protections.push(None);
                hash_key_sources.push(None);
                upstream_tls.push(RouteUpstreamTls::Default);
            }

            // Health checker is stored inside the LB object; this slot is a
            // tombstone kept only for index alignment with load_balancers.
            health_checkers.push(None);

            // File server (possibly nested inside a handle/route block)
            let file_server = build_file_server(&route.handler, &config);
            if file_server.is_some() {
                tracing::info!("📁 Initialized file server for route {}", route.path);
            }
            file_servers.push(file_server);

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

            let mut compiled = HashMap::new();
            collect_route_regexes(&route.handler, &mut compiled);
            route_regexes.push(compiled);
            route_body_ceilings.push(collect_request_body_ceiling(&route.handler));
            route_body_timeouts.push(collect_request_body_timeouts(&route.handler));
            // 🧱 Found by the same recursive walk as every other proxy slot,
            // so a `reverse_proxy` nested inside `handle { … }` buffers too.
            route_buffering.push(
                find_reverse_proxy_config(&route.handler)
                    .map(|proxy| RouteBuffering {
                        request: crate::body_buffer::resolve_limit(proxy.request_buffer_bytes),
                        response: crate::body_buffer::resolve_limit(proxy.response_buffer_bytes),
                    })
                    .unwrap_or_default(),
            );
        }

        // A misconfigured log sink must not take the whole server down at
        // boot: fall back to tracing and say so loudly.
        // 🪵 Resolve channel references to shared loggers. A name that does
        // not resolve was already rejected by `validate_config`, so a failure
        // here is an I/O problem — reported and skipped rather than fatal,
        // since losing one log destination must not stop the server starting.
        // 🔌 A site reaches a global channel two ways: by naming it, or by the
        // channel subscribing to the site's log source with
        // `include http.log.access.<name>`. Only the first used to resolve, so
        // the second passed validation and then received nothing.
        let mut log_channels: Vec<Arc<pingclair_runtime::access_log::AccessLogger>> = Vec::new();
        for name in &config.log_channels {
            if let Some(logger) = pingclair_runtime::access_log::channel_logger(name) {
                log_channels.push(logger);
            }
            for subscriber in pingclair_runtime::access_log::channels_admitting(&format!(
                "http.log.access.{name}"
            )) {
                // 🚫 A channel named directly and subscribing by namespace is
                // still one destination; two entries would double every line.
                if !log_channels
                    .iter()
                    .any(|existing| Arc::ptr_eq(existing, &subscriber))
                {
                    log_channels.push(subscriber);
                }
            }
        }
        let mut named_loggers = Vec::new();
        // 🏠 A named logger's `hostnames` decides which requests reach it. The
        // list travels with the logger so `LogTargets` can resolve it once,
        // here, instead of the request path re-reading configuration.
        let mut named_targets: Vec<(
            Vec<String>,
            Arc<pingclair_runtime::access_log::AccessLogger>,
        )> = Vec::new();
        for named in &config.named_logs {
            match pingclair_runtime::access_log::AccessLogger::from_config(Some(&named.config)) {
                Ok(Some(logger)) => {
                    let logger = Arc::new(logger);
                    named_targets.push((named.config.hostnames.clone(), logger.clone()));
                    named_loggers.push((named.name.clone(), logger));
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        logger = %named.name,
                        "❌ Could not open named access logger"
                    );
                }
            }
        }

        let access_logger =
            match pingclair_runtime::access_log::AccessLogger::from_config(config.log.as_ref()) {
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

        // 🪵 The server's own `log` block and any global channels are not
        // host-restricted; only named loggers carry `hostnames`.
        let mut target_entries: Vec<(
            Vec<String>,
            Arc<pingclair_runtime::access_log::AccessLogger>,
        )> = Vec::new();
        if let Some(logger) = &access_logger {
            target_entries.push((Vec::new(), logger.clone()));
        }
        for channel in &log_channels {
            target_entries.push((Vec::new(), channel.clone()));
        }
        target_entries.extend(named_targets);
        let log_targets = pingclair_runtime::access_log::LogTargets::new(target_entries);
        let strict_transport = crate::http_policy::StrictTransport::from_security(&config.security);
        let cache_scopes = Arc::new(crate::cache_key::route_scopes(&config, |route| {
            find_reverse_proxy_config(&route.handler).is_some_and(|proxy| proxy.cache.is_some())
        }));

        let route_streaming = config
            .routes
            .iter()
            .map(|route| {
                find_reverse_proxy_config(&route.handler)
                    .is_some_and(|proxy| wants_immediate_flush(proxy.flush_interval))
            })
            .collect();

        Self {
            encode_policy: pingclair_core::encoding::EncodePolicy::compile(
                &config.encode,
                &config.gzip_types,
            ),
            config: Arc::new(config),
            router: Arc::new(router),
            error_routes,
            vars_precompiles,
            load_balancers,
            dynamic_dials,
            subrequests,
            health_checkers,
            file_servers,
            response_file_servers: Arc::new(
                std::sync::Mutex::new(std::collections::HashMap::new()),
            ),
            rate_limiters,
            route_protections,
            hash_key_sources,
            upstream_tls,
            access_controls,
            route_regexes,
            route_body_ceilings,
            route_body_timeouts,
            route_buffering,
            cache_scopes,
            route_streaming,
            needs_original_uri_vars,
            log_targets,
            strict_transport,
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

    /// 🔁 Finds the pre-parsed dial plan for one inline proxy handler.
    pub(crate) fn prepared_reverse_proxy_subrequest(
        &self,
        route_index: usize,
        config: &ReverseProxyConfig,
    ) -> Option<Arc<crate::subrequest::PreparedSubrequest>> {
        self.subrequests
            .get(route_index)?
            .iter()
            .find(|prepared| prepared.matches_reverse_proxy(config))
            .cloned()
    }

    /// 🔐 Finds the pre-parsed plan for a legacy JSON forward-auth handler.
    pub(crate) fn prepared_forward_auth_subrequest(
        &self,
        route_index: usize,
        config: &pingclair_core::config::ForwardAuthConfig,
    ) -> Option<Arc<crate::subrequest::PreparedSubrequest>> {
        self.subrequests
            .get(route_index)?
            .iter()
            .find(|prepared| prepared.matches_forward_auth(config))
            .cloned()
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

    /// 📥 The most permissive body limit this route's `request_body` handlers
    /// could grant, or `None` when it has none.
    ///
    /// Needed because the `Content-Length` rejection happens before handlers
    /// run, so it cannot know which of a route's matcher-guarded
    /// `request_body` blocks will apply. Taking the maximum is the fail-safe
    /// direction: a request that would have been allowed is never refused
    /// early, and one that should be refused still is — by the streaming
    /// check, which runs with the real limit.
    pub(crate) fn route_body_ceiling(&self, route_index: usize) -> Option<u64> {
        self.route_body_ceilings.get(route_index).copied().flatten()
    }

    /// ⏱️ This route's declared `request_body` deadlines, for the seed applied
    /// before the first byte is read.
    pub(crate) fn route_body_timeouts(&self, route_index: usize) -> RouteBodyTimeouts {
        self.route_body_timeouts
            .get(route_index)
            .copied()
            .unwrap_or_default()
    }

    /// ⚡ One of this route's patterns, compiled when the configuration was
    /// published rather than when the request arrived.
    ///
    /// Every regular expression a route can need is built once, at load, and
    /// looked up here by the pattern text that named it. A request path is not
    /// a place to compile a regex: the answer can never differ from the one
    /// configuration already decided.
    ///
    /// A response header replacement is queued during handler dispatch and run
    /// when the response is written, which is later and elsewhere — so the
    /// policy has to own its patterns rather than borrow them from a snapshot
    /// it does not hold.
    pub(crate) fn route_regex_arc(&self, route_index: usize, pattern: &str) -> Option<Arc<Regex>> {
        self.route_regexes
            .get(route_index)
            .and_then(|regexes| regexes.get(pattern).cloned())
    }

    /// 🧭 Applies one precompiled route rewrite without transport-specific state.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn rewrite_request_uri(
        &self,
        route_index: usize,
        error_route: Option<usize>,
        current: &str,
        strip_prefix: Option<&str>,
        strip_suffix: Option<&str>,
        replace: Option<&str>,
        regex_pattern: Option<&str>,
        regex_replace: Option<&str>,
    ) -> Result<String, &'static str> {
        // 🚨 While an error route runs, only that route's own table answers:
        // the pattern belongs to the route body being run, and the table of
        // the route that raised the error is a different configuration (#245).
        let compiled = if let Some(pattern) = regex_pattern {
            Some(match error_route {
                Some(index) => self
                    .error_routes
                    .get(index)
                    .and_then(|route| route.regexes.get(pattern).cloned())
                    .ok_or("invalid rewrite regex in active configuration")?,
                None => self
                    .route_regex_arc(route_index, pattern)
                    .ok_or("invalid rewrite regex in active configuration")?,
            })
        } else {
            None
        };
        Ok(rewrite_uri(
            current,
            strip_prefix,
            strip_suffix,
            replace,
            compiled.as_deref(),
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
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}

/// 💬 The body this hop writes for a status it generated itself.
///
/// One shape for all three transports: the status, its reason phrase, and the
/// detail when this hop has one to add — for a `431`, the field that was too
/// large (RFC 6585 §5). Caddy's built-in bodies are empty; these are
/// deliberately informative, because the alternative was a client that could
/// not tell why it was refused, and the transports agreeing with each other
/// matters more than agreeing with an empty body (#252, #253).
pub(crate) fn builtin_error_body(status: u16, detail: Option<&str>) -> String {
    let reason = error_reason(status);
    match detail {
        Some(detail) if !detail.is_empty() => format!("{status} {reason}: {detail}"),
        _ => format!("{status} {reason}"),
    }
}

// MARK: - Server Implementation

/// 🔄 Where the automatic HTTP→HTTPS redirect sends a request whose `Host`
/// matches no configured site.
///
/// 🔐 Both ports come from the configuration, never from the request, and that
/// is the point of the type. The redirect echoes the caller's `Host` back, and
/// a redirect whose authority a caller can choose is an open redirect. Fixing
/// the port here means the most a forged `Host` can achieve is naming a host
/// the client already asked for, on *this* server's HTTPS port.
#[derive(Debug, Clone, Copy)]
pub struct AutomaticHttpsRedirect {
    /// 🚪 The plaintext port a redirect is offered on.
    ///
    /// A request that arrived anywhere else is on a listener with a different
    /// purpose, and redirecting there would turn every plaintext listener into
    /// one.
    pub http_port: u16,
    /// 🔐 The port the redirect names, which is this server's own.
    pub https_port: u16,
}

/// Pingclair reverse proxy
///
/// 🗺️ The virtual hosts live in the listener policy's generation rather than
/// here, published through `ArcSwap` together with the client-auth policy.
/// Reads are lock-free and wait-free, so concurrent requests never contend
/// with each other or with a config reload, and one load gives a request a
/// consistent view of both.
#[derive(Clone)]
pub struct PingclairProxy {
    /// 🔄 The automatic HTTP→HTTPS redirect, when this process took the plaintext
    /// companion port.
    ///
    /// The redirect itself is an ordinary site — `automatic_http_companion` in
    /// the `pingclair` crate builds one with a `308` route and the site's own
    /// names — so a request whose `Host` matches gets the redirect through the
    /// normal routing path. This field exists for the requests that match
    /// nothing: they reach the unknown-host branch, which has no site to read
    /// the listener's purpose from.
    ///
    /// 📌 Only the ports are stored, not a target template. The `Location` is
    /// rebuilt per request from the validated `Host` and this server's own
    /// HTTPS port, so there is no client-supplied string sitting in a stored
    /// value waiting to be reflected.
    pub automatic_https: Arc<ArcSwap<Option<AutomaticHttpsRedirect>>>,
    /// TLS Manager for certificate resolution
    pub tls_manager: Option<Arc<pingclair_tls::manager::TlsManager>>,
    /// Alt-Svc value advertised on this listener's responses when HTTP/3 is
    /// enabled (`None` = do not advertise, e.g. plain-HTTP listeners).
    /// Stored behind `ArcSwap` so it can be flipped without restarting the
    /// Pingora service.
    pub alt_svc: Arc<ArcSwap<Option<crate::alt_svc::Advertisement>>>,
    /// 🛡️ Immutable policy used by every protocol to resolve client identity.
    trusted_proxies: Arc<TrustedProxyPolicy>,
    /// 🧭 Trusted transport claims keyed by the private ingress tunnel sockets.
    proxy_protocol_registry: Arc<crate::proxy_protocol::ProxyProtocolRegistry>,
    /// 🚫 Rejects TCP requests that bypass the required external PROXY ingress.
    proxy_protocol_required: bool,
    /// 🔐 The versioned routes and handshake policy shared by H1, H2, and H3.
    ///
    /// A reload publishes routes and client-auth rotation as one generation,
    /// so a request never runs against a half-published security policy.
    listener_policy: Arc<crate::client_auth::PublishedListenerPolicy>,
    /// 🔌 Shared upstream connector for inline sub-requests (`forward_auth`),
    /// with the same keepalive pool the H3 path uses.
    pub connector: Arc<pingora_core::connectors::http::Connector>,
}

impl Default for PingclairProxy {
    fn default() -> Self {
        Self {
            // 🔄 Off until the runtime that bound the plaintext companion port
            // says otherwise. A proxy built by a test, or one whose
            // configuration has no automatic HTTPS, must not redirect anything.
            automatic_https: Arc::new(ArcSwap::from_pointee(None)),
            tls_manager: None,
            alt_svc: Arc::new(ArcSwap::from_pointee(None)),
            trusted_proxies: Arc::new(TrustedProxyPolicy::from_rules(&[])),
            proxy_protocol_registry: Arc::new(
                crate::proxy_protocol::ProxyProtocolRegistry::default(),
            ),
            proxy_protocol_required: false,
            listener_policy: Arc::new(crate::client_auth::PublishedListenerPolicy::new(Arc::new(
                crate::client_auth::ClientAuthTable::default(),
            ))),
            connector: Arc::new(pingora_core::connectors::http::Connector::new(Some(
                pingora_core::connectors::ConnectorOptions::new(512),
            ))),
        }
    }
}

impl ProxyState {
    /// 📂 The file server a `handle_response { file_server }` asked for, built
    /// once and shared.
    ///
    /// `root` is passed in already resolved, because the configured `"."` means
    /// "read `{http.vars.root}` at request time" and only the caller knows what
    /// that came out as.
    ///
    /// 🚫 A resolved root that did not come from the configuration is built
    /// fresh and not remembered. `{http.vars.root}` can be assembled from the
    /// request, and a map keyed on something a client can vary is a way to grow
    /// this process without bound — the same shape as the metrics label this
    /// repository already had to cap.
    pub(crate) fn response_file_server(
        &self,
        wanted: &crate::http_policy::ResponseFileServer,
        root: &str,
    ) -> Arc<pingclair_static::FileServer> {
        let build = || {
            Arc::new(pingclair_static::FileServer::new(
                pingclair_static::FileServerConfig {
                    root: std::path::PathBuf::from(root),
                    index: wanted.index.clone(),
                    browse: wanted.browse,
                    browse_limit: wanted.browse_limit,
                    compress: wanted.compress,
                    encode: self.config.encode.clone(),
                    encodings: self.config.encodings.clone(),
                    gzip_types: self.config.gzip_types.clone(),
                    // 📄 A response subroute supports only a bare `file_server`,
                    // so everything else keeps its default — sidecar lookup
                    // included, which stays off.
                    ..pingclair_static::FileServerConfig::default()
                },
            ))
        };
        if wanted.root == "." {
            return build();
        }
        let mut cache = match self.response_file_servers.lock() {
            Ok(cache) => cache,
            // 🧯 A poisoned lock means another thread panicked holding it. The
            // cache is only an optimisation, so answer without it rather than
            // turning someone else's panic into this request's.
            Err(_) => return build(),
        };
        if let Some(existing) = cache.get(wanted) {
            return Arc::clone(existing);
        }
        let built = build();
        cache.insert(wanted.clone(), Arc::clone(&built));
        built
    }
}

impl PingclairProxy {
    /// Create a new proxy
    pub fn new() -> Self {
        Self::default()
    }

    /// 🔐 Creates a proxy around an already published listener policy.
    pub fn with_published_listener_policy(
        listener_policy: Arc<crate::client_auth::PublishedListenerPolicy>,
    ) -> Self {
        Self {
            listener_policy,
            ..Self::default()
        }
    }

    /// Create a new proxy with TLS manager
    pub fn with_tls(tls_manager: Arc<pingclair_tls::manager::TlsManager>) -> Self {
        Self {
            // 🔄 Off until the runtime that bound the plaintext companion port
            // says otherwise. A proxy built by a test, or one whose
            // configuration has no automatic HTTPS, must not redirect anything.
            automatic_https: Arc::new(ArcSwap::from_pointee(None)),
            tls_manager: Some(tls_manager),
            alt_svc: Arc::new(ArcSwap::from_pointee(None)),
            trusted_proxies: Arc::new(TrustedProxyPolicy::from_rules(&[])),
            proxy_protocol_registry: Arc::new(
                crate::proxy_protocol::ProxyProtocolRegistry::default(),
            ),
            proxy_protocol_required: false,
            listener_policy: Arc::new(crate::client_auth::PublishedListenerPolicy::new(Arc::new(
                crate::client_auth::ClientAuthTable::default(),
            ))),
            connector: Arc::new(pingora_core::connectors::http::Connector::new(Some(
                pingora_core::connectors::ConnectorOptions::new(512),
            ))),
        }
    }

    /// 🛡️ Creates a TLS proxy with a pre-parsed trusted-proxy policy.
    pub fn with_tls_and_trusted_proxies(
        tls_manager: Arc<pingclair_tls::manager::TlsManager>,
        trusted_proxies: &[String],
        proxy_protocol_required: bool,
    ) -> Self {
        Self::with_listener_policy(
            tls_manager,
            trusted_proxies,
            proxy_protocol_required,
            Arc::new(crate::client_auth::PublishedListenerPolicy::new(Arc::new(
                crate::client_auth::ClientAuthTable::default(),
            ))),
        )
    }

    /// 🔐 Creates a proxy bound to one prepared listener-security policy.
    pub fn with_listener_policy(
        tls_manager: Arc<pingclair_tls::manager::TlsManager>,
        trusted_proxies: &[String],
        proxy_protocol_required: bool,
        listener_policy: Arc<crate::client_auth::PublishedListenerPolicy>,
    ) -> Self {
        Self {
            // 🔄 Off until the runtime that bound the plaintext companion port
            // says otherwise. A proxy built by a test, or one whose
            // configuration has no automatic HTTPS, must not redirect anything.
            automatic_https: Arc::new(ArcSwap::from_pointee(None)),
            tls_manager: Some(tls_manager),
            alt_svc: Arc::new(ArcSwap::from_pointee(None)),
            trusted_proxies: Arc::new(TrustedProxyPolicy::from_rules(trusted_proxies)),
            proxy_protocol_registry: Arc::new(
                crate::proxy_protocol::ProxyProtocolRegistry::default(),
            ),
            proxy_protocol_required,
            listener_policy,
            connector: Arc::new(pingora_core::connectors::http::Connector::new(Some(
                pingora_core::connectors::ConnectorOptions::new(512),
            ))),
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

    /// 🛡️ Reads the client address only from `names`, in order, when the peer
    /// is trusted (`client_ip_headers`). An empty list keeps the built-in set.
    pub fn reading_client_ip_from(mut self, names: &[String]) -> Self {
        self.trusted_proxies = Arc::new(
            TrustedProxyPolicy::clone(&self.trusted_proxies).reading_client_ip_from(names),
        );
        self
    }

    /// 🛡️ Resolves the verified client address shared by all request policies.
    pub(crate) fn verified_client_ip(&self, peer: IpAddr, headers: &http::HeaderMap) -> IpAddr {
        self.trusted_proxies.verified_client_ip(peer, headers)
    }

    fn downstream_identity(
        &self,
        session: &Session,
        headers: &http::HeaderMap,
    ) -> (IpAddr, SocketAddr, IpAddr) {
        if let Some(identity) = self.proxy_protocol_identity(session) {
            let client = self.trusted_proxies.verified_client_ip_with_fallback(
                identity.transport_peer.ip(),
                identity.client.ip(),
                headers,
            );
            return (identity.transport_peer.ip(), identity.client, client);
        }
        // 🔌 Port 0 stands for "no port" on a Unix-socket peer, which
        // `{remote_port}` renders as empty.
        let peer = session_inet_addresses(session).map_or_else(
            || SocketAddr::new(session_peer_ip(session), 0),
            |(peer, _)| peer,
        );
        (
            peer.ip(),
            peer,
            self.trusted_proxies.verified_client_ip(peer.ip(), headers),
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
    /// `init_downstream_modules`). 🚫 `excluded` names the sites that turned
    /// HTTP/3 off; their responses carry no advertisement.
    pub fn set_alt_svc<I, S>(&self, port: u16, excluded: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.alt_svc
            .store(Arc::new(Some(crate::alt_svc::Advertisement::new(
                port, excluded,
            ))));
    }

    /// 🚫 Stops advertising HTTP/3 on this listener.
    ///
    /// Called when the QUIC server for the port stops, for any reason. Every
    /// response still carrying `Alt-Svc` after that would send clients to a
    /// port nothing answers, and they would cache the claim for a day.
    pub fn clear_alt_svc(&self) {
        self.alt_svc.store(Arc::new(None));
    }

    /// 🔐 Returns the listener policy used by both TLS transports and routing.
    pub fn listener_policy(&self) -> Arc<crate::client_auth::PublishedListenerPolicy> {
        Arc::clone(&self.listener_policy)
    }

    /// ⚡ Borrows the listener policy on request paths that need no ownership.
    pub(crate) fn listener_policy_ref(&self) -> &crate::client_auth::PublishedListenerPolicy {
        &self.listener_policy
    }

    /// 🪪 Reports whether this listener enforces SNI against the routed host.
    ///
    /// Read by the HTTP/3 path, which has no Pingora `Session` to hang the
    /// handshake name off and so has to decide per connection whether to
    /// record one at all.
    pub(crate) fn requires_strict_sni_host(&self) -> bool {
        self.listener_policy.requires_client_auth()
    }

    /// 🚫 Reports whether this request may name the host it named.
    ///
    /// Returns `None` when there is nothing to check, which is the answer on
    /// every listener that never asked for a client certificate — one relaxed
    /// load and no work. A TLS connection that reached here without a recorded
    /// handshake name fails closed: the acceptor records one on exactly the
    /// listeners this check runs on, so its absence is a bug, not a client
    /// that happens to be fine.
    ///
    /// 📦 The revision compared is the one in the request's own generation,
    /// the same one its routes come from.
    fn strict_sni_host_rejection(
        generation: &crate::listener_generation::ListenerGeneration,
        session: &Session,
        hostname: &str,
    ) -> Option<&'static str> {
        if !generation.requires_client_auth() {
            return None;
        }
        let revision = generation.security().revision();
        let Some(ssl) = session
            .digest()
            .and_then(|digest| digest.ssl_digest.as_ref())
        else {
            // 🔓 A plaintext hop on a mutual-TLS listener: the PROXY-protocol
            // ingress terminates TLS elsewhere, and there is no handshake here
            // to compare against. Nothing to enforce, nothing to claim.
            return None;
        };
        match ssl
            .extension
            .get::<crate::tls_identity::DownstreamTlsIdentity>()
        {
            Some(identity)
                if identity.security_revision == revision
                    && identity.may_request_host(hostname) =>
            {
                None
            }
            Some(identity) if identity.security_revision != revision => {
                Some("TLS client-auth policy changed; reconnect")
            }
            Some(_) => Some("TLS server name and Host header name differ"),
            None => Some("TLS handshake recorded no server name"),
        }
    }

    /// Add a server configuration to this proxy
    ///
    /// 📌 Startup only, off the request path: each call copies the route
    /// table, which is the price of lock-free reads for every request.
    pub fn add_server(&self, config: ServerConfig) {
        self.listener_policy.replace_routes(|current| {
            let mut next = RouteTable {
                hosts: current.hosts.clone(),
                default: current.default.clone(),
                access_logging: current.access_logging,
            };
            Self::register_site(&mut next, current, config.clone());
            next.refresh_access_logging();
            next
        });
    }

    /// 🏠 Adds one site under each of its names, reusing state the previous
    /// generation built for the same name.
    ///
    /// A site may carry several hostnames (`example.com, www.example.com`);
    /// each one is a virtual host for the same configuration. The legacy
    /// single-name field is the fallback so JSON documents written before
    /// `names` existed still register exactly as before.
    fn register_site(next: &mut RouteTable, previous: &RouteTable, config: ServerConfig) {
        let domains: Vec<&str> = if config.names.is_empty() {
            config.name.iter().map(String::as_str).collect()
        } else {
            config.names.iter().map(String::as_str).collect()
        };
        if domains.is_empty() {
            next.default = Some(Arc::new(ProxyState::new_with_previous(
                config.clone(),
                previous.default.as_deref(),
            )));
            return;
        }
        for domain in domains {
            if domain == "_" || domain == "*" || domain.starts_with(':') {
                next.default = Some(Arc::new(ProxyState::new_with_previous(
                    config.clone(),
                    previous.default.as_deref(),
                )));
            } else {
                // 🔤 Canonical at publication, so a lookup never has to guess
                // which spelling the operator used. `RouteTable::get` applies
                // the same canonicalisation to the requested name.
                //
                // 🌐 The request side drops an IPv6 literal's brackets
                // (`Host: [::1]:8080` is looked up as `::1`), so the site name
                // `[::1]` must drop them too; kept, it was a key no request
                // could ever produce.
                let domain = crate::http_policy::request_host(domain).into_owned();
                let state = Arc::new(ProxyState::new_with_previous(
                    config.clone(),
                    previous.hosts.get(&domain).map(Arc::as_ref),
                ));
                next.hosts.insert(domain, state);
            }
        }
    }

    /// 🧱 Returns the strictest pre-routing limits shared by a listener's virtual hosts.
    pub fn listener_limits(&self) -> ResourceLimitsConfig {
        let generation = self.listener_policy.generation();
        merged_listener_limits(
            generation
                .routes()
                .states()
                .map(|state| &state.config.limits),
        )
    }

    /// 🏗️ Derives listener limits before a proxy publishes its prepared routes.
    pub fn listener_limits_for_servers(servers: &[ServerConfig]) -> ResourceLimitsConfig {
        merged_listener_limits(servers.iter().map(|server| &server.limits))
    }

    /// 🏗️ Builds the next route table without publishing it.
    ///
    /// This is the expensive half of a reload — every site compiles its
    /// router and handler state — and it runs before anything is swapped, so
    /// traffic keeps using the current generation the whole time.
    pub fn prepare_routes(&self, servers: Vec<ServerConfig>) -> RouteTable {
        let generation = self.listener_policy.generation();
        let previous = generation.routes();
        let mut next = RouteTable::default();
        for config in servers {
            Self::register_site(&mut next, previous, config);
        }
        next.refresh_access_logging();
        next
    }

    /// Replace all server configurations with a new list
    ///
    /// 📌 Keeps the client-auth generation. A reload that also rotates trust
    /// goes through [`PublishedListenerPolicy::publish`] with
    /// [`Self::prepare_routes`] instead, so both change in one swap.
    ///
    /// [`PublishedListenerPolicy::publish`]: crate::client_auth::PublishedListenerPolicy::publish
    pub fn update_config(&self, servers: Vec<ServerConfig>) {
        let next = self.prepare_routes(servers);
        let next = Arc::new(next);
        self.listener_policy.replace_routes(|_| RouteTable {
            hosts: next.hosts.clone(),
            default: next.default.clone(),
            access_logging: next.access_logging,
        });
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
        addresses: RequestAddresses,
        vars: Option<&mut std::collections::BTreeMap<String, String>>,
    ) -> Option<(Arc<ProxyState>, Option<usize>, Option<HandlerConfig>)> {
        self.match_route_index(host, path, method, headers, addresses, vars)
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
        addresses: RequestAddresses,
        vars: Option<&mut std::collections::BTreeMap<String, String>>,
    ) -> Option<(Arc<ProxyState>, Option<usize>)> {
        // 🏠 Resolves the immutable state published for this virtual host.
        let state = self.get_state(host)?;

        // 🔐 Matches the HTTPS transport used by the in-process H3 adapter.
        let protocol = "https";

        let route_index = state
            .router
            .match_normalized_request(
                path,
                method,
                &headers.headers,
                host,
                addresses,
                protocol,
                vars,
            )
            .map(|route| route.index);
        Some((state, route_index))
    }

    /// 🔄 The `Location` for a request whose `Host` matches no site, when it
    /// arrived on the plaintext port an automatic HTTPS redirect owns.
    ///
    /// 🔐 Every part of the URL is decided here except the host, and the host is
    /// the one thing the caller chose — so it is validated before being echoed.
    /// The port is this server's own, never one the request carried, which is
    /// what keeps a forged `Host` from turning this into an open redirect.
    ///
    /// 🚫 `None` for a request that did not arrive over plaintext on the
    /// configured HTTP port. A process with no automatic HTTPS, a proxied
    /// listener, a TLS listener — none of them has a redirect to offer, and
    /// inventing one would send a working client somewhere it cannot be served.
    fn automatic_https_redirect(&self, session: &Session, orig_uri: &http::Uri) -> Option<String> {
        let configured = self.automatic_https.load();
        // 🧯 Deref through the `ArcSwap` guard and the `Arc` in one step: the
        // guard borrows the published snapshot and must be dropped before this
        // returns, so the value is copied out rather than borrowed.
        let configured = (**configured).as_ref().copied()?;

        // 🔐 A completed handshake means the request is already secure.
        // Redirecting it would be a loop, and this code also runs on the TLS
        // listener, so the loop is the failure to guard against.
        if session
            .digest()
            .is_some_and(|digest| digest.ssl_digest.is_some())
        {
            return None;
        }

        let (_, listener) = session_inet_addresses(session)?;
        if listener.port() != configured.http_port {
            return None;
        }

        // 🔤 Routing normalizes names, but a redirect preserves the Host spelling.
        let authority = crate::http_policy::request_authority(session.req_header());
        let host = crate::http_policy::authority_host(authority);
        let host = host.strip_suffix('.').unwrap_or(host);

        // 🧭 The whole original target, query string included, so the redirect
        // lands on the page that was asked for rather than the site root.
        let uri = orig_uri
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str);
        // 🌐 The configured HTTPS port is an internal default, not a URL suffix.
        if host.parse::<std::net::Ipv6Addr>().is_ok() {
            Some(format!("https://[{host}]{uri}"))
        } else {
            let authority = redirect_authority(host)?;
            Some(format!("https://{authority}{uri}"))
        }
    }

    // MARK: - Internal Helpers

    /// Get the state for a specific host.
    ///
    /// Resolution order (matches Caddy semantics):
    /// 1. Exact hostname match (`api.example.com`)
    /// 2. Wildcard match (`*.example.com`) — checks all registered wildcard hosts
    /// 3. Default catch-all server
    pub(crate) fn get_state(&self, host: &str) -> Option<Arc<ProxyState>> {
        self.listener_policy.generation().routes().get(host)
    }

    /// 📦 Returns the generation this request reads, loading it on first use.
    ///
    /// Every later phase reuses the same one, which is what keeps a reload
    /// from showing a request routes from one configuration and client-auth
    /// policy from another.
    fn request_generation(
        &self,
        ctx: &mut RequestContext,
    ) -> Arc<crate::listener_generation::ListenerGeneration> {
        Arc::clone(
            ctx.generation
                .get_or_insert_with(|| self.listener_policy.generation()),
        )
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
        let state = ctx.state.as_ref()?;
        let fallback_ip = ctx.verified_client_ip.or_else(|| {
            Some(
                self.downstream_identity(session, &session.req_header().headers)
                    .2,
            )
        });
        Self::balancing_identity_for_request(
            state,
            ctx.route_index?,
            session.req_header(),
            fallback_ip,
        )
    }

    /// 🔑 Resolves a route's precompiled load-balancer key for any HTTP transport.
    pub(crate) fn balancing_identity_for_request(
        state: &ProxyState,
        route_index: usize,
        request: &RequestHeader,
        fallback_ip: Option<IpAddr>,
    ) -> Option<Vec<u8>> {
        // 🔑 A route may hash something other than the client address — a
        // session header, a cookie, a query parameter. The source was decided
        // at configuration time and precomputed into `ProxyState`, so this is a
        // lookup rather than a per-request parse of the strategy string.
        if let Some(source) = state
            .hash_key_sources
            .get(route_index)
            .and_then(|source| source.as_ref())
        {
            return extract_hash_key(request, source);
        }

        fallback_ip.map(|address| match address {
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
        self.mark_upstream(state, route_index, address, false);
    }

    /// 🩹 The same, for a failure *after* the connection was made. The last
    /// selectable backend is kept in rotation: a response-phase failure is
    /// ambiguous, and taking the only backend out turns a flaky origin into
    /// an outage until the window expires (#262).
    pub(crate) fn mark_upstream_response_failure(
        &self,
        state: &ProxyState,
        route_index: usize,
        address: &SocketAddr,
    ) {
        self.mark_upstream(state, route_index, address, true);
    }

    fn mark_upstream(
        &self,
        state: &ProxyState,
        route_index: usize,
        address: &SocketAddr,
        response_phase: bool,
    ) {
        if let Some(load_balancer) = state
            .load_balancers
            .get(route_index)
            .and_then(|load_balancer| load_balancer.as_ref())
        {
            // 🩹 The route's passive policy: Caddy's `max_fails` and
            // `fail_duration` when written down, this proxy's own default
            // (one failure, ten seconds) when not.
            let policy = self
                .get_proxy_config(state, route_index)
                .map(|config| crate::load_balancer::PassiveHealth {
                    max_fails: config.max_fails.unwrap_or(1),
                    // 🤔 `None` keeps the default cooldown; `Some(0)` is
                    // Caddy's "do not remember failures" — passive health off.
                    window: match config.fail_duration_ms {
                        None => Some(crate::FAIL_COOLDOWN),
                        Some(0) => None,
                        Some(millis) => Some(std::time::Duration::from_millis(millis)),
                    },
                })
                .unwrap_or_default();
            if response_phase {
                load_balancer.mark_response_failure(address, policy);
            } else {
                load_balancer.mark_failure(address, policy);
            }
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

    /// 🗄️ Returns the matched route's cache policy, if it configured one.
    ///
    /// 🍃 Borrowed: the policy lives in the published snapshot for as long as
    /// the request, and copying it here was the only reason this path touched
    /// the allocator at all.
    fn route_cache_config<'a>(&self, ctx: &'a RequestContext) -> Option<&'a CacheConfig> {
        let state = ctx.state.as_ref()?;
        let route_index = ctx.route_index?;
        let proxy = self.get_proxy_config(state, route_index)?;
        proxy.cache.as_deref()
    }

    /// 🔎 Reports whether a shared copy of this request's response is meaningful.
    ///
    /// `Authorization` and `Cookie` both mean "this answer is for this caller",
    /// and a cache keyed only on the URL cannot tell two callers apart. Storing
    /// such a response is how a proxy serves one person's account page to the
    /// next visitor. RFC 9111 §3.5 allows caching authorized responses under
    /// narrow conditions; none of them are implemented yet, so both are
    /// refused outright.
    fn request_may_be_served_from_cache(session: &Session) -> bool {
        let request = session.req_header();
        if !matches!(request.method, http::Method::GET | http::Method::HEAD) {
            return false;
        }
        if request.headers.contains_key("authorization") || request.headers.contains_key("cookie") {
            return false;
        }
        // 🔌 A protocol upgrade is a `GET`, so the method check above lets it
        // through. What follows is a live tunnel, not a document — there is
        // nothing to store and a replayed handshake is not a connection.
        //
        // A `101` is already absent from the status defaults, so nothing would
        // be stored anyway. This is stated rather than left implied: relying on
        // a table entry's absence means the protection disappears the day
        // somebody adds one, and nothing would say so.
        if is_websocket_upgrade(&request.headers) {
            return false;
        }
        // 🚫 A client asking to bypass the cache is asking the shared cache too.
        !request_cache_control_bypasses_cache(&request.headers)
    }

    /// 🔎 Borrows the matched route's reverse-proxy configuration.
    ///
    /// 🍃 Borrowed, not cloned: this runs several times per request, and the
    /// configuration is immutable for the lifetime of the published snapshot
    /// that owns it. Cloning here copied upstream vectors, header maps, and
    /// boxed retry/overload state on every request to answer questions that
    /// only ever read them.
    pub(crate) fn get_proxy_config<'a>(
        &self,
        state: &'a ProxyState,
        route_index: usize,
    ) -> Option<&'a ReverseProxyConfig> {
        let route = state.config.routes.get(route_index)?;
        // Recurse into handle/route blocks so a nested reverse_proxy's
        // headers/timeouts are picked up, matching how ProxyState::new sets
        // up its load balancer.
        find_reverse_proxy_config(&route.handler)
    }

    /// 🌐 Builds an [`HttpPeer`] with the selected upstream protocol and timeouts.
    ///
    /// 🤝 This shared builder keeps protocol, timeout, and SNI semantics identical
    /// between the Pingora and HTTP/3 paths.
    ///
    /// 🏗️ A Unix-socket backend needs the fallible `new_uds` peer constructor,
    /// so the builder reports failure instead of panicking on the request path.
    pub(crate) fn build_http_peer(
        upstream: &Upstream,
        config: Option<&ReverseProxyConfig>,
        request_budget: Option<Duration>,
        read_budget: Option<Duration>,
        tls_policy: Option<&Arc<crate::upstream_tls::UpstreamTls>>,
    ) -> pingora_core::Result<HttpPeer> {
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
        let (mut tls, mut max_http_version, mut min_http_version, mut protocol_group) = match scheme
        {
            Scheme::Http => (false, 1, 1, PROTOCOL_GROUP_HTTP),
            Scheme::Https => (true, 2, 1, PROTOCOL_GROUP_HTTPS),
            Scheme::H2c => (false, 2, 2, PROTOCOL_GROUP_H2C),
            Scheme::H2 => (true, 2, 2, PROTOCOL_GROUP_H2),
        };
        // 🔢 `transport http { versions … }` overrides what the scheme implied.
        //
        // The scheme is the ordinary way to say this and stays the default;
        // this exists because the format has a second spelling and an operator
        // who writes it means it. Applied before the protocol group is fixed,
        // so two upstreams that differ only in the versions they may speak do
        // not share a pooled connection — the group key is what keeps an HTTP/2
        // connection from being handed to a route that asked for HTTP/1.1.
        if let Some(versions) = config.and_then(|config| config.upstream_versions) {
            let (max, min) = versions.version_bounds();
            max_http_version = max;
            min_http_version = min;
            protocol_group = match (versions, tls) {
                (pingclair_core::config::UpstreamHttpVersions::H2, false) => PROTOCOL_GROUP_H2C,
                (pingclair_core::config::UpstreamHttpVersions::H2, true) => PROTOCOL_GROUP_H2,
                (_, true) => PROTOCOL_GROUP_HTTPS,
                (_, false) => PROTOCOL_GROUP_HTTP,
            };
        }

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

        let mut peer = match &addr {
            pingora_core::protocols::l4::socket::SocketAddr::Inet(_) => {
                HttpPeer::new(addr, tls, host)
            }
            #[cfg(unix)]
            pingora_core::protocols::l4::socket::SocketAddr::Unix(_) => {
                // 🏗️ The path stored in the backend was validated when the
                // backend was built; rebuilding the peer from the same path
                // can only fail on a platform that no longer accepts it.
                HttpPeer::new_uds(&host, tls, host.clone())?
            }
        };
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
        // ⏱️ Pingora 0.9.0 exposes one upstream read timer for both H1/H2 phases.
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

        Ok(peer)
    }

    /// 🧱 Applies one virtual host's request deadlines without buffering body data.
    fn initialize_request_limits(
        session: &mut Session,
        ctx: &mut RequestContext,
        state: &ProxyState,
        route_index: Option<usize>,
    ) {
        let limits = &state.config.limits;
        ctx.request_deadline = limits
            .request_timeout_ms
            .map(Duration::from_millis)
            .map(|duration| ctx.start_time + duration);
        ctx.upload_pacer = limits.upload_bytes_per_sec.map(BandwidthPacer::new);
        ctx.download_pacer = limits.download_bytes_per_sec.map(BandwidthPacer::new);

        // ⏱️ A route that declares `request_body { read_timeout … }` means it
        // for every request on that route, so it has to be in force here — the
        // locally answered body drain runs before dispatch, and a handler that
        // ran later could not bound a read that already happened. The seed is
        // the route's widest declaration; the handler overwrites it with the
        // exact value, and re-arms the socket, when it actually runs.
        let route_timeouts = route_index
            .map(|index| state.route_body_timeouts(index))
            .unwrap_or_default();
        ctx.request_body_read_timeout_ms = route_timeouts.read_ms;
        ctx.request_body_write_timeout_ms = route_timeouts.write_ms;

        // ⏱️ With nothing configured, a body that stops arriving still gets
        // let go of; see `body_timeout` for the value and the failure it ends.
        let read_timeout = Some(
            Self::configured_read_timeout(route_timeouts.read_ms, limits)
                .unwrap_or(crate::body_timeout::DEFAULT_BODY_TIMEOUT),
        );
        session.as_mut().set_read_timeout(read_timeout);
        session.as_mut().set_write_timeout(
            route_timeouts
                .write_ms
                .map(Duration::from_millis)
                .or_else(|| limits.idle_timeout_ms.map(Duration::from_millis)),
        );
        session.as_mut().set_total_drain_timeout(read_timeout);
        // 🔌 Preserve the parser's decision to close HTTP/1.0 or explicitly
        // closed requests. Site timeouts may bound reuse, but cannot enable it.
        if !session
            .as_downstream()
            .as_http1()
            .is_some_and(|h1| !h1.will_keepalive())
        {
            session.as_mut().set_keepalive(Some(
                limits
                    .idle_timeout_ms
                    .map_or(60, |idle_ms| idle_ms.div_ceil(1_000)),
            ));
        }
    }

    /// ⏱️ The pause between two downstream reads that the configuration asks
    /// for: the route's `request_body { read_timeout }`, else the shorter of
    /// the site's `body_timeout` and `idle_timeout`. `None` when none is set.
    fn configured_read_timeout(
        route_read_ms: Option<u64>,
        limits: &pingclair_core::config::ResourceLimitsConfig,
    ) -> Option<Duration> {
        route_read_ms.map(Duration::from_millis).or_else(|| {
            shortest_duration(
                limits.body_timeout_ms.map(Duration::from_millis),
                limits.idle_timeout_ms.map(Duration::from_millis),
            )
        })
    }

    /// 🌊 The pause between two downstream reads on a long connection: the
    /// `long_connections { idle_timeout }` when one is set (`off` meaning no
    /// limit), else only what the ordinary configuration asks for. The default
    /// body pause never applies, because a tunnel or stream may be quiet on
    /// purpose.
    fn long_connection_read_timeout(
        route_read_ms: Option<u64>,
        limits: &pingclair_core::config::ResourceLimitsConfig,
    ) -> Option<Duration> {
        match limits.long_connections.idle_timeout_ms {
            Some(idle_ms) => (idle_ms > 0).then(|| Duration::from_millis(idle_ms)),
            None => Self::configured_read_timeout(route_read_ms, limits),
        }
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
        let read_timeout = Self::long_connection_read_timeout(
            ctx.request_body_read_timeout_ms,
            &state.config.limits,
        );
        crate::body_timeout::H2BodyWatch::rearm(read_timeout);
        if let Some(idle_ms) = long.idle_timeout_ms {
            let timeout = (idle_ms > 0).then(|| Duration::from_millis(idle_ms));
            session.as_mut().set_read_timeout(timeout);
            session.as_mut().set_write_timeout(timeout);
            session.as_mut().set_total_drain_timeout(timeout);
            session
                .as_mut()
                .set_keepalive((idle_ms > 0).then(|| idle_ms.div_ceil(1_000)));
        } else {
            // 🌊 The default body pause is for an upload that stalls, not for a
            // tunnel or stream that is quiet on purpose: a WebSocket whose
            // client says nothing for a minute is healthy. Only what the
            // operator configured carries over to a long connection.
            session.as_mut().set_read_timeout(read_timeout);
            session.as_mut().set_total_drain_timeout(read_timeout);
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

    /// 🧭 Evaluates the route's `handle_response` entries (or `intercept`
    /// handlers registered for this request) against the upstream response
    /// header, before the client sees a single byte.
    ///
    /// The decision only reads status and headers. A replacement response is
    /// scheduled on the context and its static body is emitted exactly once
    /// by the body filter; a response-subroute `file_server` is scheduled as
    /// a streaming file instead. Either way the upstream body is then drained
    /// chunk by chunk and discarded, so a 20 MB upstream response costs one
    /// chunk of memory, not one whole body.
    async fn apply_response_interception(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        upstream_response: &mut ResponseHeader,
        explicit_handlers: Option<&[pingclair_core::config::ResponseHandlerConfig]>,
    ) -> pingora_core::Result<bool> {
        let (Some(state), Some(route_index)) = (ctx.state.as_ref(), ctx.route_index) else {
            return Ok(false);
        };
        let handlers = explicit_handlers.unwrap_or_else(|| {
            state
                .config
                .routes
                .get(route_index)
                .and_then(|route| find_reverse_proxy_config(&route.handler))
                .map(|config| config.handle_response.as_slice())
                .filter(|handlers| !handlers.is_empty())
                .unwrap_or(ctx.intercept_handlers.as_slice())
        });
        if handlers.is_empty() {
            return Ok(false);
        }

        let status = upstream_response.status.as_u16();
        // 🔢 Caddy publishes the proxy response status while response
        // subroutes run, so `{http.reverse_proxy.status_code}` placeholders
        // inside a rewrite or error-page path resolve to the value that
        // matched.
        ctx.request_vars
            .set("http.reverse_proxy.status_code", status.to_string());
        let Some(outcome) = crate::http_policy::evaluate_response_handlers(
            handlers,
            status,
            &upstream_response.headers,
            &mut ctx.request_vars,
        ) else {
            return Ok(false);
        };

        // 📂 A response subroute ending in `file_server` rewrites the request
        // and serves the file from the root the subroute declared. The body
        // streams from disk through the body filter, so even a large error
        // page stays bounded by one chunk.
        if let Some(file_server) = outcome.file_server {
            if let Some(template) = &outcome.request_rewrite {
                let verified_client_ip = ctx.verified_client_ip.map(|ip| ip.to_string());
                let resolved = resolve_caddy_placeholders(
                    template,
                    session.req_header(),
                    verified_client_ip.as_deref(),
                    ctx.request_scheme,
                    &ctx.request_vars,
                )
                .into_owned();
                self.apply_rewrite(
                    session,
                    ctx,
                    route_index,
                    RewriteRule {
                        strip_prefix: None,
                        strip_suffix: None,
                        replace: Some(&resolved),
                        regex: None,
                        regex_replace: None,
                    },
                )?;
            }
            let root = if file_server.root != "." {
                file_server.root.clone()
            } else {
                ctx.request_vars.get("root").unwrap_or(".").to_string()
            };
            let Some(state) = ctx.state.as_ref() else {
                return Ok(false);
            };
            let server = state.response_file_server(&file_server, &root);
            let request_path = session.req_header().uri.path();
            if let Ok(Some(stream)) = server.serve_streaming(request_path).await {
                let existing: Vec<String> = upstream_response
                    .headers
                    .keys()
                    .map(|name| name.as_str().to_string())
                    .collect();
                for name in existing {
                    upstream_response.remove_header(name.as_str());
                }
                upstream_response.set_status(http::StatusCode::OK)?;
                upstream_response.insert_header("Content-Type", stream.content_type.clone())?;
                upstream_response.insert_header("Content-Length", stream.content_length.clone())?;
                if let Some(last_modified) = &stream.last_modified {
                    upstream_response.insert_header("Last-Modified", last_modified.clone())?;
                }
                if let Some(etag) = &stream.etag {
                    upstream_response.insert_header("ETag", etag.clone())?;
                }
                if stream.vary_accept_encoding {
                    upstream_response.insert_header("Vary", "Accept-Encoding")?;
                }
                let verified_client_ip = ctx.verified_client_ip.map(|ip| ip.to_string());
                for name in outcome.header_remove {
                    upstream_response.remove_header(name.as_str());
                }
                for (name, template) in &outcome.header_set {
                    let resolved = resolve_caddy_placeholders(
                        template,
                        session.req_header(),
                        verified_client_ip.as_deref(),
                        ctx.request_scheme,
                        &ctx.request_vars,
                    )
                    .into_owned();
                    upstream_response.insert_header(name.clone(), resolved)?;
                }
                upstream_response.remove_header("transfer-encoding");
                ctx.response_status = 200;
                ctx.intercepted_file = Some(stream);
                return Ok(true);
            }
            // 🚨 A missing response-page file raises its own 404. The caller
            // routes it once through error handling instead of resurrecting
            // the upstream response the matched handler already replaced.
            ctx.response_decision_error = Some(404);
            tracing::warn!(
                path = request_path,
                root = %root,
                "⚠️ handle_response file_server found no file; raising a routable 404"
            );
            return Ok(true);
        }

        if let Some(replacement) = outcome.replacement {
            let mut headers = BTreeMap::new();
            let verified_client_ip = ctx.verified_client_ip.map(|ip| ip.to_string());
            for (name, template) in replacement.headers {
                let resolved = resolve_caddy_placeholders(
                    &template,
                    session.req_header(),
                    verified_client_ip.as_deref(),
                    ctx.request_scheme,
                    &ctx.request_vars,
                )
                .into_owned();
                headers.insert(name, resolved);
            }
            upstream_response.set_status(
                http::StatusCode::from_u16(replacement.status)
                    .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR),
            )?;
            let existing: Vec<String> = upstream_response
                .headers
                .keys()
                .map(|name| name.as_str().to_string())
                .collect();
            for name in existing {
                upstream_response.remove_header(name.as_str());
            }
            for (name, value) in &headers {
                upstream_response.insert_header(name.clone(), value.clone())?;
            }
            upstream_response.insert_header(
                "Content-Length".to_string(),
                replacement.body.len().to_string(),
            )?;
            upstream_response.remove_header("transfer-encoding");
            ctx.response_status = replacement.status;
            ctx.intercepted_response = Some(crate::http_policy::InterceptedResponse {
                status: replacement.status,
                headers,
                body: replacement.body,
            });
            return Ok(true);
        }

        if let Some(code) = outcome.passthrough_status
            && let Ok(code) = http::StatusCode::from_u16(code)
        {
            upstream_response.set_status(code)?;
            ctx.response_status = code.as_u16();
        }
        let verified_client_ip = ctx.verified_client_ip.map(|ip| ip.to_string());
        for name in outcome.header_remove {
            upstream_response.remove_header(name.as_str());
        }
        for (name, template) in outcome.header_set {
            let resolved = resolve_caddy_placeholders(
                &template,
                session.req_header(),
                verified_client_ip.as_deref(),
                ctx.request_scheme,
                &ctx.request_vars,
            )
            .into_owned();
            upstream_response.insert_header(name.clone(), resolved)?;
        }
        Ok(true)
    }

    /// 🔁 Runs one normalized reverse-proxy subrequest inline.
    async fn proxy_subrequest(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        prepared: &crate::subrequest::PreparedSubrequest,
    ) -> pingora_core::Result<bool> {
        let subrequest_error =
            |(status, message): (u16, &'static str)| -> Box<pingora_core::Error> {
                pingora_core::Error::explain(pingora_core::ErrorType::HTTPStatus(status), message)
            };
        let Some(state) = ctx.state.clone() else {
            return Err(subrequest_error((
                500,
                "Subrequest Ran Without Route State",
            )));
        };
        let verified_client_ip = ctx.verified_client_ip.map(|ip| ip.to_string());
        let outcome = crate::subrequest::execute(
            &self.connector,
            prepared,
            session.req_header_mut(),
            verified_client_ip.as_deref(),
            ctx.request_scheme,
            &ctx.request_vars,
        )
        .await
        .map_err(subrequest_error)?;
        let crate::subrequest::SubrequestOutcome::Respond(rejected) = outcome else {
            return Ok(false);
        };
        let mut rejected = *rejected;
        let mut response = rejected
            .session
            .response_header()
            .cloned()
            .unwrap_or_else(|| {
                ResponseHeader::build(502, None).expect("a status-502 response header is valid")
            });
        let response_handlers = std::mem::take(&mut ctx.intercept_handlers);
        if !response_handlers.is_empty() {
            self.apply_response_interception(
                session,
                ctx,
                &mut response,
                Some(response_handlers.as_slice()),
            )
            .await?;
        }
        if let Some(error_status) = ctx.response_decision_error.take() {
            rejected.session.shutdown().await;
            ctx.error_status = Some(error_status);
            return Ok(true);
        }
        if ctx.intercepted_file.is_some() || ctx.intercepted_response.is_some() {
            rejected.session.shutdown().await;
            return self
                .write_local_response(session, ctx, response, LocalResponseBody::Empty, false)
                .await;
        }
        if state.intercepts_error_status(response.status.as_u16()) {
            rejected.session.shutdown().await;
            ctx.error_status = Some(response.status.as_u16());
            return Ok(true);
        }
        for header in [
            "connection",
            "proxy-connection",
            "keep-alive",
            "transfer-encoding",
            "te",
            "trailer",
            "upgrade",
        ] {
            response.remove_header(header);
        }
        response.remove_header("transfer-encoding");
        ctx.response_status = response.status.as_u16();
        Self::apply_local_response_headers(&mut response, ctx)?;
        session
            .write_response_header(Box::new(response), false)
            .await?;
        let mut clean = true;
        loop {
            match rejected.session.read_response_body().await {
                Ok(Some(bytes)) => {
                    session.write_response_body(Some(bytes), false).await?;
                }
                Ok(None) => break,
                Err(error) => {
                    tracing::debug!(%error, "🔌 Subrequest response stream failed");
                    clean = false;
                    break;
                }
            }
        }
        session.write_response_body(None, true).await?;
        if clean {
            self.connector
                .release_http_session(rejected.session, &rejected.peer, None)
                .await;
        } else {
            rejected.session.shutdown().await;
        }
        Ok(true)
    }

    /// 🔐 Normalizes legacy JSON before entering the shared subrequest exchange.
    async fn forward_auth(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        route_index: usize,
        config: &pingclair_core::config::ForwardAuthConfig,
    ) -> pingora_core::Result<bool> {
        let prepared = ctx
            .state
            .as_ref()
            .and_then(|state| state.prepared_forward_auth_subrequest(route_index, config))
            .ok_or_else(|| {
                pingora_core::Error::explain(
                    pingora_core::ErrorType::HTTPStatus(500),
                    "Subrequest Plan Was Not Prepared",
                )
            })?;
        self.proxy_subrequest(session, ctx, &prepared).await
    }

    /// 📏 Reads a FastCGI request body that arrived without a `Content-Length`.
    ///
    /// The FastCGI transport has to state the body's length before it writes a
    /// single STDIN byte, so a body framed by chunked coding — which is how
    /// HTTP/1.1, and every HTTP/2 or HTTP/3 stream, can define a length by
    /// construction — is read here and measured (#248). The limit, deadline,
    /// and upload pacer of the streaming path run while it is held, because
    /// measuring a body must not become the one way past `client_max_body_size`.
    ///
    /// The ceiling is the route's own `request_buffers` when it set one, and
    /// this module's hard ceiling otherwise. Past it the length cannot be
    /// measured without unbounded memory, so the request fails closed with 413
    /// instead of reaching php-fpm as a body the responder would read as empty.
    async fn read_lengthless_fastcgi_body(
        session: &mut Session,
        ctx: &mut RequestContext,
        config: &ReverseProxyConfig,
    ) -> pingora_core::Result<Bytes> {
        let ceiling = crate::body_buffer::measure_ceiling(crate::body_buffer::resolve_limit(
            config.request_buffer_bytes,
        ));
        let h2_pause = Self::h2_body_pause(session, ctx);
        let mut held = BytesMut::new();
        while let Some(chunk) =
            crate::body_timeout::read_within(h2_pause, session.read_request_body()).await?
        {
            Self::enforce_request_body_chunk(session, ctx, chunk.len()).await?;
            if held.len() + chunk.len() > ceiling {
                session.as_mut().set_keepalive(None);
                return pingora_core::Error::e_explain(
                    pingora_core::ErrorType::HTTPStatus(413),
                    format!(
                        "a FastCGI body without a declared length must fit its \
                         {ceiling}-byte buffering ceiling so its length can be measured"
                    ),
                );
            }
            held.extend_from_slice(&chunk);
        }
        Ok(held.freeze())
    }

    /// 🧵 Serves one request through the FastCGI transport.
    ///
    /// The whole round trip runs inline in `request_filter`, like
    /// `forward_auth`, because Pingora's upstream lifecycle speaks HTTP and
    /// FastCGI is a different protocol on the wire. The CGI response header
    /// is parsed first, `handle_response` entries evaluate against it before
    /// the client sees a byte, and the body is streamed record by record, so
    /// memory stays bounded by one FastCGI record (at most 65,500 bytes).
    async fn fastcgi_proxy(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        route_index: usize,
        config: &ReverseProxyConfig,
    ) -> PingoraResult<bool> {
        let proxy_error = |status: u16, message: &'static str| -> Box<pingora_core::Error> {
            pingora_core::Error::explain(pingora_core::ErrorType::HTTPStatus(status), message)
        };
        let Some(state) = ctx.state.clone() else {
            return Err(proxy_error(500, "FastCGI ran without route state"));
        };
        let Some(fastcgi) = config.fastcgi.as_ref() else {
            return Ok(false);
        };
        let method = session.req_header().method.as_str().to_ascii_uppercase();
        let bodyless = matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS");
        let content_length = session
            .req_header()
            .headers
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        // 🧾 PHP-FPM reads exactly `CONTENT_LENGTH` bytes from STDIN, so the
        // number has to exist before the exchange opens. A client that declared
        // one has given it to us; a body framed any other way — chunked coding,
        // or an H2 stream — only supplies bytes, so it is read and measured
        // here, before the dial (#248). A request that says nothing about a
        // body simply measures zero. Reading first also keeps a body this
        // server cannot carry from consuming an upstream slot.
        let measured = if content_length.is_none() && !bodyless {
            Some(Self::read_lengthless_fastcgi_body(session, ctx, config).await?)
        } else {
            None
        };
        let content_length =
            content_length.or_else(|| measured.as_ref().map(|body| body.len() as u64));
        let balance_key = self.balancing_identity(session, ctx);
        let (upstream, mut upstream_admission) = self
            .select_admitted_upstream(&state, route_index, balance_key.as_deref(), &HashSet::new())
            .map_err(|error| match error {
                UpstreamSelectionError::NoUpstream => {
                    proxy_error(502, "FastCGI upstream is unavailable")
                }
                UpstreamSelectionError::Unavailable => {
                    proxy_error(503, "FastCGI upstream is overloaded")
                }
            })?;
        ctx.upstream = Some(upstream.clone());
        let mut exchange = match crate::fastcgi::Exchange::connect(&upstream, fastcgi).await {
            Ok(exchange) => exchange,
            Err(error) => {
                if let Some(admission) = &mut upstream_admission {
                    admission.report_failure();
                }
                // 🩺 Two separate reasons a dial failure may leave the
                // responder in rotation. The first: the health map is keyed by
                // `std::net::SocketAddr`, so a Unix-socket responder cannot be
                // marked down at all — a php-fpm socket that stops accepting
                // keeps its turn, and the dial failure still fails this request
                // closed. The second: the failure was ours, not the
                // responder's, and benching a healthy backend for our own
                // descriptor exhaustion is how a local failure becomes a
                // route-wide outage.
                if error.origin().implicates_backend()
                    && let pingora_core::protocols::l4::socket::SocketAddr::Inet(address) =
                        &upstream.addr
                {
                    self.mark_upstream_unhealthy(&state, route_index, address);
                }
                tracing::warn!(
                    %error,
                    upstream = %upstream.addr,
                    origin = ?error.origin(),
                    "🔌 FastCGI dial failed"
                );
                return Err(match error {
                    crate::fastcgi::ExchangeError::DialTimedOut => {
                        proxy_error(504, "FastCGI upstream connection timed out")
                    }
                    _ => proxy_error(502, "FastCGI upstream connection failed"),
                });
            }
        };

        let (remote_ip, remote_port) = match session.client_addr() {
            Some(pingora_core::protocols::l4::socket::SocketAddr::Inet(address)) => {
                (canonical_client_ip(address.ip()), Some(address.port()))
            }
            _ => (
                ctx.verified_client_ip
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                None,
            ),
        };
        let verified_client_ip = ctx.verified_client_ip.map(|ip| ip.to_string());
        let prepared_request = crate::fastcgi::prepare_request_header(
            session.req_header(),
            &config.headers_up,
            &config.headers_up_remove,
            verified_client_ip.as_deref(),
            ctx.request_scheme,
            &ctx.request_vars,
        )
        .map_err(|()| proxy_error(500, "FastCGI upstream header is invalid"))?;
        let mut env = crate::fastcgi::build_environment(
            crate::fastcgi::EnvironmentInput {
                request: &prepared_request,
                remote_ip,
                remote_port,
                verified_client_ip: verified_client_ip.as_deref(),
                scheme: ctx.request_scheme,
                original_uri: ctx
                    .orig_uri
                    .path_and_query()
                    .map_or("/", http::uri::PathAndQuery::as_str),
                request_vars: &ctx.request_vars,
            },
            fastcgi,
        )
        .map_err(|error| {
            tracing::warn!(%error, "⚠️ FastCGI environment preparation failed");
            proxy_error(502, "FastCGI document root could not be resolved")
        })?;
        env.insert("REQUEST_METHOD".to_string(), method.clone().into());
        env.insert(
            "CONTENT_LENGTH".to_string(),
            content_length.unwrap_or(0).to_string().into(),
        );

        let protocol_error = |error: crate::fastcgi::ExchangeError| {
            tracing::warn!(%error, "🧵 FastCGI exchange failed");
            proxy_error(error.http_status(), "FastCGI exchange failed")
        };
        exchange.begin(&env).await.map_err(protocol_error)?;
        // 🧱 `request_buffers` holds the body here, where FastCGI writes its own
        // records, with the same state machine and ceiling as the HTTP body
        // filter: a slow client keeps a php-fpm worker waiting only once it
        // has sent the whole body or outgrown the buffer.
        let mut request_buffer = ctx.request_buffer.take();
        if let Some(measured) = measured {
            // 📏 This body was read to measure it, so the limit, deadline, and
            // upload pacer already ran while it was held; hand it over as it
            // arrived rather than reading it a second time.
            if !measured.is_empty() {
                exchange
                    .send_body(&measured)
                    .await
                    .map_err(protocol_error)?;
            }
        } else if !bodyless {
            // ⏱️ An HTTP/2 upload that stops halfway would otherwise hold this
            // stream and a php-fpm worker forever; see `h2_body_pause`.
            let h2_pause = Self::h2_body_pause(session, ctx);
            while let Some(bytes) =
                crate::body_timeout::read_within(h2_pause, session.read_request_body()).await?
            {
                // 🛡️ FastCGI is the one upstream path that never enters
                // Pingora's proxy lifecycle, so the body limit, the request
                // deadline, and the upload pacer have to be applied
                // here explicitly. Skipping them would let `php_fastcgi` be the
                // single route on which `client_max_body_size` does not hold.
                if let Err(error) =
                    Self::enforce_request_body_chunk(session, ctx, bytes.len()).await
                {
                    exchange.abort().await;
                    return Err(error);
                }
                let bytes = match request_buffer.as_mut() {
                    Some(buffer) => match buffer.offer_reporting(bytes, "request") {
                        Some(released) => released,
                        None => continue,
                    },
                    None => bytes,
                };
                exchange.send_body(&bytes).await.map_err(protocol_error)?;
            }
        }
        if let Some(held) = request_buffer.as_mut().and_then(|buffer| buffer.finish()) {
            exchange.send_body(&held).await.map_err(protocol_error)?;
        }
        exchange.finish_body().await.map_err(protocol_error)?;

        let header = exchange
            .read_response_header()
            .await
            .map_err(protocol_error)?;
        if let Some(admission) = &mut upstream_admission {
            admission.report_status(header.status);
        }
        let mut response = ResponseHeader::build(header.status, Some(header.headers.len() + 4))
            .map_err(|_| proxy_error(500, "FastCGI status is not a valid HTTP status"))?;
        for (name, value) in &header.headers {
            if let (Ok(name), Ok(value)) = (
                http::header::HeaderName::from_bytes(name.as_bytes()),
                http::header::HeaderValue::from_str(value),
            ) {
                response.append_header(name, value).unwrap();
            }
        }
        ctx.response_status = header.status;
        // 🧩 FastCGI never enters `upstream_peer`, so proxy-owned response
        // fields must join the local policy before the response decision runs.
        ctx.response_headers.merge_proxy_response_ops(
            &config.headers_down,
            &config.headers_down_add,
            &config.headers_down_remove,
            &config.headers_down_default,
        );
        if !config.headers_down_replace.is_empty() {
            ctx.response_headers
                .merge_proxy_replacements(&config.headers_down_replace);
        }
        ctx.streaming_response = wants_immediate_flush(config.flush_interval);

        // 🧭 `handle_response`/`intercept` evaluate before the client sees
        // the CGI response, exactly like proxied HTTP responses.
        self.apply_response_interception(session, ctx, &mut response, None)
            .await?;
        if let Some(status) = ctx.response_decision_error.take() {
            ctx.error_status = Some(status);
            exchange.abort().await;
            return Ok(true);
        }
        Self::apply_local_response_headers(&mut response, ctx)?;

        // 🌊 A lengthless HTTP/1.1 body needs chunked framing: otherwise a
        // responder failure closes a close-delimited response normally.
        if session.req_header().version == http::Version::HTTP_11
            && ResponseContent::for_response(
                response.status.as_u16(),
                session.req_header().method == http::Method::HEAD,
            )
            .has_body()
            && !response.headers.contains_key(http::header::CONTENT_LENGTH)
        {
            response.insert_header(http::header::TRANSFER_ENCODING, "chunked")?;
        }

        // 📂 A response-subroute file server takes over after the file opens.
        // The abort comes first, before a single downstream byte: the responder
        // is already known to be unwanted, and holding its connection open for
        // the length of the error page would pin a php-fpm worker for as long
        // as the client takes to read it. The H3 path aborts at the same point.
        if let Some(mut stream) = ctx.intercepted_file.take() {
            exchange.abort().await;
            session
                .write_response_header(Box::new(response), false)
                .await?;
            while let Ok(Some(chunk)) = stream.read_chunk() {
                Self::write_local_body(session, ctx, Bytes::from(chunk), false).await?;
            }
            Self::write_local_body(session, ctx, Bytes::new(), true).await?;
            return Ok(true);
        }

        // 📄 A static replacement emits its body once and discards the
        // FastCGI stream.
        if let Some(replacement) = ctx.intercepted_response.take() {
            exchange.abort().await;
            session
                .write_response_header(Box::new(response), false)
                .await?;
            if !replacement.body.is_empty() {
                Self::write_local_body(session, ctx, Bytes::from(replacement.body), false).await?;
            }
            Self::write_local_body(session, ctx, Bytes::new(), true).await?;
            return Ok(true);
        }

        // 🌊 The normal path streams the CGI body record by record; a client
        // that leaves mid-response aborts the FastCGI request.
        //
        // 🧱 With `response_buffers`, records are held until the responder
        // finishes or the ceiling is reached, so a slow reader stops pinning
        // the php-fpm worker. What is held is released at end of stream.
        let mut response_buffer = ctx.response_buffer.take();
        session
            .write_response_header(Box::new(response), false)
            .await?;
        loop {
            let read = match exchange.read_body_chunk().await {
                Ok(Some(chunk)) => match response_buffer.as_mut() {
                    Some(buffer) => match buffer.offer_reporting(chunk, "response") {
                        Some(released) => Ok(Some(released)),
                        None => continue,
                    },
                    None => Ok(Some(chunk)),
                },
                other => other,
            };
            match read {
                Ok(Some(chunk)) => {
                    if let Err(error) = Self::write_local_body(session, ctx, chunk, false).await {
                        exchange.abort().await;
                        return Err(error);
                    }
                }
                Ok(None) => {
                    // 📤 End of stream releases whatever is still held.
                    if let Some(held) = response_buffer.as_mut().and_then(|buffer| buffer.finish())
                    {
                        Self::write_local_body(session, ctx, held, false).await?;
                    }
                    break;
                }
                Err(error) => {
                    // 🔪 Propagate the failure so `fail_to_proxy` abandons the
                    // committed response instead of declaring it complete.
                    return Err(protocol_error(error));
                }
            }
        }
        Self::write_local_body(session, ctx, Bytes::new(), true).await?;
        let stderr = exchange.take_stderr();
        if !stderr.is_empty() {
            let text = String::from_utf8_lossy(&stderr);
            if header.status >= 400 {
                tracing::error!(body = %text, "⚠️ FastCGI responder stderr");
            } else {
                tracing::warn!(body = %text, "⚠️ FastCGI responder stderr");
            }
        }
        Ok(true)
    }

    /// 📥 Enforces one streamed request-body chunk without retaining it.
    async fn enforce_request_body_chunk(
        session: &mut Session,
        ctx: &mut RequestContext,
        bytes: usize,
    ) -> pingora_core::Result<()> {
        Self::enforce_request_deadline(ctx)?;
        ctx.request_body_bytes = ctx.request_body_bytes.saturating_add(bytes as u64);
        if ctx.state.as_ref().is_some_and(|state| {
            let limit = ctx
                .request_body_limit
                .unwrap_or(state.config.client_max_body_size);
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
        // ⏱️ Without this, an HTTP/2 stream announcing a body and sending no
        // DATA would hold its `respond` route forever; the error maps to 408
        // like HTTP/1's. See `h2_body_pause`.
        let h2_pause = Self::h2_body_pause(session, ctx);
        // 📥 This error came from reading the client, even when Pingora's
        // chunk parser leaves its source unset. Handler and upstream
        // failures must keep their own classification.
        while let Some(bytes) =
            crate::body_timeout::read_within(h2_pause, session.read_request_body())
                .await
                .map_err(pingora_core::Error::into_down)?
        {
            Self::enforce_request_body_chunk(session, ctx, bytes.len()).await?;
        }
        Ok(())
    }

    /// ⏱️ The longest pause allowed between two pieces of request body: what
    /// the configuration asks for, else [`DEFAULT_BODY_TIMEOUT`] — except on a
    /// long connection, whose client may be quiet on purpose and keeps its
    /// `long_connections` value; see `long_connection_read_timeout`. HTTP/1
    /// gets the same answer through `set_read_timeout`.
    ///
    /// [`DEFAULT_BODY_TIMEOUT`]: crate::body_timeout::DEFAULT_BODY_TIMEOUT
    fn body_pause(ctx: &RequestContext) -> Option<Duration> {
        let limits = &ctx.state.as_ref()?.config.limits;
        let route_read_ms = ctx.request_body_read_timeout_ms;
        if ctx.long_connection {
            Self::long_connection_read_timeout(route_read_ms, limits)
        } else {
            Some(
                Self::configured_read_timeout(route_read_ms, limits)
                    .unwrap_or(crate::body_timeout::DEFAULT_BODY_TIMEOUT),
            )
        }
    }

    /// ⏱️ The pause to time a body read this server makes itself with, which
    /// only HTTP/2 needs: Pingora times HTTP/1 reads from the read timeout
    /// `initialize_request_limits` set, but `set_read_timeout` is a no-op on an
    /// HTTP/2 stream (pingora-core 0.9.0, `ServerSession`).
    fn h2_body_pause(session: &Session, ctx: &RequestContext) -> Option<Duration> {
        if session.as_downstream().is_http2() {
            Self::body_pause(ctx)
        } else {
            None
        }
    }

    /// 📤 Writes one local response chunk through the configured streaming budget.
    async fn write_local_body(
        session: &mut Session,
        ctx: &mut RequestContext,
        body: Bytes,
        end_of_stream: bool,
    ) -> PingoraResult<()> {
        Self::enforce_request_deadline(ctx)?;
        // 🤐 A status or a `HEAD` that carries no content gets none, whatever
        // the handler built. HTTP/1.1 would drop the bytes on its own, but
        // HTTP/2 sends them as DATA. Only the end of the stream still goes out.
        if !Self::written_response_content(session).has_body() {
            return if end_of_stream {
                session.write_response_body(None, true).await
            } else {
                Ok(())
            };
        }
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

    /// 🧾 The content rule for the response header already written on this
    /// session and the request it answers; a session with no header yet is
    /// treated as allowing content.
    fn written_response_content(session: &Session) -> ResponseContent {
        let head_request = session.req_header().method == http::Method::HEAD;
        session
            .response_written()
            .map_or(ResponseContent::Allowed, |header| {
                ResponseContent::for_response(header.status.as_u16(), head_request)
            })
    }

    /// 🧭 Writes the answer this hop gives itself — a refused `TRACE` or
    /// `CONNECT`, or a spent `OPTIONS` — and ends the request.
    ///
    /// 🔌 Shared by the matched-site and no-matching-site paths, because a
    /// `CONNECT` must be refused the same way whether or not its authority
    /// names a site, and the connection must end with the refusal: a tunnel
    /// client may already be sending tunnel bytes behind its request, and
    /// those must not be read as the next one (RFC 9931 §8).
    async fn write_local_hop_answer(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        answer: crate::http_policy::LocalHopAnswer,
    ) -> PingoraResult<bool> {
        if answer.ends_connection() {
            session.as_mut().set_keepalive(None);
        }
        let mut header = Self::build_downstream_header(session, answer.status(), Some(2))?;
        header.insert_header("Allow", crate::http_policy::ALLOWED_METHODS)?;
        header.insert_header("Content-Length", "0")?;
        self.write_local_response(session, ctx, header, LocalResponseBody::Empty, false)
            .await?;
        Ok(true)
    }

    /// 🧭 Runs a local response through the same interception decision as a proxy response.
    async fn write_local_response(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        mut response: ResponseHeader,
        original_body: LocalResponseBody,
        require_interception: bool,
    ) -> PingoraResult<bool> {
        let handlers = ctx.intercept_handlers.clone();
        let intercepted = if handlers.is_empty() {
            false
        } else {
            self.apply_response_interception(session, ctx, &mut response, Some(handlers.as_slice()))
                .await?
        };
        if require_interception && !intercepted {
            return Ok(false);
        }
        if let Some(status) = ctx.response_decision_error.take() {
            ctx.error_status = Some(status);
            return Ok(false);
        }

        let body = if let Some(stream) = ctx.intercepted_file.take() {
            LocalResponseBody::File(Box::new(stream))
        } else if let Some(replacement) = ctx.intercepted_response.take() {
            LocalResponseBody::Bytes(Bytes::from(replacement.body))
        } else {
            original_body
        };
        ctx.intercepted_body_emitted = false;
        ctx.response_status = response.status.as_u16();
        // 🧾 HTTP/1.0 clients receive their own protocol version even when a
        // local handler constructs a header with the HTTP/1.1 default.
        if session.req_header().version == http::Version::HTTP_10 {
            response.set_version(http::Version::HTTP_10);
        }
        Self::apply_local_response_headers(&mut response, ctx)?;

        match body {
            LocalResponseBody::Empty => {
                session
                    .write_response_header(Box::new(response), true)
                    .await?;
            }
            LocalResponseBody::Bytes(bytes) => {
                let empty = bytes.is_empty();
                session
                    .write_response_header(Box::new(response), empty)
                    .await?;
                if !empty {
                    Self::write_local_body(session, ctx, bytes, true).await?;
                }
            }
            LocalResponseBody::File(mut stream) => {
                session
                    .write_response_header(Box::new(response), false)
                    .await?;
                // 🤐 A `HEAD` for a large file must not read the file just to
                // throw every chunk away in `write_local_body`.
                if !Self::written_response_content(session).has_body() {
                    session.write_response_body(None, true).await?;
                    return Ok(true);
                }
                let mut wrote = false;
                while let Some(chunk) = stream.read_chunk().map_err(|error| {
                    pingora_core::Error::because(
                        pingora_core::ErrorType::ReadError,
                        "streaming intercepted file body",
                        error,
                    )
                })? {
                    wrote = true;
                    let last = stream.is_complete();
                    Self::write_local_body(session, ctx, Bytes::from(chunk), last).await?;
                }
                if !wrote {
                    session.write_response_body(None, true).await?;
                }
            }
        }
        Ok(true)
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
        let mut response = Self::build_downstream_header(session, status, Some(3)).unwrap();
        response
            .insert_header("Content-Type", "text/plain")
            .unwrap();
        response
            .insert_header("Content-Length", body.len().to_string())
            .unwrap();
        Self::apply_local_response_headers(&mut response, ctx)?;
        Self::insert_proxy_status(&mut response, ctx);
        session
            .write_response_header(Box::new(response), false)
            .await?;
        Self::write_local_body(session, ctx, Bytes::copy_from_slice(body.as_bytes()), true).await?;
        Ok(())
    }

    /// 🏷️ Marks a generated error as this hop's own (RFC 9209), when
    /// `fail_to_proxy` settled why the upstream exchange failed.
    ///
    /// Taken rather than read, so the field is written at most once, and
    /// inserted after the site's header policy so a `header` directive cannot
    /// make an origin failure look like a forwarded answer.
    fn insert_proxy_status(response: &mut ResponseHeader, ctx: &mut RequestContext) {
        if let Some(error) = ctx.proxy_error.take() {
            response
                .insert_header(crate::proxy_status::HEADER_NAME, error.header_value())
                .ok();
        }
    }

    /// Build a downstream response header using the cheapest case strategy.
    ///
    /// HTTP/2 header names are case-insensitive on the wire, so Pingora's
    /// case-preserving map is pure per-header allocation overhead there;
    /// HTTP/1.1 callers still need the original casing for the wire bytes.
    fn build_downstream_header(
        session: &Session,
        status: u16,
        size_hint: Option<usize>,
    ) -> pingora_core::Result<ResponseHeader> {
        if session.req_header().version == http::Version::HTTP_2 {
            ResponseHeader::build_no_case(status, size_hint)
        } else {
            ResponseHeader::build(status, size_hint)
        }
    }

    /// 🧊 Applies local header policy while preserving the body's encoding cache key.
    fn apply_local_response_headers(
        response: &mut ResponseHeader,
        ctx: &RequestContext,
    ) -> PingoraResult<()> {
        let varies_by_encoding =
            crate::response_encoding::vary_covers_accept_encoding(&response.headers);
        ctx.response_headers
            .apply_pingora(response, &ctx.request_id_value, None)?;
        if let Some(state) = &ctx.state {
            Self::apply_security_response_headers(response, state)?;
        }
        Self::apply_strict_transport(response, ctx)?;
        if varies_by_encoding
            || ctx.state.as_ref().is_some_and(|state| {
                crate::response_encoding::should_vary(&state.config, response.status.as_u16())
            })
        {
            crate::response_encoding::vary_on_accept_encoding(response)?;
        }
        // 🚫 Every local write site sets `Content-Length` from the body it
        // built, and a 204 or 1xx must not carry one at all (RFC 9110 §8.6).
        // Stripped here, after the header policy, because this is the one
        // function every local response passes through on its way out.
        if !ResponseContent::for_status(response.status.as_u16()).allows_content_length() {
            response.remove_header(&http::header::CONTENT_LENGTH);
        }
        // 🧼 RFC 9113 §8.2.1 / RFC 9114 §10.3 forbid a field value that starts
        // or ends with SP/HTAB, and a configured value may contain one; H1's
        // serializer is the only place that padding is invisible (#256).
        crate::http_policy::trim_pingora_response_padding(response);
        Ok(())
    }

    /// 🛡️ Applies the vhost security policy consistently to local and upstream responses.
    pub(crate) fn apply_security_response_headers(
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
        if let Some(csp) = &state.config.security.csp {
            response.insert_header("Content-Security-Policy", csp)?;
        }
        Ok(())
    }

    /// 🔐 Adds or strips `Strict-Transport-Security` by what this response
    /// travels on, not by whether the site has a `tls` block.
    ///
    /// Kept outside the security policy on purpose: an operator's `header`
    /// can set the field on a site with no security policy at all, and that
    /// value must still be stripped from plaintext.
    fn apply_strict_transport(
        response: &mut ResponseHeader,
        ctx: &RequestContext,
    ) -> PingoraResult<()> {
        crate::http_policy::StrictTransport::apply_pingora(
            ctx.state.as_ref().map(|state| &state.strict_transport),
            response,
            ctx.request_scheme == "https",
        )
    }

    /// Apply an internal rewrite to the downstream request before Pingora
    /// clones it for the upstream connection. Existing query parameters are
    /// preserved unless the replacement supplies its own query string.
    /// 🏷️ Applies one `request_header` handler to the request being routed.
    ///
    /// Order matters and follows upstream: additions and sets first, then
    /// replacements over whatever is now there, then removals last — so
    /// `-Foo` beside a `Foo` set in the same block removes it, rather than the
    /// two racing on declaration order.
    #[allow(clippy::too_many_arguments)]
    fn apply_request_headers(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        route_index: usize,
        set: &std::collections::BTreeMap<String, String>,
        add: &std::collections::BTreeMap<String, Vec<String>>,
        remove: &[String],
        replace: &[pingclair_core::config::HeaderReplacement],
    ) -> PingoraResult<()> {
        // 🧭 Values are templates, the same as they are on the response side.
        // Resolved against the request as it stands now, so a later
        // `request_header` sees what an earlier one wrote.
        let verified_client_ip = ctx.verified_client_ip.map(|ip| ip.to_string());
        let scheme = ctx.request_scheme;
        let mut resolved: Vec<(String, String, bool)> = Vec::new();
        for (name, template, is_add) in set
            .iter()
            .map(|(name, value)| (name, value, false))
            // 📋 Every value of every `+Name` line, in order: the request side
            // is multi-valued now too (#276).
            .chain(
                add.iter()
                    .flat_map(|(name, values)| values.iter().map(move |value| (name, value, true))),
            )
        {
            let value = if template.contains('{') {
                resolve_caddy_placeholders(
                    template,
                    session.req_header(),
                    verified_client_ip.as_deref(),
                    scheme,
                    &ctx.request_vars,
                )
                .into_owned()
            } else {
                template.clone()
            };
            resolved.push((name.clone(), value, is_add));
        }

        let header = session.req_header_mut();
        for (name, value, is_add) in resolved {
            let failed = if is_add {
                header.append_header(name.clone(), value).is_err()
            } else {
                header.insert_header(name.clone(), value).is_err()
            };
            if failed {
                tracing::warn!(header = %name, "🚫 request_header names an invalid header");
            }
        }

        for replacement in replace {
            // ⚡ The pattern was compiled when the configuration was published,
            // so this is a lookup rather than a compile. Compiling here would
            // put a regex build on every request that touches this route.
            let Some((regex, resolved_replacement)) = ctx.state.as_ref().and_then(|state| {
                compiled_header_replacement(
                    state,
                    route_index,
                    ctx.error_scope.map(|scope| scope.route),
                    replacement,
                    header,
                    verified_client_ip.as_deref(),
                    scheme,
                    &ctx.request_vars,
                )
            }) else {
                continue;
            };
            let existing: Vec<String> = header
                .headers
                .get_all(&replacement.field)
                .iter()
                .filter_map(|value| value.to_str().ok().map(str::to_owned))
                .collect();
            if existing.is_empty() {
                continue;
            }
            let _ = header.remove_header(&replacement.field);
            for value in existing {
                let rewritten = regex.replace_all(&value, resolved_replacement.as_str());
                if header
                    .append_header(replacement.field.clone(), rewritten.as_ref())
                    .is_err()
                {
                    tracing::warn!(
                        header = %replacement.field,
                        "🚫 request_header replacement produced an invalid value"
                    );
                }
            }
        }

        for name in remove {
            let _ = header.remove_header(name.as_str());
        }
        Ok(())
    }

    /// 🌐 Writes the site name into a `Host` header, where reshaping the URI
    /// cannot erase it.
    ///
    /// HTTP/1.1 already sends one. HTTP/2 sends `:authority` instead, which
    /// Pingora keeps *in the URI* — and `set_raw_path`, which every `uri`
    /// rewrite goes through, replaces the URI with a path-only one.
    ///
    /// 🤡 So a route with `uri strip_prefix` silently dropped the site name on
    /// HTTP/2, and with no `Host` header to fall back to the origin received a
    /// literal `Host:` with nothing after it. An origin that routes by name
    /// served its default site; one that validates the header rejected the
    /// request. The identical request over HTTP/1.1 and HTTP/3 was fine, which
    /// is what made it invisible — HTTP/3 does exactly this, in
    /// `quic.rs`'s request builder, and has done since it was written.
    ///
    /// Called once, before anything can rewrite. Nothing is overwritten: a
    /// request that already names itself keeps what it sent.
    /// 🍪 Rejoins a cookie that HTTP/2 split across field lines.
    ///
    /// RFC 9113 §8.2.3 lets a client send `Cookie` as several field lines —
    /// browsers do, because each piece then compresses against its own HPACK
    /// entry — and requires the pieces to be concatenated with `"; "` before
    /// the request is passed into a context that is not HTTP/2. An HTTP/1
    /// upstream is exactly that context, and it was receiving three lines.
    ///
    /// 🤡 The identical rule for HTTP/3 (RFC 9114 §4.2.1) was fixed first, and
    /// only there. Fixing one transport and leaving the other is the shape this
    /// repository keeps rediscovering, and it survived a public comparison of
    /// all three transports run on the day the HTTP/3 half shipped.
    ///
    /// 📌 HTTP/1.1 is deliberately untouched. A client that sent three lines
    /// over HTTP/1.1 really did send three, and passing them through unchanged
    /// is faithful — the requirement to join is about what HTTP/2 and HTTP/3
    /// are allowed to do to a header on the wire, not about what an origin may
    /// be shown.
    ///
    /// 🍃 Returns before allocating unless the request actually split it, which
    /// no request does in the common case.
    fn join_split_cookies(header: &mut RequestHeader) {
        if header.version != http::Version::HTTP_2 {
            return;
        }
        // 🍃 Nothing to do for the request that did not split it, which is
        // almost every request — and counting is cheaper than building.
        if header.headers.get_all(http::header::COOKIE).iter().count() < 2 {
            return;
        }
        let mut fold = crate::http_policy::CookieFold::default();
        for piece in header.headers.get_all(http::header::COOKIE) {
            let Ok(piece) = piece.to_str() else {
                // 🚫 A cookie that is not text is not one this proxy can join,
                // and inventing bytes for it would be worse than leaving the
                // request as the client sent it.
                return;
            };
            fold.push(piece);
        }
        // 🍪 The fold owns its string, so the borrow of `header` ends here.
        let Some(joined) = fold.finish().map(std::borrow::Cow::into_owned) else {
            return;
        };
        header
            .insert_header(http::header::COOKIE, joined.as_str())
            .ok();
    }

    fn pin_request_authority(header: &mut RequestHeader) {
        if header.headers.contains_key(http::header::HOST) {
            return;
        }
        let Some(authority) = header
            .uri
            .authority()
            .map(|value| value.as_str().to_owned())
        else {
            return;
        };
        let _ = header.insert_header(http::header::HOST, authority);
    }

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
                ctx.error_scope.map(|scope| scope.route),
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
            Self::insert_proxy_status(&mut response, ctx);
            session
                .write_response_header(Box::new(response), false)
                .await?;
            Self::write_local_body(session, ctx, Bytes::from(content), true).await?;
            return Ok(());
        }
        // 📌 `error_detail` is taken, not read: it belongs to the one response
        // that answers the failure it describes.
        let detail = ctx.error_detail.take();
        let body = builtin_error_body(status, detail.as_deref());
        Self::write_simple_response(session, ctx, status, &body).await
    }

    /// 🚨 Writes the default response for a raised error status.
    ///
    /// The operator's message wins when one exists; otherwise the site's
    /// custom error page, and finally the status's canonical text.
    async fn write_error_response(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        status: u16,
        message: Option<String>,
    ) -> PingoraResult<()> {
        let Some(message) = message else {
            self.serve_error_page(session, ctx, status).await?;
            return Ok(());
        };
        let body_bytes = {
            let verified_client_ip = if message.contains('{') {
                ctx.verified_client_ip.map(|ip| ip.to_string())
            } else {
                None
            };
            let resolved = resolve_caddy_placeholders(
                &message,
                session.req_header(),
                verified_client_ip.as_deref(),
                ctx.request_scheme,
                &ctx.request_vars,
            );
            Bytes::copy_from_slice(resolved.as_bytes())
        };
        let mut response = ResponseHeader::build(status, Some(3)).unwrap();
        response
            .insert_header("Content-Type", "text/plain; charset=utf-8")
            .unwrap();
        response
            .insert_header("Content-Length", body_bytes.len().to_string())
            .unwrap();
        Self::apply_local_response_headers(&mut response, ctx)?;
        session
            .write_response_header(Box::new(response), false)
            .await?;
        Self::write_local_body(session, ctx, body_bytes, true).await?;
        Ok(())
    }

    /// 🚨 Runs the server's error routes for a raised status, falling back to
    /// the default error response when none of them answers.
    async fn handle_raised_error(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        status: u16,
    ) -> PingoraResult<()> {
        let message = ctx.error_message.take();
        // 🚨 Published before the routes run, so a `respond "err={err.status_code}"`
        // inside `handle_errors` renders the status that was raised rather than
        // an empty string. The response's own status is independent of it:
        // Caddy's `respond` still answers with the code it was written with.
        ctx.request_vars.set_error(status, message.as_deref());
        // 📎 Cloned so `state` does not borrow `ctx`: the error routes below
        // need `&mut ctx` for the same handler machinery that matched them.
        let Some(state) = ctx.state.clone() else {
            self.write_error_response(session, ctx, status, message)
                .await?;
            return Ok(());
        };
        ctx.handling_error = true;
        let path = session.req_header().uri.path().to_string();
        let route_index = ctx.route_index.unwrap_or(0);
        for (index, route) in state.config.error_routes.iter().enumerate() {
            if !route.matches(status) {
                continue;
            }
            let Some(prepared) = state.error_routes.get(index) else {
                continue;
            };
            ctx.error_scope = Some(crate::error_routes::ErrorScope {
                route: index,
                status,
            });
            if self
                .handle_config(
                    session,
                    ctx,
                    &prepared.pipeline,
                    &path,
                    route_index,
                    Some(&prepared.precompile),
                )
                .await?
            {
                // 🚫 A handler inside the error route raised again (a
                // `file_server` 404, say): answer it directly rather than
                // routing a second time — that re-entry is the recursion the
                // guard exists to stop.
                if let Some(inner_status) = ctx.error_status.take() {
                    let inner_message = ctx.error_message.take();
                    self.write_error_response(session, ctx, inner_status, inner_message)
                        .await?;
                }
                return Ok(());
            }
        }
        self.write_error_response(session, ctx, status, message)
            .await
    }

    /// 🎯 Evaluates one pipeline element's precompiled matcher.
    fn element_matcher_matches(
        &self,
        precompile: Option<&MatcherPrecompile>,
        session: &Session,
        ctx: &mut RequestContext,
        path: &str,
    ) -> MatcherVerdict {
        let Some(compiled) = precompile.and_then(|node| node.element_matcher.as_ref()) else {
            return MatcherVerdict::Match;
        };
        let host = crate::http_policy::request_host(crate::http_policy::request_authority(
            session.req_header(),
        ));
        let mut request = MatcherRequest {
            path,
            method: session.req_header().method.as_str(),
            headers: &session.req_header().headers,
            host: host.as_ref(),
            addresses: RequestAddresses {
                client_ip: ctx.verified_client_ip,
                remote_ip: ctx.remote_ip,
            },
            protocol: ctx.request_scheme,
            vars: Some(ctx.request_vars.values_mut()),
        };
        evaluate_verdict(compiled, &mut request)
    }

    /// 🗂️ Runs the `file` matcher for the JSON-only `try_files` handler.
    ///
    /// Returns the URI path to rewrite to, or `None` when no candidate exists.
    /// The `=code` error fallback is not reachable from here — a JSON
    /// `try_files` has a `fallback` handler for that case, and letting a
    /// candidate raise a status as well would give one configuration two ways
    /// to say what happens when nothing matched.
    fn resolve_try_files(
        &self,
        session: &Session,
        ctx: &mut RequestContext,
        files: &[String],
        root: Option<&str>,
        path: &str,
    ) -> Option<String> {
        let host = crate::http_policy::request_host(crate::http_policy::request_authority(
            session.req_header(),
        ));
        let mut request = MatcherRequest {
            path,
            method: session.req_header().method.as_str(),
            headers: &session.req_header().headers,
            host: host.as_ref(),
            addresses: RequestAddresses {
                client_ip: ctx.verified_client_ip,
                remote_ip: ctx.remote_ip,
            },
            protocol: ctx.request_scheme,
            vars: Some(ctx.request_vars.values_mut()),
        };
        match pingclair_core::server::evaluate_file_matcher(&mut request, files, root, None, &[]) {
            MatcherVerdict::Match => ctx
                .request_vars
                .values_mut()
                .get("http.matchers.file.relative")
                .cloned(),
            MatcherVerdict::NoMatch | MatcherVerdict::Error(_) => None,
        }
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
        precompile: Option<&MatcherPrecompile>,
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
                // 🧭 Caddy's `respond` defaults to `text/plain; charset=utf-8`
                // unless the config names a Content-Type explicitly.
                if !headers
                    .keys()
                    .any(|name| name.eq_ignore_ascii_case("content-type"))
                {
                    response
                        .insert_header("Content-Type", "text/plain; charset=utf-8")
                        .unwrap();
                }
                // 🏷️ The body is a template, exactly like a redirect target:
                // `respond "hello {host}"` is ordinary syntax. It used to be
                // written out verbatim, so Day 26 measured `v={host}` reaching
                // the client where the value belonged: `v=probe.example`.
                // 🔒 Scoped so the borrow of `session` ends here: the resolved
                // value is copied into `Bytes` (which the write needed anyway,
                // so this costs nothing extra) and `session` is free to be
                // borrowed mutably for the write below.
                let body_bytes = {
                    let raw_body = body.as_deref().unwrap_or("");
                    let verified_client_ip = if raw_body.contains('{') {
                        ctx.verified_client_ip.map(|ip| ip.to_string())
                    } else {
                        None
                    };
                    let resolved = resolve_caddy_placeholders(
                        raw_body,
                        session.req_header(),
                        verified_client_ip.as_deref(),
                        ctx.request_scheme,
                        &ctx.request_vars,
                    );
                    Bytes::copy_from_slice(resolved.as_bytes())
                };
                response
                    .insert_header("Content-Length", body_bytes.len().to_string())
                    .unwrap();
                self.write_local_response(
                    session,
                    ctx,
                    response,
                    LocalResponseBody::Bytes(body_bytes),
                    false,
                )
                .await?;
                Ok(true)
            }
            // 📊 The Prometheus scrape, served from a normal route.
            //
            // The body is encoded on demand rather than cached: a scrape is
            // supposed to observe the registry at the moment it is asked, and
            // scrapes arrive every fifteen seconds or so, not every
            // millisecond. This is one of the few local responses where doing
            // the work per request is the point rather than a defect.
            HandlerConfig::Metrics { .. } => {
                let body_bytes = Bytes::from(crate::metrics::gather());
                let mut response = ResponseHeader::build(200, Some(2)).unwrap();
                response
                    .insert_header("Content-Type", crate::metrics::SCRAPE_CONTENT_TYPE)
                    .unwrap();
                response
                    .insert_header("Content-Length", body_bytes.len().to_string())
                    .unwrap();
                self.write_local_response(
                    session,
                    ctx,
                    response,
                    LocalResponseBody::Bytes(body_bytes),
                    false,
                )
                .await?;
                Ok(true)
            }
            // 🧭 Response handlers only make sense against an upstream
            // response; a configuration that reaches the request dispatcher
            // with one is inert here by construction.
            HandlerConfig::CopyResponse { .. } | HandlerConfig::CopyResponseHeaders { .. } => {
                Ok(false)
            }
            // 🚨 A static error raises its status into the request context
            // instead of writing: the dispatch then runs the server's error
            // routes, and only falls back to a direct response when none
            // handles it. Inside an error route a second raise responds
            // directly — that is the recursion guard.
            HandlerConfig::Error { status, message } => {
                if ctx.handling_error {
                    self.write_error_response(session, ctx, *status, message.clone())
                        .await?;
                    return Ok(true);
                }
                ctx.error_status = Some(*status);
                ctx.error_message = message.clone();
                Ok(true)
            }
            HandlerConfig::Redirect { to, code } => {
                // 🧭 A redirect target is a template, so `redir https://{host}{uri}`
                // can send a client to the same resource over another scheme.
                let verified_client_ip = if to.contains('{') {
                    ctx.verified_client_ip.map(|ip| ip.to_string())
                } else {
                    None
                };
                let location = resolve_caddy_placeholders(
                    to,
                    session.req_header(),
                    verified_client_ip.as_deref(),
                    ctx.request_scheme,
                    &ctx.request_vars,
                );
                let mut response = ResponseHeader::build(*code, Some(3)).unwrap();
                response
                    .insert_header("Location", location.as_ref())
                    .unwrap();
                self.write_local_response(session, ctx, response, LocalResponseBody::Empty, false)
                    .await?;
                Ok(true)
            }
            HandlerConfig::Templates { root } => {
                // 🧭 Caddy's `templates` directive renders `.html` files with
                // `{{ ... }}` before the file server would serve them raw.
                // Non-template files fall through so `file_server` handles
                // them unchanged.
                let root = root.clone().unwrap_or_else(|| ".".to_string());
                // 🔤 Decoded and confined by the same helper the H3 path uses, so
                // a template named in escapes resolves and a `..` — encoded or
                // not — does not. Falling through on `None` is the existing
                // answer for a path this handler will not open.
                let Some(mut file_path) =
                    pingclair_core::percent::resolve_under_root(std::path::Path::new(&root), path)
                else {
                    return Ok(false);
                };
                if file_path.is_dir() {
                    file_path = file_path.join("index.html");
                }
                let Ok(source) = std::fs::read_to_string(&file_path) else {
                    return Ok(false);
                };
                if !source.contains("{{") {
                    return Ok(false);
                }

                let rendered = match render_template(&source, &root) {
                    Ok(rendered) => rendered,
                    Err(error) => {
                        tracing::warn!(%error, path, "⚠️ Template rendering failed");
                        // 🚨 Raised rather than written here: Caddy returns a
                        // template error to its chain, so `handle_errors` is
                        // where an operator's 500 page lives. Answering inline
                        // skipped that route on this transport and produced a
                        // different 500 from HTTP/3 (#245).
                        ctx.error_status = Some(500);
                        ctx.error_message = Some("Template Rendering Failed".to_string());
                        return Ok(true);
                    }
                };
                let body = rendered.into_bytes();
                let mut response = ResponseHeader::build(200, Some(3)).unwrap();
                response
                    .insert_header("Content-Type", "text/html; charset=utf-8")
                    .unwrap();
                response
                    .insert_header("Content-Length", body.len().to_string())
                    .unwrap();
                self.write_local_response(
                    session,
                    ctx,
                    response,
                    LocalResponseBody::Bytes(Bytes::from(body)),
                    false,
                )
                .await?;
                Ok(true)
            }
            HandlerConfig::FileServer { pass_thru, .. } => {
                // 🚨 Inside an error route the file server is that route's
                // own, and the page goes out with the error's status.
                let error_scope = ctx.error_scope;
                let maybe_file_server = ctx.state.as_ref().and_then(|state| match error_scope {
                    Some(scope) => state
                        .error_routes
                        .get(scope.route)
                        .and_then(|route| route.file_server.clone()),
                    None => state.file_servers.get(route_index).and_then(|f| f.clone()),
                });
                let status_for = |own: u16| error_scope.map_or(own, |scope| scope.status);

                if let Some(file_server) = maybe_file_server {
                    // 🏷️ The method and header fields go over whole:
                    // pingclair-static reads `Range`, `If-Range`, and the
                    // four preconditions from them itself, the same way for
                    // both transports. An error page is read plainly instead;
                    // see `error_page_method`. The encode policy sees the
                    // status that actually goes out, which for an error page
                    // is the error's.
                    let encode_policy = |status, headers: &mut http::HeaderMap| {
                        ctx.state.as_ref().is_some_and(|state| {
                            crate::static_encode::apply_policy(
                                &ctx.response_headers,
                                state,
                                &ctx.request_id_value,
                                ctx.request_scheme == "https",
                                status_for(status),
                                headers,
                            )
                        })
                    };
                    let no_fields = http::HeaderMap::new();
                    let request = match error_scope {
                        Some(_) => pingclair_static::FileRequest::new(
                            crate::error_routes::error_page_method(&session.req_header().method),
                            &no_fields,
                        ),
                        None => pingclair_static::FileRequest::new(
                            &session.req_header().method,
                            &session.req_header().headers,
                        ),
                    }
                    .with_response_policy(&encode_policy);
                    let accept_encoding = session
                        .req_header()
                        .headers
                        .get("Accept-Encoding")
                        .and_then(|v| v.to_str().ok());

                    // serve_auto makes the buffered-vs-streaming call in one
                    // pass (single resolve + stat per request): large,
                    // complete, uncompressed responses stream in 64KB chunks
                    // instead of being buffered whole in memory.
                    // 🔁 `ctx.orig_uri` is the request as it arrived, before
                    // any rewrite: the canonical redirect is decided against
                    // it and points back to it — see `serve_auto`.
                    //
                    // 📄 An error page has no "as it arrived" path of its own:
                    // it is wherever the error route rewrote to.
                    let original_path = match error_scope {
                        Some(_) => path,
                        None => ctx
                            .orig_uri
                            .path_and_query()
                            .map_or("/", |uri| uri.as_str()),
                    };
                    match file_server
                        .serve_auto(path, original_path, request, accept_encoding)
                        .await
                    {
                        // 🧊 A 304 carries the validators and `Vary` a 200
                        // would have, and no `Content-Length`: there is no
                        // content, and the header write strips nothing here.
                        Ok(Some(pingclair_static::ServedResponse::NotModified(not_modified))) => {
                            let mut header =
                                Self::build_downstream_header(session, 304, Some(3)).unwrap();
                            header.insert_header("ETag", not_modified.etag).unwrap();
                            if let Some(lm) = not_modified.last_modified {
                                header.insert_header("Last-Modified", lm).unwrap();
                            }
                            if not_modified.vary_accept_encoding {
                                header.insert_header("Vary", "Accept-Encoding").unwrap();
                            }
                            self.write_local_response(
                                session,
                                ctx,
                                header,
                                LocalResponseBody::Empty,
                                false,
                            )
                            .await?;
                            return Ok(true);
                        }
                        // 🚫 `Allow` is required on a 405 (RFC 9110 §15.5.6).
                        Ok(Some(pingclair_static::ServedResponse::MethodNotAllowed)) => {
                            let mut header =
                                Self::build_downstream_header(session, 405, Some(2)).unwrap();
                            header.insert_header("Allow", "GET, HEAD").unwrap();
                            header.insert_header("Content-Length", "0").unwrap();
                            self.write_local_response(
                                session,
                                ctx,
                                header,
                                LocalResponseBody::Empty,
                                false,
                            )
                            .await?;
                            return Ok(true);
                        }
                        Ok(Some(pingclair_static::ServedResponse::PreconditionFailed)) => {
                            let mut header =
                                Self::build_downstream_header(session, 412, Some(1)).unwrap();
                            header.insert_header("Content-Length", "0").unwrap();
                            self.write_local_response(
                                session,
                                ctx,
                                header,
                                LocalResponseBody::Empty,
                                false,
                            )
                            .await?;
                            return Ok(true);
                        }
                        Ok(Some(pingclair_static::ServedResponse::Redirect(location))) => {
                            let mut header =
                                Self::build_downstream_header(session, 308, Some(2)).unwrap();
                            header.insert_header("Location", location.as_str()).unwrap();
                            self.write_local_response(
                                session,
                                ctx,
                                header,
                                LocalResponseBody::Empty,
                                false,
                            )
                            .await?;
                            return Ok(true);
                        }
                        Ok(Some(pingclair_static::ServedResponse::Stream(stream))) => {
                            // 🪟 The stream's own status: 206 for a range, or a
                            // configured override such as a maintenance tree's 503.
                            // Hardcoding 200 would tell a range request it received
                            // the whole file.
                            let mut header = Self::build_downstream_header(
                                session,
                                status_for(stream.status),
                                Some(7),
                            )
                            .unwrap();
                            header
                                .insert_header("Content-Type", stream.content_type.clone())
                                .unwrap();
                            header
                                .insert_header("Content-Length", stream.content_length.clone())
                                .unwrap();
                            if let Some(range) = &stream.content_range {
                                header
                                    .insert_header("Content-Range", range.clone())
                                    .unwrap();
                            }
                            // 🗜️ Set when the bytes on disk are already compressed —
                            // a streamed `.br`/`.gz`/`.zst` sidecar.
                            if let Some(encoding) = &stream.content_encoding {
                                header
                                    .insert_header("Content-Encoding", encoding.clone())
                                    .unwrap();
                            }
                            if let Some(lm) = &stream.last_modified {
                                header.insert_header("Last-Modified", lm.clone()).unwrap();
                            }
                            if let Some(etag) = &stream.etag {
                                header.insert_header("ETag", etag.clone()).unwrap();
                            }
                            // 🧊 A streamed response is the uncompressed variant of a
                            // resource that compression could have encoded. Without this a
                            // shared cache stores it as if it were the only variant and
                            // then serves it to a client that asked for gzip.
                            if stream.vary_accept_encoding {
                                header.insert_header("Vary", "Accept-Encoding").unwrap();
                            }
                            header.insert_header("Accept-Ranges", "bytes").unwrap();
                            self.write_local_response(
                                session,
                                ctx,
                                header,
                                LocalResponseBody::File(Box::new(stream)),
                                false,
                            )
                            .await?;
                            return Ok(true);
                        }
                        Ok(Some(pingclair_static::ServedResponse::Buffered(file))) => {
                            let mut header = Self::build_downstream_header(
                                session,
                                status_for(file.status),
                                Some(6),
                            )
                            .unwrap();
                            header
                                .insert_header("Content-Type", file.content_type.clone())
                                .unwrap();
                            header
                                .insert_header("Content-Length", file.content_length.clone())
                                .unwrap();

                            if let Some(range) = file.content_range {
                                header
                                    .insert_header("Content-Range", range.as_str())
                                    .unwrap();
                            }
                            if let Some(lm) = file.last_modified {
                                header.insert_header("Last-Modified", lm).unwrap();
                            }
                            if let Some(etag) = file.etag {
                                header.insert_header("ETag", etag).unwrap();
                            }
                            if let Some(encoding) = file.content_encoding {
                                header
                                    .insert_header("Content-Encoding", encoding.as_str())
                                    .unwrap();
                            }
                            // 🧊 Announced whenever compression is enabled, not only when
                            // this response was compressed. The header describes the
                            // *resource*, so omitting it on the identity copy is what lets
                            // a cache hand that copy to a client expecting gzip.
                            if file.vary_accept_encoding {
                                header.insert_header("Vary", "Accept-Encoding").unwrap();
                            }
                            header.insert_header("Accept-Ranges", "bytes").unwrap();
                            self.write_local_response(
                                session,
                                ctx,
                                header,
                                LocalResponseBody::Bytes(file.content),
                                false,
                            )
                            .await?;
                            return Ok(true);
                        }
                        // ➡️ `pass_thru`: the site said a miss is not this
                        // handler's answer, so report "not handled" and let the
                        // next one try. This is the `file_server` that fronts a
                        // proxy — static assets win, everything else goes
                        // upstream — and without it the 404 below would shadow
                        // the application entirely.
                        _ if *pass_thru => return Ok(false),
                        // Missing file (or read error): a file_server route
                        // has no upstream to fall back to, so answer 404
                        // here — through the error routes when configured —
                        // instead of falling through to upstream_peer, which
                        // would surface a 500 (ConnectNoRoute).
                        _ => {
                            let mut header =
                                Self::build_downstream_header(session, 404, Some(2)).unwrap();
                            header.insert_header("Content-Length", "0").unwrap();
                            if self
                                .write_local_response(
                                    session,
                                    ctx,
                                    header,
                                    LocalResponseBody::Empty,
                                    true,
                                )
                                .await?
                            {
                                return Ok(true);
                            }
                            ctx.error_status = Some(404);
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            }
            HandlerConfig::Pipeline { handlers } => {
                let mut current_path = path.to_string();
                // 🧭 Caddy's directive order runs `reverse_proxy` before
                // `file_server`; in Pingclair the proxy executes in the
                // Pingora phase after local handlers, so a file server in
                // the same chain must stand down or it would shadow the
                // proxy for every request.
                let has_proxy = handlers
                    .iter()
                    .any(|element| contains_reverse_proxy(&element.handler));
                for (index, element) in handlers.iter().enumerate() {
                    let handler = &element.handler;
                    let element_precompile = precompile.and_then(|node| node.children.get(index));
                    match self.element_matcher_matches(
                        element_precompile,
                        session,
                        ctx,
                        &current_path,
                    ) {
                        MatcherVerdict::Match => {}
                        MatcherVerdict::NoMatch => continue,
                        // 🚨 A `=code` try_files fallback inside an element
                        // matcher raises the status, like upstream.
                        MatcherVerdict::Error(code) => {
                            ctx.error_status = Some(code);
                            return Ok(true);
                        }
                    }
                    if has_proxy && matches!(handler, HandlerConfig::FileServer { .. }) {
                        continue;
                    }
                    if self
                        .handle_config(
                            session,
                            ctx,
                            handler,
                            &current_path,
                            route_index,
                            element_precompile,
                        )
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
            HandlerConfig::FirstMatch { handlers } => {
                let has_proxy = handlers
                    .iter()
                    .any(|element| contains_reverse_proxy(&element.handler));
                for (index, element) in handlers.iter().enumerate() {
                    let element_precompile = precompile.and_then(|node| node.children.get(index));
                    match self.element_matcher_matches(element_precompile, session, ctx, path) {
                        MatcherVerdict::Match => {}
                        MatcherVerdict::NoMatch => continue,
                        MatcherVerdict::Error(code) => {
                            ctx.error_status = Some(code);
                            return Ok(true);
                        }
                    }
                    if has_proxy && matches!(&element.handler, HandlerConfig::FileServer { .. }) {
                        continue;
                    }
                    // 🧭 A `handle` group is mutually exclusive: the first
                    // matching element owns the request, and later elements
                    // never run even when it passes through.
                    return self
                        .handle_config(
                            session,
                            ctx,
                            &element.handler,
                            path,
                            route_index,
                            element_precompile,
                        )
                        .await;
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
                // 🔤 The route matcher chose this group without regard to
                // case, so the strip compares the same way (#214).
                let rewritten = if strip_path_prefix(path, prefix).is_some() {
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

                for (index, element) in handlers.iter().enumerate() {
                    let element_precompile = precompile.and_then(|node| node.children.get(index));
                    match self.element_matcher_matches(element_precompile, session, ctx, new_path) {
                        MatcherVerdict::Match => {}
                        MatcherVerdict::NoMatch => continue,
                        MatcherVerdict::Error(code) => {
                            ctx.error_status = Some(code);
                            return Ok(true);
                        }
                    }
                    if self
                        .handle_config(
                            session,
                            ctx,
                            &element.handler,
                            new_path,
                            route_index,
                            element_precompile,
                        )
                        .await?
                    {
                        return Ok(true);
                    }
                    // 🧭 `handle_path` is a `handle` under another name:
                    // first matching element owns the group.
                    return Ok(false);
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
            HandlerConfig::Headers {
                set,
                add,
                remove,
                replace,
                default_set,
                require,
            } => {
                // 🧭 This block's operations are collected apart from the
                // route's policy and merged at the end, because a block written
                // with `match { … }` has to stay identifiable as one block —
                // folded in, its gate would end up gating the whole route.
                let mut block = ResponseHeaderPolicy::default();
                // 🔁 Patterns come from the per-route table compiled when the
                // configuration was published, so this is a lookup.
                let verified_client_ip = ctx.verified_client_ip.map(|ip| ip.to_string());
                for entry in replace {
                    let resolved = ctx.state.as_ref().and_then(|state| {
                        compiled_header_replacement(
                            state,
                            route_index,
                            ctx.error_scope.map(|scope| scope.route),
                            entry,
                            session.req_header(),
                            verified_client_ip.as_deref(),
                            ctx.request_scheme,
                            &ctx.request_vars,
                        )
                    });
                    if let Some((pattern, replacement)) = resolved {
                        block.replace(entry.field.clone(), pattern, replacement);
                    }
                }
                // 🏷️ `header X-Trace {host}` is ordinary syntax, and the value used
                // to reach the client verbatim — Day 26 measured `x-probe: {host}`
                // where the hostname belonged.
                //
                // Resolved here, as the value enters the request, rather than at
                // write time: this is the one place that has both the configured
                // template and the request, so the policy downstream stays a plain
                // list of literal values and every response path benefits without
                // being touched.
                let needs_resolution = set.values().any(|value| value.contains('{'))
                    || add.values().flatten().any(|value| value.contains('{'));
                let resolve = |value: &String, session: &Session, ctx: &RequestContext| {
                    if value.contains('{') {
                        resolve_caddy_placeholders(
                            value,
                            session.req_header(),
                            ctx.verified_client_ip.map(|ip| ip.to_string()).as_deref(),
                            ctx.request_scheme,
                            &ctx.request_vars,
                        )
                        .into_owned()
                    } else {
                        value.clone()
                    }
                };
                if needs_resolution {
                    // 🔒 Collected first so `ctx` is not borrowed while it is being
                    // written to.
                    let resolved_set: Vec<(String, String)> = set
                        .iter()
                        .map(|(k, v)| (k.clone(), resolve(v, session, ctx)))
                        .collect();
                    let resolved_add: Vec<(String, String)> = add
                        .iter()
                        .flat_map(|(k, values)| {
                            values.iter().map(|v| (k.clone(), resolve(v, session, ctx)))
                        })
                        .collect();
                    for (k, v) in resolved_set {
                        block.set(k, v);
                    }
                    for (k, v) in resolved_add {
                        block.add(k, v);
                    }
                } else {
                    for (k, v) in set {
                        block.set(k, v.clone());
                    }
                    // 📋 Every value of every `+Name` line, in order (#276).
                    for (k, values) in add {
                        for v in values {
                            block.add(k, v.clone());
                        }
                    }
                }
                for name in remove {
                    block.remove(name);
                }
                for (name, value) in default_set {
                    block.set_if_absent(name, value.clone());
                }
                ctx.response_headers.merge_block(require.clone(), block);
                Ok(false)
            }
            HandlerConfig::RequestHeaders {
                set,
                add,
                remove,
                replace,
            } => {
                self.apply_request_headers(session, ctx, route_index, set, add, remove, replace)?;
                Ok(false)
            }
            HandlerConfig::RequestBody {
                max_size,
                read_timeout_ms,
                write_timeout_ms,
                set,
            } => {
                // 📥 Recorded rather than enforced here: the body has not been
                // read yet, and the places that do read it already know how to
                // stop. Enforcing twice would mean two limits to keep in step.
                if let Some(limit) = max_size {
                    ctx.request_body_limit = Some(*limit);
                }
                // ⏱️ Re-armed here with the exact value, because the seed that
                // `initialize_request_limits` applied was the route's widest
                // declaration and a matcher may have selected a narrower one.
                if let Some(millis) = read_timeout_ms {
                    ctx.request_body_read_timeout_ms = Some(*millis);
                    session
                        .as_mut()
                        .set_read_timeout(Some(Duration::from_millis(*millis)));
                    session
                        .as_mut()
                        .set_total_drain_timeout(Some(Duration::from_millis(*millis)));
                }
                if let Some(millis) = write_timeout_ms {
                    ctx.request_body_write_timeout_ms = Some(*millis);
                    session
                        .as_mut()
                        .set_write_timeout(Some(Duration::from_millis(*millis)));
                }
                // 🧾 `set` expands its placeholders once, here, where the
                // request and the replacer are both in hand — the same shape
                // and the same reason as a `header` value above. Caddy does the
                // same at this point in its chain, so `{http.request.method}`
                // inside the template means the method of *this* request.
                if let Some(template) = set {
                    // 🔒 Bound before the call so `ctx` is not borrowed while it
                    // is read — the same shape the header handler uses.
                    let verified_client_ip = ctx.verified_client_ip.map(|ip| ip.to_string());
                    let resolved = resolve_caddy_placeholders(
                        template,
                        session.req_header(),
                        verified_client_ip.as_deref(),
                        ctx.request_scheme,
                        &ctx.request_vars,
                    );
                    ctx.request_body_set = Some(Bytes::from(resolved.into_owned()));
                }
                Ok(false)
            }
            HandlerConfig::Abort => {
                // 🔪 No status line, no body, no error page — the connection
                // ends. `fail_to_proxy` maps a downstream `ConnectionClosed`
                // to error code 0, which is its established spelling for "do
                // not write a response", and refuses reuse. Anything with a
                // status would be an answer, and an answer is the one thing
                // `abort` exists not to give.
                session.as_mut().set_keepalive(None);
                Err(pingora_core::Error::create(
                    pingora_core::ErrorType::ConnectionClosed,
                    pingora_core::ErrorSource::Downstream,
                    Some("aborted by configuration".into()),
                    None,
                ))
            }
            HandlerConfig::LogSkip => {
                ctx.log_skip = true;
                Ok(false)
            }
            HandlerConfig::Vars { values } => {
                // 🧰 Values are templates resolved against the same request,
                // so a value may reference placeholders and earlier vars.
                for (name, template) in values {
                    let verified_client_ip = ctx.verified_client_ip.map(|ip| ip.to_string());
                    let resolved = resolve_caddy_placeholders(
                        template,
                        session.req_header(),
                        verified_client_ip.as_deref(),
                        ctx.request_scheme,
                        &ctx.request_vars,
                    );
                    ctx.request_vars.set(name.clone(), resolved.into_owned());
                }
                Ok(false)
            }
            HandlerConfig::Intercept { handlers } => {
                // 🧭 Registers response handlers for the response of later
                // handlers in this request. Local, proxied, and FastCGI
                // responses all enter the same response decision before any
                // downstream bytes are committed.
                ctx.intercept_handlers = handlers.clone();
                Ok(false)
            }
            HandlerConfig::Rewrite {
                strip_prefix,
                strip_suffix,
                replace,
                regex,
                regex_replace,
                method,
            } => {
                // 🔤 The method is a template too, and is upper-cased after
                // resolution — `method post` and `method POST` are the same
                // instruction, and an HTTP method is case-sensitive on the
                // wire, so the lower-case spelling would otherwise reach the
                // upstream verbatim and be refused.
                if let Some(template) = method {
                    let verified_client_ip = if template.contains('{') {
                        ctx.verified_client_ip.map(|ip| ip.to_string())
                    } else {
                        None
                    };
                    let resolved = resolve_caddy_placeholders(
                        template,
                        session.req_header(),
                        verified_client_ip.as_deref(),
                        ctx.request_scheme,
                        &ctx.request_vars,
                    );
                    match http::Method::from_bytes(resolved.to_ascii_uppercase().as_bytes()) {
                        Ok(parsed) => session.req_header_mut().set_method(parsed),
                        Err(_) => {
                            tracing::warn!(
                                method = %resolved,
                                "🚫 `method` resolved to something that is not a method"
                            );
                            return Err(pingora_core::Error::explain(
                                pingora_core::ErrorType::HTTPStatus(500),
                                "rewritten method is not a valid HTTP method",
                            ));
                        }
                    }
                }
                // 🧭 Every rewrite operand is a template: `php_fastcgi` writes
                // `{http.matchers.file.relative}`, operators write `{host}`,
                // and `uri strip_prefix /api/{re.tenant.1}` names a prefix
                // only the matcher knows. Resolving here keeps `apply_rewrite`
                // purely mechanical, like every other URI rewrite.
                //
                // 🤡 Until #278 only `replace` was resolved, so a strip whose
                // prefix held a placeholder compared against literal braces,
                // never matched, and forwarded the path untouched.
                let verified_client_ip = if [replace, strip_prefix, strip_suffix, regex_replace]
                    .iter()
                    .any(|operand| operand.as_deref().is_some_and(|value| value.contains('{')))
                {
                    ctx.verified_client_ip.map(|ip| ip.to_string())
                } else {
                    None
                };
                let (resolved_prefix, resolved_suffix, resolved_replace, resolved_regex_replace) = {
                    let operands = RewriteOperands {
                        req: session.req_header(),
                        verified_client_ip: verified_client_ip.as_deref(),
                        scheme: ctx.request_scheme,
                        vars: &ctx.request_vars,
                    };
                    (
                        operands.resolve(strip_prefix.as_deref()),
                        operands.resolve(strip_suffix.as_deref()),
                        operands.resolve(replace.as_deref()),
                        operands.resolve(regex_replace.as_deref()),
                    )
                };
                self.apply_rewrite(
                    session,
                    ctx,
                    route_index,
                    RewriteRule {
                        strip_prefix: resolved_prefix.as_deref(),
                        strip_suffix: resolved_suffix.as_deref(),
                        replace: resolved_replace.as_deref(),
                        regex: regex.as_deref(),
                        regex_replace: resolved_regex_replace.as_deref(),
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
            HandlerConfig::TryFiles {
                files,
                root,
                fallback,
            } => {
                // 🗂️ A match rewrites the request and stands down; whatever
                // runs next — normally `file_server` — is what serves it.
                // Returning "not handled" is how the pipeline learns to carry
                // on, and `apply_rewrite` is reused rather than reimplemented
                // so the query string survives and `ctx.rewritten_path` is
                // published the same way every other rewrite publishes it.
                //
                // 🧭 Only a JSON configuration reaches this arm: since
                // 2026-08-11 the Pingclairfile adapter expands `try_files` into
                // the `file` matcher plus a rewrite, exactly as upstream does.
                // The lookup goes through that same matcher rather than a
                // second one, which is what the two used to be — and they
                // disagreed about policies, globs, and every placeholder but
                // `{path}`.
                match self.resolve_try_files(session, ctx, files, root.as_deref(), path) {
                    Some(target) => {
                        self.apply_rewrite(
                            session,
                            ctx,
                            route_index,
                            RewriteRule {
                                strip_prefix: None,
                                strip_suffix: None,
                                replace: Some(&target),
                                regex: None,
                                regex_replace: None,
                            },
                        )?;
                        Ok(false)
                    }
                    // 🧭 No candidate exists. A JSON configuration may name a
                    // handler for that case; a Pingclairfile never does, and
                    // the request simply continues with its original path.
                    None => match fallback {
                        Some(fallback) => {
                            let fallback_precompile =
                                precompile.and_then(|node| node.children.first());
                            self.handle_config(
                                session,
                                ctx,
                                fallback,
                                path,
                                route_index,
                                fallback_precompile,
                            )
                            .await
                        }
                        None => Ok(false),
                    },
                }
            }
            // 🔁 An HTTP reverse proxy is not answered here on purpose:
            // returning "not handled" is what hands the request to Pingora's
            // `upstream_peer` phase, which is where proxying happens. A
            // FastCGI transport cannot ride Pingora's HTTP lifecycle, so it
            // answers inline instead.
            HandlerConfig::ReverseProxy(config) => {
                if config.subrequest.is_some() {
                    let prepared = ctx
                        .state
                        .as_ref()
                        .and_then(|state| {
                            state.prepared_reverse_proxy_subrequest(route_index, config)
                        })
                        .ok_or_else(|| {
                            pingora_core::Error::explain(
                                pingora_core::ErrorType::HTTPStatus(500),
                                "Subrequest Plan Was Not Prepared",
                            )
                        })?;
                    self.proxy_subrequest(session, ctx, &prepared).await
                } else if config.fastcgi.is_some() {
                    self.fastcgi_proxy(session, ctx, route_index, config).await
                } else {
                    Ok(false)
                }
            }
            // 🔐 `forward_auth` answers inline because its 2xx branch must
            // fall through to the next handler — something the Pingora
            // upstream lifecycle cannot do after a response arrives.
            HandlerConfig::ForwardAuth(config) => {
                self.forward_auth(session, ctx, route_index, config).await
            }
            // 🚫 Unreachable by construction — `validate_config` refuses a
            // `plugin` handler, so no accepted configuration contains one.
            // It is answered rather than ignored anyway: this used to be a
            // wildcard arm that returned "not handled", which made an
            // unimplemented handler indistinguishable from a route that
            // deliberately falls through. A loud 500 beats a silent bypass.
            // 🏛️ Same reasoning as `plugin` below: startup refuses a
            // configuration with an ACME server, so this cannot be reached.
            // Failing loudly keeps that true if the refusal is ever loosened.
            HandlerConfig::AcmeServer(_) => {
                tracing::error!(
                    "🚫 An acme_server handler reached the request path, which startup should \
                     have refused; failing closed"
                );
                Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::InternalError,
                    "acme_server handler is not implemented",
                ))
            }
            HandlerConfig::Plugin { name, .. } => {
                tracing::error!(
                    plugin = %name,
                    "🚫 A plugin handler reached the request path, which validation should \
                     have refused; failing closed"
                );
                Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::InternalError,
                    "plugin handler is not implemented",
                ))
            }
        }
    }
}

// MARK: - Caddy Placeholder Resolution

// MARK: - Response cache

/// 🗄️ The memory store survives reloads alongside its resizable eviction manager.
pub(crate) fn response_cache_storage() -> &'static MemCache {
    static STORAGE: OnceLock<MemCache> = OnceLock::new();
    STORAGE.get_or_init(MemCache::new)
}

/// 🧮 Applies the complete document's process-wide cache ceiling at publication.
pub fn configure_response_cache(servers: &[ServerConfig]) {
    crate::cache_budget::configure(servers);
}

/// 🔑 Where a route's consistent-hash key is read from.
///
/// Resolved once at configuration time — the strategy name and the field name
/// never change per request, so parsing them per request would be work the
/// configuration already settled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HashKeySource {
    Header(String),
    Cookie(String),
    Query(String),
}

/// 🔑 Reads the value a route hashes on, or `None` when the request does not
/// carry it.
///
/// Returning `None` is deliberate and matters: it makes the balancer fall back
/// to its default selection for that request rather than hashing an empty
/// string. Hashing `""` would send every client that omits the header to the
/// same backend — a hot spot that looks like a load-balancing bug and is
/// really a configuration one.
fn extract_hash_key(request: &RequestHeader, source: &HashKeySource) -> Option<Vec<u8>> {
    // 🍃 Every arm borrows from the request; the one copy is made at the end,
    // because the balancer takes an owned key.
    let value: &str = match source {
        HashKeySource::Header(name) => request
            .headers
            .get(name.as_str())
            .and_then(|value| value.to_str().ok())?,

        HashKeySource::Cookie(name) => affinity_cookie(&request.headers, name)?,

        HashKeySource::Query(name) => request.uri.query().and_then(|query| {
            query.split('&').find_map(|pair| {
                let (key, value) = pair.split_once('=')?;
                (key == name).then_some(value)
            })
        })?,
    };

    // 🚫 A present-but-empty value is the same hot-spot problem as an absent
    // one, so it is treated the same way.
    (!value.is_empty()).then(|| value.as_bytes().to_vec())
}

/// 🍪 The value of cookie `name` that session affinity hashes on.
///
/// Every `Cookie` field line is read, not only the first: an HTTP/1.1 client
/// may send several, and a cookie on the second line is still a cookie the
/// client sent. Splitting each pair on its first `=` keeps values that
/// themselves contain `=`, which base64 session identifiers routinely do.
///
/// 🎯 A name can appear more than once — a browser holding `sid` for
/// `Path=/` and another `sid` for `Path=/app` sends both — and RFC 6265
/// §4.2.2 says a server should not rely on the order they arrive in. Taking
/// the first match did exactly that, so the same user could be pinned to a
/// different backend depending on how their client serialized the cookies.
/// The rule is instead order-independent: among the non-empty values, the
/// smallest by bytes wins. Any fixed choice would do; this one borrows.
fn affinity_cookie<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|line| line.to_str().ok())
        .flat_map(|line| line.split(';'))
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            let value = value.trim();
            (key.trim() == name && !value.is_empty()).then_some(value)
        })
        .min()
}

/// 🗄️ A read-only snapshot of the shared response store, for the admin API.
///
/// 🧮 The complete configuration establishes the ceiling before traffic.
/// A reload that removes caching leaves the retained manager at a zero limit.
#[derive(Debug, serde::Serialize)]
pub struct CacheStatus {
    pub configured: bool,
    pub size_bytes: usize,
    pub limit_bytes: usize,
    pub entries: usize,
    pub evicted_bytes_total: usize,
}

/// 🗄️ Reports what the shared response store currently holds.
pub fn cache_status() -> CacheStatus {
    match CACHE_EVICTION.get() {
        Some(eviction) => CacheStatus {
            configured: eviction.weight_limit() > 0,
            size_bytes: eviction.total_size(),
            limit_bytes: eviction.weight_limit(),
            entries: eviction.total_items(),
            evicted_bytes_total: eviction.evicted_size(),
        },
        None => CacheStatus {
            configured: false,
            size_bytes: 0,
            limit_bytes: 0,
            entries: 0,
            evicted_bytes_total: 0,
        },
    }
}

/// 🧹 Drops one stored response, addressed exactly the way the request path
/// addresses it. Returns whether an entry was actually there.
///
/// Purging by URL rather than emptying the store is deliberate: an operator
/// purges because one page changed, and throwing away every other route's
/// warm entries to fix one of them turns a small correction into a traffic
/// spike at the origin.
///
/// 🔑 The key is built by the same [`crate::cache_key::primary`] as
/// [`ProxyService::cache_key_callback`], once per route scope, because the
/// same URL may be stored separately by every route that caches it. If the two
/// ever disagree, purge silently stops working — which is why the caller gets
/// a boolean rather than a cheerful unconditional success.
pub async fn purge_cached_response(host: &str, path_and_query: &str) -> bool {
    let mut purged = false;
    for scope in crate::cache_key::known_scopes() {
        purged |= purge_cached_entry(crate::cache_key::primary(&scope, host, path_and_query)).await;
    }
    purged
}

/// 🧹 Drops the one stored response with this primary key, keeping the
/// eviction accounting in step.
async fn purge_cached_entry(primary: Vec<u8>) -> bool {
    use pingora_cache::eviction::CacheEntryKeyRef;
    use pingora_cache::key::CacheKey;
    use pingora_cache::storage::{PurgeOutcome, PurgeTarget, PurgeType, Storage};

    let key = CacheKey::new(primary, "").to_compact();
    let outcome = Storage::purge(
        response_cache_storage(),
        PurgeTarget::Active(&key),
        PurgeType::Invalidation,
        &pingora_cache::trace::Span::inactive().handle(),
    )
    .await
    .ok();
    let Some(PurgeOutcome::Purged(entry_id)) = outcome else {
        return false;
    };

    // 🧮 Keep the eviction manager's accounting in step with the store, or the
    // size gauge drifts upward forever and the ceiling starts evicting entries
    // that are no longer there.
    if let Some(eviction) = CACHE_EVICTION.get() {
        eviction.remove(CacheEntryKeyRef::from_entry_id(&key, entry_id));
        metrics::CACHE_SIZE_BYTES.set(eviction.total_size() as i64);
    }
    true
}

/// 🚫 Recognizes only cache-bypass directives, across every field line, without
/// mistaking an extension name or a directive value for a request to bypass.
fn request_cache_control_bypasses_cache(headers: &http::HeaderMap) -> bool {
    headers
        .get_all(http::header::CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|directive| {
            let name = directive
                .split_once('=')
                .map_or(directive, |(name, _)| name);
            let name = name.trim();
            name.eq_ignore_ascii_case("no-store") || name.eq_ignore_ascii_case("no-cache")
        })
}

/// 🔮 Remembers which keys turned out to be uncacheable, so the next request
/// for one skips the lock and the storage lookup and goes straight upstream.
///
/// Without it every request for a permanently uncacheable URL — anything that
/// sets a cookie, any SSE endpoint — pays for a cache miss it can never win,
/// and worse, queues behind the single-flight lock while one of them proves it
/// again. The predictor is a bounded bloom-style filter, so it costs a fixed
/// amount of memory and can only ever be wrong in the safe direction: a false
/// "probably cacheable" just means doing the full check, which is what would
/// have happened anyway.
fn response_cache_predictor() -> &'static Predictor<32> {
    static PREDICTOR: OnceLock<&'static Predictor<32>> = OnceLock::new();
    PREDICTOR.get_or_init(|| Box::leak(Box::new(Predictor::new(8192, None))))
}

/// 🔒 Collapses concurrent misses for the same key into one upstream request.
///
/// Without it, N clients arriving together for an uncached URL become N origin
/// requests — the thundering herd that caching is supposed to prevent. The
/// timeout bounds how long a waiter blocks before giving up and going to the
/// origin itself, so a slow origin degrades into today's behaviour rather than
/// into a stall.
fn response_cache_lock() -> &'static CacheKeyLockImpl {
    static LOCK: OnceLock<&'static CacheKeyLockImpl> = OnceLock::new();
    // 📌 The extra deref is load-bearing: `get_or_init` hands back a
    // reference *to* the stored `&'static` pointer, and a `&&dyn Trait` will
    // not coerce to `&dyn Trait` the way a sized type would.
    *LOCK.get_or_init(|| {
        let lock: &'static CacheLock = Box::leak(CacheLock::new_boxed(Duration::from_secs(2)));
        lock as &'static CacheKeyLockImpl
    })
}

/// 🗄️ Counts one cacheable request under the outcome it reached, and refreshes
/// the store's size gauges from the eviction manager.
///
/// The gauges are read here rather than pushed from the storage layer because
/// Pingora owns the accounting and exposes it on the manager; sampling it once
/// per cacheable request keeps the two from drifting, at the cost of the value
/// being as fresh as the last request rather than the last second. For a
/// ceiling you are watching for saturation, that is the right trade.
fn record_cache_outcome(session: &Session, host: &str, route: &str) {
    use pingora_cache::CachePhase;

    // 🍃 Off by default, so a cached site pays nothing here unless the
    // configuration asked for metrics.
    if !metrics::enabled() {
        return;
    }

    // 🏷️ `Bypass` covers everything deliberately refused storage, which is the
    // outcome an operator most often needs to explain ("why is nothing being
    // cached?"). Phases that mean the request never reached a decision are not
    // counted at all rather than being folded into `miss`, which would make the
    // hit ratio quietly wrong.
    let outcome = match session.cache.phase() {
        CachePhase::Hit => "hit",
        CachePhase::Miss | CachePhase::Expired => "miss",
        CachePhase::Stale | CachePhase::StaleUpdating => "stale",
        CachePhase::Bypass => "bypass",
        _ => return,
    };
    // 🛡️ Same reasoning as the request metrics: `host` comes from the client.
    let host = metrics::host_label(host);
    metrics::CACHE_REQUESTS_TOTAL
        .with_label_values(&[host.as_ref(), route, outcome])
        .inc();

    if let Some(eviction) = CACHE_EVICTION.get() {
        metrics::CACHE_SIZE_BYTES.set(eviction.total_size() as i64);
        metrics::CACHE_EVICTED_BYTES_TOTAL.set(eviction.evicted_size() as i64);
    }
}

/// Resolve Caddy-style `{placeholder}` variables in a header value string
/// using the actual downstream request headers.
///
/// Supported placeholders:
/// - `{http.request.header.Header-Name}` → value of the named request header
/// - `{host}`                            → request Host header
/// - 🛡️ `{client_ip}`                    → verified client IP
/// - 🔌 `{remote_host}` / `{remote_port}` → the connection's immediate peer
/// - `{http.request.method}`             → HTTP method
/// - `{http.request.uri}`                → full URI
/// - `{http.request.uri.path}`           → URI path only
///
/// If a placeholder references a header that doesn't exist, it resolves to
/// an empty string (matching Caddy's behavior).
pub(crate) fn resolve_caddy_placeholders<'a>(
    template: &'a str,
    req: &'a RequestHeader,
    verified_client_ip: Option<&'a str>,
    scheme: &'static str,
    vars: &crate::http_policy::RequestVars,
) -> std::borrow::Cow<'a, str> {
    if !template.contains('{') {
        // ⚡ OPTIMIZATION: Fast path — no placeholders, return as-is.
        return std::borrow::Cow::Borrowed(template);
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
            let resolved =
                resolve_single_placeholder(&placeholder, req, verified_client_ip, scheme, vars);
            result.push_str(&resolved);
        } else {
            result.push(c);
        }
    }

    std::borrow::Cow::Owned(result)
}

/// 🧭 Resolves rewrite operands against one request, borrowing from the
/// configuration whenever an operand is a literal.
///
/// A `uri` operation's operands are templates — `uri strip_prefix
/// /api/{re.tenant.1}` names a prefix that only exists once the matcher has
/// run — so each one has to be resolved before the path is touched. Results
/// borrow the configured text rather than the request, which is what lets the
/// caller resolve every operand first and then hand the request to the rewrite
/// mutably.
pub(crate) struct RewriteOperands<'r> {
    pub(crate) req: &'r RequestHeader,
    pub(crate) verified_client_ip: Option<&'r str>,
    pub(crate) scheme: &'static str,
    pub(crate) vars: &'r crate::http_policy::RequestVars,
}

impl RewriteOperands<'_> {
    /// 🏎️ A literal operand, the overwhelmingly common case, comes back as the
    /// configured `&str` itself: no copy, nothing beyond the one `{` search.
    pub(crate) fn resolve<'t>(
        &self,
        operand: Option<&'t str>,
    ) -> Option<std::borrow::Cow<'t, str>> {
        let template = operand?;
        if !template.contains('{') {
            return Some(std::borrow::Cow::Borrowed(template));
        }
        Some(std::borrow::Cow::Owned(
            resolve_caddy_placeholders(
                template,
                self.req,
                self.verified_client_ip,
                self.scheme,
                self.vars,
            )
            .into_owned(),
        ))
    }
}

/// 🧱 `fmt::Write` target backed by a fixed stack buffer, so short header
/// values (IP addresses and `Forwarded` fields) are formatted without a
/// per-request heap allocation.
struct StackBuf<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl std::fmt::Write for StackBuf<'_> {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        let end = self.len + text.len();
        if end > self.buf.len() {
            return Err(std::fmt::Error);
        }
        self.buf[self.len..end].copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// 🌐 Formats one IP into caller-owned stack storage and returns its length.
fn write_ip(ip: IpAddr, buf: &mut [u8; 64]) -> usize {
    let mut out = StackBuf { buf, len: 0 };
    write!(out, "{ip}").expect("IPv4/IPv6 addresses fit a 64-byte buffer");
    out.len
}

/// 🌐 Formats one client IP into a reusable `HeaderValue`.
///
/// Every standard forwarding header starts from the same address; building
/// the value once means X-Real-IP and X-Forwarded-For clone a shared-bytes
/// reference (one atomic increment) instead of each formatting and copying
/// its own string.
fn ip_header_value(ip: IpAddr) -> http::HeaderValue {
    let mut buf = [0u8; 64];
    let len = write_ip(ip, &mut buf);
    http::HeaderValue::from_str(std::str::from_utf8(&buf[..len]).expect("ASCII address"))
        .expect("formatted address is a valid header value")
}

/// 🔀 Formats the `Forwarded` `for=` parameter for one client IP.
///
/// 🛡️ Shared with HTTP/3, which has to rebuild the same field: the client's own
/// `Forwarded` is dropped as unverifiable, so something has to put the verified
/// identity back or the origin simply loses it.
pub(crate) fn forwarded_header_value(ip: IpAddr) -> http::HeaderValue {
    let mut buf = [0u8; 96];
    let len = {
        let mut out = StackBuf {
            buf: &mut buf,
            len: 0,
        };
        match ip {
            IpAddr::V4(address) => {
                write!(out, "for={address}").expect("IPv4 Forwarded fits a 96-byte buffer");
            }
            IpAddr::V6(address) => {
                write!(out, "for=\"[{address}]\"").expect("IPv6 Forwarded fits a 96-byte buffer");
            }
        }
        out.len
    };
    http::HeaderValue::from_str(std::str::from_utf8(&buf[..len]).expect("ASCII address"))
        .expect("formatted Forwarded is a valid header value")
}

/// Resolve a single Caddy placeholder name to its value.
fn resolve_single_placeholder(
    name: &str,
    req: &RequestHeader,
    verified_client_ip: Option<&str>,
    scheme: &'static str,
    vars: &crate::http_policy::RequestVars,
) -> String {
    // 🏷️ Caddy's `{header.X}` shorthand for `{http.request.header.X}`, and the
    // long form, are one lookup. Every value of a repeated field is joined
    // with a comma, which is what Caddy reads out of `req.Header`
    // (`modules/caddyhttp/replacer.go`) and what a client that sent two
    // `X-Forwarded-Proto` fields expects to see.
    if let Some(header_name) = name
        .strip_prefix("http.request.header.")
        .or_else(|| name.strip_prefix("header."))
    {
        let mut joined = String::new();
        let mut first = true;
        for value in req.headers.get_all(header_name) {
            let Ok(value) = value.to_str() else {
                continue;
            };
            if !first {
                joined.push(',');
            }
            first = false;
            joined.push_str(value);
        }
        return joined;
    }
    // 🧭 `{query.X}` and `{http.request.uri.query.X}` are one query parameter,
    // read the way Go's `url.Values` exposes it. The bare `{query}` below is
    // the whole query string, which is a different thing.
    if let Some(parameter) = name
        .strip_prefix("http.request.uri.query.")
        .or_else(|| name.strip_prefix("query."))
    {
        return query_parameter(req.uri.query().unwrap_or_default(), parameter);
    }
    // 🧭 `{path.N}` and `{http.request.uri.path.N}` are path segments,
    // 0-based from the left; `dir` and `file` are Go's `path.Split` halves
    // (`modules/caddyhttp/replacer.go`). A suffix that is neither is not a
    // placeholder this resolver knows, so the name is left as written.
    if let Some(suffix) = name
        .strip_prefix("http.request.uri.path.")
        .or_else(|| name.strip_prefix("path."))
        && let Some(part) = path_part(req.uri.path(), suffix)
    {
        return part;
    }
    // 🧰 `{http.vars.<name>}` reads a request-scoped variable set by a
    // `vars` handler or rule; an unset variable is empty, like every other
    // missing placeholder.
    if let Some(var_name) = name.strip_prefix("http.vars.") {
        return vars.get(var_name).unwrap_or("").to_string();
    }
    // 🧭 `{http.request.orig_uri.*}` (captured before rewrites),
    // `{http.matchers.file.*}` (published by the file matcher) and
    // `{http.reverse_proxy.status_code}` (published while response handlers
    // run) all live in the request-scoped variable map.
    if name.starts_with("http.request.orig_uri.")
        || name.starts_with("http.matchers.file.")
        || name == "http.reverse_proxy.status_code"
    {
        return vars.get(name).unwrap_or("").to_string();
    }
    // 🔍 `{re.<name>.<index>}`, `{re.<index>}` and named groups read regexp
    // captures recorded by `path_regexp`/`header_regexp` matchers into the
    // same request-scoped map.
    if name == "re" || name.starts_with("re.") {
        return vars.get(name).unwrap_or("").to_string();
    }
    // 🚨 `{err.*}` and its long form `{http.error.*}` describe the error that
    // entered an error route. Caddy's Caddyfile adapter rewrites the short
    // spelling into the long one before the config is stored, so a file may
    // carry either; both read the same three values here.
    //
    // 🚧 `{err.trace}` and `{err.id}` are the error's origin and an identifier
    // for this occurrence. Nothing here records either, so they resolve to the
    // empty string — the format's behaviour for a name it does not know —
    // rather than to an invented value.
    if let Some(field) = name
        .strip_prefix("err.")
        .or_else(|| name.strip_prefix("http.error."))
    {
        let key = match field {
            "status_code" | "status" => "err.status_code",
            "status_text" => "err.status_text",
            "message" => "err.message",
            _ => return String::new(),
        };
        return vars.get(key).unwrap_or("").to_string();
    }

    // 🧭 Caddy's `{host}` shorthand is the hostname without the port; the
    // port lives in `{hostport}` instead. Stripping it here keeps
    // `redir https://{host}{uri}` correct on non-standard ports.
    let host_without_port = |host: &str| -> String {
        if let Some((name, _)) = host.rsplit_once(':')
            && !host.starts_with('[')
        {
            name.to_string()
        } else {
            host.to_string()
        }
    };
    // 🌐 Where the site name lives depends on the protocol: HTTP/1.1 sends a
    // `Host` header, HTTP/2 and HTTP/3 send `:authority`, which Pingora keeps
    // in the URI and does not copy into a header. `request_authority` already
    // knows both and is the one place that rule is written down — reading the
    // header directly here is what made every one of these placeholders
    // resolve to nothing over HTTP/2.
    let authority = crate::http_policy::request_authority(req);
    match name {
        "host" | "http.request.host" => host_without_port(authority),
        "hostport" | "http.request.hostport" => authority.to_string(),
        "port" | "http.request.port" => authority
            .rsplit_once(':')
            .filter(|_| !authority.starts_with('['))
            .map(|(_, port)| port.to_string())
            .unwrap_or_default(),
        // 🧭 `{query}` is the bare query string; `{?query}` keeps the leading
        // `?` (Caddy's prefixed_query shorthand).
        "query" | "http.request.uri.query" => req
            .uri
            .to_string()
            .split_once('?')
            .map(|(_, query)| query.to_string())
            .unwrap_or_default(),
        "?query" => req
            .uri
            .to_string()
            .split_once('?')
            .map(|(_, query)| format!("?{query}"))
            .unwrap_or_default(),
        // 🧭 `{labels.N}` is the hostname split on dots, indexed from the
        // right: `{labels.0}` is the TLD, `{labels.1}` the registrable label.
        _label if name.starts_with("labels.") || name.starts_with("http.request.host.labels.") => {
            let raw = name
                .strip_prefix("http.request.host.labels.")
                .or_else(|| name.strip_prefix("labels."))
                .unwrap_or("");
            let host = host_without_port(authority);
            let labels: Vec<&str> = host.split('.').collect();
            raw.parse::<usize>()
                .ok()
                .and_then(|index| labels.get(labels.len() - 1 - index))
                .unwrap_or(&"")
                .to_string()
        }
        // 🛡️ `{client_ip}` is the client after `trusted_proxies`: the forwarded
        // address when the peer is a trusted proxy, the peer otherwise. An
        // untrusted `X-Forwarded-For` cannot forge it. Our old `{remote_ip}`
        // spelling of it is refused when the configuration loads.
        "client_ip" | "http.request.client_ip" => verified_client_ip.unwrap_or("").to_string(),
        // 🔌 `{remote_host}`, `{remote_port}` and `{remote}` are the socket
        // peer, whatever any header claims, as in Caddy. Behind a load
        // balancer they name the balancer, which is what makes them useful for
        // telling one hop from another; the client is `{client_ip}`.
        "remote_host" | "http.request.remote.host" => vars
            .remote()
            .map(|remote| remote.ip().to_string())
            .unwrap_or_default(),
        "remote_port" | "http.request.remote.port" => vars
            .remote()
            .filter(|remote| remote.port() != 0)
            .map(|remote| remote.port().to_string())
            .unwrap_or_default(),
        // 🌐 `SocketAddr` renders IPv6 bracketed (`[::1]:443`), the same
        // `host:port` shape Go gives a request's remote address.
        "remote" | "http.request.remote" => vars
            .remote()
            .map(|remote| remote.to_string())
            .unwrap_or_default(),
        "method" | "http.request.method" => req.method.as_str().to_string(),
        // 🧭 `{scheme}` is what the *client* used, which is why it is passed in
        // rather than derived here: a request arriving over a plaintext
        // listener behind a trusted proxy that terminated TLS is `https`, and
        // the request header alone cannot say so.
        "scheme" | "http.request.scheme" => scheme.to_string(),
        // 🧭 `{uri}` is Caddy's shorthand for the full request target, and it is
        // what `redir https://{host}{uri}` depends on.
        // 🧭 Path and query, never the scheme and authority. Rendering the
        // whole URI hands back whatever the protocol put in it, and HTTP/2
        // puts the site name there — so `{uri}` meant one thing on HTTP/1.1
        // and another on HTTP/2 for the identical request.
        "uri" | "http.request.uri" => req
            .uri
            .path_and_query()
            .map(|target| target.as_str().to_string())
            .unwrap_or_else(|| req.uri.path().to_string()),
        "path" | "http.request.uri.path" => req.uri.path().to_string(),
        // 🗂️ The bare shorthands for the two halves of `path.Split`; their
        // long forms were handled above, where the suffix is read.
        "dir" => path_part(req.uri.path(), "dir").unwrap_or_default(),
        "file" => path_part(req.uri.path(), "file").unwrap_or_default(),
        _ => {
            // 🚧 Still missing: {dir}, {file}, {file.*}, {re.*}, {env.*},
            // {http.vars.*}, {err.*}.
            //
            // 🧭 An unknown name is left exactly as written, which is what
            // Caddy's replacer does: a body carrying literal braces — JSON,
            // JavaScript, documentation — survives, and a `header_down` value
            // such as `{some.unknown.thing}` stays readable as a debugging
            // tool. Erasing it was the only answer that silently changed
            // content the operator wrote (#260).
            //
            // 🤡 This list used to name `{scheme}` and `{method}` too, six and
            // eleven lines above where both are handled. On 2026-08-07 a survey
            // read the stale comment instead of the match arms and filed both
            // as unimplemented, which put a day of planned work into the queue
            // for features that already existed. A comment that outlives what
            // it describes does not announce itself; it just gets believed.
            tracing::debug!("⚠️ Unresolved Caddy placeholder: {{{}}}", name);
            format!("{{{name}}}")
        }
    }
}

/// 🧭 One `{path.*}` part: a segment index, the directory, or the file name.
///
/// The split mirrors Caddy's: the path is split on `/`, the leading empty
/// element is dropped, and an index past the end is empty rather than unknown.
/// Middle empty segments stay, so `/a//b` has three parts.
fn path_part(path: &str, suffix: &str) -> Option<String> {
    match suffix {
        // 🗂️ Go's `path.Split`: everything up to and including the last
        // slash, and everything after it.
        "dir" => Some(path.rsplit_once('/').map_or_else(String::new, |(dir, _)| {
            let mut with_slash = dir.to_string();
            with_slash.push('/');
            with_slash
        })),
        "file" => Some(
            path.rsplit_once('/')
                .map_or_else(|| path.to_string(), |(_, file)| file.to_string()),
        ),
        index => {
            let index: usize = index.parse().ok()?;
            let mut parts: Vec<&str> = path.split('/').collect();
            if parts.first() == Some(&"") {
                parts.remove(0);
            }
            Some(parts.get(index).copied().unwrap_or("").to_string())
        }
    }
}

/// 🧭 One query parameter the way Go's `url.Values` exposes it: every
/// occurrence, percent-decoded, joined with a comma.
///
/// 📌 `+` is a space here and not in a path component, and a malformed escape
/// drops the pair rather than the whole query — both are `url.ParseQuery`'s
/// behaviour, which `req.URL.Query()` exposes.
fn query_parameter(query: &str, wanted: &str) -> String {
    let mut joined = String::new();
    let mut first = true;
    for pair in query.split('&') {
        let (name, raw) = pair.split_once('=').unwrap_or((pair, ""));
        if decode_query_component(name).as_deref() != Some(wanted) {
            continue;
        }
        let Some(value) = decode_query_component(raw) else {
            continue;
        };
        if !first {
            joined.push(',');
        }
        first = false;
        joined.push_str(&value);
    }
    joined
}

/// 🔤 Percent-decodes one query component, or `None` when the escape is
/// malformed.
fn decode_query_component(raw: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(raw.len());
    let mut chars = raw.bytes();
    while let Some(byte) = chars.next() {
        match byte {
            b'+' => bytes.push(b' '),
            b'%' => {
                let digits = [chars.next()?, chars.next()?];
                bytes.push(u8::from_str_radix(std::str::from_utf8(&digits).ok()?, 16).ok()?);
            }
            other => bytes.push(other),
        }
    }
    String::from_utf8(bytes).ok()
}

// MARK: - ProxyHttp Trait

/// 📉 The severity a request failure deserves in the log.
///
/// A client that goes away mid-request is *routine*: a browser navigating
/// away, a user pressing stop, a phone changing cell, a load balancer
/// recycling idle connections. Reporting that at ERROR buries the failures an
/// operator can actually act on. One `wrk -c200` run closing its connections
/// produced 225 ERROR lines in a single second here, none of which described
/// anything wrong with the server — and 727,414 requests had just succeeded.
///
/// The classification follows the error's *source*, which is the only thing
/// that answers "whose fault is this":
///
/// - **Downstream** means Pingora attributes the failure to the remote
///   client. A closed connection or a failed read/write on that connection is
///   the client leaving, so it is DEBUG. Anything else the client did wrong —
///   malformed framing, a bad request line — is nameable and worth WARN, but
///   it is still not a server error.
/// - **Upstream, Internal and Unset** are ours or the origin's, and stay at
///   ERROR.
///
/// nginx logs a prematurely closed client connection at `info`, and Caddy at
/// `debug`; neither treats it as an error.
fn failure_severity(error: &pingora_core::Error) -> tracing::Level {
    use pingora_core::{ErrorSource, ErrorType};

    match error.esource() {
        ErrorSource::Downstream => match error.etype() {
            // 🔌 The client's connection ended. Nothing here is actionable.
            ErrorType::ConnectionClosed | ErrorType::ReadError | ErrorType::WriteError => {
                tracing::Level::DEBUG
            }
            // 🚫 The client did something specific and wrong. Visible, but
            // still not a fault of this server.
            _ => tracing::Level::WARN,
        },
        _ => tracing::Level::ERROR,
    }
}

/// 🔊 Emits one event at a level chosen at runtime.
///
/// `tracing`'s macros need the level as a compile-time constant, so a
/// runtime decision has to fan out into one arm per level. Keeping that in a
/// macro means the call sites read as a single log statement instead of
/// repeating every structured field three times.
macro_rules! log_at_level {
    ($level:expr, $($field:tt)*) => {
        match $level {
            tracing::Level::DEBUG => tracing::debug!($($field)*),
            tracing::Level::WARN => tracing::warn!($($field)*),
            _ => tracing::error!($($field)*),
        }
    };
}

/// 🔁 The policy a request without a proxy route is judged by.
///
/// Shared rather than built per failure: the retry decision runs on every
/// upstream response, and cloning a route's policy there copied its whole
/// predicate tree — a heap allocation per response for a question that only
/// needs to borrow it.
static DEFAULT_RETRY_POLICY: std::sync::LazyLock<RetryConfig> =
    std::sync::LazyLock::new(RetryConfig::default);

/// 🔁 Applies Pingora's reuse-safety rule, the replay-safety rule, and the route
/// retry budget to an upstream error before the retry loop reads it.
///
/// Pingora marks response-phase errors `ReusedOnly`; the default
/// `error_while_proxy` resolves that marker with `decide_reuse`, and the
/// retry loop panics ("Retry is not decided") when a custom override returns
/// the error unchanged. This helper restores that contract, then caps the
/// final decision.
///
/// 🛡️ `body_is_empty` is the important one, and it is why this failure phase
/// needs its own gate rather than inheriting Pingora's answer. An error here
/// means the connection was already established and the request was already
/// going out, so the origin may have received all of it and acted on it — the
/// failure could be nothing more than the reply going missing on the way back.
/// Pingora's `retry_buffer_truncated` only reports whether the body was *too
/// large to buffer*; a body that fits is replayed happily, which turns one
/// `POST` into two. "Ambiguous" has to resolve to "do not repeat it".
///
/// 🛡️ The body is only half of it: a bodyless `POST` can place an order just
/// as well, so `request_is_repeatable` also requires an idempotent method (see
/// `retry::request_is_repeatable`). Connection-phase failures do not come
/// through here — `fail_to_connect` owns those, and the origin never saw the
/// request, so any method stays retryable there.
fn decide_upstream_error_retry(
    e: &mut pingora_core::Error,
    client_reused: bool,
    retry_buffer_truncated: bool,
    request_is_repeatable: bool,
    retry_policy: &RetryConfig,
    attempts: usize,
    retry_deadline: Option<std::time::Instant>,
) -> bool {
    // 🧭 Always decided, whatever the answer: leaving the marker unresolved is
    // what makes the retry loop panic.
    e.retry
        .decide_reuse(client_reused && !retry_buffer_truncated);
    let budget_allows =
        crate::retry::permits_another_attempt(retry_policy, attempts, retry_deadline);
    let retry = request_is_repeatable && budget_allows && e.retry();
    e.retry = retry.into();
    retry
}

#[async_trait]
impl ProxyHttp for PingclairProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        // 🚰 Counted here rather than in `Default`, so only a request Pingora
        // actually hands over can hold shutdown open, and the token ends with
        // the context whether the request finished, failed, or was abandoned.
        RequestContext {
            _in_flight: Some(crate::drain::InFlight::enter()),
            ..RequestContext::default()
        }
    }

    /// Register downstream modules that run on every response written
    /// through this proxy (both locally generated and upstream-proxied),
    /// which is exactly the property Alt-Svc advertisement needs.
    fn init_downstream_modules(&self, modules: &mut pingora_core::modules::http::HttpModules) {
        modules.add_module(Box::new(crate::alt_svc::AltSvcModuleBuilder::new(
            self.alt_svc.clone(),
        )));
        // 🗜️ Compression runs as a downstream module so it applies after the
        // cache has stored the origin's bytes, and so it sees the `Done` that
        // ends a body served out of the cache.
        modules.add_module(Box::new(
            crate::response_encoding::ResponseEncodingModuleBuilder,
        ));
    }

    /// 🧾 Rejects decoded headers that exceed the selected virtual host's explicit bounds.
    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()> {
        let request = session.req_header();
        let host = crate::http_policy::request_host(crate::http_policy::request_authority(request));
        let generation = self.request_generation(ctx);
        let Some(state) = generation.routes().get(host.as_ref()) else {
            return Ok(());
        };
        let breach = crate::header_limits::check(
            &state.config.limits,
            request.headers.len(),
            request
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_bytes().len())),
        );
        // 🧭 Kept for `request_filter`, which would otherwise look the host
        // up again, and for the 431 below: without a state the error-page
        // lookup finds no site and the configured page is unreachable.
        let detail = breach.as_ref().and_then(|breach| breach.detail());
        ctx.state = Some(state);
        if breach.is_some() {
            ctx.error_detail = detail;
            ctx.refused_before_routing = true;
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

    /// 🗄️ Turns caching on for this request, or leaves it off.
    ///
    /// Runs after `request_filter`, so the matched route is already in `ctx`.
    /// Everything here is a reason *not* to cache: the route has to ask for it,
    /// and the request has to be one where a shared copy is meaningful. Getting
    /// this wrong does not fail loudly — it serves one visitor's response to
    /// somebody else — so the conditions are deliberately narrow.
    fn request_cache_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()> {
        // 🔢 Copied out of the borrowed policy immediately: the rest of this
        // function mutates `ctx`, and there is nothing else to read from it.
        let Some((cache_ttl_secs, cache_max_size_bytes)) = self
            .route_cache_config(ctx)
            .map(|cache| (cache.ttl_secs, cache.max_size_bytes))
        else {
            return Ok(());
        };

        if !Self::request_may_be_served_from_cache(session) {
            return Ok(());
        }

        // 🔑 No scope means the entry could not be told apart from another
        // route's, so this route is not cached at all rather than shared.
        let Some((state, route_index)) = ctx.state.as_ref().zip(ctx.route_index) else {
            return Ok(());
        };
        // 🌊 Immediate-flush routes bypass storage before upstream selection.
        // 🧮 Their loaded policy is available before response flags are set.
        if state
            .route_streaming
            .get(route_index)
            .copied()
            .unwrap_or(false)
        {
            return Ok(());
        }

        let Some(route_scope) = state.cache_scopes.get(route_index) else {
            return Ok(());
        };
        // 🧭 A dial with placeholders reaches a different upstream per request,
        // so the upstream it resolves to joins the key, the way nginx's
        // `$proxy_host` does. It joins as a variant of the URL's entry rather
        // than as part of the primary key, so a purge by URL still reaches
        // every upstream's copy. Expanded here with the same inputs
        // `upstream_peer` uses; a dial that does not resolve is not cached,
        // and `upstream_peer` answers it with a 502 anyway.
        let cache_upstream = match state
            .dynamic_dials
            .get(route_index)
            .and_then(Option::as_ref)
        {
            None => None,
            Some(dial_plan) => {
                let verified_client_ip = ctx.verified_client_ip.map(|ip| ip.to_string());
                let Some(upstream) = dial_plan.resolve(
                    session.req_header(),
                    verified_client_ip.as_deref(),
                    &ctx.request_vars,
                ) else {
                    return Ok(());
                };
                Some(crate::cache_key::upstream_digest(&upstream))
            }
        };
        let cache_scope = route_scope;

        ctx.cache_ttl_secs = Some(cache_ttl_secs);
        ctx.cache_scope = Some(cache_scope);
        ctx.cache_upstream = cache_upstream;

        let Some(eviction) = CACHE_EVICTION.get() else {
            return Ok(());
        };
        session.cache.enable(
            response_cache_storage(),
            Some(eviction),
            Some(response_cache_predictor()),
            Some(response_cache_lock()),
            None,
        );

        // 📏 A ceiling on the *store* is not a ceiling on one response.
        //
        // Without this, a body far larger than the whole budget still streams
        // into the store, consuming memory the entire way, and is only evicted
        // once it has finished arriving and the eviction manager finally sees
        // its size. Day 22 measured it: one 20 MiB response through a cache
        // configured with a 64 KiB ceiling cost 7.6 MiB of resident memory
        // more than the same response with caching off — for an entry that was
        // then thrown away immediately.
        //
        // ⚠️ Must come after `enable`: the setter panics while the cache is
        // still in the `Disabled` phase.
        session
            .cache
            .set_max_file_size_bytes(cache_max_size_bytes.min(eviction.weight_limit()));
        ctx.cache_size_tracked = true;
        Ok(())
    }

    /// 🔑 Identifies a cached response by the parts that change what is served.
    ///
    /// The route's scope, then host, path and query — nginx's default
    /// `proxy_cache_key` is `$scheme$proxy_host$request_uri`, which names the
    /// upstream; the scope does the same job, and also separates two routes
    /// that share an upstream but not a guard. The method is not in the key
    /// because only safe methods reach here, and the scheme is not either: a
    /// route serves the same upstream bytes whichever way the client arrived.
    fn cache_key_callback(
        &self,
        session: &Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<CacheKey> {
        // 🛡️ `request_cache_filter` enables the cache only after setting the
        // scope, so this is unreachable; refusing beats sharing if it ever is.
        let Some(scope) = ctx.cache_scope.as_ref() else {
            return pingora_core::Error::e_explain(
                pingora_core::ErrorType::InternalError,
                "cache enabled without a route scope",
            );
        };
        let request = session.req_header();
        let host = request
            .headers
            .get("host")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let path_and_query = request
            .uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");

        Ok(CacheKey::new(
            crate::cache_key::primary(scope, host, path_and_query),
            "",
        ))
    }

    /// 🗄️ Decides whether an upstream response may be stored.
    ///
    /// Two stages: a short list of refusals this proxy owns, then RFC 9111's
    /// freshness rules. Anything a shared copy could get wrong is refused
    /// before the standard logic runs, because the cost of a wrong answer here
    /// is not an error — it is the wrong bytes, served repeatedly, in silence.
    fn response_cache_filter(
        &self,
        _session: &Session,
        response: &ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<RespCacheable> {
        let corrected_response = ctx
            .cache_revalidation_headers
            .as_ref()
            .map(|headers| headers.apply(response));
        let response = corrected_response.as_ref().unwrap_or(response);
        let Some(ttl_secs) = ctx.cache_ttl_secs else {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                "cache not enabled for this route",
            )));
        };

        if let Some(reason) = uncacheable_response_reason(response) {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(reason)));
        }

        // 📜 Pingora applies storage restrictions and sanitizes private fields;
        // RFC 9111 age accounting below supplies the time already spent upstream.
        let cache_control = CacheControl::from_resp_headers(response);
        if crate::cache_policy::strips_vary(cache_control.as_ref()) {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                "origin keeps Vary out of the stored copy",
            )));
        }
        let decision = filters::resp_cacheable(
            cache_control.as_ref(),
            response.clone(),
            // 🛡️ Requests carrying credentials never reach here: they are
            // refused before the cache is enabled at all.
            false,
            cache_defaults(),
        );

        // ⏳ The route's `ttl` is a fallback, not an override — the same shape
        // as nginx's `proxy_cache_valid`. An origin that states its own
        // lifetime knows more about its content than the proxy config does,
        // so it wins; the route only answers for responses that say nothing.
        //
        // 🔐 Age correction retains Pingora's sanitized stored headers. Raw
        // clock fields must not restore fields stripped by private or no-cache.
        let RespCacheable::Cacheable(meta) = decision else {
            return Ok(decision);
        };
        let delay = ctx
            .cache_request_started
            .map_or(Duration::ZERO, |started| started.elapsed());
        match origin_freshness(cache_control.as_ref(), response) {
            OriginFreshness::Stated => {
                let lifetime = Duration::from_secs(meta.fresh_sec());
                return Ok(crate::cache_age::account(
                    meta,
                    response,
                    cache_control.as_ref(),
                    lifetime,
                    delay,
                ));
            }
            OriginFreshness::StaleOnArrival => {
                // 🔁 One second in the past is how Pingora itself stores a
                // response that must be revalidated before every reuse.
                tracing::debug!(
                    status = response.status.as_u16(),
                    "🔁 origin sent conflicting Expires; stored stale, route ttl not applied"
                );
                return Ok(crate::cache_age::account(
                    meta,
                    response,
                    cache_control.as_ref(),
                    Duration::ZERO,
                    delay,
                ));
            }
            OriginFreshness::Silent => {}
        }

        // 🚫 Pingora only reaches here through `cache_defaults`, which lists the
        // same statuses, so `None` means the two tables drifted apart. Refusing
        // is the safe answer to that: nothing is stored for longer than meant.
        let Some(fresh_for) = heuristic_lifetime(response.status, Duration::from_secs(ttl_secs))
        else {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                "no lifetime for this status",
            )));
        };
        Ok(crate::cache_age::account(
            meta,
            response,
            cache_control.as_ref(),
            fresh_for,
            delay,
        ))
    }

    /// 🎯 Builds the variance key from the request fields `Vary` names, and
    /// from the upstream a placeholder dial resolved to.
    ///
    /// Without this a response that differs by request header is stored under a
    /// key that cannot tell the variants apart, and the first one stored is
    /// served to everyone. `Vary: *` is handled earlier by refusing to store at
    /// all, since it means "no two requests are interchangeable".
    fn cache_vary_filter(
        &self,
        meta: &CacheMeta,
        ctx: &mut Self::CTX,
        request: &RequestHeader,
    ) -> Option<HashBinary> {
        let vary = crate::cache_vary::variance(meta.headers(), &request.headers);
        match ctx.cache_upstream {
            None => vary,
            Some(upstream) => Some(crate::cache_key::with_variance(&upstream, vary)),
        }
    }

    /// Request filter (Handle static files and early return)
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<bool> {
        // 📦 Routes and client-auth policy come from one generation, loaded
        // once, so a reload that lands mid-request changes neither under it.
        // A reload therefore never has to refuse a request.
        let generation = self.request_generation(ctx);

        // 🌐 Before any middleware can reshape the URI: HTTP/2 keeps the site
        // name there and a rewrite would take it with it.
        Self::pin_request_authority(session.req_header_mut());
        // 🍪 Before any middleware reads a cookie, and before the request is
        // written to an upstream that is not HTTP/2.
        Self::join_split_cookies(session.req_header_mut());

        if self.proxy_protocol_required && self.proxy_protocol_identity(session).is_none() {
            tracing::warn!("🚫 Rejected a TCP request that bypassed the PROXY protocol ingress");
            session.as_mut().set_keepalive(None);
            Self::write_simple_response(session, ctx, 400, "PROXY Protocol Required").await?;
            return Ok(true);
        }

        // 📊 Track in-flight requests per virtual host; released in `logging`.
        let host = crate::http_policy::request_authority(session.req_header());
        let host = if host.is_empty() { "-" } else { host };
        ctx.active_connection_metric = metrics::request_started(host);

        // 🧭 Keep the URI before routing or handlers mutate it. `Uri::clone`
        // shares its backing bytes; owned placeholder variables are built only
        // after the selected site's configuration proves they can be observed.
        ctx.orig_uri = session.req_header().uri.clone();

        // 🛡️ Resolve the client identity once, before any answer can be
        // produced. A refused `Host`, refused framing, or a `Host` that names
        // no site still writes an access record, and every one of those used to
        // fall back to the session peer — which on a PROXY-protocol listener is
        // the ingress hop, so the traffic an operator goes looking for
        // (scanners, misdirected hosts) was logged as `127.0.0.1` (#281).
        // Neither input needs a site: the trusted-proxy policy is global and
        // the tunnel registry is per listener.
        let (transport_peer_ip, transport_client_ip, verified_client_ip) =
            self.downstream_identity(session, &session.req_header().headers);
        ctx.verified_client_ip = Some(verified_client_ip);
        ctx.remote_ip = Some(transport_client_ip.ip());

        // 🛡️ Framing is settled before anything else reads the request, because
        // a message whose length two parsers can read differently must not be
        // routed, logged as a normal request, or forwarded at all.
        {
            let request_header = session.req_header();

            // 🏠 RFC 9112 §3.2 makes this a MUST: exactly one well-formed Host,
            // or this proxy and the origin may resolve different virtual hosts.
            let host_rejection = crate::http_policy::check_request_host(
                request_header.version,
                &request_header.headers,
            )
            .err()
            .or_else(|| {
                request_header
                    .uri
                    .authority()
                    .filter(|authority| {
                        !crate::http_policy::request_host_is_valid(authority.as_str().as_bytes())
                    })
                    .map(|_| crate::http_policy::FramingRejection::MalformedHost)
            });
            if let Some(rejection) = host_rejection {
                tracing::warn!(
                    "🚫 Rejected a request whose Host cannot be resolved: {}",
                    rejection.reason()
                );
                if rejection != crate::http_policy::FramingRejection::MalformedHost
                    || !crate::http_policy::request_authority(session.req_header()).is_empty()
                {
                    // 🔌 Go closes malformed nonempty authorities and missing
                    // required Host. An empty Host keeps its measured 400 reuse.
                    session.as_mut().set_keepalive(None);
                }
                Self::write_simple_response(session, ctx, 400, rejection.reason()).await?;
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

        // 🪪 On a listener where some site demands a client certificate, the
        // name in the handshake and the name in `Host` have to be the same one.
        // Admission was decided from the ClientHello; routing is decided from
        // the header. Let them disagree and a client offers the site that asks
        // for nothing, gets in, then asks for the site that asks for a
        // certificate. 421 is the status for "this connection is not the right
        // one for that host", and the connection is closed so the client opens
        // a new one with honest SNI rather than reusing this one.
        if generation.requires_client_auth() {
            // 🏠 Owned only on the listeners that enforce this; every other
            // request never reaches past the atomic load above.
            // 🔤 Canonical, so `Host: EXAMPLE.com.` is compared as the name it
            // is rather than refused for its spelling.
            let requested_host = crate::http_policy::request_host(
                crate::http_policy::request_authority(session.req_header()),
            )
            .into_owned();
            if let Some(reason) =
                Self::strict_sni_host_rejection(&generation, session, &requested_host)
            {
                tracing::warn!(
                    host = %requested_host,
                    "🚫 Rejected a request on a mutual-TLS listener: {reason}"
                );
                session.as_mut().set_keepalive(None);
                Self::write_simple_response(session, ctx, 421, reason).await?;
                return Ok(true);
            }
        }

        // 🛡️ GHSA-f59h-q822-g45g: a header name containing `_` aliases its
        // hyphenated CGI/FastCGI form, so a client could inject the exact
        // identity headers `forward_auth copy_headers` is supposed to own.
        // Drop underscore-named headers before anything routes on them,
        // matching Caddy's default.
        let underscore_headers =
            crate::http_policy::underscore_named_fields(&session.req_header().headers);
        if !underscore_headers.is_empty() {
            // 👁️ The drop used to be invisible at every log level, which is
            // what made "the field is simply gone" a support-ticket mystery
            // (#269).
            tracing::debug!(
                fields = ?underscore_headers,
                "🚫 Dropped underscore-named request fields before routing"
            );
        }
        for name in underscore_headers {
            session.req_header_mut().remove_header(name.as_str());
        }

        // 🧭 Resolve `.` and `..` before anything routes on the path, so this
        // proxy and the origin agree on which resource was asked for. nginx and
        // Caddy both do this — and both leave interior empty segments alone,
        // which this does too — and the policy that matters is the one attached
        // to the resolved path.
        //
        // ⚠️ Only the path-and-query is rewritten, never the whole URI. An H2
        // request target is absolute (`https://host/path`), and rewriting it
        // wholesale would corrupt the authority.
        {
            let path_and_query = session
                .req_header()
                .uri
                .path_and_query()
                .map(|value| value.as_str());
            if let Some(current) = path_and_query
                && let Some(normalized) = crate::http_policy::normalize_request_path(current)
            {
                let mut parts = session.req_header().uri.clone().into_parts();
                match normalized.parse::<http::uri::PathAndQuery>() {
                    Ok(rebuilt) => {
                        tracing::debug!("🧭 Normalized request path to {}", normalized);
                        parts.path_and_query = Some(rebuilt);
                        match http::Uri::from_parts(parts) {
                            Ok(uri) => session.req_header_mut().set_uri(uri),
                            Err(_) => {
                                tracing::warn!(
                                    "🚫 Rejected a request path that could not be rebuilt"
                                );
                                Self::write_simple_response(session, ctx, 400, "Bad Request")
                                    .await?;
                                return Ok(true);
                            }
                        }
                    }
                    Err(_) => {
                        // 🚫 A path we cannot rebuild is one we cannot reason
                        // about, so it must not be routed on a guess.
                        tracing::warn!("🚫 Rejected a request path that could not be normalized");
                        Self::write_simple_response(session, ctx, 400, "Bad Request").await?;
                        return Ok(true);
                    }
                }
            }
        }

        // Handle ACME Challenges (HTTP-01)
        let request_header = session.req_header();
        let path = request_header.uri.path();

        // 🔐 Only the exact RFC 8555 §8.3 path shape is answered; a repeated
        // prefix or a nested segment falls through to normal routing.
        if let Some(token) = crate::acme_challenge::acme_challenge_token(path)
            && let Some(manager) = &self.tls_manager
        {
            // Lookup token in challenge handler
            let handler = manager.challenge_handler();
            if let Some(key_auth) = handler.get_token(token) {
                tracing::info!("🔐 Serving ACME challenge for token: {}", token);

                let mut header = pingora_http::ResponseHeader::build(200, Some(2))?;
                header.insert_header("Content-Type", "application/octet-stream")?;
                header.insert_header("Content-Length", key_auth.len())?;
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

        // Match route in a scope to release borrow of session. The textual IP
        // lives in stack storage because routing only borrows it; policy keeps
        // the already-parsed address separately.
        let mut remote_ip_buf = [0u8; 64];
        let (path_str, route_index, remote_ip_len, verified_client_ip, request_scheme) = {
            let request_header = session.req_header();
            let path = request_header.uri.path();
            let method = request_header.method.as_str();

            // 🌐 Prefer URI authority so HTTP/2 virtual hosts match the HTTP/1.1 Host path.
            let authority = crate::http_policy::request_authority(request_header);
            let host = crate::http_policy::request_host(authority);
            let host = host.as_ref();

            // 🧭 `early_request_filter` already resolved this same host from
            // the same header, so its answer is reused rather than looked up
            // twice. The fallback lookup keeps this phase correct on its own
            // should a request ever reach it without that earlier phase.
            let state = match ctx.state.clone().or_else(|| generation.routes().get(host)) {
                Some(s) => s,
                None => {
                    // 🔌 A `CONNECT` whose authority names no site is refused
                    // exactly as on a matched one, and before the redirect and
                    // the empty 200 below. That 200 told the client its tunnel
                    // was open, and the bytes it then sent were parsed and
                    // served as the next request (RFC 9110 §9.3.6, RFC 9931 §8).
                    if request_header.method == http::Method::CONNECT
                        && let Some(answer) = crate::http_policy::local_hop_answer(
                            &request_header.method,
                            authority,
                            &request_header.headers,
                        )
                    {
                        return self.write_local_hop_answer(session, ctx, answer).await;
                    }

                    // 🔄 Before falling to 404: is this the request an automatic
                    // HTTPS redirect exists for?
                    //
                    // 🤡 The listener that holds the plaintext port has one job —
                    // send plaintext visitors to HTTPS — and it did it only for
                    //  `Host` values that named a site. A visitor who arrived by
                    // IP, by an old hostname, or through a load balancer that
                    // sends its own `Host` got a bare 404 from the port whose
                    // entire purpose was to forward them, while `https://` typed
                    // by hand worked. Caddy answers the same request with the
                    // redirect.
                    if let Some(redirect) = self.automatic_https_redirect(session, &ctx.orig_uri) {
                        let mut header =
                            Self::build_downstream_header(session, 308, Some(1)).unwrap();
                        header.insert_header("Location", redirect.as_str()).unwrap();
                        header.insert_header("Content-Length", "0").unwrap();
                        self.write_local_response(
                            session,
                            ctx,
                            header,
                            LocalResponseBody::Empty,
                            false,
                        )
                        .await?;
                        return Ok(true);
                    }

                    // 📭 An unmatched plaintext site has no response body and
                    // succeeds, as Caddy does. TLS and invalid companion hosts
                    // keep their existing refusal instead of inventing a route.
                    let status = if self.automatic_https.load().is_none()
                        && !session
                            .digest()
                            .is_some_and(|digest| digest.ssl_digest.is_some())
                    {
                        200
                    } else {
                        404
                    };
                    let mut header =
                        Self::build_downstream_header(session, status, Some(1)).unwrap();
                    header.insert_header("Content-Length", "0").unwrap();
                    self.write_local_response(
                        session,
                        ctx,
                        header,
                        LocalResponseBody::Empty,
                        false,
                    )
                    .await?;
                    return Ok(true);
                }
            };
            ctx.state = Some(state.clone());

            if state.needs_original_uri_vars {
                let path_and_query = ctx
                    .orig_uri
                    .path_and_query()
                    .map_or("/", http::uri::PathAndQuery::as_str);
                let (orig_path, orig_query) = path_and_query
                    .split_once('?')
                    .map_or((path_and_query, ""), |(path, query)| (path, query));
                ctx.request_vars
                    .set("http.request.orig_uri.path", orig_path);
                ctx.request_vars.set(
                    "http.request.orig_uri.prefixed_query",
                    if orig_query.is_empty() {
                        String::new()
                    } else {
                        format!("?{orig_query}")
                    },
                );
            }

            // 🌐 `remote_ip` matches the connection's peer and `client_ip` the
            // client a trusted proxy vouched for, as in Caddy. A PROXY-protocol
            // source is the peer: that header replaces the connection address.
            let addresses = RequestAddresses {
                client_ip: Some(verified_client_ip),
                remote_ip: Some(transport_client_ip.ip()),
            };
            ctx.remote_ip = addresses.remote_ip;
            ctx.request_vars.set_remote(transport_client_ip);
            let remote_ip_len = write_ip(verified_client_ip, &mut remote_ip_buf);
            let remote_ip = std::str::from_utf8(&remote_ip_buf[..remote_ip_len])
                .expect("formatted IP addresses are ASCII");

            // 🔐 The request scheme comes from the handshake, never from a number
            // the client chose.
            //
            // 🤡 This used to guess: if the URI carried no scheme and no trusted
            // `X-Forwarded-Proto` said otherwise, it looked for port 443 or 8443
            // in the *authority* — which on HTTP/1.1 is the client's own `Host`
            // header. Both directions were wrong, and the dangerous one is not
            // the obvious one. `Host: x:443` over cleartext was reported as
            // `https`, so `{http.request.scheme}`, the `X-Forwarded-Proto` sent
            // upstream, and the access log all claimed a secure connection that
            // never happened — and anything behind this proxy that reads the
            // scheme as "already encrypted, no redirect needed" believed it. The
            // other direction merely broke things: a genuine handshake on any
            // other port was reported as `http`, which is why HTTP/1.1 over TLS
            // on a high port told its origin the request arrived in cleartext.
            //
            // The old comment blamed Pingora for removing a per-request TLS flag.
            // `Session::digest()` carries `ssl_digest`, which is `Some` exactly
            // when this connection completed a handshake here — the same field
            // `strict_sni_host_rejection` already reads. Nothing had to be
            // guessed (`pingora-core` 0.9.0, `protocols/mod.rs:62`, 2026-09-10).
            let protocol = if session
                .digest()
                .is_some_and(|digest| digest.ssl_digest.is_some())
            {
                "https"
            } else if self.is_trusted_proxy(transport_peer_ip)
                && request_header
                    .headers
                    .get("x-forwarded-proto")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value.eq_ignore_ascii_case("https"))
            {
                // 🤝 Cleartext to us, but a trusted ingress may have terminated
                // TLS and told us so. This is the one case where a header is the
                // authority, and it is gated on the peer being trusted — the same
                // gate every other forwarded fact goes through. A PROXY-protocol
                // ingress that terminates TLS elsewhere leaves `ssl_digest`
                // empty, so without this branch it would look like cleartext.
                "https"
            } else {
                "http"
            };

            // 🧰 Site-level `vars` rules run before route matching, so a
            // route-level `vars` matcher and every later placeholder see
            // them. Rules are ordered least specific first, and all matching
            // rules run — the most specific value therefore wins.
            for (index, rule) in state.config.vars_routes.iter().enumerate() {
                let compiled = state.vars_precompiles.get(index).and_then(Option::as_ref);
                let matches = match compiled {
                    Some(compiled) => {
                        let mut request = MatcherRequest {
                            path,
                            method,
                            headers: &request_header.headers,
                            host,
                            addresses,
                            protocol,
                            vars: Some(ctx.request_vars.values_mut()),
                        };
                        evaluate(compiled, &mut request)
                    }
                    None => true,
                };
                if matches {
                    for (name, template) in &rule.values {
                        let resolved = resolve_caddy_placeholders(
                            template,
                            request_header,
                            Some(remote_ip),
                            protocol,
                            &ctx.request_vars,
                        );
                        ctx.request_vars.set(name.clone(), resolved.into_owned());
                    }
                }
            }

            if let Some(route) = state.router.match_normalized_request(
                path,
                method,
                &request_header.headers,
                host,
                addresses,
                protocol,
                Some(ctx.request_vars.values_mut()),
            ) {
                let index = route.index;
                (
                    path.to_string(),
                    Some(index),
                    remote_ip_len,
                    verified_client_ip,
                    protocol,
                )
            } else {
                (
                    path.to_string(),
                    None,
                    remote_ip_len,
                    verified_client_ip,
                    protocol,
                )
            }
        };
        let remote_ip = std::str::from_utf8(&remote_ip_buf[..remote_ip_len])
            .expect("formatted IP addresses are ASCII");

        // 🛡️ Retain the parsed address and static scheme directly; converting
        // them to owned text and then parsing the address again added work to
        // every request without changing any policy decision.
        ctx.verified_client_ip = Some(verified_client_ip);
        ctx.request_scheme = request_scheme;

        if let Some(state) = ctx.state.clone() {
            Self::initialize_request_limits(session, ctx, &state, route_index);
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
            ctx.request_id_value = http::HeaderValue::try_from(client_id)
                .expect("sanitized request id is valid header bytes");
        }

        // 🧭 `CONNECT` is refused (RFC 9110 §9.3.6), `TRACE` is refused by
        // this server's own policy, and `OPTIONS` with a spent `Max-Forwards`
        // (RFC 9110 §7.6.2) stops here, before any handler could forward
        // them. HTTP/3 asks the same question at the same point in its dispatch.
        let request = session.req_header();
        if let Some(answer) = crate::http_policy::local_hop_answer(
            &request.method,
            crate::http_policy::request_authority(request),
            &request.headers,
        ) {
            return self.write_local_hop_answer(session, ctx, answer).await;
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
            // 📥 A route can raise this for itself with `request_body`, but
            // that handler runs during dispatch, and for a locally answered
            // route the body is drained even earlier than that. So the route's
            // declared ceiling — the widest limit any `request_body` in its
            // tree could grant, computed at load — is seeded here, before
            // anything reads a byte. The handler overwrites it with the exact
            // value when it runs, which is what a proxied body is measured
            // against.
            //
            // ⚖️ Seeding the *widest* value is deliberate. When a route holds
            // several matcher-guarded `request_body` blocks, this cannot know
            // which one applies until the matchers run, and refusing an upload
            // the operator explicitly configured the route to accept is the
            // worse of the two errors. The ceiling is still a number that
            // operator wrote.
            let site_limit = state.config.client_max_body_size;
            if let Some(ceiling) = route_index.and_then(|index| state.route_body_ceiling(index))
                && (ceiling == 0 || ceiling > site_limit)
            {
                ctx.request_body_limit = Some(ceiling);
            }
            let limit = ctx.request_body_limit.unwrap_or(site_limit);
            if limit > 0
                && let Some(content_length) = session
                    .req_header()
                    .headers
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                && content_length > limit
            {
                // 🚨 Too large is an error the handler chain raised, so a
                // `handle_errors` route that answers 413 renders it, as in
                // Caddy. The connection still closes: the body was never
                // read, so nothing after it can be trusted as a next request.
                if state.has_error_route_for(413) {
                    session.as_mut().set_keepalive(None);
                    ctx.route_index = route_index;
                    self.handle_raised_error(session, ctx, 413).await?;
                    return Ok(true);
                }
                // 🧾 The built-in refusal is the same sentence H1-chunked, H2
                // and H3 write: a body on three of the four paths and none on
                // the fourth was the drift #252 names. The connection still
                // closes, because the body was never read.
                session.as_mut().set_keepalive(None);
                let body = builtin_error_body(413, None);
                Self::write_simple_response(session, ctx, 413, &body).await?;
                return Ok(true);
            }
        }

        if let Some(index) = route_index {
            ctx.route_index = Some(index);
            // 🍃 Keep one published snapshot alive and borrow its handler tree.
            // Cloning `HandlerConfig` here copied nested vectors, maps, and
            // strings on every request even though configuration is immutable.
            let Some(state) = ctx.state.clone() else {
                self.serve_error_page(session, ctx, 500).await?;
                return Ok(true);
            };
            let handler = state.config.routes.get(index).map(|route| &route.handler);

            let immediate_flush = state.route_streaming.get(index).copied().unwrap_or(false);
            if immediate_flush || is_websocket_upgrade(&session.req_header().headers) {
                Self::activate_long_connection(session, ctx, &state);
            }

            // 🧱 Arm the body buffers here, where the route is finally known
            // and before any body chunk has been read. The limits themselves
            // were resolved at load time; this only decides whether this
            // request gets a buffer at all.
            let buffering = state.buffering(index);
            ctx.request_buffer = buffering.request.map(crate::body_buffer::BufferedBody::new);
            ctx.response_buffer = buffering
                .response
                .map(crate::body_buffer::BufferedBody::new);

            // Access rules run before authentication, static-file lookup, or
            // an upstream connection. This keeps denied traffic out of every
            // later request path and makes the policy apply uniformly to all
            // terminal handler types.
            if !state.allows_access(index, remote_ip, &session.req_header().headers) {
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
            if let Some(limiter) = state.rate_limiters.get(index).and_then(|l| l.as_ref()) {
                let decision = limiter.check_request(remote_ip, &session.req_header().headers);
                for (name, value) in decision.info.to_headers() {
                    ctx.response_headers.set(name, value);
                }
                if decision.reject {
                    // 🚫 Answered through the error-page path so the client
                    // gets a body that explains the rejection (RFC 6585 §4),
                    // or the site's configured page, instead of a bare status.
                    // The `Retry-After` and `RateLimit` fields set above ride
                    // along in `ctx.response_headers`.
                    self.serve_error_page(session, ctx, 429).await?;
                    return Ok(true);
                }
            }

            if handler.is_some_and(|handler| find_reverse_proxy_config(handler).is_some()) {
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
                if find_reverse_proxy_config(h).is_none() {
                    Self::drain_local_request_body(session, ctx).await?;
                }
                let route_precompile = state
                    .router
                    .compiled_route(index)
                    .map(|route| &route.matcher_precompile);
                if self
                    .handle_config(session, ctx, h, &path_str, index, route_precompile)
                    .await?
                {
                    // ⏱️ A locally produced response never reaches `response_filter`.
                    // ⏱️ Record its TTFB immediately after the synchronous write.
                    ctx.first_byte_at
                        .get_or_insert_with(std::time::Instant::now);
                    // 🚨 A handler that raised an error status hands the
                    // response over to the server's error routes before the
                    // request is considered finished.
                    if let Some(status) = ctx.error_status.take() {
                        self.handle_raised_error(session, ctx, status).await?;
                    }
                    return Ok(true);
                }
            }

            // 🛡️ `header_down` joins the response policy here, once, before the
            // cache is consulted. It used to be merged in `upstream_peer`, which
            // a cache hit never reaches: the stored copy holds the origin's raw
            // headers, so a field `header_down -X-Internal` strips went out to
            // every later visitor, and a field it adds was missing. Merging per
            // attempt also appended a `+` field once for every retry.
            //
            // 🧭 After `handle_config`, so a `header` directive around the proxy
            // has already claimed its fields and keeps winning a shared `set`.
            if let Some(proxy_config) = self.get_proxy_config(&state, index) {
                ctx.response_headers.merge_proxy_response_ops(
                    &proxy_config.headers_down,
                    &proxy_config.headers_down_add,
                    &proxy_config.headers_down_remove,
                    &proxy_config.headers_down_default,
                );
                if !proxy_config.headers_down_replace.is_empty() {
                    ctx.response_headers
                        .merge_proxy_replacements(&proxy_config.headers_down_replace);
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

    /// 📦 Enforces streamed body size, timeout, and upload rate, then applies
    /// `request_buffers` if the route asked for it.
    ///
    /// Order matters: the limits are enforced against the bytes as they arrive
    /// from the client, not against what this filter chooses to forward. A
    /// 413 has to fire on the chunk that crosses `client_max_body_size` even
    /// when that chunk is about to be withheld — otherwise turning buffering
    /// on would quietly raise every size limit on the route.
    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let h2 = session.as_downstream().is_http2();
        if let Some(bytes) = body.as_ref() {
            let enforce = Self::enforce_request_body_chunk(session, ctx, bytes.len());
            // 🐢 Pacing sleeps here, and that is this server's wait, not the
            // client's, so the HTTP/2 body watch is stopped for it.
            if h2 {
                crate::body_timeout::H2BodyWatch::excused(enforce).await?;
            } else {
                enforce.await?;
            }
        }
        // ⏱️ Every chunk Pingora reads pushes the HTTP/2 body deadline back,
        // and the last one stops it, so waiting on the upstream's answer
        // afterwards is never mistaken for a stalled upload.
        if h2 {
            if end_of_stream {
                crate::body_timeout::H2BodyWatch::arm(None);
            } else {
                crate::body_timeout::H2BodyWatch::moved();
            }
        }

        // 🧾 A `request_body { set … }` handler replaces the body outright, so
        // the client's bytes are discarded one chunk at a time and the
        // replacement goes up in their place. Bounded on both sides: nothing
        // accumulates the upload, and the replacement is the configured string.
        //
        // 📌 It has to be released on the *last* chunk rather than the first.
        // `pingora-proxy 0.9.0` decides the upstream body is finished from
        // `end_of_body || data.is_none()` (`proxy_h1.rs:1044`), and a body that
        // exists downstream arrives chunk by chunk — so emitting early would
        // send the replacement *ahead of* the client's body rather than instead
        // of it. Withholding keeps the upstream request a single body: the
        // replacement, sent on the call that ends the stream, with the framing
        // rewritten to match in `upstream_request_filter`.
        if let Some(replacement) = ctx.request_body_set.clone() {
            // 🪤 "Last" is `end_of_stream || body.is_none()`, which is exactly
            // how pingora computes the flag it will use, so the release can
            // never land on a call that leaves the upstream body open. And
            // withholding is `Some(Bytes::new())`, never `None`: a `None` here
            // would end the upstream body before the replacement was written,
            // the failure the buffering path below documents.
            let last = end_of_stream || body.is_none();
            *body = if last {
                Some(replacement)
            } else {
                Some(Bytes::new())
            };
            return Ok(());
        }

        let Some(buffer) = ctx.request_buffer.as_mut() else {
            return Ok(());
        };

        // 🪤 Withholding is spelled `Some(Bytes::new())`, never `None`.
        // `pingora-proxy 0.9.0` recomputes end-of-body from `data.is_none()`
        // after this filter returns (`proxy_h1.rs:1035`), so a `None` here ends
        // the upstream request body early — silently, and with the client's
        // remaining bytes discarded.
        let was_streaming = buffer.overflowed();
        let held = match body.take() {
            Some(chunk) => buffer.offer(chunk),
            None => None,
        };
        *body = match held {
            Some(released) => Some(released),
            None if end_of_stream => Some(buffer.finish().unwrap_or_default()),
            None => Some(Bytes::new()),
        };
        if !was_streaming && buffer.overflowed() {
            crate::body_buffer::report_overflow("request", buffer.limit());
        }
        Ok(())
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

        // 🧭 A reverse_proxy `method`/`rewrite` mutates the request before
        // Pingora clones it for the upstream connection, so the change is
        // visible to routing, retry policy, and the upstream request alike.
        if let Some(proxy_config) = self.get_proxy_config(&state, route_index) {
            if let Some(rewritten) = &proxy_config.rewrite_method
                && let Ok(rewritten) = http::Method::from_bytes(rewritten.as_bytes())
            {
                session.req_header_mut().set_method(rewritten);
            }
            if let Some(template) = &proxy_config.rewrite_uri {
                let verified_client_ip = ctx.verified_client_ip.map(|ip| ip.to_string());
                let resolved = resolve_caddy_placeholders(
                    template,
                    session.req_header(),
                    verified_client_ip.as_deref(),
                    ctx.request_scheme,
                    &ctx.request_vars,
                )
                .into_owned();
                session.req_header_mut().set_raw_path(resolved.as_bytes())?;
            }
        }

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
        ctx.upstream_attempted = true;
        ctx.cache_request_started = ctx.cache_ttl_secs.map(|_| std::time::Instant::now());
        ctx.cache_revalidation_headers = None;
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
        // 🚫 A FastCGI route is answered entirely in `request_filter`; a
        // request that reaches upstream selection (an element matcher that
        // did not match, say) must not be HTTP-proxied to php-fpm.
        if proxy_config
            .as_ref()
            .is_some_and(|config| config.fastcgi.is_some())
        {
            tracing::error!(
                route = route_index,
                "🚫 A FastCGI route reached HTTP upstream selection; failing closed"
            );
            return Err(pingora_core::Error::explain(
                pingora_core::ErrorType::HTTPStatus(502),
                "FastCGI route reached HTTP upstream selection",
            ));
        }
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

        // 🧭 A route whose dials contain placeholders resolves them per
        // request. The plan was precomputed at configuration time, so this
        // branch only substitutes captured values and consults the bounded
        // resolution cache — no parsing or DNS setup work repeats here.
        if let Some(dial_plan) = state
            .dynamic_dials
            .get(route_index)
            .and_then(|plan| plan.as_ref())
        {
            let verified_client_ip = ctx.verified_client_ip.map(|ip| ip.to_string());
            let Some(spec) = dial_plan.resolve(
                session.req_header(),
                verified_client_ip.as_deref(),
                &ctx.request_vars,
            ) else {
                return pingora_core::Error::e_explain(
                    pingora_core::ErrorType::HTTPStatus(502),
                    "dynamic upstream template did not resolve for this request",
                );
            };
            let Some(upstream) = crate::upstream::resolve_dynamic_dial(spec).await else {
                return pingora_core::Error::e_explain(
                    pingora_core::ErrorType::HTTPStatus(502),
                    "dynamic upstream did not resolve for this request",
                );
            };
            if let Some(proxy_config) = &proxy_config {
                ctx.headers_upstream = proxy_config.headers_up.clone();
                ctx.headers_upstream_remove = proxy_config.headers_up_remove.clone();
                ctx.streaming_response = wants_immediate_flush(proxy_config.flush_interval);
            }
            // ⌛ Only the whole-request deadline bounds this attempt; see the
            // note on the balanced branch below for why the retry budget does not.
            let request_budget = ctx
                .request_deadline
                .and_then(|deadline| deadline.checked_duration_since(std::time::Instant::now()));
            let read_budget = match state.config.limits.long_connections.idle_timeout_ms {
                Some(0) => None,
                Some(value) => Some(Duration::from_millis(value)),
                None => request_budget,
            };
            let peer = Self::build_http_peer(
                &upstream,
                proxy_config,
                request_budget,
                read_budget,
                tls_policy,
            )?;
            return Ok(Box::new(peer));
        }

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
            // 🔁 Attempts beyond the first. A rising retry rate against a flat
            // error rate is a backend degrading while the proxy hides it —
            // users are fine, the origin is not, and nothing else says so.
            if metrics::enabled() && ctx.retry_attempts > 0 {
                let route = ctx
                    .state
                    .as_ref()
                    .and_then(|state| {
                        ctx.route_index
                            .and_then(|index| state.config.routes.get(index))
                            .map(|route| route.path.as_str())
                    })
                    .unwrap_or("-");
                metrics::UPSTREAM_RETRIES_TOTAL
                    .with_label_values(&[route, "dispatched"])
                    .inc();
            }
            ctx.retry_attempts += 1;
            ctx.upstream = Some(upstream.clone());
            ctx.upstream_admission = admission;

            Self::enforce_request_deadline(ctx)?;
            if let Some(proxy_config) = &proxy_config {
                ctx.headers_upstream = proxy_config.headers_up.clone();
                ctx.headers_upstream_remove = proxy_config.headers_up_remove.clone();
                ctx.streaming_response = wants_immediate_flush(proxy_config.flush_interval);
            }
            // ⌛ `lb_try_duration` is deliberately absent here. It decides
            // whether another attempt may *start* (checked above and in
            // `crate::retry`), as in Caddy; it is not a deadline on the attempt
            // that is running. Folding it into these timers cut every event
            // stream at the budget and turned an origin that answered late into
            // a 504 — the answer had arrived, only the retrying had run out.
            // The transport's own timeouts and the whole-request deadline are
            // what bound an attempt in progress.
            let request_budget = ctx
                .request_deadline
                .and_then(|deadline| deadline.checked_duration_since(std::time::Instant::now()));
            let read_budget = match state.config.limits.long_connections.idle_timeout_ms {
                Some(0) => None,
                Some(value) => Some(Duration::from_millis(value)),
                None => request_budget,
            };

            // 🌐 Builds the peer through the transport-neutral timeout policy.
            let peer = Self::build_http_peer(
                &upstream,
                proxy_config,
                request_budget,
                read_budget,
                tls_policy,
            )?;
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
        // 🏷️ A backend in its failure cooldown is never dialled, so nothing
        // after this point learns why the request failed. RFC 9209's
        // `destination_unavailable` names exactly this case — recent attempts
        // failed, so the next hop is considered down. A failure an earlier
        // attempt of this same request recorded is more specific and wins.
        if matches!(selected, Err(UpstreamSelectionError::NoUpstream)) {
            ctx.proxy_error
                .get_or_insert(crate::proxy_status::ProxyError::DestinationUnavailable);
        }
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
        reused: bool,
        peer: &HttpPeer,
        #[cfg(unix)] _fd: std::os::unix::io::RawFd,
        #[cfg(windows)] _sock: std::os::windows::io::RawSocket,
        digest: Option<&pingora_core::protocols::Digest>,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()>
    where
        Self::CTX: Send + Sync,
    {
        // 🧹 This attempt reached its backend, so an earlier attempt's
        // failure no longer explains how the request ends.
        ctx.proxy_error = None;
        // 🔗 Every `new` is a TCP handshake, plus a TLS negotiation for
        // secure upstreams. The ratio against `reused` shows a keepalive pool
        // that is too small long before it shows up as latency. A fixed
        // two-value label, so no cardinality cap is needed.
        if metrics::enabled() {
            metrics::UPSTREAM_CONNECTIONS_TOTAL
                .with_label_values(&[if reused { "reused" } else { "new" }])
                .inc();
        }

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
        // ⏱️ The upstream connection exists, so Pingora is about to start
        // reading the body to send it: from here an HTTP/2 upload that stops
        // is timed, because Pingora's own loop cannot time it; see
        // `H2BodyWatch`. Armed per attempt, so a retry starts a fresh pause,
        // and not before, so a slow upstream connect is not charged to the
        // client.
        if session.as_downstream().is_http2() && !session.is_body_done() {
            crate::body_timeout::H2BodyWatch::arm(Self::body_pause(ctx));
        }

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

        // 🧼 RFC 9113 §8.2.1 / RFC 9114 §10.3 forbid a field value that starts
        // or ends with SP/HTAB; an HTTP/1 parser strips it silently, so the
        // same padded header is harmless on H1 and malformed on H2. Trimming
        // here makes the transports agree (#256).
        crate::http_policy::trim_pingora_request_padding(upstream_request);

        // 🧾 A replaced body is a different length from the one the client
        // declared, so the framing is rewritten here or the origin waits for
        // bytes that are never coming. This is the only place that can do it:
        // the body filter runs after this, and by then the request line is
        // already committed.
        if let Some(replacement) = &ctx.request_body_set {
            // 🚫 Never alongside `Transfer-Encoding`. A message carrying both is
            // the framing ambiguity request smuggling lives in, and the
            // hop-by-hop pass above deliberately leaves `Transfer-Encoding` for
            // pingora to own. A chunked request keeps its chunked framing, and
            // pingora terminates the body after the single chunk we emit.
            if upstream_request.headers.get("transfer-encoding").is_none() {
                upstream_request.insert_header("content-length", replacement.len().to_string())?;
            }
        }

        let downstream_headers = session.req_header();
        // 🚫 A name the operator deleted counts as configured, so the automatic
        // forwarding header below is not re-added behind their back:
        // `header_up -X-Forwarded-For` means the origin sees no
        // `X-Forwarded-For`, not one this server put there after removing the
        // client's.
        let has_header_up = |name: &str| {
            ctx.headers_upstream
                .keys()
                .any(|key| key.eq_ignore_ascii_case(name))
                || ctx
                    .headers_upstream_remove
                    .iter()
                    .any(|key| key.eq_ignore_ascii_case(name))
        };

        // Add configured upstream headers with variable resolution
        let needs_placeholder = ctx
            .headers_upstream
            .values()
            .any(|template| template.contains('{'));
        let verified_client_ip = if needs_placeholder {
            ctx.verified_client_ip.map(|ip| ip.to_string())
        } else {
            None
        };
        for (key, value_template) in &ctx.headers_upstream {
            let resolved = resolve_caddy_placeholders(
                value_template,
                downstream_headers,
                verified_client_ip.as_deref(),
                ctx.request_scheme,
                &ctx.request_vars,
            );
            upstream_request.insert_header(key.clone(), resolved.as_ref())?;
        }

        // 🚫 Deletions run after the sets and before the automatic headers
        // below, which is the order Caddy's `HeaderOps` applies them in — so
        // `header_up -Name` also removes whatever the client sent, rather than
        // only declining to add one of our own.
        for name in &ctx.headers_upstream_remove {
            upstream_request.remove_header(name.as_str());
        }

        // Add standard proxy headers (only if not already configured by user)
        if !has_header_up("X-Forwarded-Proto") {
            upstream_request.insert_header("X-Forwarded-Proto", ctx.request_scheme)?;
        }
        if !has_header_up("X-Forwarded-Host") {
            upstream_request.insert_header(
                "X-Forwarded-Host",
                crate::http_policy::request_authority(downstream_headers),
            )?;
        }

        // 🛡️ Untrusted peers cannot smuggle a forged forwarding chain upstream.
        let (transport_peer_ip, transport_client_ip, resolved_client_ip) =
            self.downstream_identity(session, &downstream_headers.headers);
        let client_ip = ctx.verified_client_ip.unwrap_or(resolved_client_ip);

        // 🌐 Every forwarding header below starts from the same address;
        // format it once and clone the `HeaderValue` (a shared-bytes
        // reference bump) instead of rebuilding a string per header.
        let client_ip_value = ip_header_value(client_ip);
        if !has_header_up("X-Forwarded-For") {
            let xff = if self.trusted_proxies.contains(transport_peer_ip) {
                let value = self.trusted_proxies.forwarded_for_with_fallback(
                    transport_peer_ip,
                    transport_client_ip.ip(),
                    &downstream_headers.headers,
                );
                http::HeaderValue::from_str(&value).map_err(|_| {
                    pingora_core::Error::explain(
                        pingora_core::ErrorType::InvalidHTTPHeader,
                        "invalid X-Forwarded-For value",
                    )
                })?
            } else {
                // An untrusted peer's chain is just the direct peer, which is
                // exactly `client_ip` in this branch.
                client_ip_value.clone()
            };
            upstream_request.insert_header("X-Forwarded-For", xff)?;
        }
        if !has_header_up("X-Real-IP") {
            upstream_request.insert_header("X-Real-IP", client_ip_value.clone())?;
        }
        if !has_header_up("Forwarded") {
            upstream_request.insert_header("Forwarded", forwarded_header_value(client_ip))?;
        }

        // Forward the request ID so upstream services can correlate their
        // logs with ours; a user-configured `header_up X-Request-Id` wins.
        if !has_header_up("X-Request-Id") {
            upstream_request.insert_header("X-Request-Id", ctx.request_id_value.clone())?;
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

        // 🧭 RFC 9110 §7.6.2: this hop spends one unit of an `OPTIONS`
        // request's `Max-Forwards` budget. Zero never gets here.
        if let Some(remaining) = crate::http_policy::forwarded_max_forwards(
            &upstream_request.method,
            &upstream_request.headers,
        ) {
            upstream_request.insert_header(http::header::MAX_FORWARDS, remaining)?;
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
        if ctx.cache_ttl_secs.is_some()
            && upstream_response.status == http::StatusCode::NOT_MODIFIED
        {
            ctx.cache_revalidation_headers = Some(
                crate::cache_age::RevalidationHeaders::from_response(upstream_response),
            );
        }
        // 🧹 Fields the origin named in its own `Connection` are scoped to that
        // hop: RFC 9110 §7.6.1 makes forwarding one a MUST NOT (#263).
        for name in crate::http_policy::connection_named_fields(&upstream_response.headers) {
            upstream_response.remove_header(name.as_ref());
        }
        // 🧾 A `Trailer:` announcement is not an invalid response: RFC 9112
        // §7.1.2 makes the trailer section part of the chunked coding, and
        // RFC 9110 §15.6.3 reserves 502 for a response the proxy cannot parse.
        // The same bytes already relay when the origin forgets to announce
        // them, so the announcement must not turn a 200 into a 502 — trailer
        // fields that cannot be forwarded downstream are dropped instead
        // (#273). The H3 path carries the same rule.

        let retry_policy = ctx
            .state
            .as_ref()
            .zip(ctx.route_index)
            .and_then(|(state, route_index)| self.get_proxy_config(state, route_index))
            .map_or(&*DEFAULT_RETRY_POLICY, |config| &*config.retry);
        // 💡 An informational response is a prediction about the answer still
        // to come (RFC 8297 §2), not the answer. The breaker keeps only the
        // first verdict it is given, so reporting a `103` here would record
        // it as a success and discard the 503 behind it; letting it reach the
        // retry predicate would redispatch on a status that is not a result.
        // `101` is the exception: it is the final response of an upgrade.
        if upstream_response.status.is_informational()
            && upstream_response.status != http::StatusCode::SWITCHING_PROTOCOLS
        {
            return Ok(());
        }

        let method = session.req_header().method.clone();
        let body_is_empty = session.as_mut().is_body_empty();
        let status = upstream_response.status.as_u16();
        if let Some(admission) = &mut ctx.upstream_admission {
            admission.report_status(status);
        }
        // 🔁 Built here rather than inside the retry module so every borrow of
        // `session` ends before the decision is acted on — and built only on
        // the failure path, which is the only place it is ever asked for.
        // 📤 These are already the upstream view: `proxy_upstream_filter`
        // applies `reverse_proxy { method … }` and `rewrite` by mutating
        // `session.req_header_mut()` in place, so reading the header back here
        // reads what went out. H3 has to assemble the same thing by hand
        // because it leaves the client's header alone.
        let request_header = session.req_header();
        let facts = crate::retry::AttemptFacts {
            upstream_method: &method,
            upstream_path: request_header.uri.path(),
            upstream_query: request_header.uri.query(),
            host: request_header
                .uri
                .host()
                .or_else(|| {
                    request_header
                        .headers
                        .get(http::header::HOST)
                        .and_then(|value| value.to_str().ok())
                })
                .unwrap_or(""),
            scheme: ctx.request_scheme,
            request_headers: &request_header.headers,
            status: Some(status),
            response_headers: Some(&upstream_response.headers),
        };
        let route_index = ctx.route_index;
        let state = ctx.state.as_ref();
        // 🔤 Hands out the shared copy compiled at load. Cloning an `Arc` costs
        // one atomic increment and only happens when a regex predicate is
        // actually reached; compiling one here would cost microseconds at the
        // moment an upstream is already failing.
        let resolve_regex = |pattern: &str| {
            state
                .zip(route_index)
                .and_then(|(state, index)| state.route_regex_arc(index, pattern))
        };
        if crate::retry::permits_retry(
            retry_policy,
            &facts,
            body_is_empty,
            ctx.retry_attempts,
            ctx.retry_deadline,
            &resolve_regex,
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
        if let Some(headers) = &ctx.cache_revalidation_headers {
            // 🔁 A validated body's clock updates even when the 304 forbids storage.
            headers.apply_to(upstream_response);
        }
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

        // 🧭 `handle_response`/`intercept` evaluate before any response byte
        // reaches the client, and before compression decides what to do with
        // the body.
        self.apply_response_interception(session, ctx, upstream_response, None)
            .await?;
        if let Some(status) = ctx.response_decision_error {
            return pingora_core::Error::e_explain(
                pingora_core::ErrorType::HTTPStatus(status),
                "response subroute raised an error status",
            );
        }

        // ⏱️ TTFB is measured at the response header, which is the first byte
        // the client can actually observe. Recorded once — a retry or an
        // interceptor running this filter again must not reset it.
        let first_byte = *ctx
            .first_byte_at
            .get_or_insert_with(std::time::Instant::now);

        // ⏱️ Upstream time separately from total request time. Total latency
        // rising says something is slow; this says whether it is the origin or
        // this proxy, which is the difference between the two useful actions.
        // Both labels come from configuration, so no cardinality cap applies.
        if metrics::enabled()
            && let Some(upstream) = &ctx.upstream
        {
            let route = ctx
                .state
                .as_ref()
                .and_then(|state| {
                    ctx.route_index
                        .and_then(|index| state.config.routes.get(index))
                        .map(|route| route.path.as_str())
                })
                .unwrap_or("-");
            let elapsed = first_byte.saturating_duration_since(ctx.start_time);
            metrics::UPSTREAM_DURATION_SECONDS
                .with_label_values(&[route, &upstream.addr.to_string()])
                .observe(elapsed.as_secs_f64());
        }

        ctx.response_headers.apply_pingora(
            upstream_response,
            &ctx.request_id_value,
            Some(upstream_response.version),
        )?;

        // 🧼 The same padding rule in the other direction: a configured value
        // with a stray space is a protocol error on H2/H3 (#256).
        crate::http_policy::trim_pingora_response_padding(upstream_response);

        // 🚫 RFC 9110 §8.6: a 1xx or 204 response cannot carry a
        // `Content-Length`. An origin that sends one made its mistake here;
        // forwarding it would make it ours, and an HTTP/1.1 client that
        // believes the announced length on a bodiless status waits for bytes
        // that never arrive (#270). This is the last header hook before the
        // response is written, and the one every transport passes through.
        if !crate::http_policy::ResponseContent::for_status(upstream_response.status.as_u16())
            .allows_content_length()
        {
            upstream_response.remove_header(&http::header::CONTENT_LENGTH);
        }

        // 🧾 RFC 9112 §6.1: `Transfer-Encoding` may only be sent to a client
        // that speaks HTTP/1.1 or later, and §2.3 asks that an HTTP/1.0
        // recipient receive a message it can parse. The status line follows
        // the client's version, and a body whose length the origin never
        // declared is delimited by the close that ends the connection —
        // never by chunk sizes an HTTP/1.0 client would read as content
        // (#277). Local responses already downgrade their version; this is
        // the proxied half.
        if session.req_header().version == http::Version::HTTP_10 {
            upstream_response.set_version(http::Version::HTTP_10);
            if upstream_response
                .headers
                .contains_key(http::header::TRANSFER_ENCODING)
            {
                upstream_response.remove_header(&http::header::TRANSFER_ENCODING);
                session.as_mut().set_keepalive(None);
            }
        }

        // 🌊 Pingora's HTTP/1 writer flushes a known-length body only once the
        // body ends, so a bounded event stream that declares its length sits
        // in the buffer until it is over and reaches the client in one lump
        // (#247). A stream can drop the length instead: chunked framing (1.1)
        // and close-delimited framing (1.0) are both flushed per chunk, and
        // neither loses a byte. Only responses whose whole point is immediacy
        // pay that trade — `Content-Type: text/event-stream`, or a route that
        // asked for `flush_interval -1` — and only when a body is coming.
        let immediate_stream = upstream_response
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(is_streaming_content_type)
            || ctx
                .state
                .as_ref()
                .zip(ctx.route_index)
                .and_then(|(state, route_index)| self.get_proxy_config(state, route_index))
                .is_some_and(|config| wants_immediate_flush(config.flush_interval));
        let body_is_coming = session.req_header().method != http::Method::HEAD
            && crate::http_policy::ResponseContent::for_status(upstream_response.status.as_u16())
                .has_body();
        if immediate_stream
            && body_is_coming
            && upstream_response
                .headers
                .contains_key(http::header::CONTENT_LENGTH)
        {
            upstream_response.remove_header(&http::header::CONTENT_LENGTH);
            if session.req_header().version == http::Version::HTTP_10 {
                // 🧾 A 1.0 client cannot be chunked; the close delimits it,
                // and `do_write_until_close_body` flushes every chunk.
                session.as_mut().set_keepalive(None);
            }
        }

        // 🌊 A lengthless HTTP/1.1 body needs chunked framing: pingora frames
        // a response whose head declares neither `Content-Length` nor
        // `Transfer-Encoding` as close-delimited, and a close-delimited body
        // ends the connection. An origin's early close would then read as a
        // complete message (#249), and the route would pay a fresh handshake
        // for every request. This mirrors the rule local responses already
        // follow, and it also covers an origin that answered close-delimited.
        if session.req_header().version == http::Version::HTTP_11
            && body_is_coming
            && !upstream_response
                .headers
                .contains_key(http::header::CONTENT_LENGTH)
            && !upstream_response
                .headers
                .contains_key(http::header::TRANSFER_ENCODING)
        {
            upstream_response.insert_header(http::header::TRANSFER_ENCODING, "chunked")?;
        }

        // 🛡️ Applies the same security policy used by locally generated responses.
        if let Some(state) = &ctx.state {
            Self::apply_security_response_headers(upstream_response, state)?;
        }
        Self::apply_strict_transport(upstream_response, ctx)?;

        // 🌊 A response-subroute file owns the downstream stream once its
        // header decision succeeds. Writing the complete bounded-chunk stream
        // here avoids tying progress to upstream body callbacks: an empty
        // upstream response may produce only one callback, while the local
        // replacement can contain arbitrarily many chunks.
        if let Some(mut stream) = ctx.intercepted_file.take() {
            let mut response = upstream_response.clone();
            if session.req_header().version == http::Version::HTTP_2 {
                // 🧭 Pingora's HTTP/2 writer expects the same HTTP/1.1
                // compatibility version that its normal response path applies
                // after this hook returns.
                response.set_version(http::Version::HTTP_11);
            }
            session
                .write_response_header(Box::new(response), false)
                .await?;
            // 🤐 Nothing to read for a `HEAD` or a status without content:
            // the file is never read, and only the end of stream goes out.
            let mut wrote = false;
            let has_body = Self::written_response_content(session).has_body();
            while has_body
                && let Some(chunk) = stream.read_chunk().map_err(|error| {
                    pingora_core::Error::because(
                        pingora_core::ErrorType::ReadError,
                        "streaming intercepted proxy response file",
                        error,
                    )
                })?
            {
                wrote = true;
                let last = stream.is_complete();
                Self::write_local_body(session, ctx, Bytes::from(chunk), last).await?;
            }
            if !wrote {
                session.write_response_body(None, true).await?;
            }
            ctx.response_takeover_complete = true;
            return pingora_core::Error::e_explain(
                pingora_core::ErrorType::InternalError,
                "response interception takeover completed",
            );
        }

        if ctx.state.as_ref().is_some_and(|state| {
            crate::response_encoding::should_vary(&state.config, upstream_response.status.as_u16())
        }) {
            crate::response_encoding::vary_on_accept_encoding(upstream_response)?;
        }

        // 🗜️ Both transports share eligibility; the downstream module keeps cached bytes identity.
        // 💡 An informational response (a `103 Early Hints`, say) passes
        // through this filter too, but it has no body and only predicts the
        // final response's fields (RFC 8297 §2). Letting it decide would arm
        // an encoder for the final body while leaving the final header, which
        // may have declined compression, announcing no coding at all.
        //
        // 📐 Partial and bodiless responses are excluded by
        // `is_full_representation`: a re-encoded `206` would keep a
        // `Content-Range` counted in identity bytes.
        if let Some(encoding) = ctx.negotiated_encoding
            && crate::response_encoding::request_allows_encoding(&session.req_header().headers)
            && let Some(state) = &ctx.state
            && crate::response_encoding::eligible(
                &state.config,
                &state.encode_policy,
                upstream_response,
            )
            && !ctx.streaming_response
            && ctx.intercepted_response.is_none()
        {
            // 🤐 A `HEAD` describes the response its `GET` would receive but
            // has no body, so the header rewrite below is the whole answer and
            // no encoder is installed (#264).
            let encodes_body = crate::response_encoding::encodes_a_body(
                &session.req_header().method,
                upstream_response,
            );
            let token = encoding.token();
            let ready = if encodes_body {
                match ResponseEncoder::at_gzip_level(encoding, state.config.encode.gzip_level) {
                    Ok(encoder) => {
                        // 🛡️ Headers are only rewritten once the encoder is
                        // in place. Announcing a coding that nothing then
                        // applies would hand the client a body it cannot
                        // decode.
                        if !crate::response_encoding::install(
                            &mut session.downstream_modules_ctx,
                            encoder,
                        ) {
                            return Ok(());
                        }
                        true
                    }
                    Err(e) => {
                        tracing::warn!(
                            "⚠️ Could not initialize {} encoder, serving identity: {}",
                            encoding.token(),
                            e
                        );
                        false
                    }
                }
            } else {
                true
            };
            if ready {
                upstream_response.insert_header("Content-Encoding", token)?;
                let _ = upstream_response.remove_header("Content-Length");
                crate::response_encoding::drop_integrity_fields(upstream_response);
                crate::response_encoding::weaken_etag(upstream_response)?;
                // 🌊 With Content-Length gone, HTTP/1.1 needs explicit
                // chunked framing. Pingora only adds it before this
                // filter runs, and has already promised keep-alive,
                // so leaving it out ends the body by closing a
                // connection the client was told would stay open.
                // HTTP/1.0 has no chunked coding and closes anyway;
                // Pingora's H2 writer strips the field itself. A `HEAD`
                // has no body to frame, so it needs none of this.
                if encodes_body && session.req_header().version == http::Version::HTTP_11 {
                    upstream_response.insert_header("Transfer-Encoding", "chunked")?;
                }
                crate::response_encoding::vary_on_accept_encoding(upstream_response)?;
            }
        }

        Ok(())
    }

    /// 📥 Filters upstream response body chunks before the cache stores them.
    ///
    /// 🗄️ Pingora hands this filter's output to the cache, so nothing here may
    /// change the body into something the stored headers do not describe.
    /// Compression therefore lives in the downstream module in
    /// `response_encoding.rs` instead.
    ///
    /// 🧱 A route that configured `response_buffers` holds the body first, and
    /// even then memory is bounded by the configured ceiling rather than by
    /// the response — the two rules do not conflict, which is the point of
    /// [`crate::body_buffer`].
    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Option<Duration>> {
        Self::enforce_request_deadline(ctx)?;

        // 🧭 A `handle_response` replacement emits its static body exactly
        // once and then discards every upstream chunk, keeping memory bounded
        // by the replacement, not by the upstream body size.
        if ctx.intercepted_response.is_some() {
            if !ctx.intercepted_body_emitted {
                ctx.intercepted_body_emitted = true;
                if let Some(replacement) = &ctx.intercepted_response {
                    *body = Some(Bytes::copy_from_slice(&replacement.body));
                }
            } else {
                *body = None;
            }
            return Ok(None);
        }

        // 🧱 `response_buffers` holds the upstream body before the client sees
        // any of it, so a slow reader stops holding the upstream connection
        // open. It runs before compression and before the byte accounting:
        // what those measure is what actually leaves this filter.
        //
        // Unlike the request side, `None` is a safe way to withhold here —
        // `pingora-proxy 0.9.0` carries end-of-stream past this filter in the
        // task itself (`lib.rs:802`) instead of recomputing it from the data.
        // An empty `Bytes` is used anyway, so the two directions read the same.
        if let Some(buffer) = ctx.response_buffer.as_mut() {
            let was_streaming = buffer.overflowed();
            let held = match body.take() {
                Some(chunk) => buffer.offer(chunk),
                None => None,
            };
            *body = match held {
                Some(released) => Some(released),
                None if end_of_stream => Some(buffer.finish().unwrap_or_default()),
                None => Some(Bytes::new()),
            };
            if !was_streaming && buffer.overflowed() {
                crate::body_buffer::report_overflow("response", buffer.limit());
            }
        }

        // Track response bytes for access log
        if let Some(b) = body.as_ref() {
            ctx.response_bytes += b.len() as u64;
        }

        // 📏 Pingora tracks the per-response cache ceiling only if we hand it
        // each chunk. Once the body passes the limit the tracker says so, and
        // the response finishes as an ordinary uncached stream — which is the
        // whole point: the alternative is buffering a body we have already
        // decided not to keep.
        if ctx.cache_size_tracked
            && let Some(chunk) = body.as_ref()
            && !_session
                .cache
                .track_body_bytes_for_max_file_size(chunk.len())
        {
            _session.cache.disable(NoCacheReason::ResponseTooLarge);
            ctx.cache_size_tracked = false;
        }

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
        // 🏷️ Remembered for `Proxy-Status`: when this was the only backend,
        // the retry that follows ends in a bare "no upstream available", and
        // this is the last place that still knows the backend refused.
        ctx.proxy_error = Some(crate::proxy_status::ProxyError::from_upstream_error(&e));
        // 🩺 A connect failure this process caused says nothing about the
        // backend. Descriptor exhaustion fails `socket()` before a packet
        // leaves the machine, so the backend is healthy, idle, and unaware —
        // and taking it out of rotation for that turns one local failure into
        // an outage for every request that arrives during the cooldown.
        // Measured on 2026-08-11 at `4ed66ec`: five local `socket()` failures
        // produced 139 rejected requests, and a single probe against a
        // completely healthy backend kept returning 502 for nine seconds after
        // the load stopped. Evidence in
        // `benchmarks/results/20260811_fd_exhaustion_4ed66ec/`.
        let origin = crate::upstream_failure::classify_connect_error(&e);
        if let pingora_core::protocols::l4::socket::SocketAddr::Inet(address) = peer.address() {
            if origin.implicates_backend() {
                // 🚫 Excluding the peer from this request's retries is the same
                // claim as marking it down — that this address is the problem —
                // so the two travel together.
                ctx.retry_excluded.insert(*address);
                if let (Some(state), Some(route_index)) = (ctx.state.as_ref(), ctx.route_index) {
                    tracing::warn!(
                        error_type = ?e.etype(),
                        cause = %e,
                        "🔻 Marking upstream {} down after connect failure (cooldown {:?})",
                        address,
                        crate::FAIL_COOLDOWN
                    );
                    self.mark_upstream_unhealthy(state, route_index, address);
                }
            } else if let Some(suppressed) = crate::upstream_failure::LOCAL_FAILURE_LOG.admit_now()
            {
                // 🧯 Rate limited, because running out of descriptors does not
                // fail one request — it fails every request arriving while the
                // budget is empty. The suppressed count rides along so the
                // scale of the event is not the thing the rate limit hides.
                tracing::warn!(
                    upstream = %address,
                    error_type = ?e.etype(),
                    suppressed,
                    cause = %e,
                    "🧯 Local resource failure on connect — backend left in rotation"
                );
            }
        }

        let retry_policy = ctx
            .state
            .as_ref()
            .zip(ctx.route_index)
            .and_then(|(state, route_index)| self.get_proxy_config(state, route_index))
            .map(|config| config.retry.clone())
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
        session: &mut Session,
        mut e: Box<pingora_core::Error>,
        ctx: &mut Self::CTX,
        client_reused: bool,
    ) -> Box<pingora_core::Error> {
        if let Some(mut admission) = ctx.upstream_admission.take() {
            admission.report_failure();
        }
        // 🏷️ The same memory as in `fail_to_connect`, for a failure after
        // the connection was made.
        ctx.proxy_error = Some(crate::proxy_status::ProxyError::from_upstream_error(&e));
        // 🩹 A failure after the connection was made is the backend's too, when
        // the error names the response side: a truncated body, a reset
        // mid-response, a malformed response. A downstream abort or an internal
        // fault is not, and evicting a backend for one impatient client would
        // turn that into an outage (#262).
        if crate::upstream_failure::classify_response_error(&e).implicates_backend()
            && let pingora_core::protocols::l4::socket::SocketAddr::Inet(address) = peer.address()
            && let (Some(state), Some(route_index)) = (ctx.state.as_ref(), ctx.route_index)
        {
            tracing::warn!(
                error_type = ?e.etype(),
                cause = %e,
                "🔻 Marking upstream {address} down after response-phase failure"
            );
            self.mark_upstream_response_failure(state, route_index, address);
        }
        let elapsed = ctx.start_time.elapsed();
        log_at_level!(
            failure_severity(&e),
            peer = %peer,
            elapsed_ms = elapsed.as_millis(),
            error = %e,
            "❌ Proxy error"
        );

        let retry_policy = ctx
            .state
            .as_ref()
            .zip(ctx.route_index)
            .and_then(|(state, route_index)| self.get_proxy_config(state, route_index))
            .map_or(&*DEFAULT_RETRY_POLICY, |config| &*config.retry);
        let retry_buffer_truncated = session.as_ref().retry_buffer_truncated();
        let body_is_empty = session.as_mut().is_body_empty();
        let retry = decide_upstream_error_retry(
            &mut e,
            client_reused,
            retry_buffer_truncated,
            // 📤 Already the upstream method: `reverse_proxy { method … }`
            // rewrote this header in place before the request went out.
            crate::retry::request_is_repeatable(&session.req_header().method, body_is_empty),
            retry_policy,
            ctx.retry_attempts,
            ctx.retry_deadline,
        );
        if !retry && !body_is_empty {
            // 🚫 Worth saying out loud: a body-bearing request that failed after
            // the connection was up is exactly the case an operator will come
            // asking about, and "we chose not to repeat it" is a different
            // answer from "we ran out of attempts".
            tracing::warn!(
                peer = %peer,
                method = %session.req_header().method,
                "🛡️ Not repeating a request that carried a body; the origin may already have acted on it"
            );
        }
        ctx.retry_pending = retry;
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

        // 🌊 The response filter uses a private control-flow error after it
        // has streamed a response-subroute file to completion. The downstream
        // framing is complete and reusable; no second error response belongs
        // on the wire.
        if ctx.response_takeover_complete {
            return pingora_proxy::FailToProxy {
                error_code: ctx.response_status,
                can_reuse_downstream: true,
            };
        }

        if matches!(e.esource(), ErrorSource::Downstream) {
            // 🔌 Broken request framing cannot be reused. Set this before
            // writing the error so its header advertises the closure too.
            session.as_mut().set_keepalive(None);
        } else if ctx.upstream_attempted {
            // 🔌 A failure inside Pingora's upstream loop (no peer, refused
            // connect, upstream timeout) reaches here from `process_request`,
            // which closes the client connection with the upstream's reuse
            // flag and ignores `can_reuse_downstream` below (pingora-proxy
            // 0.9.0, `process_request` → `finish(session, ctx, server_reuse,
            // ..)`). The 502 used to say `Connection: keep-alive` anyway, so a
            // client that reused the socket had its next request reset.
            // nginx keeps this connection open; that needs Pingora to honour
            // the flag on this path, so the honest answer is to say `close`.
            session.as_mut().set_keepalive(None);
        }

        // 💥 Count upstream and internal failures as *attempts*, which is a
        // different number from requests the client saw fail: a request retried
        // twice and then served contributes two here and none to
        // `caddy_http_request_errors_total`. That gap is exactly the degradation
        // a proxy hides, so it is worth its own metric.
        if metrics::enabled() && !matches!(e.esource(), ErrorSource::Downstream) {
            let route = ctx
                .state
                .as_ref()
                .and_then(|state| {
                    ctx.route_index
                        .and_then(|index| state.config.routes.get(index))
                        .map(|route| route.path.as_str())
                })
                .unwrap_or("-");
            let upstream = ctx
                .upstream
                .as_ref()
                .map(|upstream| upstream.addr.to_string())
                .unwrap_or_else(|| "-".to_string());
            // 🏷️ The *deepest* type in the chain, not the one on top: Pingora
            // reports descriptor exhaustion and ephemeral-port exhaustion as
            // `InternalError` alike, which is exactly the distinction the
            // operator needs this label to carry.
            let reason = format!("{:?}", crate::upstream_failure::deepest_error_type(e));
            metrics::UPSTREAM_ERRORS_TOTAL
                .with_label_values(&[route, &upstream, &reason])
                .inc();
        }

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
                        // 🧯 502 means "the backend gave me a bad answer", and
                        // that is a lie when this process ran out of
                        // descriptors before reaching it. 503 says what is
                        // actually true — this server cannot serve the request
                        // right now — and it is the same code the overload
                        // path already uses, so an operator alerting on
                        // capacity does not need to learn a second signal.
                        _ if !crate::upstream_failure::classify_connect_error(e)
                            .implicates_backend() =>
                        {
                            503
                        }
                        _ => 502,
                    },
                    ErrorSource::Downstream => match e.etype() {
                        ErrorType::WriteError
                        | ErrorType::ReadError
                        | ErrorType::ConnectionClosed => 0,
                        ErrorType::ReadTimedout | ErrorType::WriteTimedout => 408,
                        _ => 400,
                    },
                    // ⏱️ A read or write deadline that fired is this connection's
                    // own, whichever side of it pingora happened to attribute:
                    // the site's `limits` and a route's `request_body {
                    // read_timeout }` both arm the session, and an *upstream*
                    // timeout arrives above with `ErrorSource::Upstream` and
                    // stays a 504. 500 blamed this server for a client that
                    // stopped sending, and the H3 path already answers 408 for
                    // the same event (`drain_local_h3_body`), so the two
                    // transports disagreed on the status of one failure.
                    ErrorSource::Internal | ErrorSource::Unset => match e.etype() {
                        ErrorType::ReadTimedout | ErrorType::WriteTimedout => 408,
                        _ => 500,
                    },
                },
            }
        };
        // 🏷️ `Proxy-Status` goes only on an error this hop generated because
        // the next hop failed: an upstream-sourced error, or the gateway
        // status a retry ends with after an attempt already recorded why
        // (`fail_to_connect`, `error_while_proxy`). Anything else — a deadline
        // 408, a downstream fault, a handler's own status — is cleared, so a
        // stale attempt is never blamed for it.
        ctx.proxy_error = match (e.esource(), e.etype()) {
            _ if code == 408 => None,
            (ErrorSource::Upstream, ErrorType::HTTPStatus(_)) => ctx.proxy_error,
            (ErrorSource::Upstream, _) => {
                Some(crate::proxy_status::ProxyError::from_upstream_error(e))
            }
            (_, ErrorType::HTTPStatus(502..=504)) => ctx.proxy_error,
            _ => None,
        };
        let served = if already_responded {
            // 🔪 An error page cannot be spliced onto a response that is
            // already on the wire: on H2 its header block would be dropped and
            // its body would arrive as more DATA on the same stream; on H1 it
            // would land inside the first response's framing.
            //
            // 🔚 Whether the message may be *ended* instead depends on who
            // broke it. An origin that closed mid-response already formed the
            // status and headers the client is entitled to, so the relay ends
            // where the origin did: with a declared `Content-Length` the short
            // body is the evidence, exactly as Caddy passes along the head it
            // formed (#249). A response this hop abandons — a deadline, a
            // write failure, an internal fault — has no origin answer to
            // relay, and the break must be the visible signal, so it keeps
            // RST_STREAM(INTERNAL_ERROR) on H2 (#95). The same reset stays for
            // an origin break without a declared length: a clean end of a
            // chunked or close-delimited message would look complete.
            let declared_length = session.response_written().is_some_and(|response| {
                response.headers.contains_key(http::header::CONTENT_LENGTH)
            });
            let origin_broke_mid_response =
                crate::upstream_failure::classify_response_error(e).implicates_backend();
            if declared_length && origin_broke_mid_response {
                session.write_response_body(None, true).await.is_ok()
            } else {
                session.downstream_session.shutdown().await;
                false
            }
        } else if let Some(status) = ctx.response_decision_error.take() {
            // 🚫 A response subroute owns the original upstream response once
            // it matches. Its raised status may enter error routing once, but
            // the outer interceptor is cleared so the error response cannot
            // wrap itself recursively.
            ctx.intercept_handlers.clear();
            self.handle_raised_error(session, ctx, status).await.is_ok()
        } else if ctx.refused_before_routing && code > 0 {
            // 🚫 A refusal this hop made before any route could run — an
            // oversized header block, today — never reaches `handle_errors`:
            // that exists so a site can answer for its handlers, and this
            // request never reached one. A configured `error_page` for the
            // status still applies, and without one the built-in body keeps
            // the detail that names what was wrong, which is the client's
            // whole diagnosis (#288). HTTP/3 answers through the same two
            // steps, so the three transports agree.
            self.serve_error_page(session, ctx, code).await.is_ok()
        } else if code > 0
            && !ctx.handling_error
            && ctx
                .state
                .as_ref()
                .is_some_and(|state| state.has_error_route_for(code))
        {
            // 🚨 A proxy that could not reach its upstream (502, 503, 504), a
            // body over its limit (413) or a stalled one (408) is an error the
            // handler chain produced, and Caddy hands every such error to
            // `handle_errors`. Only when no route answers the status does the
            // site's error page below take it. `handling_error` is the loop
            // guard: an error route that itself fails is answered directly.
            ctx.intercept_handlers.clear();
            self.handle_raised_error(session, ctx, code).await.is_ok()
        } else {
            code > 0 && self.serve_error_page(session, ctx, code).await.is_ok()
        };

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

    fn suppress_error_log(
        &self,
        _session: &Session,
        ctx: &Self::CTX,
        _error: &pingora_core::Error,
    ) -> bool {
        ctx.response_takeover_complete
    }

    async fn logging(
        &self,
        session: &mut Session,
        e: Option<&pingora_core::Error>,
        ctx: &mut Self::CTX,
    ) {
        // 🚫 `log_skip` excludes the request before any entry is built.
        if ctx.log_skip {
            return;
        }
        let response_code = session
            .response_written()
            .map(|resp| resp.status.as_u16())
            .unwrap_or(ctx.response_status);

        let req_header = session.req_header();
        let method = req_header.method.as_str();
        let host = match crate::http_policy::request_authority(req_header) {
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
            .unwrap_or_else(|| session_peer_ip(session));
        let elapsed = ctx.start_time.elapsed();

        // 📊 Release exactly the gauge incremented at request entry, without
        // resolving the host label through Prometheus a second time.
        if let Some(active) = ctx.active_connection_metric.take() {
            active.dec();
        }

        if metrics::enabled() {
            let status = response_code.to_string();
            // 🛡️ `host` is the request's `Host`/`:authority`, so it is entirely
            // client-controlled. Prometheus keeps one time series per label
            // combination, so feeding it raw would let anyone grow this
            // process without bound by varying the header. The `metrics` block
            // decides what is safe to say here; by default nothing is, and the
            // label is empty.
            let capped_host = metrics::host_label(host);
            let host = capped_host.as_ref();
            let labels = [method, status.as_str(), host];
            let request_size = req_header
                .headers
                .get("content-length")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<f64>().ok())
                .unwrap_or(0.0);
            metrics::REQUESTS_TOTAL.with_label_values(&labels).inc();
            metrics::REQUEST_DURATION_SECONDS
                .with_label_values(&labels)
                .observe(elapsed.as_secs_f64());
            metrics::REQUEST_SIZE_BYTES
                .with_label_values(&labels)
                .observe(request_size);
            metrics::RESPONSE_SIZE_BYTES
                .with_label_values(&labels)
                .observe(ctx.response_bytes as f64);
            if let Some(first_byte_at) = ctx.first_byte_at {
                metrics::RESPONSE_DURATION_SECONDS
                    .with_label_values(&labels)
                    .observe(first_byte_at.duration_since(ctx.start_time).as_secs_f64());
            }
            if e.is_some() {
                metrics::REQUEST_ERRORS_TOTAL
                    .with_label_values(&[method, host])
                    .inc();
            }
        }

        // 🗄️ Record how this request resolved against the response cache, once,
        // here — this is the one phase that runs for every request whatever
        // happened earlier, so a hit and a fail-to-connect are counted the same
        // number of times.
        if ctx.cache_ttl_secs.is_some() {
            let route = ctx
                .state
                .as_ref()
                .and_then(|state| {
                    ctx.route_index
                        .and_then(|index| state.config.routes.get(index))
                        .map(|route| route.path.as_str())
                })
                .unwrap_or("-");
            record_cache_outcome(session, host, route);
        }

        // 📝 Which destinations this request belongs in was decided when the
        // configuration was compiled; here it is a walk over a precomputed
        // list. Only when the server configured nothing at all do we fall back
        // to the process-wide tracing output.
        if let Some(state) = ctx.state.as_ref() {
            let mut selected = state.log_targets.select(host).peekable();
            if selected.peek().is_none() {
                // 🪵 No configured destination matched this host, so preserve
                // the process-wide tracing fallback below.
            } else {
                let upstream = ctx
                    .upstream
                    .as_ref()
                    .map(|value| pingclair_runtime::access_log::LogUpstream::Address(&value.addr));
                let route = ctx
                    .route_index
                    .and_then(|index| state.config.routes.get(index))
                    .map(|route| route.path.as_str());
                let error_text = e.map(|err| err.to_string());

                // 🙈 Log the full request target, but redact secret-looking query
                // parameters first. Operators need the query to debug; a logged
                // `?api_key=...` is a leaked credential.
                let target = req_header
                    .uri
                    .path_and_query()
                    .map_or_else(|| req_header.uri.path(), |value| value.as_str());
                let logged_path = pingclair_runtime::redaction::redact_target(target);
                // 🙈 Referer carries the *previous* page's URL, so it can leak a
                // token this request never contained.
                let redacted_referer = pingclair_runtime::redaction::redact_referer(referer);

                // 🏷️ The entry lends each destination the original maps. Each
                // logger narrows and masks them while writing its own final buffer,
                // avoiding dozens of temporary strings per request.
                let logged_request_headers =
                    pingclair_runtime::access_log::LogHeaders::new(&req_header.headers);
                let logged_response_headers = session.response_written().map(|response| {
                    pingclair_runtime::access_log::LogHeaders::new(&response.headers)
                });
                // 🔐 `digest` carries the handshake result; a plaintext listener
                // simply has none, which is why both fields are optional rather
                // than empty strings.
                let (tls_version, tls_cipher) = if state.log_targets.includes_tls() {
                    session
                        .digest()
                        .and_then(|digest| digest.ssl_digest.as_ref())
                        .map(|ssl| (Some(ssl.version.as_ref()), Some(ssl.cipher.as_ref())))
                        .unwrap_or((None, None))
                } else {
                    (None, None)
                };

                let entry = pingclair_runtime::access_log::AccessEntry {
                    request_headers: Some(logged_request_headers),
                    response_headers: logged_response_headers,
                    tls_version,
                    tls_cipher,
                    // 🕰️ The record says when the request started, not when it
                    // finished: a five-second request logged at its end would
                    // otherwise sit in a shipper's timeline beside requests that
                    // arrived after it.
                    started_unix: pingclair_runtime::access_log::unix_started_at(ctx.start_time),
                    request_id: ctx.request_id(),
                    method,
                    host,
                    path: logged_path.as_ref(),
                    status: response_code,
                    // 📏 Keep one explicit body-only counter across H1, H2, and
                    // H3. The session API now reports body-only bytes on H1 as
                    // well, but this counter remains Pingclair's cross-transport
                    // access-log contract.
                    bytes: ctx.response_bytes,
                    // ⏱️ Fractional milliseconds: a whole-millisecond
                    // integer renders every fast request as `0`, which no
                    // average or percentile can recover (#160).
                    duration_ms: elapsed.as_secs_f64() * 1000.0,
                    ttfb_ms: ctx
                        .first_byte_at
                        .map(|at| at.duration_since(ctx.start_time).as_secs_f64() * 1000.0),
                    client_ip: remote_ip,
                    route,
                    upstream,
                    user_agent,
                    referer: redacted_referer.as_ref(),
                    protocol: match session.req_header().version {
                        http::Version::HTTP_09 => "HTTP/0.9",
                        http::Version::HTTP_10 => "HTTP/1.0",
                        http::Version::HTTP_11 => "HTTP/1.1",
                        http::Version::HTTP_2 => "HTTP/2",
                        http::Version::HTTP_3 => "HTTP/3",
                        _ => "-",
                    },
                    error: error_text.as_deref(),
                };

                // 🪵 One borrowed entry is formatted separately per destination,
                // because destinations may select different headers and fields.
                for destination in selected {
                    destination.log(&entry);
                }
                return;
            }
        }

        // 🚫 Nothing on this listener asked for access logging, so this request
        // gets no record. Caddy's `ServerLogConfig` is per server: one site's
        // `log` enables records for the whole listener, and a server whose
        // sites never mention `log` writes none at all — which is what the
        // documented "Default: no access log" means (#213). The fallback below
        // is therefore kept only for a listener that logs, where an unmapped
        // `Host` belongs to Caddy's default access logger.
        //
        // ⚡ One bit read: whether this listener logs was decided when its route
        // table was published, so the request path does not walk the sites.
        if !self.request_generation(ctx).routes().has_access_logging() {
            return;
        }

        // Structured access log
        if let Some(err) = e {
            // 📉 The access record for a failed request follows the same
            // severity rule as the error above, so a client that hung up does
            // not produce two ERROR lines for something nobody can fix. The
            // `error` field still carries the reason at whatever level it
            // lands on, so nothing is lost — only the volume changes.
            log_at_level!(
                failure_severity(err),
                request_id = ctx.request_id(),
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
            // 📌 Ten structured fields, not one pre-formatted string. Collapsing
            // them was measured: it is worth ~6 % on the static path and nothing
            // on the proxy path, and it changes the record's shape from fields a
            // collector can index to a single quoted `access="…"` blob. The
            // throughput does not buy that, so the structured form stays.
            tracing::info!(
                request_id = ctx.request_id(),
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
pub(crate) fn find_reverse_proxy_config(handler: &HandlerConfig) -> Option<&ReverseProxyConfig> {
    match handler {
        HandlerConfig::ReverseProxy(config) if config.subrequest.is_none() => Some(config),
        HandlerConfig::Pipeline { handlers }
        | HandlerConfig::FirstMatch { handlers }
        | HandlerConfig::HandlePath { handlers, .. } => handlers
            .iter()
            .find_map(|element| find_reverse_proxy_config(&element.handler)),
        _ => None,
    }
}

/// ⚖️ Apply each upstream weight to Pingora's native weighted backend.
///
/// Repeating an identical backend is incorrect because Pingora stores its
/// backend set by value and deduplicates those entries before selection.
/// A zero-weight upstream is drained and left out; a defensive cap keeps
/// every selector's internal weighted table bounded.
///
/// Addresses are *not* resolved here: the load balancer keeps the parsed
/// specs so a hostname can be re-resolved later, and an upstream that is not
/// answering DNS yet stays in the list instead of being dropped for good.
///
/// 🧭 Dial strings containing placeholders cannot join the static pool at
/// all — their address is only known per request — so they are returned as
/// templates instead of being parsed into a hostname that can never dial.
fn build_weighted_upstreams(
    config: &ReverseProxyConfig,
) -> (Vec<UpstreamEntry>, Vec<UpstreamEntry>, Vec<String>) {
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
    let mut dynamic_templates = Vec::new();
    for option in options {
        if option.address.contains('{') {
            dynamic_templates.push(option.address);
            continue;
        }
        // ⚖️ Zero drains the upstream: it is left out of the pool, so no
        // policy can pick it. `validate_config` refuses a pool where every
        // primary is drained and any weight above 100, so nothing is clamped
        // here; the `min` only bounds the selector's table should a
        // configuration ever arrive unvalidated.
        //
        // 🤡 Until #266 this was `clamp(1, 100)`: weight 0 became 1, and a
        // backend drained for a cutover kept taking its share of traffic.
        if option.weight == 0 {
            continue;
        }
        let weight = option.weight.min(100);
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
            None => {
                tracing::warn!(upstream = %option.address, "🧯 Ignoring invalid upstream address")
            }
        }
    }
    (primary, backup, dynamic_templates)
}

fn find_access_control_config(handler: &HandlerConfig) -> Option<&AccessControlConfig> {
    match handler {
        HandlerConfig::AccessControl(config) => Some(config),
        HandlerConfig::Pipeline { handlers }
        | HandlerConfig::FirstMatch { handlers }
        | HandlerConfig::HandlePath { handlers, .. } => handlers
            .iter()
            .find_map(|element| find_access_control_config(&element.handler)),
        _ => None,
    }
}

/// 🧭 Whether a handler tree contains a reverse proxy (used to make
/// `file_server` stand down when Caddy's directive order would proxy first).
pub(crate) fn contains_reverse_proxy(handler: &HandlerConfig) -> bool {
    match handler {
        HandlerConfig::ReverseProxy(config) => config.subrequest.is_none(),
        HandlerConfig::Pipeline { handlers }
        | HandlerConfig::FirstMatch { handlers }
        | HandlerConfig::HandlePath { handlers, .. } => handlers
            .iter()
            .any(|element| contains_reverse_proxy(&element.handler)),
        _ => false,
    }
}

/// 🔁 Collects every inline proxy target before the route becomes reachable.
fn collect_subrequest_plans(
    handler: &HandlerConfig,
    prepared: &mut Vec<Arc<crate::subrequest::PreparedSubrequest>>,
) {
    match handler {
        HandlerConfig::ReverseProxy(config) if config.subrequest.is_some() => {
            if let Some(plan) = crate::subrequest::PreparedSubrequest::new((**config).clone()) {
                prepared.push(Arc::new(plan));
            }
        }
        // 🔐 Direct JSON may still use the legacy handler; it enters the same
        // prepared exchange as the normalized Pingclairfile form.
        HandlerConfig::ForwardAuth(config) => {
            if let Some(plan) =
                crate::subrequest::PreparedSubrequest::new(config.as_reverse_proxy_subrequest())
            {
                prepared.push(Arc::new(plan));
            }
        }
        HandlerConfig::Pipeline { handlers }
        | HandlerConfig::FirstMatch { handlers }
        | HandlerConfig::HandlePath { handlers, .. } => {
            for element in handlers {
                collect_subrequest_plans(&element.handler, prepared);
            }
        }
        HandlerConfig::HandleErrors { errors } => {
            for handlers in errors.values() {
                for handler in handlers {
                    collect_subrequest_plans(handler, prepared);
                }
            }
        }
        HandlerConfig::TryFiles {
            fallback: Some(fallback),
            ..
        } => collect_subrequest_plans(fallback, prepared),
        _ => {}
    }
}

/// 📥 The widest limit any `request_body` handler in this tree could set.
///
/// A route may hold several, each behind its own matcher, and which one runs
/// is a per-request answer. This is the load-time answer to a different
/// question — "what is the most this route could ever allow?" — which is
/// exactly what a check that runs before the matchers do is able to use.
fn collect_request_body_ceiling(handler: &HandlerConfig) -> Option<u64> {
    match handler {
        HandlerConfig::RequestBody { max_size, .. } => *max_size,
        HandlerConfig::Pipeline { handlers }
        | HandlerConfig::FirstMatch { handlers }
        | HandlerConfig::HandlePath { handlers, .. } => handlers
            .iter()
            .filter_map(|element| collect_request_body_ceiling(&element.handler))
            // 🔓 Zero means unlimited, so it outranks every finite ceiling
            // rather than losing the comparison to one.
            .reduce(|left, right| {
                if left == 0 || right == 0 {
                    0
                } else {
                    left.max(right)
                }
            }),
        _ => None,
    }
}

/// ⏱️ The deadlines a route's `request_body` handlers could set, in
/// milliseconds, for the seeding described at `initialize_request_limits`.
///
/// Both fields are the *longest* declared value, not the shortest. The seed is
/// what applies when the handler has not run yet — the locally answered body
/// drain runs before dispatch — and a route that says "this upload may take up
/// to 10 minutes" must not be cut off at 2 because a second, matcher-guarded
/// block in the same route mentioned 2.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RouteBodyTimeouts {
    pub(crate) read_ms: Option<u64>,
    pub(crate) write_ms: Option<u64>,
}

impl RouteBodyTimeouts {
    /// 🔗 Keeps the longer of two candidates per field.
    fn merge(self, other: Self) -> Self {
        Self {
            read_ms: longest(self.read_ms, other.read_ms),
            write_ms: longest(self.write_ms, other.write_ms),
        }
    }
}

/// 🔓 Zero would mean "no deadline" in Caddy's vocabulary, but durations here
/// are already positive-only, so an absent value is the only "unset".
fn longest(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (value, None) | (None, value) => value,
    }
}

/// ⏱️ The widest deadlines any `request_body` handler in this tree could set.
fn collect_request_body_timeouts(handler: &HandlerConfig) -> RouteBodyTimeouts {
    match handler {
        HandlerConfig::RequestBody {
            read_timeout_ms,
            write_timeout_ms,
            ..
        } => RouteBodyTimeouts {
            read_ms: *read_timeout_ms,
            write_ms: *write_timeout_ms,
        },
        HandlerConfig::Pipeline { handlers }
        | HandlerConfig::FirstMatch { handlers }
        | HandlerConfig::HandlePath { handlers, .. } => handlers
            .iter()
            .map(|element| collect_request_body_timeouts(&element.handler))
            .fold(RouteBodyTimeouts::default(), RouteBodyTimeouts::merge),
        _ => RouteBodyTimeouts::default(),
    }
}

/// 🔁 Resolves one header replacement into a pattern and a replacement string.
///
/// Almost every pattern is a literal, and those were compiled when the
/// configuration was published — this is a lookup. A pattern that carries a
/// placeholder is a different thing: it is not a regex until the request
/// supplies the value, so it is built here, per request. That cost is real and
/// it is the price of the feature; a configuration that does not ask for a
/// per-request pattern never pays it.
///
/// Returns `None` when the pattern is missing or does not compile, having said
/// so — a replacement that cannot run must not silently rewrite nothing.
// 🚨 One argument past the lint's limit: the lookup needs both the route whose
// table it reads and, while an error route runs, which error route (#245).
#[allow(clippy::too_many_arguments)]
pub(crate) fn compiled_header_replacement(
    state: &ProxyState,
    route_index: usize,
    error_route: Option<usize>,
    entry: &pingclair_core::config::HeaderReplacement,
    request_header: &pingora_http::RequestHeader,
    verified_client_ip: Option<&str>,
    scheme: &'static str,
    vars: &crate::http_policy::RequestVars,
) -> Option<(Arc<Regex>, String)> {
    let replacement = if entry.replace.contains('{') {
        resolve_caddy_placeholders(
            &entry.replace,
            request_header,
            verified_client_ip,
            scheme,
            vars,
        )
        .into_owned()
    } else {
        entry.replace.clone()
    };

    if !entry.search_regexp.contains('{') {
        // 🚨 While an error route runs, its own table answers: the header
        // operation belongs to the route body being run, and the table of the
        // route that raised the error is a different configuration (#245).
        let compiled = match error_route {
            Some(index) => state
                .error_routes
                .get(index)
                .and_then(|route| route.regexes.get(&entry.search_regexp).cloned()),
            None => state.route_regex_arc(route_index, &entry.search_regexp),
        };
        return match compiled {
            Some(pattern) => Some((pattern, replacement)),
            None => {
                tracing::warn!(
                    pattern = %entry.search_regexp,
                    "🚫 header replace pattern missing from the active configuration"
                );
                None
            }
        };
    }

    let resolved = resolve_caddy_placeholders(
        &entry.search_regexp,
        request_header,
        verified_client_ip,
        scheme,
        vars,
    );
    match Regex::new(&resolved) {
        Ok(pattern) => Some((Arc::new(pattern), replacement)),
        Err(error) => {
            tracing::warn!(
                pattern = %resolved,
                %error,
                "🚫 header replace pattern did not compile once its placeholders were resolved"
            );
            None
        }
    }
}

pub(crate) fn collect_route_regexes(
    handler: &HandlerConfig,
    regexes: &mut HashMap<String, Arc<Regex>>,
) {
    match handler {
        HandlerConfig::Rewrite {
            regex: Some(pattern),
            ..
        } => match Regex::new(pattern) {
            Ok(regex) => {
                regexes.insert(pattern.clone(), Arc::new(regex));
            }
            Err(error) => tracing::error!(pattern, %error, "🧯 Invalid rewrite regex"),
        },
        // 🏷️ Both header directives search with a regex, and both are compiled
        // here for the same reason: the pattern is known at load and can never
        // change per request.
        HandlerConfig::RequestHeaders { replace, .. } | HandlerConfig::Headers { replace, .. } => {
            for replacement in replace {
                // 🧭 A pattern with a placeholder in it only becomes a pattern
                // once the request supplies the value, so there is nothing to
                // compile here. Those are built per request instead — the cost
                // of a feature that asks for a different pattern each time.
                if replacement.search_regexp.contains('{') {
                    continue;
                }
                match Regex::new(&replacement.search_regexp) {
                    Ok(regex) => {
                        regexes.insert(replacement.search_regexp.clone(), Arc::new(regex));
                    }
                    Err(error) => tracing::error!(
                        pattern = %replacement.search_regexp,
                        %error,
                        "🧯 Invalid request_header replace regex"
                    ),
                }
            }
        }
        // 🔁 A retry predicate's regex is compiled here for a sharper reason
        // than the rest: it is only ever consulted *after* an attempt has
        // already failed, so compiling it lazily would put the cost exactly
        // where the machine can least afford it.
        HandlerConfig::ReverseProxy(proxy) => {
            for predicate in &proxy.retry.retry_match {
                predicate.for_each_regex(&mut |pattern| match Regex::new(pattern) {
                    Ok(regex) => {
                        regexes.insert(pattern.to_string(), Arc::new(regex));
                    }
                    Err(error) => {
                        tracing::error!(pattern, %error, "🧯 Invalid lb_retry_match regex")
                    }
                });
            }
        }
        HandlerConfig::Pipeline { handlers }
        | HandlerConfig::FirstMatch { handlers }
        | HandlerConfig::HandlePath { handlers, .. } => {
            for element in handlers {
                collect_route_regexes(&element.handler, regexes);
            }
        }
        _ => {}
    }
}

/// 🧭 Renders a Caddy-compatible template with the functions the tutorial
/// relies on: `now` plus the `date` filter (Go layouts) and `include`.
pub(crate) fn render_template(source: &str, root: &str) -> Result<String, String> {
    use minijinja::{Environment, Error, ErrorKind};

    let source = normalize_variable_calls(&normalize_filter_calls(source));
    let root_owned = root.to_string();
    let mut env = Environment::new();
    env.add_filter("date", move |_value: String, layout: String| {
        let format = go_layout_to_chrono(&layout);
        Ok(chrono::Local::now().format(&format).to_string())
    });
    let include_root = root_owned.clone();
    env.add_function("include", move |path: String| {
        let target = std::path::Path::new(&include_root).join(path.trim_start_matches('/'));
        std::fs::read_to_string(&target)
            .map_err(|error| Error::new(ErrorKind::InvalidOperation, error.to_string()))
    });
    let template = env
        .template_from_str(&source)
        .map_err(|error| error.to_string())?;
    template
        .render(minijinja::context!())
        .map_err(|error| error.to_string())
}

/// 🧭 Caddy writes filters as `| date "layout"`; Jinja (minijinja) wants
/// `| date("layout")`. Rewriting the quoted argument form keeps Caddy
/// templates readable while the engine accepts them.
fn normalize_filter_calls(source: &str) -> String {
    let mut output = String::new();
    let mut rest = source;
    while let Some(pipe) = rest.find("| ") {
        output.push_str(&rest[..pipe]);
        rest = &rest[pipe + 2..];
        let name_end = rest
            .find(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .unwrap_or(rest.len());
        let name = &rest[..name_end];
        rest = &rest[name_end..];
        if let Some(after_space) = rest.strip_prefix(" \"")
            && let Some(quote_end) = after_space.find('"')
        {
            let argument = &after_space[..quote_end];
            output.push_str(&format!("| {name}(\"{argument}\")"));
            rest = &after_space[quote_end + 1..];
        } else {
            output.push_str(&format!("| {name}"));
        }
    }
    output.push_str(rest);
    output
}

/// 🧭 Caddy also writes bare function calls as `{{include "path"}}`; Jinja
/// needs parentheses. This rewrites the leading `{{name "arg"` form.
fn normalize_variable_calls(source: &str) -> String {
    let mut output = String::new();
    let mut rest = source;
    while let Some(open) = rest.find("{{") {
        output.push_str(&rest[..open + 2]);
        rest = &rest[open + 2..];
        let name_end = rest
            .find(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .unwrap_or(rest.len());
        output.push_str(&rest[..name_end]);
        rest = &rest[name_end..];
        if let Some(after_space) = rest.strip_prefix(" \"")
            && let Some(quote_end) = after_space.find('"')
        {
            output.push_str(&format!("(\"{}\")", &after_space[..quote_end]));
            rest = &after_space[quote_end + 1..];
        }
    }
    output.push_str(rest);
    output
}

/// 🧭 Translates Go's reference time layout into a chrono/strftime format.
///
/// Caddy templates use Go layouts (`"Mon Jan 2 15:04:05 MST 2006"`); the
/// tutorial's `date` filter passes one through verbatim, so the common
/// tokens are mapped here.
fn go_layout_to_chrono(layout: &str) -> String {
    layout
        .replace("MST", "%Z")
        .replace("Mon", "%a")
        .replace("Jan", "%b")
        .replace("2006", "%Y")
        .replace("02", "%d")
        .replace("15", "%H")
        .replace("04", "%M")
        .replace("05", "%S")
        .replace('2', "%-d")
}

/// 📂 Builds the file server for the first `file_server` in a handler tree.
///
/// Off the request path: it runs once per route, and once per error route,
/// when a configuration is loaded.
pub(crate) fn build_file_server(
    handler: &HandlerConfig,
    site: &ServerConfig,
) -> Option<Arc<pingclair_static::FileServer>> {
    let Some(HandlerConfig::FileServer {
        root,
        index,
        browse,
        browse_limit,
        compress,
        precompressed,
        hide,
        status,
        pass_thru: _,
        canonical_uris,
        etag_file_extensions,
    }) = find_file_server_config(handler)
    else {
        return None;
    };
    Some(Arc::new(pingclair_static::FileServer::new(
        pingclair_static::FileServerConfig::from_handler(
            root,
            index,
            *browse,
            *browse_limit,
            *compress,
            precompressed,
            hide,
            *status,
            *canonical_uris,
            etag_file_extensions,
        )
        .with_site_encode(site),
    )))
}

/// Find the first `FileServer` config in a handler tree, recursing through
/// `Pipeline`/`Handle`/`HandlePath` wrappers. Returns the `FileServer`
/// handler node itself so the caller can destructure its fields.
fn find_file_server_config(handler: &HandlerConfig) -> Option<&HandlerConfig> {
    match handler {
        HandlerConfig::FileServer { .. } => Some(handler),
        HandlerConfig::Pipeline { handlers }
        | HandlerConfig::FirstMatch { handlers }
        | HandlerConfig::HandlePath { handlers, .. } => handlers
            .iter()
            .find_map(|element| find_file_server_config(&element.handler)),
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
        | HandlerConfig::FirstMatch { handlers }
        | HandlerConfig::HandlePath { handlers, .. } => {
            for element in handlers {
                if let Some(config) = find_rate_limit_config(&element.handler, route) {
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
// Targeted tests for the 4 P0 issues fixed in the 2026-07-26 nginx-parity
// production-risk audit: gzip OOM risk, request ID syscall overhead, hosts
// lock contention, and upstream connection pool sizing.
#[cfg(test)]
mod forwarded_headers_tests;

#[cfg(test)]
mod p0_regression_tests;

#[cfg(test)]
mod placeholder_shorthand_tests {
    use super::{decode_query_component, path_part, query_parameter};

    /// 🧭 Path parts follow Caddy's split: the leading empty element goes,
    /// middle empty segments stay, and `dir`/`file` are `path.Split`'s halves.
    #[test]
    fn path_parts_match_caddys_split() {
        assert_eq!(path_part("/a/b", "0").as_deref(), Some("a"));
        assert_eq!(path_part("/a/b", "1").as_deref(), Some("b"));
        assert_eq!(path_part("/a/b", "2").as_deref(), Some(""));
        assert_eq!(path_part("/a//b", "1").as_deref(), Some(""));
        assert_eq!(path_part("/a/b", "dir").as_deref(), Some("/a/"));
        assert_eq!(path_part("/a/b", "file").as_deref(), Some("b"));
        assert_eq!(path_part("/only", "dir").as_deref(), Some("/"));
        assert_eq!(path_part("relative", "dir").as_deref(), Some(""));
        assert_eq!(path_part("/a/b", "not-a-part"), None);
        assert_eq!(path_part("/a/b", "01"), Some("b".to_string()));
    }

    /// 🧭 Query parameters keep every occurrence, decode escapes, and treat
    /// `+` as a space — Go's `url.Values`, which is what Caddy reads.
    #[test]
    fn query_parameters_match_go_values() {
        assert_eq!(query_parameter("a=1&a=2&b=3", "a"), "1,2");
        assert_eq!(query_parameter("b=x+y", "b"), "x y");
        assert_eq!(query_parameter("a%2Fb=1", "a/b"), "1");
        assert_eq!(query_parameter("a=1", "missing"), "");
        assert_eq!(query_parameter("a", "a"), "");
        // 🚫 A malformed escape drops that pair, as `url.ParseQuery` does.
        assert_eq!(query_parameter("a=%zz&a=2", "a"), "2");
        assert_eq!(decode_query_component("a%2Fb").as_deref(), Some("a/b"));
        assert_eq!(decode_query_component("%zz"), None);
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
mod caddy_parity_tests;

#[cfg(test)]
mod template_tests {
    use super::*;

    #[test]
    fn go_layout_to_chrono_converts_caddy_layouts() {
        assert_eq!(
            go_layout_to_chrono("Mon Jan 2 15:04:05 MST 2006"),
            "%a %b %-d %H:%M:%S %Z %Y"
        );
        assert_eq!(go_layout_to_chrono("2006-01-02"), "%Y-01-%d");
        assert_eq!(
            normalize_filter_calls("{{now | date \"Mon Jan 2\"}}"),
            "{{now | date(\"Mon Jan 2\")}}"
        );
    }

    #[test]
    fn templates_render_now_date_and_include() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("part.html"), "included").unwrap();
        let source = "{{now | date \"2006-01-02\"}} {{include \"/part.html\"}}";
        let rendered = render_template(source, dir.path().to_str().unwrap()).unwrap();
        assert!(
            !rendered.contains("{{"),
            "template must be evaluated: {rendered}"
        );
        assert!(rendered.contains("included"));
        let year = rendered.split('-').next().unwrap();
        assert_eq!(
            year.len(),
            4,
            "date must render a four-digit year: {rendered}"
        );
    }

    #[test]
    fn plain_files_are_not_treated_as_templates() {
        assert!(
            !render_template("no braces here", ".")
                .unwrap()
                .contains("{{")
        );
    }
}

#[cfg(test)]
mod upstream_error_retry_tests;

// MARK: - Log severity for request failures

/// 📉 Which failures are worth an operator's attention, and which are just
/// clients being clients.
#[cfg(test)]
mod failure_severity_tests;

#[cfg(test)]
mod response_cache_tests;

#[cfg(test)]
mod hash_key_tests;
