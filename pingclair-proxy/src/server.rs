//! Pingclair HTTP Proxy implementation using Pingora
//!
//! 🌐 This module implements the core reverse proxy using Pingora's ProxyHttp trait.

use pingclair_core::config::{ServerConfig, HandlerConfig, ReverseProxyConfig, BasicAuthCredential};
use pingclair_core::server::Router;

use async_trait::async_trait;
use pingora_core::upstreams::peer::{HttpPeer, Peer};
use pingora_core::Result as PingoraResult;
use pingora_proxy::{ProxyHttp, Session};
use pingora_http::{RequestHeader, ResponseHeader};

use std::sync::Arc;
use std::collections::HashMap;
use std::time::Duration;
use arc_swap::ArcSwap;
use async_recursion::async_recursion;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;

use crate::{LoadBalancer, Strategy, Upstream, HealthChecker};
use crate::upstream::{create_upstream, Scheme, HostName};
use crate::metrics;
use bytes::Bytes;

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
    /// Extra headers to add downstream (set)
    pub headers_downstream: HashMap<String, String>,
    /// Extra headers to add downstream (append)
    pub headers_downstream_add: HashMap<String, String>,
    /// Headers to remove from downstream response
    pub headers_remove: Vec<String>,
    /// Whether to suppress the default Server header
    pub suppress_server_header: bool,
    /// Whether response compression is enabled for this request
    pub compress_response: bool,
    /// Client accepts gzip
    pub client_accepts_gzip: bool,
    /// Whether the matched route requested immediate per-chunk flushing
    /// (`flush_interval: -1`). When true, body chunks flow downstream as
    /// they arrive from upstream and response compression is disabled so
    /// SSE / LLM-style streaming endpoints work through the proxy.
    pub streaming_response: bool,
    /// Gzip encoder accumulating response body chunks
    pub gzip_encoder: Option<GzEncoder<Vec<u8>>>,
    /// Request method (for access log)
    pub request_method: String,
    /// Request path (for access log)
    pub request_path: String,
    /// Request host (for access log)
    pub request_host: String,
    /// Upstream response status (for access log)
    pub response_status: u16,
    /// Response body bytes written (for access log)
    pub response_bytes: u64,
    /// Unique request ID
    pub request_id: String,
    /// Start time for logging
    pub start_time: std::time::Instant,
}

impl Default for RequestContext {
    fn default() -> Self {
        Self {
            state: None,
            route_index: None,
            upstream: None,
            headers_upstream: HashMap::new(),
            headers_downstream: HashMap::new(),
            headers_downstream_add: HashMap::new(),
            headers_remove: Vec::new(),
            suppress_server_header: false,
            compress_response: false,
            client_accepts_gzip: false,
            streaming_response: false,
            gzip_encoder: None,
            request_method: String::new(),
            request_path: String::new(),
            request_host: String::new(),
            response_status: 0,
            response_bytes: 0,
            request_id: generate_request_id(),
            start_time: std::time::Instant::now(),
        }
    }
}

/// Process-wide base timestamp for request IDs, captured once instead of
/// on every request.
static REQUEST_ID_EPOCH_US: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
/// Monotonic per-process request counter.
static REQUEST_ID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Generate a compact, sortable request ID (process epoch + counter).
///
/// The original implementation called `SystemTime::now()` — a syscall — on
/// every single request. At high QPS that syscall overhead is pure waste:
/// the ID only needs to be unique and roughly time-ordered, not carry a
/// precise per-request timestamp. So the wall-clock read happens exactly
/// once per process (lazily, on the first request), and every subsequent
/// request just does one relaxed atomic increment.
fn generate_request_id() -> String {
    use std::sync::atomic::Ordering;
    let epoch = *REQUEST_ID_EPOCH_US.get_or_init(|| {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64
    });
    let seq = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:x}-{:x}", epoch, seq)
}

/// Feed one response body chunk through a streaming gzip encoder.
///
/// 🏗️ ARCHITECTURE: real streaming, not full-body buffering.
///
/// A naive implementation accumulates every chunk in the encoder and only
/// emits output once, at `end_of_stream` — so a large upstream response (or
/// an adversarial client requesting one) means buffering the *entire* body
/// in memory before the first byte goes out: an OOM risk independent of
/// how big the response actually needs to be in flight at once. Here we
/// force a sync flush after every chunk, which pushes whatever the deflate
/// stream has buffered internally out into the encoder's small `Vec<u8>`,
/// then drain that Vec as this chunk's output via `mem::take`. Memory use
/// is bounded by one chunk's worth of compressed bytes, regardless of
/// total response size.
///
/// Extracted as a free function (rather than inlined in the `ProxyHttp`
/// trait impl) so it can be unit-tested without needing a live Pingora
/// `Session`.
fn stream_gzip_chunk(
    encoder_slot: &mut Option<GzEncoder<Vec<u8>>>,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
) {
    if encoder_slot.is_none() {
        return;
    }

    // Feed this chunk into the encoder.
    if let Some(chunk) = body.as_ref() {
        if let Some(encoder) = encoder_slot.as_mut() {
            if let Err(e) = encoder.write_all(chunk) {
                tracing::warn!(
                    "⚠️ Gzip compression failed, aborting compression for the rest of this response: {}",
                    e
                );
                // Bail out of compression entirely; the client already
                // received a Content-Encoding: gzip header for this
                // response so we cannot fall back to plaintext mid-stream
                // — better to end the response short than to send a
                // client a body it can't decode.
                *encoder_slot = None;
                *body = None;
                return;
            }
        }
    }

    if end_of_stream {
        // Finalize: flushes any remaining buffered bytes plus the gzip
        // trailer (CRC32 + uncompressed size) into the encoder's Vec.
        if let Some(encoder) = encoder_slot.take() {
            match encoder.finish() {
                Ok(tail) => *body = Some(Bytes::from(tail)),
                Err(e) => {
                    tracing::warn!("⚠️ Gzip finalize failed: {}", e);
                    *body = Some(Bytes::new());
                }
            }
        }
        return;
    }

    if let Some(encoder) = encoder_slot.as_mut() {
        if let Err(e) = encoder.flush() {
            tracing::warn!("⚠️ Gzip flush failed: {}", e);
        }
        let out = std::mem::take(encoder.get_mut());
        *body = Some(Bytes::from(out));
    }
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
        let router = Router::new(config.routes.clone());
        
        // Initialize components for each route
        let mut load_balancers = Vec::new();
        let mut health_checkers = Vec::new();
        let mut file_servers = Vec::new();
        let mut rate_limiters = Vec::new();

        for route in &config.routes {
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
                let upstreams: Vec<Upstream> = proxy_config.upstreams.iter()
                    .filter_map(|addr| create_upstream(addr))
                    .collect();

                if upstreams.is_empty() {
                    tracing::warn!("⚠️ No valid upstreams found for route {}", route.path);
                }

                let strategy = match proxy_config.load_balance.strategy.as_str() {
                    "random"     => Strategy::Random,
                    "least_conn" => Strategy::LeastConn,
                    "ip_hash"    => Strategy::IpHash,
                    "first"      => Strategy::RoundRobin,
                    _            => Strategy::RoundRobin,
                };

                let mut load_balancer = Arc::new(LoadBalancer::new(upstreams, strategy));

                if let Some(hc_config) = &proxy_config.health_check {
                    let health_check_conf = crate::health_check::HealthCheckConfig {
                         path: hc_config.path.clone(),
                         timeout: std::time::Duration::from_secs(hc_config.timeout),
                         positive_threshold: 1,
                         negative_threshold: hc_config.threshold as usize,
                         expected_status: (200, 299),
                    };

                    let health_checker = HealthChecker::new(health_check_conf);

                    if let Some(load_balancer_mut) = Arc::get_mut(&mut load_balancer) {
                        load_balancer_mut.set_health_check(health_checker);
                        load_balancer_mut.set_health_check_frequency(std::time::Duration::from_secs(hc_config.interval));
                    } else {
                        tracing::warn!("Correlation ID: Init - Could not attach health checker to LB");
                    }
                }

                load_balancers.push(Some(load_balancer));
                tracing::info!(
                    "⚖️ Initialized load balancer for route {} with strategy {:?}",
                    route.path, strategy
                );
            } else {
                load_balancers.push(None);
            }

            // Health checker is stored inside the LB object; this slot is a
            // tombstone kept only for index alignment with load_balancers.
            health_checkers.push(None);

            // File server (possibly nested inside a handle/route block)
            if let Some(HandlerConfig::FileServer { root, index, browse, compress }) =
                find_file_server_config(&route.handler)
            {
                let fs_config = pingclair_static::FileServerConfig {
                    root: std::path::PathBuf::from(root),
                    index: if index.is_empty() { vec!["index.html".to_string()] } else { index.clone() },
                    browse: *browse,
                    compress: *compress,
                    precompressed: true,  // Enable pre-compressed file detection by default
                };

                file_servers.push(Some(Arc::new(pingclair_static::FileServer::new(fs_config))));
                tracing::info!("📁 Initialized file server for route {}", route.path);
            } else {
                file_servers.push(None);
            }

            // Check for rate limit config
            if let Some(rl_config) = find_rate_limit_config(&route.handler) {
                use crate::rate_limit::RateLimiter;
                rate_limiters.push(Some(RateLimiter::new(rl_config)));
                tracing::info!("🚦 Initialized rate limiter for route {}", route.path);
            } else {
                rate_limiters.push(None);
            }
        }
        
        Self {
            config: Arc::new(config),
            router: Arc::new(router),
            load_balancers,
            health_checkers,
            file_servers,
            rate_limiters,
        }
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
}

impl Default for PingclairProxy {
    fn default() -> Self {
        Self {
            hosts: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            default: Arc::new(ArcSwap::from_pointee(None)),
            tls_manager: None,
            alt_svc: Arc::new(ArcSwap::from_pointee(None)),
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
        }
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
        let state = ProxyState::new(config.clone());

        if let Some(domain) = &config.name {
            if domain == "_" || domain == "*" || domain.starts_with(':') {
                self.default.store(Arc::new(Some(state)));
            } else {
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
            self.default.store(Arc::new(Some(state)));
        }
    }

    /// Replace all server configurations with a new list
    pub fn update_config(&self, servers: Vec<ServerConfig>) {
        let mut new_hosts = HashMap::new();
        let mut new_default = None;

        for config in servers {
            let state = ProxyState::new(config.clone());
            if let Some(domain) = &config.name {
                if domain == "_" || domain == "*" || domain.starts_with(':') {
                    new_default = Some(state);
                } else {
                    new_hosts.insert(domain.clone(), state);
                }
            } else {
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
    pub fn match_route(&self, host: &str, path: &str, method: &str, headers: &pingora_http::RequestHeader, remote_ip: &str) -> Option<(ProxyState, Option<usize>, Option<HandlerConfig>)> {
        // 1. Get state for this host
        let state = self.get_state(host)?;
        
        // 2. Match route
        // Identify protocol (stub)
        let protocol = "https"; 
        
        if let Some(route) = state.router.match_request(path, method, &headers.headers, host, remote_ip, protocol) {
            let index = route.index;
            let handler = state.config.routes.get(index).map(|r| r.handler.clone());
            Some((state, Some(index), handler))
        } else {
            // No route matched
            Some((state, None, None))
        }
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
                if host.ends_with(&format!(".{}", wildcard_suffix)) {
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
    
    /// Select an upstream using the load balancer
    pub(crate) fn select_upstream(&self, state: &ProxyState, route_index: usize, remote_addr: Option<&[u8]>) -> Option<Upstream> {
        if let Some(load_balancer) = state.load_balancers.get(route_index).and_then(|lb| lb.as_ref()) {
            load_balancer.select(remote_addr)
        } else {
            None
        }
    }
    
    /// Parse upstream URL into (host, port, tls)
    pub fn parse_upstream(upstream: &str) -> Option<(String, u16, bool)> {
        let upstream = upstream.trim();
        
        let (scheme, rest) = if upstream.starts_with("https://") {
            (true, &upstream[8..])
        } else if upstream.starts_with("http://") {
            (false, &upstream[7..])
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
    pub(crate) fn get_proxy_config(&self, state: &ProxyState, route_index: usize) -> Option<ReverseProxyConfig> {
        let route = state.config.routes.get(route_index)?;
        // Recurse into handle/route blocks so a nested reverse_proxy's
        // headers/timeouts are picked up, matching how ProxyState::new sets
        // up its load balancer.
        find_reverse_proxy_config(&route.handler).cloned()
    }

    /// Build an [`HttpPeer`] for a selected upstream, applying the route's
    /// configured read/write timeouts plus a default 10s connect timeout.
    ///
    /// Shared by the Pingora proxy path (`upstream_peer`) and the HTTP/3
    /// reverse-proxy path (`crate::quic`) so both honor identical timeout
    /// and SNI semantics.
    pub(crate) fn build_http_peer(
        upstream: &Upstream,
        read_timeout_ms: Option<i64>,
        write_timeout_ms: Option<i64>,
    ) -> HttpPeer {
        let addr = upstream.addr.clone();
        let scheme = upstream.ext.get::<Scheme>().unwrap_or(&Scheme::Http);
        let host = upstream.ext.get::<HostName>().map(|h| h.0.clone()).unwrap_or_else(|| match &addr {
             pingora_core::protocols::l4::socket::SocketAddr::Inet(inet) => inet.ip().to_string(),
             pingora_core::protocols::l4::socket::SocketAddr::Unix(u) => u.as_pathname().map(|p| p.to_string_lossy().to_string()).unwrap_or("unix_socket".to_string()),
        });
        let tls = *scheme == Scheme::Https;

        let mut peer = HttpPeer::new(addr, tls, host);

        // Apply timeouts if configured
        if let Some(read_timeout) = read_timeout_ms {
            if read_timeout > 0 {
                peer.options.read_timeout = Some(std::time::Duration::from_millis(read_timeout as u64));
            }
        }

        if let Some(write_timeout) = write_timeout_ms {
            if write_timeout > 0 {
                peer.options.write_timeout = Some(std::time::Duration::from_millis(write_timeout as u64));
            }
        }

        // Set default connection timeout (10 seconds) if not configured
        if peer.options.connection_timeout.is_none() {
            peer.options.connection_timeout = Some(std::time::Duration::from_secs(10));
        }

        peer
    }

    /// Write a minimal plain-text response and end the request.
    /// Used for early, handler-less answers such as 404s.
    async fn write_simple_response(session: &mut Session, status: u16, body: &str) -> PingoraResult<()> {
        let mut response = ResponseHeader::build(status, Some(3)).unwrap();
        response.insert_header("Content-Type", "text/plain").unwrap();
        response.insert_header("Content-Length", body.len().to_string()).unwrap();
        response.insert_header("Server", "Pingclair").unwrap();
        session.write_response_header(Box::new(response), false).await?;
        session.write_response_body(Some(Bytes::copy_from_slice(body.as_bytes())), true).await?;
        Ok(())
    }

    /// Handle a specific handler configuration
    #[async_recursion]
    async fn handle_config(
        &self, 
        session: &mut Session, 
        ctx: &mut RequestContext, 
        handler: &HandlerConfig, 
        path: &str, 
        route_index: usize
    ) -> PingoraResult<bool> {
        match handler {
            HandlerConfig::Respond { status, body, headers } => {
                let mut response = ResponseHeader::build(*status, Some(3)).unwrap();
                for (k, v) in headers {
                    if let (Ok(name), Ok(value)) = (
                        http::header::HeaderName::from_bytes(k.as_bytes()),
                        http::header::HeaderValue::from_str(v.as_str())
                    ) {
                        response.insert_header(name, value).unwrap();
                    }
                }
                let body_bytes = body.as_deref().unwrap_or("").as_bytes();
                response.insert_header("Content-Length", body_bytes.len().to_string()).unwrap();
                response.insert_header("Server", "Pingclair").unwrap();
                session.write_response_header(Box::new(response), false).await?;
                session.write_response_body(Some(Bytes::copy_from_slice(body_bytes)), true).await?;
                Ok(true)
            }
            HandlerConfig::Redirect { to, code } => {
                let mut response = ResponseHeader::build(*code, Some(3)).unwrap();
                response.insert_header("Location", to.as_str()).unwrap();
                response.insert_header("Server", "Pingclair").unwrap();
                session.write_response_header(Box::new(response), true).await?;
                Ok(true)
            }
            HandlerConfig::FileServer { .. } => {
                let maybe_file_server = {
                    ctx.state.as_ref().and_then(|state| {
                        state.file_servers.get(route_index).and_then(|f| f.clone())
                    })
                };

                if let Some(file_server) = maybe_file_server {
                    let range_header = session.req_header().headers.get("Range")
                        .and_then(|v| v.to_str().ok());
                    let accept_encoding = session.req_header().headers.get("Accept-Encoding")
                        .and_then(|v| v.to_str().ok());

                    // serve_auto makes the buffered-vs-streaming call in one
                    // pass (single resolve + stat per request): large,
                    // complete, uncompressed responses stream in 64KB chunks
                    // instead of being buffered whole in memory.
                    match file_server.serve_auto(path, range_header, accept_encoding).await {
                        Ok(Some(pingclair_static::ServedResponse::Stream(mut stream))) => {
                            let mut header = ResponseHeader::build(200, Some(3)).unwrap();
                            header.insert_header("Content-Type", stream.mime_type.as_str()).unwrap();
                            header.insert_header("Content-Length", stream.file_size.to_string()).unwrap();
                            if let Some(lm) = &stream.last_modified {
                                header.insert_header("Last-Modified", lm.as_str()).unwrap();
                            }
                            if let Some(etag) = &stream.etag {
                                header.insert_header("ETag", etag.as_str()).unwrap();
                            }
                            header.insert_header("Accept-Ranges", "bytes").unwrap();
                            header.insert_header("Server", "Pingclair").unwrap();

                            session.write_response_header(Box::new(header), false).await?;
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
                                session.write_response_body(Some(Bytes::from(chunk)), last).await?;
                            }
                            return Ok(true);
                        }
                        Ok(Some(pingclair_static::ServedResponse::Buffered(file))) => {
                            let mut header = ResponseHeader::build(file.status, Some(3)).unwrap();
                            header.insert_header("Content-Type", file.mime_type.as_str()).unwrap();
                            header.insert_header("Content-Length", file.content.len().to_string()).unwrap();

                            if let Some(range) = file.content_range {
                                header.insert_header("Content-Range", range.as_str()).unwrap();
                            }
                            if let Some(lm) = file.last_modified {
                                header.insert_header("Last-Modified", lm.as_str()).unwrap();
                            }
                            if let Some(etag) = file.etag {
                                header.insert_header("ETag", etag.as_str()).unwrap();
                            }
                            if let Some(encoding) = file.content_encoding {
                                header.insert_header("Content-Encoding", encoding.as_str()).unwrap();
                            }
                            header.insert_header("Accept-Ranges", "bytes").unwrap();
                            header.insert_header("Server", "Pingclair").unwrap();

                            session.write_response_header(Box::new(header), false).await?;
                            session.write_response_body(Some(Bytes::from(file.content)), true).await?;
                            return Ok(true);
                        }
                        // Missing file (or read error): a file_server route
                        // has no upstream to fall back to, so answer 404
                        // here instead of falling through to upstream_peer,
                        // which would surface a 500 (ConnectNoRoute).
                        _ => {
                            Self::write_simple_response(session, 404, "404 Not Found").await?;
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            }
            HandlerConfig::Pipeline(handlers) => {
                for h in handlers {
                    if self.handle_config(session, ctx, h, path, route_index).await? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            HandlerConfig::Handle(handlers) => {
                 for h in handlers {
                    if self.handle_config(session, ctx, h, path, route_index).await? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            HandlerConfig::HandlePath { prefix, handlers } => {
                let new_path = if path.starts_with(prefix) {
                    let p = &path[prefix.len()..];
                     if p.is_empty() {
                         "/"
                     } else if !p.starts_with('/') {
                         // Should ensure leading slash if we want strict path compliance, 
                         // but Caddy handle_path strips exact prefix.
                         // Let's assume absolute paths are preferred.
                         p // Simple strip
                     } else {
                         p
                     }
                } else {
                    path
                };
                
                for h in handlers {
                    if self.handle_config(session, ctx, h, new_path, route_index).await? {
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
                // Rate limiting is handled in request_filter (TODO: verify integration)
                // Returning Ok(false) to proceed
                Ok(false)
            }
            HandlerConfig::BasicAuth { realm, credentials } => {
                // Verify the request's credentials before any later handler
                // in the chain runs. Success falls through (Ok(false)) like
                // the Headers handler; failure answers a 401 challenge.
                if pingclair_core::server::verify_basic_auth(
                    &session.req_header().headers,
                    credentials,
                ) {
                    Ok(false)
                } else {
                    let body = "Unauthorized";
                    let challenge = pingclair_core::server::basic_auth_challenge(realm);
                    let mut response = ResponseHeader::build(401, Some(3)).unwrap();
                    response.insert_header("WWW-Authenticate", challenge.as_str()).unwrap();
                    response.insert_header("Content-Length", body.len().to_string()).unwrap();
                    response.insert_header("Server", "Pingclair").unwrap();
                    session.write_response_header(Box::new(response), false).await?;
                    session.write_response_body(Some(Bytes::copy_from_slice(body.as_bytes())), true).await?;
                    Ok(true)
                }
            }
            HandlerConfig::Headers { set, add, remove } => {
                for (k, v) in set {
                    ctx.headers_downstream.insert(k.clone(), v.clone());
                }
                for (k, v) in add {
                    ctx.headers_downstream_add.insert(k.clone(), v.clone());
                }
                for h in remove {
                    ctx.headers_remove.push(h.clone());
                    // If removing "Server", set flag to suppress default
                    if h.eq_ignore_ascii_case("server") {
                        ctx.suppress_server_header = true;
                    }
                }
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
                let req_header = session.req_header();
                let origin = req_header.headers
                    .get("origin")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();

                // Check if origin is allowed
                let origin_allowed = allowed_origins.is_empty()
                    || allowed_origins.contains(&"*".to_string())
                    || allowed_origins.contains(&origin);

                if !origin_allowed {
                    return Ok(false); // Not a CORS request or origin not allowed
                }

                let allow_origin = if allowed_origins.contains(&"*".to_string()) {
                    "*".to_string()
                } else {
                    origin.clone()
                };

                // Handle preflight OPTIONS request
                if req_header.method == http::Method::OPTIONS {
                    let mut header = pingora_http::ResponseHeader::build(204, Some(8)).unwrap();
                    header.insert_header("Access-Control-Allow-Origin", &allow_origin).unwrap();
                    header.insert_header("Access-Control-Allow-Methods", &allowed_methods.join(", ")).unwrap();
                    header.insert_header("Access-Control-Allow-Headers", &allowed_headers.join(", ")).unwrap();
                    header.insert_header("Access-Control-Max-Age", &max_age.to_string()).unwrap();
                    if *allow_credentials {
                        header.insert_header("Access-Control-Allow-Credentials", "true").unwrap();
                    }
                    if !exposed_headers.is_empty() {
                        header.insert_header("Access-Control-Expose-Headers", &exposed_headers.join(", ")).unwrap();
                    }
                    header.insert_header("Content-Length", "0").unwrap();
                    session.write_response_header(Box::new(header), true).await?;
                    return Ok(true);
                }

                // For non-preflight requests, add CORS headers to downstream
                ctx.headers_downstream.insert(
                    "Access-Control-Allow-Origin".to_string(),
                    allow_origin,
                );
                if *allow_credentials {
                    ctx.headers_downstream.insert(
                        "Access-Control-Allow-Credentials".to_string(),
                        "true".to_string(),
                    );
                }
                if !exposed_headers.is_empty() {
                    ctx.headers_downstream.insert(
                        "Access-Control-Expose-Headers".to_string(),
                        exposed_headers.join(", "),
                    );
                }
                Ok(false)
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
                        let parent = full_path.parent()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_else(|| ".".to_string());
                        let file_handler = HandlerConfig::FileServer {
                            root: parent,
                            index: vec![],
                            browse: false,
                            compress: true,
                        };
                        return self.handle_config(session, ctx, &file_handler, &resolved, route_index).await;
                    }
                }
                // No file found — execute fallback
                if let Some(fb) = fallback {
                    return self.handle_config(session, ctx, fb, path, route_index).await;
                }
                Ok(false)
            }
            _ => Ok(false),
        }
    }
}

// MARK: - Caddy Placeholder Resolution

/// Compute the outgoing `X-Forwarded-For` value: the client IP appended to
/// any existing proxy chain (`"a, b"` → `"a, b, client"`). An absent or
/// blank incoming value starts a fresh chain.
pub(crate) fn append_forwarded_for(existing: Option<&str>, client_ip: &str) -> String {
    match existing {
        Some(chain) if !chain.trim().is_empty() => format!("{}, {}", chain.trim(), client_ip),
        _ => client_ip.to_string(),
    }
}

/// Resolve Caddy-style `{placeholder}` variables in a header value string
/// using the actual downstream request headers.
///
/// Supported placeholders:
/// - `{http.request.header.Header-Name}` → value of the named request header
/// - `{host}`                            → request Host header
/// - `{remote_ip}`                       → client IP (from X-Forwarded-For or peer)
/// - `{http.request.method}`             → HTTP method
/// - `{http.request.uri}`                → full URI
/// - `{http.request.uri.path}`           → URI path only
///
/// If a placeholder references a header that doesn't exist, it resolves to
/// an empty string (matching Caddy's behavior).
pub(crate) fn resolve_caddy_placeholders(template: &str, req: &RequestHeader) -> String {
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
            let resolved = resolve_single_placeholder(&placeholder, req);
            result.push_str(&resolved);
        } else {
            result.push(c);
        }
    }

    result
}

/// Resolve a single Caddy placeholder name to its value.
fn resolve_single_placeholder(name: &str, req: &RequestHeader) -> String {
    // {http.request.header.Header-Name}
    if let Some(header_name) = name.strip_prefix("http.request.header.") {
        return req.headers
            .get(header_name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
    }

    // Common shortcuts
    match name {
        "host" => {
            req.headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        }
        "http.request.host" => {
            req.headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        }
        "remote_ip" | "http.request.remote.host" => {
            // Best effort: try X-Forwarded-For, then X-Real-IP, then empty
            req.headers
                .get("x-forwarded-for")
                .or_else(|| req.headers.get("x-real-ip"))
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        }
        "http.request.method" => {
            req.method.as_str().to_string()
        }
        "http.request.uri" => {
            req.uri.to_string()
        }
        "http.request.uri.path" => {
            req.uri.path().to_string()
        }
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

    /* 
    // Removed in Pingora 0.6: TLS resolution is handled by listeners, not the proxy trait.
    /// Resolve TLS certificate for SNI
    */
    
    /// Request filter (Handle static files and early return)
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> pingora_core::Result<bool> {
        // Handle ACME Challenges (HTTP-01)
        let request_header = session.req_header();
        let path = request_header.uri.path();
        
        if path.starts_with("/.well-known/acme-challenge/") {
            if let Some(manager) = &self.tls_manager {
                 // Extract token
                 let token = path.trim_start_matches("/.well-known/acme-challenge/");
                 
                 // Lookup token in challenge handler
                 let handler = manager.challenge_handler();
                 if let Some(key_auth) = handler.get_token(token) {
                     tracing::info!("🔐 Serving ACME challenge for token: {}", token);
                     
                     let mut header = pingora_http::ResponseHeader::build(200, Some(2)).unwrap();
                     header.insert_header("Content-Type", "application/octet-stream").unwrap();
                     header.insert_header("Content-Length", key_auth.len().to_string()).unwrap();
                     session.write_response_header(Box::new(header), false).await?;
                     session.write_response_body(Some(Bytes::from(key_auth)), true).await?;
                     return Ok(true);
                 } else {
                     tracing::warn!("⚠️ ACME challenge token not found: {}", token);
                 }
            }
        }

        // Match route in a scope to release borrow of session
        let (path_str, route_index, handler, remote_ip, request_host, request_method) = {
            let request_header = session.req_header();
            let path = request_header.uri.path();
            let method = request_header.method.as_str();
            
            // Extract host and strip port
            let host_raw = request_header.headers.get("Host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let host = host_raw.split(':').next().unwrap_or("");
                
            // Get state for this host
            let state = match self.get_state(host) {
                Some(s) => s,
                None => {
                    // Unknown virtual host: nothing could ever proxy this
                    // request, so answer 404 now. Returning Ok(false) here
                    // would land in upstream_peer with no state and surface
                    // as a 500 (ConnectNoRoute).
                    Self::write_simple_response(session, 404, "404 Not Found").await?;
                    return Ok(true);
                }
            };
            ctx.state = Some(state.clone());

            // Extract remote IP
            let remote_ip = session.client_addr()
                .map(|addr| match addr {
                    pingora_core::protocols::l4::socket::SocketAddr::Inet(inet) => inet.ip().to_string(),
                    pingora_core::protocols::l4::socket::SocketAddr::Unix(_) => "127.0.0.1".to_string(),
                })
                .unwrap_or_else(|| "0.0.0.0".to_string());
                
            // ⚡ OPTIMIZATION: Identify protocol via port heuristic and X-Forwarded-Proto.
            // Pingora 0.6 removed the per-request TLS flag; we detect HTTPS by:
            //   (a) checking the X-Forwarded-Proto header (set by our upstream_request_filter), or
            //   (b) checking whether the local port is 443 / 8443 as a fallback.
            let protocol = {
                let via_header = request_header.headers
                    .get("x-forwarded-proto")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if via_header == "https" {
                    "https"
                } else {
                    // Fallback: infer from the Host header port or the server listen config.
                    let host_header = request_header.headers
                        .get("Host")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    let port_in_host = host_header
                        .split(':')
                        .nth(1)
                        .and_then(|p| p.parse::<u16>().ok())
                        .unwrap_or(80);
                    if port_in_host == 443 || port_in_host == 8443 {
                        "https"
                    } else {
                        "http"
                    }
                }
            };
                
            if let Some(route) = state.router.match_request(path, method, &request_header.headers, host, &remote_ip, protocol) {
                let index = route.index;
                let handler = state.config.routes.get(index).map(|r| r.handler.clone());
                (path.to_string(), Some(index), handler, remote_ip, host.to_string(), method.to_string())
            } else {
                (path.to_string(), None, None, remote_ip, host.to_string(), method.to_string())
            }
        };

        // Capture request metadata for access log
        ctx.request_path = path_str.clone();
        ctx.request_host = request_host;
        ctx.request_method = request_method;

        // Detect Accept-Encoding for response compression
        {
            let ae = session.req_header().headers
                .get("accept-encoding")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            ctx.client_accepts_gzip = ae.contains("gzip");
        }

        // Check if server has compression enabled.
        // For now, enable for all proxied responses if the client supports
        // gzip. This matches Caddy's `encode gzip` behavior.
        if ctx.client_accepts_gzip && ctx.state.is_some() {
            ctx.compress_response = true;
        }

        // Check request body size (Content-Length)
        if let Some(state) = &ctx.state {
             let limit = state.config.client_max_body_size;
             if limit > 0 {
                 if let Some(content_length) = session.req_header().headers.get("content-length")
                     .and_then(|v| v.to_str().ok())
                     .and_then(|v| v.parse::<u64>().ok()) 
                 {
                     if content_length > limit {
                         let mut header = pingora_http::ResponseHeader::build(413, Some(4)).unwrap();
                         header.insert_header("Connection", "close").unwrap();
                         header.insert_header("Server", "Pingclair").unwrap();
                         session.write_response_header(Box::new(header), true).await?;
                         return Ok(true);
                     }
                 }
             }
        }

        if let Some(index) = route_index {
            ctx.route_index = Some(index);

            // Check rate limit
            if let Some(state) = &ctx.state {
                 if let Some(limiter) = state.rate_limiters.get(index).and_then(|l| l.as_ref()) {
                      let key = if limiter.config.by_ip {
                           Some(remote_ip.as_str())
                      } else {
                           None
                      };
                      
                      if let Err(info) = limiter.check(key) {
                           let mut header = pingora_http::ResponseHeader::build(429, Some(4)).unwrap();
                           for (k, v) in info.to_headers() {
                               if let Ok(val) = http::header::HeaderValue::from_str(&v) {
                                   if let Ok(name) = http::header::HeaderName::from_bytes(k.as_bytes()) {
                                        header.insert_header(name, val).unwrap();
                                   }
                               }
                           }
                           header.insert_header("Server", "Pingclair").unwrap();
                           session.write_response_header(Box::new(header), true).await?;
                           return Ok(true);
                      }
                 }
            }
            
            if let Some(h) = handler {
                if self.handle_config(session, ctx, &h, &path_str, index).await? {
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
            Self::write_simple_response(session, 404, "404 Not Found").await?;
            return Ok(true);
        }

        Ok(false)
    }
    
    /// Called for each request to determine the upstream
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Box<HttpPeer>>
    where
        Self::CTX: Send + Sync,
    {
         // Route should be matched in request_filter
         
         let route_index = if let Some(index) = ctx.route_index {
             index
         } else {
             return Err(pingora_core::Error::new(pingora_core::ErrorType::ConnectNoRoute));
         };
         
         // Get client IP for IP-hash load balancing
        let client_ip = session.client_addr()
             .map(|addr| match addr {
                 pingora_core::protocols::l4::socket::SocketAddr::Inet(inet) => match inet {
                     std::net::SocketAddr::V4(v4) => v4.ip().octets().to_vec(),
                     std::net::SocketAddr::V6(v6) => v6.ip().octets().to_vec(),
                 },
                 pingora_core::protocols::l4::socket::SocketAddr::Unix(_) => vec![], 
             });

        // 🛑 SAFETY: state must have been set by request_filter. If it wasn't
        // (e.g. no virtual host matched), fail gracefully instead of panic.
        let state = match ctx.state.as_ref() {
            Some(s) => s,
            None => {
                tracing::warn!("⚠️ upstream_peer called with no state in context — no virtual host matched");
                return Err(pingora_core::Error::new(pingora_core::ErrorType::ConnectNoRoute));
            }
        };
        if let Some(upstream) = self.select_upstream(state, route_index, client_ip.as_deref()) {
            ctx.upstream = Some(upstream.clone()); // Backend is light to clone

            // Get proxy config for headers and timeouts
            let mut read_timeout_ms = None;
            let mut write_timeout_ms = None;

            if let Some(proxy_config) = self.get_proxy_config(state, route_index) {
                ctx.headers_upstream = proxy_config.headers_up.clone();
                ctx.headers_downstream = proxy_config.headers_down.clone();
                read_timeout_ms = proxy_config.read_timeout;
                write_timeout_ms = proxy_config.write_timeout;
                ctx.streaming_response = wants_immediate_flush(proxy_config.flush_interval);
            }

            // Parse and create peer (shared with the HTTP/3 path so both
            // honor identical timeout semantics).
            return Ok(Box::new(Self::build_http_peer(
                &upstream,
                read_timeout_ms,
                write_timeout_ms,
            )));
        }
        
        // No upstream found
        Err(pingora_core::Error::new(pingora_core::ErrorType::ConnectNoRoute))
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
        let downstream_headers = session.req_header();

        // Add configured upstream headers with variable resolution
        for (key, value_template) in &ctx.headers_upstream {
            let resolved = resolve_caddy_placeholders(value_template, downstream_headers);
            upstream_request.insert_header(key.clone(), resolved.as_str())?;
        }

        // Add standard proxy headers (only if not already configured by user)
        if !ctx.headers_upstream.contains_key("X-Forwarded-Proto") {
            upstream_request.insert_header("X-Forwarded-Proto", "https")?;
        }

        // Client IP forwarding (de-facto proxy standard): append the client
        // IP to any incoming X-Forwarded-For chain and set X-Real-IP when
        // absent. User-configured `header_up` values for these headers win.
        let client_ip = session.client_addr()
            .map(|addr| match addr {
                pingora_core::protocols::l4::socket::SocketAddr::Inet(inet) => inet.ip().to_string(),
                pingora_core::protocols::l4::socket::SocketAddr::Unix(_) => "127.0.0.1".to_string(),
            })
            .unwrap_or_else(|| "0.0.0.0".to_string());

        if !ctx.headers_upstream.contains_key("X-Forwarded-For") {
            let existing = upstream_request.headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok());
            upstream_request.insert_header("X-Forwarded-For", append_forwarded_for(existing, &client_ip))?;
        }
        if !ctx.headers_upstream.contains_key("X-Real-IP")
            && !upstream_request.headers.contains_key("x-real-ip")
        {
            upstream_request.insert_header("X-Real-IP", &client_ip)?;
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
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Capture response status for access log
        ctx.response_status = upstream_response.status.as_u16();

        // 1. Set configured downstream headers
        for (key, value) in &ctx.headers_downstream {
            upstream_response.insert_header(key.clone(), value.as_str())?;
        }

        // 2. Append configured downstream headers
        for (key, value) in &ctx.headers_downstream_add {
            upstream_response.append_header(key.clone(), value.as_str())?;
        }

        // 3. Remove configured headers
        for header_name in &ctx.headers_remove {
            let _ = upstream_response.remove_header(header_name);
        }

        // 4. Server header (only if not suppressed by `header -Server`)
        if !ctx.suppress_server_header {
            upstream_response.insert_header("Server", "Pingclair")?;
        }

        // 5. Add request ID header for tracing
        upstream_response.insert_header("X-Request-Id", &ctx.request_id)?;

        // 6. Security headers based on configuration
        if let Some(state) = &ctx.state {
            if state.config.security.enabled {
                upstream_response.insert_header("X-Content-Type-Options", &state.config.security.x_content_type_options)?;
                upstream_response.insert_header("X-Frame-Options", &state.config.security.x_frame_options)?;
                upstream_response.insert_header("X-XSS-Protection", &state.config.security.x_xss_protection)?;
                upstream_response.insert_header("X-Permitted-Cross-Domain-Policies", &state.config.security.x_permitted_cross_domain)?;
                upstream_response.insert_header("Referrer-Policy", &state.config.security.referrer_policy)?;
                upstream_response.insert_header("Permissions-Policy", &state.config.security.permissions_policy)?;

                if state.config.tls.as_ref().map_or(false, |tls| tls.auto || tls.cert.is_some()) {
                    if let Some(ref hsts_config) = state.config.security.hsts {
                        let hsts_value = format!(
                            "max-age={};{}{}",
                            hsts_config.max_age,
                            if hsts_config.include_subdomains { " includeSubDomains;" } else { "" },
                            if hsts_config.preload { " preload" } else { "" }
                        );
                        upstream_response.insert_header("Strict-Transport-Security", &hsts_value)?;
                    }
                }

                if let Some(ref csp) = state.config.security.csp {
                    upstream_response.insert_header("Content-Security-Policy", csp)?;
                }
            }
        }

        // 7. Setup gzip compression if applicable
        // Only compress if:
        //   - Client accepts gzip
        //   - Route did not request immediate flushing (`flush_interval: -1`)
        //   - Response is not a real-time stream (e.g. text/event-stream)
        //   - Response is not already compressed
        //   - Content type is compressible (text/*, application/json, etc.)
        //   - Body is not too small (> 256 bytes via Content-Length)
        if ctx.compress_response && ctx.client_accepts_gzip && !ctx.streaming_response {
            let already_encoded = upstream_response.headers
                .get("content-encoding")
                .is_some();
            let content_type = upstream_response.headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let is_compressible = content_type.starts_with("text/")
                || content_type.contains("json")
                || content_type.contains("xml")
                || content_type.contains("javascript")
                || content_type.contains("css")
                || content_type.contains("svg");
            let content_length = upstream_response.headers
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok());
            let too_small = content_length.map_or(false, |len| len < 256);

            if !already_encoded && is_compressible && !is_streaming_content_type(content_type) && !too_small {
                // Initialize gzip encoder
                ctx.gzip_encoder = Some(GzEncoder::new(Vec::new(), Compression::fast()));
                // Set response headers for compressed content
                upstream_response.insert_header("Content-Encoding", "gzip")?;
                let _ = upstream_response.remove_header("Content-Length");
                // Transfer-Encoding: chunked will be set by Pingora automatically
                upstream_response.insert_header("Vary", "Accept-Encoding")?;
            }
        }

        Ok(())
    }

    /// Filter upstream response body chunks for gzip compression.
    ///
    /// 🏗️ ARCHITECTURE: Streaming gzip — each body chunk is fed into the
    /// GzEncoder. Every chunk is written in, sync-flushed, and drained
    /// immediately — memory use is bounded by one chunk's worth of
    /// compressed output, never by the size of the whole response body.
    /// `end_of_stream` finalizes the encoder (trailer + final flush).
    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Option<Duration>> {
        // Track response bytes for access log
        if let Some(b) = body.as_ref() {
            ctx.response_bytes += b.len() as u64;
        }

        stream_gzip_chunk(&mut ctx.gzip_encoder, body, end_of_stream);

        Ok(None)
    }
    
    /// Called when establishing the connection to the selected upstream fails.
    ///
    /// Passive health check with nginx `max_fails`/`fail_timeout` semantics:
    /// the failed backend is marked down on the route's load balancer (see
    /// [`LoadBalancer::mark_unhealthy`]) so `select` skips it for
    /// [`crate::FAIL_COOLDOWN`], and the error is marked retryable so
    /// Pingora's retry loop calls `upstream_peer` again *within the same
    /// request* — the client sees a single slightly-slower request instead
    /// of a 502, as long as another backend is up. Retrying is safe here
    /// because the connection never came up: no part of the request was
    /// sent to the failed peer.
    fn fail_to_connect(
        &self,
        _session: &mut Session,
        peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<pingora_core::Error>,
    ) -> Box<pingora_core::Error> {
        if let (Some(state), Some(route_index)) = (ctx.state.as_ref(), ctx.route_index) {
            if let Some(lb) = state.load_balancers.get(route_index).and_then(|l| l.as_ref()) {
                if let pingora_core::protocols::l4::socket::SocketAddr::Inet(addr) = peer.address() {
                    tracing::warn!("🔻 Marking upstream {} down after connect failure (cooldown {:?})", addr, crate::FAIL_COOLDOWN);
                    lb.mark_unhealthy(addr);
                }
            }
        }
        e.retry = true.into();
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
    async fn logging(
        &self,
        session: &mut Session,
        e: Option<&pingora_core::Error>,
        ctx: &mut Self::CTX,
    ) {
        let response_code = session.response_written()
            .map(|resp| resp.status.as_u16())
            .unwrap_or(ctx.response_status);

        let req_header = session.req_header();
        let method = req_header.method.as_str();
        let host = req_header.headers.get("Host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");
        let user_agent = req_header.headers.get("User-Agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");
        let referer = req_header.headers.get("Referer")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");
        let remote_ip = session.client_addr()
            .map(|addr| match addr {
                pingora_core::protocols::l4::socket::SocketAddr::Inet(inet) => inet.ip().to_string(),
                pingora_core::protocols::l4::socket::SocketAddr::Unix(_) => "127.0.0.1".to_string(),
            })
            .unwrap_or_else(|| "0.0.0.0".to_string());
        let elapsed = ctx.start_time.elapsed();

        // Update Prometheus metrics
        metrics::REQUESTS_TOTAL.with_label_values(&[
            method,
            &response_code.to_string(),
            host
        ]).inc();

        metrics::REQUEST_DURATION_SECONDS.with_label_values(&[
            method,
            &response_code.to_string(),
            host
        ]).observe(elapsed.as_secs_f64());

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
        HandlerConfig::Pipeline(handlers)
        | HandlerConfig::Handle(handlers)
        | HandlerConfig::HandlePath { handlers, .. } => {
            handlers.iter().find_map(|h| find_reverse_proxy_config(h))
        }
        _ => None,
    }
}

/// Find the first `FileServer` config in a handler tree, recursing through
/// `Pipeline`/`Handle`/`HandlePath` wrappers. Returns the `FileServer`
/// handler node itself so the caller can destructure its fields.
fn find_file_server_config(handler: &HandlerConfig) -> Option<&HandlerConfig> {
    match handler {
        HandlerConfig::FileServer { .. } => Some(handler),
        HandlerConfig::Pipeline(handlers)
        | HandlerConfig::Handle(handlers)
        | HandlerConfig::HandlePath { handlers, .. } => {
            handlers.iter().find_map(|h| find_file_server_config(h))
        }
        _ => None,
    }
}

fn find_rate_limit_config(handler: &HandlerConfig) -> Option<crate::rate_limit::RateLimitConfig> {
    match handler {
        HandlerConfig::RateLimit { requests, window_secs, by_ip, burst } => {
            Some(crate::rate_limit::RateLimitConfig {
                requests_per_window: *requests,
                window: std::time::Duration::from_secs(*window_secs),
                by_ip: *by_ip,
                burst: *burst,
            })
        },
        HandlerConfig::Pipeline(handlers) | HandlerConfig::Handle(handlers) | HandlerConfig::HandlePath { handlers, .. } => {
            for h in handlers {
                if let Some(config) = find_rate_limit_config(h) {
                    return Some(config);
                }
            }
            None
        },
        _ => None,
    }
}

/// Find the first `BasicAuth` config in a handler tree, recursing through
/// `Pipeline`/`Handle`/`HandlePath` wrappers. Mirrors
/// [`find_rate_limit_config`]. Used by the HTTP/3 dispatch, which matches
/// only on the top-level handler and therefore cannot rely on the
/// `handle_config` arm the H1/H2 path uses.
pub(crate) fn find_basic_auth_config(handler: &HandlerConfig) -> Option<(&str, &[BasicAuthCredential])> {
    match handler {
        HandlerConfig::BasicAuth { realm, credentials } => {
            Some((realm.as_str(), credentials.as_slice()))
        }
        HandlerConfig::Pipeline(handlers)
        | HandlerConfig::Handle(handlers)
        | HandlerConfig::HandlePath { handlers, .. } => {
            handlers.iter().find_map(find_basic_auth_config)
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
    use super::append_forwarded_for;

    #[test]
    fn starts_a_fresh_chain_when_absent_or_blank() {
        assert_eq!(append_forwarded_for(None, "1.2.3.4"), "1.2.3.4");
        assert_eq!(append_forwarded_for(Some(""), "1.2.3.4"), "1.2.3.4");
        assert_eq!(append_forwarded_for(Some("  "), "1.2.3.4"), "1.2.3.4");
    }

    #[test]
    fn appends_to_an_existing_chain() {
        assert_eq!(
            append_forwarded_for(Some("203.0.113.1"), "1.2.3.4"),
            "203.0.113.1, 1.2.3.4"
        );
        assert_eq!(
            append_forwarded_for(Some("203.0.113.1, 203.0.113.2"), "1.2.3.4"),
            "203.0.113.1, 203.0.113.2, 1.2.3.4"
        );
    }
}

#[cfg(test)]
mod p0_regression_tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Barrier;

    // ---- Fix 1: streaming gzip stays bounded regardless of body size ----

    /// Feeds a large body through `stream_gzip_chunk` one chunk at a time
    /// and asserts the per-chunk output buffer never grows anywhere near
    /// the size of the accumulated body — the exact OOM scenario the audit
    /// flagged (large upstream response + gzip = whole body buffered).
    #[test]
    fn gzip_streaming_bounds_memory_regardless_of_total_body_size() {
        let mut encoder_slot = Some(GzEncoder::new(Vec::new(), Compression::fast()));
        let chunk = Bytes::from(vec![b'a'; 64 * 1024]); // 64KB per chunk
        let total_chunks = 500; // 32MB total body
        let mut max_single_output = 0usize;
        let mut full_output = Vec::new();

        for i in 0..total_chunks {
            let mut body = Some(chunk.clone());
            let end = i == total_chunks - 1;
            stream_gzip_chunk(&mut encoder_slot, &mut body, false);
            if let Some(out) = &body {
                max_single_output = max_single_output.max(out.len());
                full_output.extend_from_slice(out);
            }
            if end {
                // Final empty chunk to flush the trailer.
                let mut tail_body: Option<Bytes> = None;
                stream_gzip_chunk(&mut encoder_slot, &mut tail_body, true);
                if let Some(out) = &tail_body {
                    full_output.extend_from_slice(out);
                }
            }
        }

        // The whole uncompressed body is 32MB; if we were still buffering
        // the entire thing before emitting anything, `max_single_output`
        // would be on that order. Bounded streaming keeps it tiny.
        assert!(
            max_single_output < 1024 * 1024,
            "a single chunk's compressed output was {max_single_output} bytes — \
             gzip streaming appears to be buffering the whole body again"
        );
        assert!(encoder_slot.is_none(), "encoder should be consumed after end_of_stream");

        // And the output must still be valid, correct gzip data.
        let mut decoder = GzDecoder::new(&full_output[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert_eq!(decompressed.len(), total_chunks * chunk.len());
        assert!(decompressed.iter().all(|&b| b == b'a'));
    }

    #[test]
    fn gzip_streaming_handles_single_chunk_response() {
        let mut encoder_slot = Some(GzEncoder::new(Vec::new(), Compression::fast()));
        let mut body = Some(Bytes::from_static(b"hello world"));
        stream_gzip_chunk(&mut encoder_slot, &mut body, true);

        let out = body.expect("should produce compressed output");
        let mut decoder = GzDecoder::new(&out[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert_eq!(decompressed, b"hello world");
    }

    #[test]
    fn gzip_streaming_handles_empty_body() {
        let mut encoder_slot = Some(GzEncoder::new(Vec::new(), Compression::fast()));
        let mut body: Option<Bytes> = None;
        stream_gzip_chunk(&mut encoder_slot, &mut body, true);

        // Even a zero-byte response still gets a valid (empty) gzip stream.
        let out = body.expect("finalize should still emit gzip header+trailer");
        let mut decoder = GzDecoder::new(&out[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn gzip_streaming_noop_when_no_encoder_present() {
        // Uncompressed responses (client doesn't accept gzip, etc.) must
        // pass through completely untouched.
        let mut encoder_slot: Option<GzEncoder<Vec<u8>>> = None;
        let mut body = Some(Bytes::from_static(b"passthrough"));
        stream_gzip_chunk(&mut encoder_slot, &mut body, false);
        assert_eq!(body, Some(Bytes::from_static(b"passthrough")));
    }

    // ---- Fix 2: request ID generation is syscall-free per request ----

    #[test]
    fn request_ids_are_unique_across_many_sequential_calls() {
        let mut ids = std::collections::HashSet::new();
        for _ in 0..100_000 {
            assert!(ids.insert(generate_request_id()), "duplicate request ID generated");
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
                    (0..per_thread).map(|_| generate_request_id()).collect::<Vec<_>>()
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
            assert!(!saw_none, "reader observed stable host missing during reload — reload is not atomic per-map");
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
        assert!(is_streaming_content_type("text/event-stream; charset=utf-8"));
        assert!(is_streaming_content_type("Text/Event-Stream"));
        assert!(is_streaming_content_type(" text/event-stream ; charset=utf-8"));
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
    fn streaming_route_disables_gzip_gate() {
        // The gzip branch in `response_filter` requires
        // `ctx.compress_response && ctx.client_accepts_gzip && !ctx.streaming_response`.
        // A route with `flush_interval: -1` sets streaming_response, which
        // must keep the gate closed even when the client accepts gzip.
        let mut ctx = RequestContext {
            compress_response: true,
            client_accepts_gzip: true,
            ..Default::default()
        };
        ctx.streaming_response = wants_immediate_flush(Some(-1));
        let gzip_gate_opens =
            ctx.compress_response && ctx.client_accepts_gzip && !ctx.streaming_response;
        assert!(!gzip_gate_opens, "flush_interval: -1 must disable the gzip filter");

        // Sanity: without the streaming flag the same request would compress.
        ctx.streaming_response = wants_immediate_flush(None);
        let gzip_gate_opens =
            ctx.compress_response && ctx.client_accepts_gzip && !ctx.streaming_response;
        assert!(gzip_gate_opens);
    }
}

#[cfg(test)]
mod basic_auth_tests {
    use super::*;

    fn basic_auth_handler() -> HandlerConfig {
        HandlerConfig::BasicAuth {
            realm: "Restricted".to_string(),
            credentials: vec![BasicAuthCredential {
                username: "alice".to_string(),
                password: "s3cret".to_string(),
                hashed: false,
            }],
        }
    }

    fn respond_handler() -> HandlerConfig {
        HandlerConfig::Respond {
            status: 200,
            body: None,
            headers: HashMap::new(),
        }
    }

    #[test]
    fn finds_bare_basic_auth_config() {
        let handler = basic_auth_handler();
        let (realm, credentials) = find_basic_auth_config(&handler).unwrap();
        assert_eq!(realm, "Restricted");
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].username, "alice");
    }

    #[test]
    fn finds_basic_auth_nested_in_pipeline_and_handle_path() {
        let handler = HandlerConfig::HandlePath {
            prefix: "/admin".to_string(),
            handlers: vec![HandlerConfig::Pipeline(vec![
                basic_auth_handler(),
                respond_handler(),
            ])],
        };
        let (realm, _) = find_basic_auth_config(&handler).unwrap();
        assert_eq!(realm, "Restricted");
    }

    #[test]
    fn returns_none_when_no_basic_auth_present() {
        let handler = HandlerConfig::Pipeline(vec![respond_handler()]);
        assert!(find_basic_auth_config(&handler).is_none());
        assert!(find_basic_auth_config(&respond_handler()).is_none());
    }
}
