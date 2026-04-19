//! Pingclair HTTP Proxy implementation using Pingora
//!
//! 🌐 This module implements the core reverse proxy using Pingora's ProxyHttp trait.

use pingclair_core::config::{ServerConfig, HandlerConfig, ReverseProxyConfig};
use pingclair_core::server::Router;

use async_trait::async_trait;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result as PingoraResult;
use pingora_proxy::{ProxyHttp, Session};
use pingora_http::{RequestHeader, ResponseHeader};

use std::sync::Arc;
use std::collections::HashMap;
use std::time::Duration;
use parking_lot::RwLock;
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

/// Generate a compact, sortable request ID (timestamp + random suffix)
fn generate_request_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros();
    // Base36 encode for compactness: ~13 chars timestamp + 4 random
    let rand_part: u16 = (ts as u16).wrapping_mul(31421).wrapping_add(6927);
    format!("{:x}-{:04x}", ts, rand_part)
}

// MARK: - Proxy State

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
            match &route.handler {
                HandlerConfig::ReverseProxy(proxy_config) => {
                    // 1. Create Upstreams (Backends)
                    let upstreams: Vec<Upstream> = proxy_config.upstreams.iter()
                        .filter_map(|addr| create_upstream(addr))
                        .collect();
                    
                    if upstreams.is_empty() {
                        tracing::warn!("⚠️ No valid upstreams found for route {}", route.path);
                    }

                    // 2. Create Strategy
                    let strategy = match proxy_config.load_balance.strategy.as_str() {
                        "random"     => Strategy::Random,
                        "least_conn" => Strategy::LeastConn,
                        "ip_hash"    => Strategy::IpHash,
                        "first"      => Strategy::RoundRobin,
                        _            => Strategy::RoundRobin,
                    };
                    
                    // 3. Create Load Balancer
                    let mut load_balancer = Arc::new(LoadBalancer::new(upstreams, strategy));
                    
                    // 4. Setup Health Checker if configured
                    if let Some(hc_config) = &proxy_config.health_check {
                        let health_check_conf = crate::health_check::HealthCheckConfig {
                             path: hc_config.path.clone(),
                             timeout: std::time::Duration::from_secs(hc_config.timeout),
                             positive_threshold: 1,
                             negative_threshold: hc_config.threshold as usize,
                             expected_status: (200, 299),
                        };
                        
                        let health_checker = HealthChecker::new(health_check_conf);
                        
                        // Attach to LB (needs mutable access to LB wrapper during init)
                        if let Some(load_balancer_mut) = Arc::get_mut(&mut load_balancer) {
                            load_balancer_mut.set_health_check(health_checker);
                            load_balancer_mut.set_health_check_frequency(std::time::Duration::from_secs(hc_config.interval));
                        } else {
                            tracing::warn!("Correlation ID: Init - Could not attach health checker to LB");
                        }
                        // 🛑 SAFETY: Always push to keep health_checkers aligned with
                        // load_balancers by index. Health checker is stored inside the LB
                        // object; this slot is a tombstone for index alignment only.
                        health_checkers.push(None);
                    } else {
                        health_checkers.push(None);
                    }

                    load_balancers.push(Some(load_balancer));
                    file_servers.push(None); // No file server for this route

                    tracing::info!(
                        "⚖️ Initialized load balancer for route {} with strategy {:?}", 
                        route.path, strategy
                    );

                },
                HandlerConfig::FileServer { root, index, browse, compress } => {
                    // Initialize File Server
                    let fs_config = pingclair_static::FileServerConfig {
                        root: std::path::PathBuf::from(root),
                        index: if index.is_empty() { vec!["index.html".to_string()] } else { index.clone() },
                        browse: *browse,
                        compress: *compress,
                        precompressed: true,  // Enable pre-compressed file detection by default
                    };
                    
                    let file_server = Arc::new(pingclair_static::FileServer::new(fs_config));
                    
                    load_balancers.push(None);
                    health_checkers.push(None);
                    file_servers.push(Some(file_server));
                    
                    tracing::info!("📁 Initialized file server for route {}", route.path);
                },
                _ => {
                    load_balancers.push(None);
                    health_checkers.push(None);
                    file_servers.push(None);
                }
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
#[derive(Clone)]
pub struct PingclairProxy {
    /// Map of hostname -> server state
    pub hosts: Arc<RwLock<HashMap<String, ProxyState>>>,
    /// Default server state (catch-all)
    pub default: Arc<RwLock<Option<ProxyState>>>,
    /// TLS Manager for certificate resolution
    pub tls_manager: Option<Arc<pingclair_tls::manager::TlsManager>>,
}

impl Default for PingclairProxy {
    fn default() -> Self {
        Self {
            hosts: Arc::new(RwLock::new(HashMap::new())),
            default: Arc::new(RwLock::new(None)),
            tls_manager: None,
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
            hosts: Arc::new(RwLock::new(HashMap::new())),
            default: Arc::new(RwLock::new(None)),
            tls_manager: Some(tls_manager),
        }
    }

    /// Add a server configuration to this proxy
    pub fn add_server(&self, config: ServerConfig) {
        let state = ProxyState::new(config.clone());
        
        // Add to hosts map for each domain
        let mut hosts = self.hosts.write();
        let mut default = self.default.write();
        
        if let Some(domain) = &config.name {
            if domain == "_" || domain == "*" || domain.starts_with(':') {
                *default = Some(state.clone());
            } else {
                hosts.insert(domain.clone(), state.clone());
            }
        } else {
            *default = Some(state.clone());
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

        let mut hosts = self.hosts.write();
        let mut default = self.default.write();
        *hosts = new_hosts;
        *default = new_default;
        
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
        let hosts = self.hosts.read();

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
        self.default.read().clone()
    }
    
    /// Select an upstream using the load balancer
    fn select_upstream(&self, state: &ProxyState, route_index: usize, remote_addr: Option<&[u8]>) -> Option<Upstream> {
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
    fn get_proxy_config(&self, state: &ProxyState, route_index: usize) -> Option<ReverseProxyConfig> {
        let route = state.config.routes.get(route_index)?;
        match &route.handler {
            HandlerConfig::ReverseProxy(config) => Some(config.clone()),
            _ => None,
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
                    
                    if let Ok(Some(file)) = file_server.serve(path, range_header, accept_encoding).await {
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
fn resolve_caddy_placeholders(template: &str, req: &RequestHeader) -> String {
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
                None => return Ok(false), // No virtual host found
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

        // Check if server has compression enabled
        if ctx.client_accepts_gzip {
            if let Some(state) = &ctx.state {
                // Check for compress config in the server routes (encode gzip)
                // The compress list is not in ServerConfig directly, but
                // we enable compression if the server has any compress algos
                // For now, enable for all proxied responses if client supports it
                // This matches Caddy's `encode gzip` behavior.
                ctx.compress_response = true;
            }
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
            }

            // Parse and create peer
            let addr = upstream.addr.clone();
            let scheme = upstream.ext.get::<Scheme>().unwrap_or(&Scheme::Http);
            let host = upstream.ext.get::<HostName>().map(|h| h.0.clone()).unwrap_or_else(|| match &addr {
                 pingora_core::protocols::l4::socket::SocketAddr::Inet(inet) => inet.ip().to_string(),
                 pingora_core::protocols::l4::socket::SocketAddr::Unix(u) => u.as_pathname().map(|p| p.to_string_lossy().to_string()).unwrap_or("unix_socket".to_string()),
            });
            let tls = *scheme == Scheme::Https;

            let mut peer = HttpPeer::new(
                addr,
                tls,
                host.clone(),
            );

                // Apply timeouts if configured
                if let Some(read_timeout) = read_timeout_ms {
                    if read_timeout > 0 {
                        peer.options.read_timeout = Some(std::time::Duration::from_millis(read_timeout as u64));
                        tracing::debug!("⏱️ Applied read timeout: {}ms for {}", read_timeout, host);
                    }
                }

                if let Some(write_timeout) = write_timeout_ms {
                    if write_timeout > 0 {
                        peer.options.write_timeout = Some(std::time::Duration::from_millis(write_timeout as u64));
                        tracing::debug!("⏱️ Applied write timeout: {}ms for {}", write_timeout, host);
                    }
                }

                // Set default connection timeout (10 seconds) if not configured
                if peer.options.connection_timeout.is_none() {
                    peer.options.connection_timeout = Some(std::time::Duration::from_secs(10));
                    tracing::debug!("⏱️ Applied default connection timeout: 10s for {}", host);
                }

                return Ok(Box::new(peer));
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
        //   - Response is not already compressed
        //   - Content type is compressible (text/*, application/json, etc.)
        //   - Body is not too small (> 256 bytes via Content-Length)
        if ctx.compress_response && ctx.client_accepts_gzip {
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

            if !already_encoded && is_compressible && !too_small {
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
    /// GzEncoder. On `end_of_stream`, we flush and finalize the encoder,
    /// replacing the last chunk with the compressed output.
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

        // Streaming gzip compression
        if let Some(ref mut encoder) = ctx.gzip_encoder {
            if let Some(chunk) = body.as_ref() {
                let _ = encoder.write_all(chunk);
            }
            // Suppress intermediate chunks — we'll emit the full compressed
            // body as the final chunk (simpler than true streaming for now)
            if end_of_stream {
                // Take ownership of the encoder, finalize, emit compressed body
                if let Some(encoder) = ctx.gzip_encoder.take() {
                    match encoder.finish() {
                        Ok(compressed) => {
                            *body = Some(Bytes::from(compressed));
                        }
                        Err(e) => {
                            tracing::warn!("⚠️ Gzip compression failed: {}", e);
                            // On failure, pass through uncompressed
                        }
                    }
                }
            } else {
                // Suppress intermediate chunks — they're buffered in the encoder
                *body = Some(Bytes::new());
            }
        }

        Ok(None)
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
