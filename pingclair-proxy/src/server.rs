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
use parking_lot::RwLock;

use crate::{LoadBalancer, Strategy, Upstream, UpstreamPool, HealthChecker};
use bytes::Bytes;

/// Context for each request
pub struct RequestCtx {
    /// Matched server state
    pub state: Option<ProxyState>,
    /// Matched route
    pub route: Option<usize>,
    /// Selected upstream (kept for connection tracking)
    pub upstream: Option<std::sync::Arc<Upstream>>,
    /// Extra headers to add upstream
    pub headers_up: HashMap<String, String>,
    /// Extra headers to add downstream
    pub headers_down: HashMap<String, String>,
    /// Start time for logging
    pub start_time: std::time::Instant,
}

impl Default for RequestCtx {
    fn default() -> Self {
        Self {
            state: None,
            route: None,
            upstream: None,
            headers_up: HashMap::new(),
            headers_down: HashMap::new(),
            start_time: std::time::Instant::now(),
        }
    }
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
}

impl ProxyState {
    pub fn new(config: ServerConfig) -> Self {
        let router = Router::new(config.routes.clone());
        
        // Initialize load balancers for each route
        let mut load_balancers = Vec::new();
        let mut health_checkers = Vec::new();
        let mut file_servers = Vec::new();

        for route in &config.routes {
            match &route.handler {
                HandlerConfig::ReverseProxy(proxy_config) => {
                    // 1. Create Upstream Pool
                    let upstreams: Vec<Upstream> = proxy_config.upstreams.iter()
                        .map(|addr| Upstream::new(addr.clone()))
                        .collect();
                    
                    let pool = Arc::new(UpstreamPool::new(upstreams));
                    
                    // 2. Create Strategy
                    let strategy = match proxy_config.load_balance.strategy.as_str() {
                        "random" => Strategy::Random,
                        "least_conn" => Strategy::LeastConn,
                        "ip_hash" => Strategy::IpHash,
                        "first" => Strategy::First,
                        _ => Strategy::RoundRobin,
                    };
                    
                    // 3. Create Load Balancer
                    let lb = Arc::new(LoadBalancer::new(pool.clone(), strategy));
                    load_balancers.push(Some(lb));
                    
                    // 4. Setup Health Checker if configured
                    if let Some(hc_config) = &proxy_config.health_check {
                        let hc_conf = crate::health_check::HealthCheckConfig {
                             path: hc_config.path.clone(),
                             interval: std::time::Duration::from_secs(hc_config.interval),
                             timeout: std::time::Duration::from_secs(hc_config.timeout),
                             threshold: hc_config.threshold,
                             expected_status: (200, 299),
                             http_check: true,
                        };
                        
                        let hc = Arc::new(HealthChecker::new(hc_conf));
                        hc.start(pool);
                        health_checkers.push(Some(hc));
                    } else {
                        health_checkers.push(None);
                    }
                    
                    file_servers.push(None); // No file server for this route

                    tracing::info!(
                        "⚖️ Initialized load balancer for route {} with strategy {:?}", 
                        route.path, strategy
                    );

                },
                HandlerConfig::FileServer { root, index, browse, compress } => {
                    // Initialize File Server
                    let config = pingclair_static::FileServerConfig {
                        root: std::path::PathBuf::from(root),
                        index: if index.is_empty() { vec!["index.html".to_string()] } else { index.clone() },
                        browse: *browse,
                        compress: *compress,
                        precompressed: true,  // Enable pre-compressed file detection by default
                    };
                    
                    let fs = Arc::new(pingclair_static::FileServer::new(config));
                    
                    load_balancers.push(None);
                    health_checkers.push(None);
                    file_servers.push(Some(fs));
                    
                    tracing::info!("📁 Initialized file server for route {}", route.path);
                },
                _ => {
                    load_balancers.push(None);
                    health_checkers.push(None);
                    file_servers.push(None);
                }
            }
        }
        
        Self {
            config: Arc::new(config),
            router: Arc::new(router),
            load_balancers,
            health_checkers,
            file_servers,
        }
    }
}

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
        let name = config.name.clone();
        let state = ProxyState::new(config);
        
        if let Some(hostname) = name {
            // Check if it's a wildcard or simple hostname
            // For now, simple match
            self.hosts.write().insert(hostname, state);
        } else {
            let mut def = self.default.write();
            *def = Some(state);
        }
    }
    
    /// Get the state for a specific host
    fn get_state(&self, host: &str) -> Option<ProxyState> {
        // 1. Exact match
        if let Some(state) = self.hosts.read().get(host) {
            return Some(state.clone());
        }
        
        // 2. TODO: Wildcard matches (*.example.com)
        
        // 3. Default
        self.default.read().clone()
    }
    
    /// Select an upstream using the load balancer
    fn select_upstream(&self, state: &ProxyState, route_idx: usize, remote_addr: Option<&[u8]>) -> Option<Arc<Upstream>> {
        if let Some(lb) = state.load_balancers.get(route_idx).and_then(|lb| lb.as_ref()) {
            lb.select(remote_addr)
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
    fn get_proxy_config(&self, state: &ProxyState, route_idx: usize) -> Option<ReverseProxyConfig> {
        let route = state.config.routes.get(route_idx)?;
        match &route.handler {
            HandlerConfig::ReverseProxy(config) => Some(config.clone()),
            _ => None,
        }
    }

    /// Handle a specific handler configuration
    async fn handle_config(&self, session: &mut Session, ctx: &mut RequestCtx, handler: &HandlerConfig, path: &str, route_idx: usize) -> PingoraResult<bool> {
        match handler {
            HandlerConfig::Respond { status, body, headers } => {
                let mut resp = ResponseHeader::build(*status, Some(3)).unwrap();
                for (k, v) in headers {
                    let name = http::header::HeaderName::from_bytes(k.as_bytes()).unwrap();
                    let value = http::header::HeaderValue::from_str(v.as_str()).unwrap();
                    resp.insert_header(name, value).unwrap();
                }
                let body_bytes = body.as_deref().unwrap_or("").as_bytes();
                resp.insert_header("Content-Length", body_bytes.len().to_string()).unwrap();
                session.write_response_header(Box::new(resp), false).await?;
                session.write_response_body(Some(Bytes::copy_from_slice(body_bytes)), true).await?;
                Ok(true)
            }
            HandlerConfig::Redirect { to, code } => {
                let mut resp = ResponseHeader::build(*code, Some(3)).unwrap();
                resp.insert_header("Location", to.as_str()).unwrap();
                session.write_response_header(Box::new(resp), true).await?;
                Ok(true)
            }
            HandlerConfig::FileServer { .. } => {
                let maybe_fs = {
                    ctx.state.as_ref().and_then(|state| {
                        state.file_servers.get(route_idx).and_then(|f| f.clone())
                    })
                };

                if let Some(fs) = maybe_fs {
                    let range_header = session.req_header().headers.get("Range")
                        .and_then(|v| v.to_str().ok());
                    let accept_encoding = session.req_header().headers.get("Accept-Encoding")
                        .and_then(|v| v.to_str().ok());
                    
                    if let Ok(Some(file)) = fs.serve(path, range_header, accept_encoding).await {
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
                        
                        session.write_response_header(Box::new(header), false).await?;
                        session.write_response_body(Some(Bytes::from(file.content)), true).await?;
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            HandlerConfig::Pipeline(_handlers) | HandlerConfig::Handle(_handlers) => {
                // TODO: Support nested pipelines without recursion issues
                Ok(false)
            }
            HandlerConfig::Headers { set, add: _, remove: _ } => {
                for (k, v) in set {
                    ctx.headers_down.insert(k.clone(), v.clone());
                }
                Ok(false)
            }
            _ => Ok(false),
        }
    }
}

#[async_trait]
impl ProxyHttp for PingclairProxy {
    type CTX = RequestCtx;
    
    fn new_ctx(&self) -> Self::CTX {
        RequestCtx::default()
    }
    
    /// Request filter (Handle static files and early return)
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> pingora_core::Result<bool> {
        // Match route in a scope to release borrow of session
        let (path_str, route_idx, handler) = {
            let req_header = session.req_header();
            let path = req_header.uri.path();
            let method = req_header.method.as_str();
            
            // Extract host and strip port
            let host_raw = req_header.headers.get("Host")
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
                
            // Identify protocol (scheme)
            let protocol = "http"; // TODO: Implement proper TLS detection for Pingora 0.6
                
            if let Some(route) = state.router.match_request(path, method, &req_header.headers, host, &remote_ip, protocol) {
                let idx = route.index;
                let handler = state.config.routes.get(idx).map(|r| r.handler.clone());
                (path.to_string(), Some(idx), handler)
            } else {
                (path.to_string(), None, None)
            }
        };

        if let Some(idx) = route_idx {
            ctx.route = Some(idx);
            
            if let Some(h) = handler {
                if self.handle_config(session, ctx, &h, &path_str, idx).await? {
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
         
         let route_idx = if let Some(idx) = ctx.route {
             idx
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

        // Check if this is a proxy handler
        let state = ctx.state.as_ref().unwrap();
        if let Some(upstream) = self.select_upstream(state, route_idx, client_ip.as_deref()) {
            ctx.upstream = Some(upstream.clone());
            
            // Track active connections
            upstream.inc_connections();
            
            // Get proxy config for headers
            if let Some(proxy_config) = self.get_proxy_config(state, route_idx) {
                ctx.headers_up = proxy_config.headers_up.clone();
                ctx.headers_down = proxy_config.headers_down.clone();
            }
            
            // Parse and create peer
            if let Some((host, port, tls)) = Self::parse_upstream(&upstream.addr) {
                let peer = HttpPeer::new(
                    (host.as_str(), port),
                    tls,
                    host.clone(),
                );
                return Ok(Box::new(peer));
            }
        }
        
        // No upstream found
        Err(pingora_core::Error::new(pingora_core::ErrorType::ConnectNoRoute))
    }

    
    /// Called before sending request to upstream
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Add configured upstream headers
        for (key, value) in &ctx.headers_up {
            upstream_request.insert_header(key.clone(), value.as_str())?;
        }
        
        // Add proxy headers
        upstream_request.insert_header("X-Forwarded-Proto", "https")?;
        
        Ok(())
    }
    
    /// Called before sending response to client
    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Decrement active connections
        if let Some(upstream) = &ctx.upstream {
            upstream.dec_connections();
        }

        // Add configured downstream headers
        for (key, value) in &ctx.headers_down {
            upstream_response.insert_header(key.clone(), value.as_str())?;
        }
        
        // Add server identification headers
        upstream_response.insert_header("Server", "Pingclair")?;
        
        // Add security headers
        upstream_response.insert_header("X-Content-Type-Options", "nosniff")?;
        upstream_response.insert_header("X-Frame-Options", "DENY")?;
        
        // Log request timing (only in debug or non-benchmark)
        let elapsed = ctx.start_time.elapsed();
        tracing::debug!(
            upstream = ?ctx.upstream.as_ref().map(|u| &u.addr),
            route = ?ctx.route,
            elapsed_ms = elapsed.as_millis(),
            "✅ Request completed"
        );
        
        Ok(())
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
        // Decrement active connections
        if let Some(upstream) = &ctx.upstream {
            upstream.dec_connections();
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
}
