//! HTTP/3 (QUIC) server implementation integrated with Pingclair Proxy
//!
//! 🚀 Provides HTTP/3 support using quinn and h3 crates.

use pingclair_tls::acme::Certificate;
use h3::server::Connection as H3Connection;
use h3_quinn::Connection as QuinnConnection;
use quinn::{Endpoint, ServerConfig as QuinnServerConfig};
use rustls::pki_types::CertificateDer;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use bytes::Bytes;
use http::{Request, Response};

use crate::server::PingclairProxy;
use pingclair_core::config::HandlerConfig;

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

// MARK: - Configuration

/// ⚙️ QUIC server configuration
#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// Listen address
    pub listen: SocketAddr,
    /// Maximum concurrent streams
    pub max_concurrent_streams: u32,
    /// Initial send window
    pub initial_window: u64,
    /// Maximum UDP payload size
    pub max_udp_payload_size: u16,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:443".parse().unwrap(),
            max_concurrent_streams: 100,
            initial_window: 1024 * 1024, // 1MB
            max_udp_payload_size: 1472,  // Standard Ethernet MTU - overhead
        }
    }
}

// MARK: - Server

/// 🚀 HTTP/3 QUIC server
pub struct QuicServer {
    config: QuicConfig,
    endpoint: Option<Endpoint>,
    /// Currently loaded certificate
    cert: Arc<RwLock<Option<Certificate>>>,
    /// Proxy logic
    proxy: Option<Arc<PingclairProxy>>,
}

impl QuicServer {
    /// Create a new QUIC server
    pub fn new(config: QuicConfig) -> Self {
        Self {
            config,
            endpoint: None,
            cert: Arc::new(RwLock::new(None)),
            proxy: None,
        }
    }
    
    /// Set the proxy logic
    pub fn set_proxy(&mut self, proxy: Arc<PingclairProxy>) {
        self.proxy = Some(proxy);
    }
    
    // MARK: - TLS Management
    
    /// 🔐 Load a certificate
    pub async fn load_certificate(&self, cert: Certificate) -> Result<(), QuicError> {
        tracing::info!("🔐 Loading certificate for QUIC server");
        let mut current = self.cert.write().await;
        *current = Some(cert);
        tracing::info!("✅ Certificate loaded");
        Ok(())
    }
    
    /// 🔧 Build TLS configuration from certificate
    fn build_tls_config(cert: &Certificate) -> Result<rustls::ServerConfig, QuicError> {
        use rustls::ServerConfig;
        
        let cert_chain: Vec<CertificateDer> = rustls_pemfile::certs(
            &mut cert.cert_pem.as_bytes()
        )
        .filter_map(|r| r.ok())
        .collect();
        
        if cert_chain.is_empty() {
            return Err(QuicError::Tls("No certificates found in PEM".to_string()));
        }
        
        let key = rustls_pemfile::private_key(&mut cert.key_pem.as_bytes())
            .map_err(|e| QuicError::Tls(e.to_string()))?
            .ok_or_else(|| QuicError::Tls("No private key found in PEM".to_string()))?;
        
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| QuicError::Tls(e.to_string()))?;
            
        config.alpn_protocols = vec![b"h3".to_vec()];
        
        Ok(config)
    }
    
    /// 🔧 Build QUIC server configuration
    fn build_quic_config(&self, tls_config: rustls::ServerConfig) -> Result<QuinnServerConfig, QuicError> {
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(self.config.max_concurrent_streams.into());
        transport.initial_mtu(self.config.max_udp_payload_size);
        
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| QuicError::Tls(e.to_string()))?;
        
        let mut server_config = QuinnServerConfig::with_crypto(Arc::new(crypto));
        server_config.transport_config(Arc::new(transport));
        
        Ok(server_config)
    }
    
    // MARK: - Lifecycle
    
    /// 🚀 Start the QUIC server
    pub async fn start(mut self) -> Result<(), QuicError> {
        let cert = {
            let guard = self.cert.read().await;
            guard.clone().ok_or_else(|| QuicError::Tls("No certificate loaded".to_string()))?
        };
        
        let tls_config = Self::build_tls_config(&cert)?;
        let quic_config = self.build_quic_config(tls_config)?;
        
        let endpoint = Endpoint::server(quic_config, self.config.listen)?;
        
        tracing::info!(
            "🚀 HTTP/3 QUIC server started on {}",
            self.config.listen
        );
        
        self.endpoint = Some(endpoint.clone());
        let proxy = self.proxy.clone();
        
        // Accept connections in background
        tokio::spawn(async move {
            tracing::info!("👂 Listening for QUIC connections...");
            
            while let Some(incoming) = endpoint.accept().await {
                let proxy_ref = proxy.clone();
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(connection) => {
                             if let Err(e) = Self::handle_connection(connection, proxy_ref).await {
                                 tracing::error!("❌ QUIC Connection error: {}", e);
                             }
                        }
                        Err(e) => {
                            tracing::warn!("⚠️ Failed to accept connection: {}", e);
                        }
                    }
                });
            }
        });
        
        Ok(())
    }
    
    async fn handle_connection(connection: quinn::Connection, proxy: Option<Arc<PingclairProxy>>) -> Result<(), QuicError> {
        let h3_conn = h3::server::Connection::new(QuinnConnection::new(connection))
            .await
            .map_err(|e| QuicError::H3(e.to_string()))?;
        
        Self::handle_h3_connection(h3_conn, proxy).await
    }
    
    async fn handle_h3_connection(
        mut connection: H3Connection<QuinnConnection, Bytes>,
        proxy: Option<Arc<PingclairProxy>>,
    ) -> Result<(), QuicError> {
        loop {
            match connection.accept().await {
                Ok(Some(resolver)) => {
                    let proxy = proxy.clone();
                    tokio::spawn(async move {
                         match resolver.resolve_request().await {
                            Ok((req, mut stream)) => {
                                let resp = if let Some(p) = proxy {
                                    Self::process_request(req, p).await
                                } else {
                                    Response::builder()
                                        .status(503)
                                        .body(Bytes::from("Service Unavailable: No proxy logic"))
                                        .unwrap()
                                };
                                
                                // Send response
                                let (parts, body) = resp.into_parts();
                                let response = Response::from_parts(parts, ());
                                
                                if let Err(e) = stream.send_response(response).await {
                                    tracing::error!("Failed to send response: {}", e);
                                    return;
                                }
                                
                                if !body.is_empty() {
                                    if let Err(e) = stream.send_data(body).await {
                                        tracing::error!("Failed to send body: {}", e);
                                    }
                                }
                                
                                let _ = stream.finish().await;
                            }
                            Err(e) => tracing::error!("Resolve error: {}", e),
                        }
                    });
                }
                Ok(None) => break,
                Err(e) => {
                    tracing::error!("H3 Accept error: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }
    
    async fn process_request(req: Request<()>, proxy: Arc<PingclairProxy>) -> Response<Bytes> {
        let (parts, _) = req.into_parts();

        let mut header = match pingora_http::RequestHeader::build(
            parts.method.clone(),
            parts.uri.path().as_bytes(),
            None,
        ) {
            Ok(h) => h,
            Err(_) => return Self::error_response(400, "Bad Request"),
        };
        for (k, v) in parts.headers.iter() {
            header.insert_header(k, v).ok();
        }

        // Extract host (strip port)
        let host = parts
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_else(|| parts.uri.host().unwrap_or(""))
            .to_string();
        let host_bare = host.split(':').next().unwrap_or(&host).to_string();

        // Match route via shared proxy logic
        let (state, route_index, handler_opt) = match proxy.match_route(
            &host_bare,
            parts.uri.path(),
            parts.method.as_str(),
            &header,
            "0.0.0.0",
        ) {
            Some(t) => t,
            None => return Self::error_response(404, "No Matching Virtual Host"),
        };

        let handler = match handler_opt {
            Some(h) => h,
            None => return Self::error_response(404, "No Matching Route"),
        };

        match handler {
            // ─────────────────────────────────────────────────────────────
            // Respond: inline response
            // ─────────────────────────────────────────────────────────────
            HandlerConfig::Respond { status, body, headers } => {
                let mut builder = Response::builder().status(status);
                for (k, v) in &headers {
                    builder = builder.header(k, v);
                }
                builder
                    .body(Bytes::from(body.unwrap_or_default()))
                    .unwrap_or_else(|_| Self::error_response(500, "Response Build Error"))
            }

            // ─────────────────────────────────────────────────────────────
            // Redirect: 3xx
            // ─────────────────────────────────────────────────────────────
            HandlerConfig::Redirect { to, code } => {
                Response::builder()
                    .status(code)
                    .header("location", to)
                    .body(Bytes::new())
                    .unwrap_or_else(|_| Self::error_response(500, "Redirect Build Error"))
            }

            // ─────────────────────────────────────────────────────────────
            // FileServer: delegate to the full FileServer object
            // (compression, range, ETag, directory listing, precompressed)
            // ─────────────────────────────────────────────────────────────
            HandlerConfig::FileServer { .. } => {
                let maybe_fs = route_index.and_then(|idx| {
                    state.file_servers.get(idx)?.clone()
                });

                if let Some(fs) = maybe_fs {
                    let accept_encoding = parts
                        .headers
                        .get("accept-encoding")
                        .and_then(|v| v.to_str().ok());
                    let range_header = parts
                        .headers
                        .get("range")
                        .and_then(|v| v.to_str().ok());

                    match fs.serve(parts.uri.path(), range_header, accept_encoding).await {
                        Ok(Some(file)) => {
                            let mut builder = Response::builder().status(file.status);
                            builder = builder.header("content-type", file.mime_type);
                            builder = builder.header("content-length", file.content.len().to_string());
                            builder = builder.header("accept-ranges", "bytes");
                            builder = builder.header("server", "Pingclair");
                            if let Some(enc) = file.content_encoding {
                                builder = builder.header("content-encoding", enc);
                            }
                            if let Some(lm) = file.last_modified {
                                builder = builder.header("last-modified", lm);
                            }
                            if let Some(etag) = file.etag {
                                builder = builder.header("etag", etag);
                            }
                            if let Some(range) = file.content_range {
                                builder = builder.header("content-range", range);
                            }
                            builder
                                .body(Bytes::from(file.content))
                                .unwrap_or_else(|_| Self::error_response(500, "File Response Error"))
                        }
                        Ok(None) => Self::error_response(404, "Not Found"),
                        Err(e) => {
                            tracing::error!("❌ H3 FileServer error: {}", e);
                            Self::error_response(500, "File Server Error")
                        }
                    }
                } else {
                    Self::error_response(503, "File Server Unavailable")
                }
            }

            // ─────────────────────────────────────────────────────────────
            // ReverseProxy: forward request to upstream over plain HTTP/1.1
            //
            // 🏗️ ARCHITECTURE: Raw tokio TCP + minimal HTTP/1.1 framing is
            // used to avoid a heavy hyper dependency in this crate.
            // Future work: hyper for keep-alive and HTTP/2 upstream.
            // ─────────────────────────────────────────────────────────────
            HandlerConfig::ReverseProxy(_) => {
                let upstream = match route_index
                    .and_then(|idx| state.load_balancers.get(idx)?.as_ref())
                    .and_then(|lb| lb.select(None))
                {
                    Some(u) => u,
                    None => return Self::error_response(502, "No Upstream Available"),
                };
                Self::proxy_to_upstream(&upstream, &parts, &host).await
            }

            // All other handlers are not applicable over the H3 in-process path
            _ => Self::error_response(501, "Handler Not Supported Over HTTP/3"),
        }
    }

    /// Forward an HTTP/1.1 request to an upstream backend over a raw TCP connection.
    ///
    /// 🏗️ ARCHITECTURE: Uses tokio raw TCP + hand-crafted request framing so that
    /// no additional crate dependency is required. Connection is short-lived
    /// (`Connection: close`) — keep-alive pooling is a future improvement.
    async fn proxy_to_upstream(
        upstream: &crate::upstream::Upstream,
        parts: &http::request::Parts,
        host: &str,
    ) -> Response<Bytes> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // 1. Resolve target address
        let target_addr = match &upstream.addr {
            pingora_core::protocols::l4::socket::SocketAddr::Inet(inet) => *inet,
            pingora_core::protocols::l4::socket::SocketAddr::Unix(_) => {
                return Self::error_response(502, "Unix Socket Upstream Not Supported Over H3");
            }
        };

        // 2. Connect with timeout
        let mut stream = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio::net::TcpStream::connect(target_addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::error!("❌ H3 proxy connect error: {}", e);
                return Self::error_response(502, "Upstream Connect Failed");
            }
            Err(_) => return Self::error_response(504, "Upstream Connect Timeout"),
        };

        // 3. Build HTTP/1.1 request
        let path_and_query = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        let mut req_buf = format!(
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: close\r\n\
             X-Forwarded-Proto: https\r\n",
            parts.method, path_and_query, host
        );
        // Forward original headers — skip hop-by-hop
        for (k, v) in &parts.headers {
            let name = k.as_str().to_ascii_lowercase();
            if matches!(
                name.as_str(),
                "host" | "connection" | "transfer-encoding" | "keep-alive"
            ) {
                continue;
            }
            if let Ok(v_str) = v.to_str() {
                req_buf.push_str(&format!("{}: {}\r\n", k, v_str));
            }
        }
        req_buf.push_str("\r\n");

        if let Err(e) = stream.write_all(req_buf.as_bytes()).await {
            tracing::error!("❌ H3 proxy write error: {}", e);
            return Self::error_response(502, "Upstream Write Failed");
        }

        // 4. Read full response (upstream sends Connection: close so this terminates)
        let mut raw = Vec::with_capacity(8192);
        if tokio::time::timeout(
            std::time::Duration::from_secs(30),
            stream.read_to_end(&mut raw),
        )
        .await
        .is_err()
        {
            return Self::error_response(504, "Upstream Read Timeout");
        }

        // 5. Parse status line and header block
        let raw_str = String::from_utf8_lossy(&raw);
        let (status_code, body_start) = Self::parse_http_response_head(&raw_str);

        let mut builder = Response::builder().status(status_code);
        builder = builder.header("server", "Pingclair");

        if let Some(hdr_block) = raw_str.get(..body_start) {
            for line in hdr_block.lines().skip(1) {
                if line.is_empty() { break; }
                if let Some((k, v)) = line.split_once(": ") {
                    let k_lc = k.to_ascii_lowercase();
                    if !matches!(k_lc.as_str(), "connection" | "transfer-encoding" | "keep-alive") {
                        builder = builder.header(k, v);
                    }
                }
            }
        }

        let body = Bytes::copy_from_slice(raw.get(body_start..).unwrap_or(b""));
        builder
            .body(body)
            .unwrap_or_else(|_| Self::error_response(502, "Response Parse Error"))
    }

    /// Parse an HTTP/1.1 response head, returning `(status_code, body_start_byte_index)`.
    fn parse_http_response_head(raw: &str) -> (u16, usize) {
        let status = raw
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(502);

        let body_start = raw.find("\r\n\r\n").map(|i| i + 4).unwrap_or(raw.len());
        (status, body_start)
    }

    /// Build a plain-text error response.
    fn error_response(status: u16, msg: &'static str) -> Response<Bytes> {
        Response::builder()
            .status(status)
            .header("content-type", "text/plain")
            .header("server", "Pingclair")
            .body(Bytes::from(msg))
            .unwrap_or_else(|_| Response::new(Bytes::new()))
    }

    pub fn alt_svc_header(&self) -> String {
        let port = self.config.listen.port();
        format!("h3=\":{}\"; ma=86400", port)
    }
}


