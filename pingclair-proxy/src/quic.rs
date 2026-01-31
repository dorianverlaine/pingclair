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
        
        let mut header = pingora_http::RequestHeader::build(parts.method.clone(), parts.uri.path().as_bytes(), None).unwrap();
        // Copy headers
        for (k, v) in parts.headers.iter() {
            header.insert_header(k, v).ok();
        }
        
        // Extract host
        let host = parts.headers.get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_else(|| parts.uri.host().unwrap_or(""));
        let host = host.split(':').next().unwrap_or(host);
            
        // Match route
        if let Some((_state, _index, handler_opt)) = proxy.match_route(host, parts.uri.path(), parts.method.as_str(), &header, "0.0.0.0") {
             if let Some(config) = handler_opt {
                 match config {
                     HandlerConfig::Respond { status, body, headers } => {
                         let mut builder = Response::builder().status(status);
                         for (k, v) in headers {
                             builder = builder.header(k, v);
                         }
                         builder.body(Bytes::from(body.unwrap_or_default())).unwrap()
                     },
                     HandlerConfig::FileServer { root, .. } => {
                         // Simple file serving logic
                         let path = parts.uri.path();
                         let root_path = std::path::Path::new(&root);
                         let file_path = root_path.join(path.trim_start_matches('/'));
                         
                         if file_path.exists() && file_path.is_file() {
                             if let Ok(content) = tokio::fs::read(file_path).await {
                                 Response::builder()
                                    .status(200)
                                    .body(Bytes::from(content))
                                    .unwrap()
                             } else {
                                  Response::builder().status(404).body(Bytes::from("Not Found")).unwrap()
                             }
                         } else {
                             Response::builder().status(404).body(Bytes::from("Not Found")).unwrap()
                         }
                     },
                     _ => {
                         // Fallback for ReverseProxy/etc: Not implemented for H3 yet
                         Response::builder()
                            .header("x-proxy-status", "h3-fallback")
                            .status(501)
                            .body(Bytes::from("HTTP/3 Reverse Proxy Not Yet Implemented (Static/Respond only)"))
                            .unwrap()
                     }
                 }
             } else {
                 Response::builder().status(404).body(Bytes::from("No Handler")).unwrap()
             }
        } else {
             Response::builder().status(404).body(Bytes::from("No Route")).unwrap()
        }
    }

    pub fn alt_svc_header(&self) -> String {
        let port = self.config.listen.port();
        format!("h3=\":{}\"; ma=86400", port)
    }
}
