//! HTTP/3 (QUIC) server implementation
//!
//! 🚀 Provides HTTP/3 support using quinn and h3 crates.

use crate::acme::Certificate;
use h3::server::Connection as H3Conn;
use h3_quinn::Connection as QuinnConnection;
use quinn::{Endpoint, ServerConfig as QuinnServerConfig};
use rustls::pki_types::CertificateDer;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use bytes::Bytes;

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

/// 🚀 HTTP/3 QUIC server
pub struct QuicServer {
    config: QuicConfig,
    endpoint: Option<Endpoint>,
    /// Currently loaded certificate
    cert: Arc<RwLock<Option<Certificate>>>,
}

impl QuicServer {
    /// Create a new QUIC server
    pub fn new(config: QuicConfig) -> Self {
        Self {
            config,
            endpoint: None,
            cert: Arc::new(RwLock::new(None)),
        }
    }
    
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
        
        // Parse certificate chain
        let cert_chain: Vec<CertificateDer> = rustls_pemfile::certs(
            &mut cert.cert_pem.as_bytes()
        )
        .filter_map(|r| r.ok())
        .collect();
        
        if cert_chain.is_empty() {
            return Err(QuicError::Tls("No certificates found in PEM".to_string()));
        }
        
        // Parse private key
        let key = rustls_pemfile::private_key(&mut cert.key_pem.as_bytes())
            .map_err(|e| QuicError::Tls(e.to_string()))?
            .ok_or_else(|| QuicError::Tls("No private key found in PEM".to_string()))?;
        
        // Build server config with modern TLS 1.3 settings
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| QuicError::Tls(e.to_string()))?;
        
        tracing::debug!("🔒 TLS config built with TLS 1.3");
        
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
    
    /// 🚀 Start the QUIC server
    pub async fn start(&mut self) -> Result<(), QuicError> {
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
        tracing::info!("📡 Max concurrent streams: {}", self.config.max_concurrent_streams);
        tracing::info!("💨 Initial window: {} bytes", self.config.initial_window);
        
        self.endpoint = Some(endpoint.clone());
        
        // Accept connections in background
        tokio::spawn(async move {
            tracing::info!("👂 Listening for QUIC connections...");
            
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            let remote = conn.remote_address();
                            tracing::debug!("📥 New QUIC connection from {}", remote);
                            
                            if let Err(e) = Self::handle_connection(conn).await {
                                tracing::error!("❌ Connection error from {}: {}", remote, e);
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
    
    /// 🔗 Handle a single QUIC connection
    async fn handle_connection(conn: quinn::Connection) -> Result<(), QuicError> {
        let remote = conn.remote_address();
        tracing::debug!("🔗 Handling connection from {}", remote);
        
        let h3_conn = h3::server::Connection::new(QuinnConnection::new(conn))
            .await
            .map_err(|e| QuicError::H3(e.to_string()))?;
        
        Self::handle_h3_connection(h3_conn).await
    }
    
    /// 🌐 Handle HTTP/3 requests on a connection
    async fn handle_h3_connection(
        mut conn: H3Conn<QuinnConnection, Bytes>,
    ) -> Result<(), QuicError> {
        loop {
            match conn.accept().await {
                Ok(Some(resolver)) => {
                    tracing::debug!("📥 New HTTP/3 request stream");
                     
                    match resolver.resolve_request().await {
                        Ok((req, mut stream)) => {
                            tracing::info!(
                                "🌐 HTTP/3 {} {}",
                                req.method(),
                                req.uri()
                            );
                            
                            // Build response
                            let response = http::Response::builder()
                                .status(200)
                                .header("content-type", "text/plain; charset=utf-8")
                                .header("alt-svc", "h3=\":443\"; ma=86400")
                                .header("x-powered-by", "Pingclair 🚀")
                                .body(())
                                .unwrap();
                            
                            if let Err(e) = stream.send_response(response).await {
                                tracing::error!("❌ Failed to send response: {}", e);
                                return Ok(());
                            }
                            
                            if let Err(e) = stream.send_data(Bytes::from("🚀 Hello from Pingclair HTTP/3!\n")).await {
                                tracing::error!("❌ Failed to send data: {}", e);
                                return Ok(());
                            }
                            
                            if let Err(e) = stream.finish().await {
                                tracing::error!("❌ Failed to finish stream: {}", e);
                                return Ok(());
                            }
                            
                            tracing::debug!("✅ Response sent");
                        }
                        Err(e) => {
                             tracing::error!("❌ Failed to resolve request: {}", e);
                        }
                    }
                }
                Ok(None) => {
                    tracing::debug!("👋 Connection closed cleanly");
                    break;
                }
                Err(e) => {
                    tracing::error!("❌ H3 accept error: {}", e);
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    /// 📡 Advertise HTTP/3 support via Alt-Svc header
    pub fn alt_svc_header(&self) -> String {
        let port = self.config.listen.port();
        format!("h3=\":{}\"; ma=86400", port)
    }
    
    /// 🛑 Shutdown the server
    pub async fn shutdown(&mut self) {
        if let Some(endpoint) = self.endpoint.take() {
            tracing::info!("🛑 Shutting down QUIC server...");
            endpoint.close(0u32.into(), b"shutdown");
            endpoint.wait_idle().await;
            tracing::info!("✅ QUIC server stopped");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_quic_config_default() {
        let config = QuicConfig::default();
        assert_eq!(config.listen.port(), 443);
        assert_eq!(config.max_concurrent_streams, 100);
    }
    
    #[test]
    fn test_alt_svc_header() {
        let server = QuicServer::new(QuicConfig::default());
        let header = server.alt_svc_header();
        assert!(header.contains("h3=\":443\""));
        assert!(header.contains("ma=86400"));
    }
    
    #[test]
    fn test_custom_port() {
        let config = QuicConfig {
            listen: "0.0.0.0:8443".parse().unwrap(),
            ..Default::default()
        };
        let server = QuicServer::new(config);
        let header = server.alt_svc_header();
        assert!(header.contains("h3=\":8443\""));
    }
}
