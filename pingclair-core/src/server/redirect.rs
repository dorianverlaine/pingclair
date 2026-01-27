//! HTTP to HTTPS automatic redirect server
//!
//! 🔄 Listens on HTTP port and redirects all requests to HTTPS.

use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Configuration for HTTP→HTTPS redirect server
#[derive(Debug, Clone)]
pub struct RedirectConfig {
    /// HTTP port to listen on (default: 80)
    pub http_port: u16,
    /// HTTPS port to redirect to (default: 443)
    pub https_port: u16,
    /// Bind address (default: 0.0.0.0)
    pub bind_addr: String,
}

impl Default for RedirectConfig {
    fn default() -> Self {
        Self {
            http_port: 80,
            https_port: 443,
            bind_addr: "0.0.0.0".to_string(),
        }
    }
}

/// HTTP→HTTPS redirect server
pub struct HttpRedirectServer {
    config: RedirectConfig,
}

impl HttpRedirectServer {
    /// Create a new redirect server
    pub fn new(config: RedirectConfig) -> Self {
        Self { config }
    }
    
    /// Start the redirect server
    pub async fn start(&self) -> std::io::Result<()> {
        let addr: SocketAddr = format!("{}:{}", self.config.bind_addr, self.config.http_port)
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            
        let listener = TcpListener::bind(addr).await?;
        
        tracing::info!(
            "🔄 HTTP→HTTPS redirect server listening on http://{}",
            addr
        );
        
        let https_port = self.config.https_port;
        
        loop {
            match listener.accept().await {
                Ok((mut stream, _peer_addr)) => {
                    tokio::spawn(async move {
                        // Read the HTTP request (just enough to extract Host header)
                        let mut buf = [0u8; 4096];
                        let n = match stream.read(&mut buf).await {
                            Ok(n) if n > 0 => n,
                            _ => return,
                        };
                        
                        let request = String::from_utf8_lossy(&buf[..n]);
                        
                        // Extract Host header
                        let host = request
                            .lines()
                            .find(|l| l.to_lowercase().starts_with("host:"))
                            .map(|l| l[5..].trim())
                            .unwrap_or("localhost");
                        
                        // Remove port from host if present
                        let host_without_port = host.split(':').next().unwrap_or(host);
                        
                        // Extract path from first line
                        let path = request
                            .lines()
                            .next()
                            .and_then(|l| l.split_whitespace().nth(1))
                            .unwrap_or("/");
                        
                        // Build redirect URL
                        let redirect_url = if https_port == 443 {
                            format!("https://{}{}", host_without_port, path)
                        } else {
                            format!("https://{}:{}{}", host_without_port, https_port, path)
                        };
                        
                        // Send 301 redirect
                        let response = format!(
                            "HTTP/1.1 301 Moved Permanently\r\n\
                             Location: {}\r\n\
                             Content-Length: 0\r\n\
                             Connection: close\r\n\
                             Server: Pingclair\r\n\r\n",
                            redirect_url
                        );
                        
                        let _ = stream.write_all(response.as_bytes()).await;
                    });
                }
                Err(e) => {
                    tracing::warn!("Failed to accept redirect connection: {}", e);
                }
            }
        }
    }
}
