//! Health checking for upstreams

use std::time::Duration;

/// Health check configuration
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    /// Path to check (e.g., "/health", "/healthz", "/ping")
    pub path: String,
    /// Check interval
    pub interval: Duration,
    /// Request timeout
    pub timeout: Duration,
    /// Failures before marking unhealthy
    pub threshold: u32,
    /// Expected HTTP status code range (default: 200-299)
    pub expected_status: (u16, u16),
    /// Use HTTP check instead of TCP (default: true if path is set)
    pub http_check: bool,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            path: "/health".to_string(),
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            threshold: 3,
            expected_status: (200, 299),
            http_check: true,
        }
    }
}

/// Health checker for upstream servers
pub struct HealthChecker {
    config: HealthCheckConfig,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(config: HealthCheckConfig) -> Self {
        Self { config }
    }

    /// Start the health checker background task
    pub fn start(&self, pool: std::sync::Arc<crate::upstream::UpstreamPool>) {
        let config = self.config.clone();
        let pool = pool.clone();
        
        tracing::info!(
            "🚀 Starting health checker (interval: {:?}, path: {}, http: {})",
            config.interval,
            config.path,
            config.http_check
        );
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.interval);
            
            loop {
                interval.tick().await;
                
                for upstream in pool.all() {
                    let addr = upstream.addr.clone();
                    let timeout = config.timeout;
                    let path = config.path.clone();
                    let expected_status = config.expected_status;
                    let use_http = config.http_check;
                    
                    let is_healthy = if use_http {
                        Self::http_check(&addr, &path, timeout, expected_status).await
                    } else {
                        Self::tcp_check(&addr, timeout).await
                    };
                    
                    // Update status
                    if is_healthy != upstream.is_healthy() {
                        upstream.set_healthy(is_healthy);
                        if is_healthy {
                            tracing::info!("✅ Upstream {} is now HEALTHY", upstream.addr);
                        } else {
                            tracing::warn!("❌ Upstream {} is now UNHEALTHY", upstream.addr);
                        }
                    }
                }
            }
        });
    }
    
    /// Perform TCP connection check
    async fn tcp_check(addr: &str, timeout: Duration) -> bool {
        match tokio::time::timeout(
            timeout,
            tokio::net::TcpStream::connect(addr)
        ).await {
            Ok(Ok(_)) => true,
            _ => false,
        }
    }
    
    /// Perform HTTP health check
    async fn http_check(addr: &str, path: &str, timeout: Duration, expected_status: (u16, u16)) -> bool {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        
        // Parse host and port from address
        let (host, port) = if addr.contains(':') {
            let parts: Vec<&str> = addr.split(':').collect();
            (parts[0], *parts.get(1).unwrap_or(&"80"))
        } else {
            (addr, "80")
        };
        
        // Connect with timeout
        let connect_addr = format!("{}:{}", host, port);
        let mut stream = match tokio::time::timeout(
            timeout,
            tokio::net::TcpStream::connect(&connect_addr)
        ).await {
            Ok(Ok(s)) => s,
            _ => return false,
        };
        
        // Send HTTP request
        let request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: Pingclair-HealthCheck/1.0\r\n\
             Connection: close\r\n\
             Accept: */*\r\n\r\n",
            path, host
        );
        
        if stream.write_all(request.as_bytes()).await.is_err() {
            return false;
        }
        
        // Read response with timeout
        let mut response = vec![0u8; 512];
        let n = match tokio::time::timeout(timeout, stream.read(&mut response)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return false,
        };
        
        // Parse status code from response
        let response_str = String::from_utf8_lossy(&response[..n]);
        
        // Extract status code (e.g., "HTTP/1.1 200 OK")
        if let Some(status_line) = response_str.lines().next() {
            if let Some(status_code_str) = status_line.split_whitespace().nth(1) {
                if let Ok(status_code) = status_code_str.parse::<u16>() {
                    let (min, max) = expected_status;
                    return status_code >= min && status_code <= max;
                }
            }
        }
        
        false
    }
}
