//! Native Health Checking for Pingclair
//!
//! Implements Pingora's `HealthCheck` trait for custom health checking logic.
//! Provides a highly configurable health checker supporting HTTP checks and threshold-based status flipping.

use async_trait::async_trait;
use pingora_load_balancing::health_check::HealthCheck;
use pingora_load_balancing::Backend;
use std::time::Duration;
use pingora_core::ErrorType;

// MARK: - Configuration

/// Configuration parameters for the Health Checker.
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    /// The URL path to check (e.g., "/health").
    pub path: String,
    
    /// Maximum duration to wait for a connection or response.
    pub timeout: Duration,
    
    /// The range of HTTP status codes considered "healthy" (inclusive).
    /// Default: 200..=299
    pub expected_status: (u16, u16),
    
    /// Number of consecutive successful checks required to transition from Unhealthy -> Healthy.
    pub positive_threshold: usize,
    
    /// Number of consecutive failed checks required to transition from Healthy -> Unhealthy.
    pub negative_threshold: usize,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            path: "/health".to_string(),
            timeout: Duration::from_secs(5),
            expected_status: (200, 299),
            positive_threshold: 1,
            negative_threshold: 3,
        }
    }
}

// MARK: - Health Checker

/// A robust health checker implementing Pingora's `HealthCheck` trait.
///
/// It performs raw TCP/HTTP requests to minimize overhead while verifying
/// application-level health via status codes.
#[derive(Debug)]
pub struct HealthChecker {
    config: HealthCheckConfig,
}

impl HealthChecker {
    /// Creates a new `HealthChecker` with the provided configuration.
    pub fn new(config: HealthCheckConfig) -> Self {
        Self { config }
    }
}

// MARK: - HealthCheck Trait Implementation

#[async_trait]
impl HealthCheck for HealthChecker {
    /// Performs the health check against a specific target backend.
    ///
    /// - Parameter target: The backend to check.
    /// - Returns: `Ok(())` if healthy, `Err` with details if unhealthy.
    ///
    /// **Implementation Note:**
    /// Uses raw `tokio::net::TcpStream` instead of a full HTTP client client to avoid
    /// dependencies and overhead. Manually constructs a minimal HTTP/1.1 GET request.
    async fn check(&self, target: &Backend) -> pingora_core::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Guard: Ensure we are checking an Inet address (Unix sockets not supported yet)
        let inet_address = match &target.addr {
            pingora_core::protocols::l4::socket::SocketAddr::Inet(addr) => addr,
            pingora_core::protocols::l4::socket::SocketAddr::Unix(_) => return Err(pingora_core::Error::create(
                ErrorType::InternalError,
                pingora_core::ErrorSource::Downstream,
                Some("Unix sockets not supported for basic health check".to_string().into()),
                None
            )),
        };
        
        // Step 1: Establish Connection with Timeout
        let mut stream = match tokio::time::timeout(
            self.config.timeout,
            tokio::net::TcpStream::connect(inet_address)
        ).await {
            Ok(Ok(s)) => s,
            _ => return Err(pingora_core::Error::create(
                ErrorType::ConnectError,
                pingora_core::ErrorSource::Downstream,
                Some("Connection timeout or failed".to_string().into()),
                None
            )),
        };

        // Step 2: Send HTTP Request
        // Note: Minimal headers for maximum compatibility.
        // TODO: Support Host header customization if needed for Virtual Hosts.
        let host_header = inet_address.to_string();
        let request_buffer = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: Pingclair-HealthCheck/1.0\r\n\
             Connection: close\r\n\
             Accept: */*\r\n\r\n",
            self.config.path, host_header
        );

        if stream.write_all(request_buffer.as_bytes()).await.is_err() {
             return Err(pingora_core::Error::create(
                ErrorType::WriteError,
                pingora_core::ErrorSource::Downstream,
                Some("Failed to write request".to_string().into()),
                None
            ));
        }

        // Step 3: Read Response Head
        let mut response_buffer = vec![0u8; 128]; // Small buffer, just need the status line
        let bytes_read = match tokio::time::timeout(self.config.timeout, stream.read(&mut response_buffer)).await {
            Ok(Ok(n)) if n > 0 => n,
             _ => return Err(pingora_core::Error::create(
                ErrorType::ReadError,
                pingora_core::ErrorSource::Downstream,
                Some("Failed to read response".to_string().into()),
                None
            )),
        };

        // Step 4: Parse Status Code
        // Format: "HTTP/1.1 200 OK"
        let response_text = String::from_utf8_lossy(&response_buffer[..bytes_read]);
        if let Some(status_line) = response_text.lines().next() {
            if let Some(status_code_str) = status_line.split_whitespace().nth(1) {
                if let Ok(status_code) = status_code_str.parse::<u16>() {
                    let (min, max) = self.config.expected_status;
                    if status_code >= min && status_code <= max {
                        return Ok(());
                    }
                }
            }
        }

        Err(pingora_core::Error::create(
            ErrorType::ReadError,
            pingora_core::ErrorSource::Downstream,
            Some("Invalid status code or malformed response".to_string().into()),
            None
        ))
    }

    /// Determines the threshold count for flipping health status.
    ///
    /// - Parameter success: Whether the transition is towards healthy (true) or unhealthy (false).
    /// - Returns: The number of consecutive checks required.
     fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.config.positive_threshold
        } else {
            self.config.negative_threshold
        }
    }
}
