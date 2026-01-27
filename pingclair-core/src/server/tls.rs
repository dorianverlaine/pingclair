//! TLS Server with HTTP/3 (QUIC) support

use crate::config::TlsConfig;
use crate::error::Result;

/// TLS Server with automatic HTTPS and HTTP/3 support
pub struct TlsServer {
    config: TlsConfig,
}

impl TlsServer {
    /// Create a new TLS server
    pub fn new(config: TlsConfig) -> Self {
        Self { config }
    }

    /// Check if HTTP/3 is enabled
    pub fn http3_enabled(&self) -> bool {
        self.config.http3
    }

    /// Start the TLS server
    pub async fn run(&self) -> Result<()> {
        if self.config.auto {
            tracing::info!("Starting TLS server with automatic HTTPS");
        } else {
            tracing::info!("Starting TLS server with manual certificates");
        }

        if self.http3_enabled() {
            tracing::info!("HTTP/3 (QUIC) enabled");
        }

        // TODO: Implement TLS server with ACME and HTTP/3
        Ok(())
    }
}
