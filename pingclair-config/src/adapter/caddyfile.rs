//! Caddyfile compatibility adapter

use pingclair_core::config::PingclairConfig;
use pingclair_core::error::{Error, Result};

/// Caddyfile compatibility adapter
pub struct CaddyfileAdapter;

impl CaddyfileAdapter {
    /// Parse a Caddyfile and convert to Pingclair config
    pub fn parse(_input: &str) -> Result<PingclairConfig> {
        // TODO: Implement Caddyfile parsing for migration
        Err(Error::Config("Caddyfile adapter not yet implemented".to_string()))
    }
}
