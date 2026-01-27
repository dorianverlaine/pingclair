#![allow(dead_code)]
//! API request handlers

use pingclair_core::config::PingclairConfig;
use pingclair_core::Result;

/// Handle GET /config
pub async fn get_config(config: &PingclairConfig) -> Result<String> {
    serde_json::to_string_pretty(config)
        .map_err(|e| pingclair_core::Error::Internal(e.to_string()))
}

/// Handle POST /config
pub async fn set_config(body: &str) -> Result<PingclairConfig> {
    serde_json::from_str(body)
        .map_err(|e| pingclair_core::Error::Config(e.to_string()))
}

/// Handle GET /health
pub async fn health_check() -> &'static str {
    r#"{"status":"healthy"}"#
}
