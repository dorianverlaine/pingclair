//! JSON configuration adapter

use pingclair_core::config::PingclairConfig;
use pingclair_core::error::Result;

/// JSON configuration adapter
pub struct JsonAdapter;

impl JsonAdapter {
    /// Parse JSON configuration
    pub fn parse(input: &str) -> Result<PingclairConfig> {
        pingclair_core::config::ConfigLoader::from_json(input)
    }

    /// Serialize configuration to JSON
    pub fn serialize(config: &PingclairConfig) -> Result<String> {
        serde_json::to_string_pretty(config)
            .map_err(|e| pingclair_core::Error::Config(e.to_string()))
    }
}
