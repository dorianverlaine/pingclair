//! Configuration loader

use crate::config::PingclairConfig;
use crate::error::{Error, Result};
use std::path::Path;

/// Configuration loader for various formats
pub struct ConfigLoader;

impl ConfigLoader {
    /// Load configuration from a file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<PingclairConfig> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("Failed to read config file: {e}")))?;

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        match ext {
            "json" => Self::from_json(&content),
            "toml" => Self::from_toml(&content),
            "pingclair" | "" => Self::from_pingclairfile(&content),
            _ => Err(Error::Config(format!("Unknown config format: {ext}"))),
        }
    }

    /// Parse JSON configuration
    pub fn from_json(content: &str) -> Result<PingclairConfig> {
        serde_json::from_str(content).map_err(|e| Error::Config(format!("Invalid JSON: {e}")))
    }

    /// Parse TOML configuration
    pub fn from_toml(content: &str) -> Result<PingclairConfig> {
        toml::from_str(content).map_err(|e| Error::Config(format!("Invalid TOML: {e}")))
    }

    /// Pingclairfile sources are compiled by the `pingclair-config` crate,
    /// which depends on this one; the core loader only handles data formats.
    pub fn from_pingclairfile(_content: &str) -> Result<PingclairConfig> {
        Err(Error::Config(
            "Pingclairfile must be compiled via pingclair-config".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_loading() {
        let json = r#"{"servers": []}"#;
        let config = ConfigLoader::from_json(json).unwrap();
        assert!(config.servers.is_empty());
    }
}
