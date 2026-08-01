// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

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

#[cfg(test)]
mod tests {
    use super::*;

    /// 🚫 A Caddy JSON document must be refused, not silently loaded as an
    /// empty Pingclair config: the admin API used to answer "Config loaded"
    /// with zero servers applied, which made the Getting Started flow look
    /// successful while changing nothing.
    #[test]
    fn caddy_json_is_rejected_fail_closed() {
        let caddy_document = r#"{"apps":{"http":{"servers":{"example":{"listen":[":2015"],"routes":[{"handle":[{"handler":"static_response","body":"Hello, world!"}]}]}}}}}"#;

        let error = JsonAdapter::parse(caddy_document)
            .expect_err("Caddy JSON must not silently load as an empty config");
        let message = error.to_string();
        assert!(
            message.contains("unknown field `apps`"),
            "error must name the unknown field; got: {message}"
        );
    }

    /// 🧭 An empty document is still a valid Pingclair config: fail-closed
    /// rejects foreign schemas, not intentionally empty configurations.
    #[test]
    fn empty_document_still_loads() {
        let config = JsonAdapter::parse("{}").expect("empty config is valid");
        assert!(config.servers.is_empty());
        assert!(config.admin.is_none());
    }
}
