#![allow(dead_code)]
//! API authentication

/// API key authentication
pub struct ApiKeyAuth {
    key: String,
}

impl ApiKeyAuth {
    /// Create new API key auth
    pub fn new(key: impl Into<String>) -> Self {
        Self { key: key.into() }
    }

    /// Validate an API key
    pub fn validate(&self, provided: &str) -> bool {
        // Constant-time comparison
        self.key.len() == provided.len()
            && self.key.bytes().zip(provided.bytes()).all(|(a, b)| a == b)
    }
}
