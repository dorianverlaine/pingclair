//! Error types for Pingclair

use thiserror::Error;

/// Result type for Pingclair operations
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for Pingclair
#[derive(Error, Debug)]
pub enum Error {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Server error
    #[error("Server error: {0}")]
    Server(String),

    /// TLS error
    #[error("TLS error: {0}")]
    Tls(String),

    /// Proxy error
    #[error("Proxy error: {0}")]
    Proxy(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Plugin error
    #[error("Plugin error: {0}")]
    Plugin(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}
