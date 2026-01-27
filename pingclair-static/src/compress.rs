#![allow(dead_code)]
//! Compression support

/// Compression level
#[derive(Debug, Clone, Copy, Default)]
pub enum CompressionLevel {
    /// No compression
    None,
    /// Fast compression
    Fast,
    /// Default compression
    #[default]
    Default,
    /// Best compression (slower)
    Best,
}

/// Supported compression algorithms
#[derive(Debug, Clone, Copy)]
pub enum Algorithm {
    Gzip,
    Brotli,
    Zstd,
}

impl Algorithm {
    /// Get the content-encoding header value
    pub fn encoding(&self) -> &'static str {
        match self {
            Algorithm::Gzip => "gzip",
            Algorithm::Brotli => "br",
            Algorithm::Zstd => "zstd",
        }
    }
}
