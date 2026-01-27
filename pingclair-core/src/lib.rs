//! Pingclair Core Library
//!
//! This crate provides the core functionality for the Pingclair web server,
//! including configuration management, HTTP server, and error handling.

pub mod config;
pub mod error;
pub mod server;

pub use error::{Error, Result};

/// Pingclair version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
