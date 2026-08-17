// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Pingclair Core Library
//!
//! This crate provides the core functionality for the Pingclair web server,
//! including configuration management, HTTP server, and error handling.

/// 🔐 Writing a secret to disk, re-exported from `pingclair-tls`.
///
/// The implementation lives there because that is the crate that needed it
/// first and `pingclair-core` already depends on it; the re-export is here so
/// that everything above core reaches the writer by one name instead of
/// growing a direct TLS dependency to save a secret.
pub mod secure_file {
    pub use pingclair_tls::secure_file::write_private_file;
}

pub mod config;
// 🗜️ Shared because two crates negotiate content coding and having two
// implementations already shipped a defect — see the module's own header.
pub mod encoding;
pub mod error;
pub mod percent;
pub mod server;

pub use error::{Error, Result};

/// Pingclair version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
