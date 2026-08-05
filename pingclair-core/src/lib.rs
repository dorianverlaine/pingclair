// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Pingclair Core Library
//!
//! This crate provides the core functionality for the Pingclair web server,
//! including configuration management, HTTP server, and error handling.

pub mod config;
// 🗜️ Shared because two crates negotiate content coding and having two
// implementations already shipped a defect — see the module's own header.
pub mod encoding;
pub mod error;
pub mod server;

pub use error::{Error, Result};

/// Pingclair version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
