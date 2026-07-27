// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Pingclair Static File Server Module
//!
//! High-performance static file serving with:
//! - MIME type detection
//! - Compression (gzip, brotli, zstd)
//! - Directory browsing
//! - Index file handling

mod compress;
mod file_server;
mod mime;

pub use compress::CompressionLevel;
pub use file_server::{FileServer, FileServerConfig, ServedResponse};
