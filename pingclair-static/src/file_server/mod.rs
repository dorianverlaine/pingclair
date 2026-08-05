// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! File server implementation
//!
//! # 🗺️ Why this is a directory and not one file
//!
//! It was one file, and by 2026-08-06 that file was 1,883 lines — 795 of them
//! a single `impl FileServer`. The cost was not the length. It was that the
//! block had no seam: the compressed-body cache, the response-metadata cache,
//! the streaming decision, codec negotiation, and the request handler were all
//! peers inside one `impl`, so a change to any of them landed in the same
//! place with nothing to check it against.
//!
//! The split follows the structure the type already has — its fields. Two of
//! them are caches, one is a distinct response shape, and what remains is the
//! handler:
//!
//! | Module | Owns |
//! | --- | --- |
//! | [`cache`] | Both caches and their keys: compressed bodies, and per-file response metadata. |
//! | [`encode`] | Which coding to use, and producing it. |
//! | [`stream`] | The chunked response: its type, its threshold, and the decision to take it. |
//! | [`serve`] | The request handler, path resolution, Range parsing, and directory listings. |
//!
//! This module keeps only what all four need: the configuration, the server
//! itself, and the two buffered response types.

mod cache;
mod encode;
mod serve;
mod stream;

use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use http::HeaderValue;

use cache::{CompressCache, CompressKey, FileMeta, MetaKey};
pub use stream::StreamingFile;

/// Configuration for the file server
#[derive(Debug, Clone)]
pub struct FileServerConfig {
    /// Root directory to serve
    pub root: PathBuf,
    /// Index files to look for
    pub index: Vec<String>,
    /// Enable directory browsing
    pub browse: bool,
    /// Cap on directory entries read for a browse listing (Caddy
    /// `--file-limit` semantics).
    pub browse_limit: Option<usize>,
    /// Enable compression
    pub compress: bool,
    /// Check for pre-compressed files (.br, .gz, .zst)
    pub precompressed: bool,
}

impl Default for FileServerConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            index: vec!["index.html".to_string(), "index.htm".to_string()],
            browse: false,
            browse_limit: None,
            compress: true,
            precompressed: true, // Default to checking for pre-compressed files
        }
    }
}

/// Static file server
pub struct FileServer {
    config: FileServerConfig,
    /// Prebuilt response metadata per file identity (path, mtime, size).
    /// The values themselves are immutable `Arc`s, so a hit clones one
    /// pointer and a few `HeaderValue`s instead of reformatting dates,
    /// ETags, and content lengths on every request. Read via `ArcSwap` so a
    /// hit is one atomic load and never takes a lock; the write mutex is
    /// only contended on a cache miss. Bounded by a hard entry cap.
    meta_cache: ArcSwap<HashMap<MetaKey, Arc<FileMeta>>>,
    meta_write: Mutex<()>,
    /// Cache of already-compressed file bodies (see [`CompressCache`]).
    /// Behind a `Mutex` because `FileServer` is shared (`Arc`) across all
    /// worker threads; the lock is only ever held for a tiny map operation,
    /// never across an `.await`.
    compress_cache: Mutex<CompressCache>,
    /// Per-key async locks for compressions currently in flight, keyed the
    /// same way as `compress_cache`. On a cold cache, concurrent requests
    /// for the same file would otherwise each read and compress it
    /// independently (a cache stampede — the cold-start memory spike in
    /// benchmarks/README.md). The first request takes the lock and does the
    /// work; the rest wait on it and then serve the shared cached result.
    /// The std `Mutex` around the map itself is never held across an await.
    in_flight: Mutex<HashMap<CompressKey, Arc<tokio::sync::Mutex<()>>>>,
}

/// Response from file server
pub struct ServedFile {
    pub content: Vec<u8>,
    /// Prebuilt Content-Type header value (clone is a shared-bytes bump).
    pub content_type: HeaderValue,
    /// Prebuilt Content-Length header value for the full response body.
    pub content_length: HeaderValue,
    pub path: PathBuf,
    pub status: u16,
    pub content_range: Option<String>,
    pub last_modified: Option<HeaderValue>,
    pub etag: Option<HeaderValue>,
    pub content_encoding: Option<String>,
    /// 🧊 Whether this resource varies by `Accept-Encoding`.
    ///
    /// True whenever compression is enabled for this file server, **not only
    /// when this particular response was compressed**. A shared cache that
    /// stores the identity copy without being told this will hand it to a
    /// client that would have received gzip, and vice versa. The header belongs
    /// on both variants for exactly this reason; Day 26 measured that we set it
    /// on neither of the uncompressed ones.
    pub vary_accept_encoding: bool,
}

/// Result of [`FileServer::serve_auto`]: either a fully buffered body
/// (small, ranged, or compressed responses) or an open streaming handle
/// (large, complete, uncompressed responses). Splitting the decision at
/// this level means one path resolution + one stat per request — the
/// caller never has to probe-then-fall-back.
pub enum ServedResponse {
    Buffered(ServedFile),
    Stream(StreamingFile),
    /// 🔁 A canonical-URL redirect: directories get a trailing slash and
    /// files lose one, matching Caddy's file_server behavior.
    Redirect(String),
}

impl FileServer {
    /// Total compressed bytes to retain across all cached files.
    const COMPRESS_CACHE_BUDGET: usize = 64 * 1024 * 1024;

    /// Create a new file server
    pub fn new(config: FileServerConfig) -> Self {
        Self {
            config,
            meta_cache: ArcSwap::from_pointee(HashMap::new()),
            meta_write: Mutex::new(()),
            compress_cache: Mutex::new(CompressCache::new(Self::COMPRESS_CACHE_BUDGET)),
            in_flight: Mutex::new(HashMap::new()),
        }
    }

    /// Create a file server for a directory
    pub fn serve_dir(root: impl Into<PathBuf>) -> Self {
        Self::new(FileServerConfig {
            root: root.into(),
            ..Default::default()
        })
    }

    /// Enable directory browsing
    pub fn with_browse(mut self, enable: bool) -> Self {
        self.config.browse = enable;
        self
    }
}
