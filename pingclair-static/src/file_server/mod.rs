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
mod stream;

use arc_swap::ArcSwap;
use pingclair_core::error::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

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

    /// Try multiple file paths and return the first one that exists
    /// This is commonly used for SPA (Single Page Application) fallback
    /// Example: try_files(["{path}", "{path}/index.html", "/index.html"])
    pub async fn try_files(
        &self,
        request_path: &str,
        patterns: &[String],
        accept_encoding: Option<&str>,
    ) -> Result<Option<ServedFile>> {
        for pattern in patterns {
            // Replace {path} placeholder with actual request path
            let path = pattern.replace("{path}", request_path.trim_start_matches('/'));

            // Try to serve this path
            if let Ok(Some(file)) = self.serve(&path, None, accept_encoding).await {
                return Ok(Some(file));
            }
        }
        Ok(None)
    }

    /// Resolve a request path to an on-disk path that is verifiably inside
    /// the document root — purely lexically, with no filesystem syscalls
    /// (this runs on the per-request hot path).
    ///
    /// Dot segments are processed component by component while tracking the
    /// depth below the root: `..` at depth 0 would escape the root and is
    /// rejected (`None` → answered 404), anything else is applied to the
    /// joined path. This is the same confinement model as nginx's URI
    /// normalization and Caddy's `path.Clean` prefix check — like both of
    /// them, symlinks inside the docroot are *followed* (an attacker who
    /// can plant symlinks in the docroot already has filesystem access, so
    /// canonicalizing per request would only cost syscalls, not buy safety).
    fn resolve_path(&self, path: &str) -> Option<PathBuf> {
        let mut out = self.config.root.clone();
        // Components below the root; reaching for `..` at 0 escapes it.
        let mut depth: usize = 0;
        for comp in path.split('/') {
            match comp {
                "" | "." => {}
                ".." => {
                    if depth == 0 {
                        tracing::warn!("🚫 Rejected path escaping docroot: {}", path);
                        return None;
                    }
                    out.pop();
                    depth -= 1;
                }
                c => {
                    out.push(c);
                    depth += 1;
                }
            }
        }
        Some(out)
    }

    /// Serve a file request, choosing between a buffered body and a
    /// streaming handle: large, complete (non-Range), uncompressed
    /// responses come back as [`ServedResponse::Stream`] so the caller can
    /// write them out in chunks; everything else is
    /// [`ServedResponse::Buffered`]. One path resolution + one stat per
    /// request either way — no probe-then-fall-back double work.
    pub async fn serve_auto(
        &self,
        path: &str,
        range_header: Option<&str>,
        accept_encoding: Option<&str>,
    ) -> Result<Option<ServedResponse>> {
        // Lexical docroot check (rejects `..` traversal; no syscalls)
        let mut file_path = match self.resolve_path(path) {
            Some(p) => p,
            None => return Ok(None),
        };

        tracing::debug!("📁 Serving request: {} -> {:?}", path, file_path);

        // Check if metadata exists (synchronous by design — see
        // serve_streaming for why tokio::fs is avoided on this hot path)
        let metadata = match std::fs::metadata(&file_path) {
            Ok(m) => m,
            Err(_) => return Ok(None),
        };

        // 🔁 Canonicalize the URL shape before serving: Caddy redirects a
        // directory request without a trailing slash to the slashed form, and
        // a file request with a trailing slash to the bare form.
        let needs_directory_slash = metadata.is_dir() && !path.ends_with('/');
        let needs_file_slash_removal = metadata.is_file() && path.ends_with('/');
        if needs_directory_slash {
            return Ok(Some(ServedResponse::Redirect(format!("{path}/"))));
        }
        if needs_file_slash_removal {
            return Ok(Some(ServedResponse::Redirect(
                path.trim_end_matches('/').to_string(),
            )));
        }

        // 📁 Resolve an index only for directories. A regular file keeps the
        // metadata already fetched above, avoiding a duplicate `statx` on the
        // dominant static-file path.
        let metadata = if metadata.is_dir() {
            // Try index files
            let mut index_found = false;
            for index in &self.config.index {
                let index_path = file_path.join(index);
                if index_path.exists() {
                    file_path = index_path;
                    index_found = true;
                    break;
                }
            }

            // If still a directory (no index found)
            if !index_found {
                if self.config.browse {
                    let listing = self.generate_listing(&file_path, path).await?;
                    // Compress listing if enabled
                    let (content, encoding) = if self.config.compress && range_header.is_none() {
                        self.compress_content(listing.as_bytes(), accept_encoding)
                            .await?
                    } else {
                        (listing.into_bytes(), None)
                    };
                    let listing_len = content.len() as u64;

                    return Ok(Some(ServedResponse::Buffered(ServedFile {
                        content,
                        content_type: HeaderValue::from_static("text/html; charset=utf-8"),
                        content_length: HeaderValue::from(listing_len),
                        path: file_path,
                        status: 200,
                        content_range: None,
                        last_modified: None,
                        etag: None,
                        content_encoding: encoding,
                        vary_accept_encoding: self.config.compress,
                    })));
                } else {
                    return Ok(None);
                }
            }
            match std::fs::metadata(&file_path) {
                Ok(metadata) => metadata,
                Err(_) => return Ok(None),
            }
        } else {
            metadata
        };
        let file_size = metadata.len();

        // Reuse prebuilt response metadata (MIME, Last-Modified, ETag,
        // Content-Length) so repeated requests for the same file clone a few
        // shared `HeaderValue`s instead of reformatting strings each time.
        let meta = self.file_meta(&file_path, &metadata)?;

        // Handle Range Request
        let mut status = 200;
        let mut content_range = None;
        let mut start = 0;
        let mut length = file_size;

        if let Some(range) = range_header
            && let Some((s, e)) = self.parse_range(range, file_size)
        {
            start = s;
            length = e - s + 1;
            status = 206;
            content_range = Some(format!("bytes {s}-{e}/{file_size}"));
        }

        // Streaming branch: large, complete, uncompressed responses are
        // handed back as an open file for chunked writing — the body is
        // never held in memory. Checked before the compression cache path,
        // which only ever applies to buffered responses.
        if self.should_stream_response(file_size, range_header, accept_encoding) {
            return Ok(Some(ServedResponse::Stream(Self::open_stream(
                self, file_path, &metadata,
            )?)));
        }

        // Cache-key ingredients. Only full-file (200, non-range) responses
        // with compression enabled are cacheable; the negotiated encoding and
        // the file mtime (so an edit invalidates the stale entry) form the key.
        let cache_encoding = if self.config.compress && status == 200 {
            Self::negotiate_encoding(accept_encoding)
        } else {
            None
        };
        let mtime_ns = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_nanos());

        // Cache fast path: a hit returns the already-compressed body without
        // reading the file from disk or re-compressing it at all. This is the
        // whole point of the cache — a hot compressible file is compressed
        // once, then served from memory.
        if let (Some(enc), Some(mtime_ns)) = (cache_encoding, mtime_ns) {
            let key = CompressKey {
                path: file_path.clone(),
                mtime_ns,
                encoding: enc,
            };
            if let Some(cached) = self.compress_cache.lock().unwrap().get(&key) {
                tracing::debug!(
                    "✅ Serving cached {} compression: {}",
                    enc,
                    file_path.display()
                );
                return Ok(Some(ServedResponse::Buffered(ServedFile {
                    content: (*cached).clone(),
                    content_type: meta.content_type.clone(),
                    content_length: HeaderValue::from((*cached).len() as u64),
                    path: file_path,
                    status,
                    content_range,
                    last_modified: meta.last_modified.clone(),
                    etag: Some(meta.etag.clone()),
                    content_encoding: Some(enc.to_string()),
                    vary_accept_encoding: self.config.compress,
                })));
            }
        }

        // Check for pre-compressed files first (much faster than on-the-fly
        // compression). Only for complete (non-range) requests. This runs
        // before the raw read because it doesn't need the uncompressed body
        // — when a .br/.gz/.zst variant exists we skip buffering the full
        // file entirely.
        if self.config.precompressed
            && status == 200
            && let Some((precompressed_content, encoding)) =
                self.try_precompressed(&file_path, accept_encoding).await
        {
            let precompressed_len = precompressed_content.len() as u64;
            tracing::debug!(
                "✅ Using pre-compressed file: {} ({})",
                file_path.display(),
                encoding
            );
            return Ok(Some(ServedResponse::Buffered(ServedFile {
                content: precompressed_content,
                content_type: meta.content_type.clone(),
                content_length: HeaderValue::from(precompressed_len),
                path: file_path,
                status,
                content_range,
                last_modified: meta.last_modified.clone(),
                etag: Some(meta.etag.clone()),
                content_encoding: Some(encoding.to_string()),
                vary_accept_encoding: self.config.compress,
            })));
        }

        // In-flight request coalescing: when this request will produce a
        // cacheable compressed response, take the per-key async lock before
        // reading the file. The first request through does the read +
        // compression; concurrent requests for the same (path, mtime,
        // encoding) wait on the lock and then hit the freshly-populated
        // cache, instead of each buffering and compressing the file on its
        // own (the cold-cache stampede behind the benchmark's cold-start
        // memory spike — see benchmarks/README.md).
        let inflight = if let (Some(enc), Some(mtime_ns)) = (cache_encoding, mtime_ns) {
            let key = CompressKey {
                path: file_path.clone(),
                mtime_ns,
                encoding: enc,
            };
            let lock = {
                let mut map = self.in_flight.lock().unwrap();
                map.entry(key.clone())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                    .clone()
            };
            let guard = lock.clone().lock_owned().await;

            // Whoever held the lock before us may have populated the cache
            // while we waited — re-check before doing the work ourselves.
            if let Some(cached) = self.compress_cache.lock().unwrap().get(&key) {
                drop(guard);
                Self::release_inflight(&self.in_flight, &key, &lock);
                tracing::debug!(
                    "✅ Serving coalesced {} compression: {}",
                    enc,
                    file_path.display()
                );
                return Ok(Some(ServedResponse::Buffered(ServedFile {
                    content: (*cached).clone(),
                    content_type: meta.content_type.clone(),
                    content_length: HeaderValue::from((*cached).len() as u64),
                    path: file_path,
                    status,
                    content_range,
                    last_modified: meta.last_modified.clone(),
                    etag: Some(meta.etag.clone()),
                    content_encoding: Some(enc.to_string()),
                    vary_accept_encoding: self.config.compress,
                })));
            }
            Some((key, lock, guard))
        } else {
            None
        };

        // Read the file and, when negotiated, compress it on the fly. On a
        // cacheable compression the result is stored so subsequent requests
        // hit the fast path above and skip the read+compress entirely. We
        // still compress even if the file has no usable mtime — we just
        // can't safely cache that result.
        let result = self
            .read_and_maybe_compress(&file_path, start, length, cache_encoding, mtime_ns)
            .await;

        // Publish before releasing: the cache insert already happened inside
        // the call above, so a follower that grabs the lock next is
        // guaranteed to see the entry.
        if let Some((key, lock, guard)) = inflight {
            drop(guard);
            Self::release_inflight(&self.in_flight, &key, &lock);
        }

        let (content, content_encoding) = result?;
        let content_length = content.len() as u64;

        Ok(Some(ServedResponse::Buffered(ServedFile {
            content,
            content_type: meta.content_type.clone(),
            content_length: HeaderValue::from(content_length),
            path: file_path,
            status,
            content_range,
            last_modified: meta.last_modified.clone(),
            etag: Some(meta.etag.clone()),
            content_encoding,
            vary_accept_encoding: self.config.compress,
        })))
    }

    /// Serve a file request, always buffered.
    ///
    /// Compatibility wrapper around [`Self::serve_auto`] for callers that
    /// cannot write a chunked body (QUIC path, `try_files`): a streaming
    /// result is read into memory here, so this shares the old
    /// whole-body-in-memory behavior for large files. The main HTTP path
    /// uses `serve_auto` directly.
    pub async fn serve(
        &self,
        path: &str,
        range_header: Option<&str>,
        accept_encoding: Option<&str>,
    ) -> Result<Option<ServedFile>> {
        match self.serve_auto(path, range_header, accept_encoding).await? {
            Some(ServedResponse::Buffered(file)) => Ok(Some(file)),
            Some(ServedResponse::Redirect(_)) => Ok(None),
            Some(ServedResponse::Stream(mut stream)) => {
                let mut content = Vec::with_capacity(stream.file_size as usize);
                while let Some(chunk) = stream.read_chunk()? {
                    content.extend_from_slice(&chunk);
                }
                Ok(Some(ServedFile {
                    content,
                    content_type: stream.content_type,
                    content_length: stream.content_length,
                    path: stream.path,
                    status: 200,
                    content_range: None,
                    last_modified: stream.last_modified,
                    etag: stream.etag,
                    content_encoding: None,
                    vary_accept_encoding: self.config.compress,
                }))
            }
            None => Ok(None),
        }
    }

    /// Generate HTML directory listing
    async fn generate_listing(&self, dir_path: &std::path::Path, req_path: &str) -> Result<String> {
        // Synchronous directory read — a readdir on a local filesystem is a
        // cheap syscall, not worth a spawn_blocking round trip.
        let entries = std::fs::read_dir(dir_path)?;
        let mut html = format!(
            "<html><head><title>Index of {req_path}</title></head><body><h1>Index of {req_path}</h1><hr><pre>"
        );

        // Parent link
        if req_path != "/" {
            html.push_str("<a href=\"..\">../</a>\n");
        }

        for entry in entries.take(self.config.browse_limit.unwrap_or(usize::MAX)) {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let is_dir = entry.file_type()?.is_dir();
            let display_name = if is_dir {
                format!("{name_str}/")
            } else {
                name_str.to_string()
            };

            html.push_str(&format!("<a href=\"{display_name}\">{display_name}</a>\n"));
        }

        html.push_str("</pre><hr></body></html>");
        Ok(html)
    }

    /// Parse Range header (bytes=start-end)
    fn parse_range(&self, header: &str, file_size: u64) -> Option<(u64, u64)> {
        if !header.starts_with("bytes=") {
            return None;
        }
        let val = &header[6..];
        let parts: Vec<&str> = val.split('-').collect();
        if parts.len() != 2 {
            return None;
        }

        let start_str = parts[0];
        let end_str = parts[1];

        let start = start_str.parse::<u64>().ok().unwrap_or(0);
        let end = if end_str.is_empty() {
            file_size - 1
        } else {
            end_str.parse::<u64>().ok().unwrap_or(file_size - 1)
        };

        if start > end || start >= file_size {
            return None;
        }

        Some((start, std::cmp::min(end, file_size - 1)))
    }
}

#[cfg(test)]
mod traversal_tests {
    use super::*;

    /// Layout for each test: `base/` is a temp dir, `base/root/` is the
    /// docroot, and `base/secret.txt` lives *outside* the docroot.
    struct Fixture {
        base: tempfile::TempDir,
        root: PathBuf,
    }

    async fn fixture() -> Fixture {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("root");
        tokio::fs::create_dir_all(root.join("sub")).await.unwrap();
        tokio::fs::write(root.join("index.html"), b"hello")
            .await
            .unwrap();
        tokio::fs::write(root.join("sub/page.txt"), b"nested")
            .await
            .unwrap();
        tokio::fs::write(base.path().join("secret.txt"), b"top secret")
            .await
            .unwrap();
        Fixture { base, root }
    }

    fn server(root: &std::path::Path) -> FileServer {
        FileServer::new(FileServerConfig {
            root: root.to_path_buf(),
            index: vec!["index.html".to_string()],
            browse: false,
            browse_limit: None,
            compress: false,
            precompressed: false,
        })
    }

    #[tokio::test]
    async fn dot_dot_traversal_is_rejected() {
        let f = fixture().await;
        let fs = server(&f.root);
        assert!(
            fs.serve("/../secret.txt", None, None)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            fs.serve("/sub/../../secret.txt", None, None)
                .await
                .unwrap()
                .is_none()
        );
        assert!(fs.serve("..", None, None).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn dot_dot_traversal_is_rejected_for_streaming() {
        let f = fixture().await;
        let fs = server(&f.root);
        assert!(
            fs.serve_streaming("/../secret.txt")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn percent_encoded_traversal_does_not_resolve() {
        // The router passes the raw (still percent-encoded) URI path through,
        // so "%2e%2e"/"%2f" arrive literally; no file by that name exists
        // and the request must come back as not-found, never as the secret.
        let f = fixture().await;
        let fs = server(&f.root);
        assert!(
            fs.serve("/..%2fsecret.txt", None, None)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            fs.serve("/%2e%2e/secret.txt", None, None)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn symlink_escaping_root_is_followed_like_nginx_and_caddy() {
        // Docroot confinement is lexical (see resolve_path): like nginx and
        // Caddy by default, symlinks are followed — docroot is not a
        // security boundary against someone who can plant symlinks in it.
        let f = fixture().await;
        std::os::unix::fs::symlink(f.base.path().join("secret.txt"), f.root.join("link.txt"))
            .unwrap();
        let fs = server(&f.root);
        let served = fs.serve("/link.txt", None, None).await.unwrap().unwrap();
        assert_eq!(served.content, b"top secret");
    }

    #[tokio::test]
    async fn symlink_staying_inside_root_is_served() {
        let f = fixture().await;
        std::os::unix::fs::symlink(f.root.join("sub/page.txt"), f.root.join("inner-link.txt"))
            .unwrap();
        let fs = server(&f.root);
        let served = fs
            .serve("/inner-link.txt", None, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(served.content, b"nested");
    }

    #[tokio::test]
    async fn normal_nested_paths_still_work() {
        let f = fixture().await;
        let fs = server(&f.root);
        let index = fs.serve("/", None, None).await.unwrap().unwrap();
        assert_eq!(index.content, b"hello");
        let nested = fs
            .serve("/sub/page.txt", None, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(nested.content, b"nested");
        let streamed = fs.serve_streaming("/sub/page.txt").await.unwrap().unwrap();
        assert_eq!(streamed.file_size, 6);
    }
}

#[cfg(test)]
mod serve_cache_tests {
    use super::*;
    use std::io::Write as _;

    async fn write_file(dir: &std::path::Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(name);
        tokio::fs::write(&p, bytes).await.unwrap();
        p
    }

    #[tokio::test]
    async fn second_request_is_served_from_cache_and_is_valid_gzip() {
        let dir = tempfile::tempdir().unwrap();
        // Highly compressible ~256KB body (well over the 256B min gzip size).
        let body = vec![b'a'; 256 * 1024];
        write_file(dir.path(), "big.txt", &body).await;

        let fs = FileServer::new(FileServerConfig {
            root: dir.path().to_path_buf(),
            index: vec![],
            browse: false,
            browse_limit: None,
            compress: true,
            precompressed: false, // force the on-the-fly path we're testing
        });

        // First request: cache miss, compresses and stores.
        let first = fs
            .serve("/big.txt", None, Some("gzip"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.content_encoding.as_deref(), Some("gzip"));
        assert!(first.content.len() < body.len(), "should be compressed");
        assert_eq!(
            fs.compress_cache.lock().unwrap().entries.len(),
            1,
            "first request should populate the cache"
        );

        // Second request: must hit the cache and return byte-identical output.
        let second = fs
            .serve("/big.txt", None, Some("gzip"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            second.content, first.content,
            "cached body must match freshly compressed body"
        );

        // And the cached bytes must be valid gzip that round-trips.
        let mut d = flate2::read::GzDecoder::new(&second.content[..]);
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut d, &mut out).unwrap();
        assert_eq!(
            out, body,
            "cached gzip must decompress to the original file"
        );
    }

    #[tokio::test]
    async fn editing_the_file_invalidates_the_cached_compression() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_file(dir.path(), "f.txt", &vec![b'a'; 4096]).await;

        let fs = FileServer::new(FileServerConfig {
            root: dir.path().to_path_buf(),
            index: vec![],
            browse: false,
            browse_limit: None,
            compress: true,
            precompressed: false,
        });

        let first = fs
            .serve("/f.txt", None, Some("gzip"))
            .await
            .unwrap()
            .unwrap();
        let mut d1 = flate2::read::GzDecoder::new(&first.content[..]);
        let mut out1 = Vec::new();
        std::io::Read::read_to_end(&mut d1, &mut out1).unwrap();
        assert_eq!(out1, vec![b'a'; 4096]);

        // Rewrite with different, longer content and bump mtime forward so the
        // filesystem definitely reports a newer modified time.
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(&vec![b'z'; 8192]).unwrap();
        }
        let future = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
        filetime_set(&path, future);

        let second = fs
            .serve("/f.txt", None, Some("gzip"))
            .await
            .unwrap()
            .unwrap();
        let mut d2 = flate2::read::GzDecoder::new(&second.content[..]);
        let mut out2 = Vec::new();
        std::io::Read::read_to_end(&mut d2, &mut out2).unwrap();
        assert_eq!(
            out2,
            vec![b'z'; 8192],
            "must serve the NEW content, not the stale cached compression"
        );
    }

    // Minimal mtime setter without pulling in the `filetime` crate: reopen and
    // set times via std where available, else touch by rewriting. We use a
    // libc-free approach: set the file's mtime by writing then relying on the
    // OS clock advancing is unreliable, so use utimes through std is not
    // available — instead we sleep-free bump by using `set_modified` (Rust
    // 1.75+) on the File handle.
    fn filetime_set(path: &std::path::Path, t: std::time::SystemTime) {
        let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.set_modified(t).unwrap();
    }

    /// Cold-cache requests for the same file must coalesce: a request that
    /// arrives while another compression for the same (path, mtime,
    /// encoding) is in flight waits for it and then serves the shared
    /// cached result, instead of reading + compressing on its own.
    #[tokio::test]
    async fn concurrent_cold_cache_requests_are_coalesced() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_file(dir.path(), "big.txt", &vec![b'a'; 4096]).await;

        let fs = Arc::new(FileServer::new(FileServerConfig {
            root: dir.path().to_path_buf(),
            index: vec![],
            browse: false,
            browse_limit: None,
            compress: true,
            precompressed: false,
        }));

        // The key serve() will compute for this file: the lexically
        // resolved docroot-joined path (see resolve_path).
        let resolved_path = dir.path().join("big.txt");
        let mtime_ns = std::fs::metadata(&path)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let key = CompressKey {
            path: resolved_path,
            mtime_ns,
            encoding: "gzip",
        };

        // Simulate an in-flight compression: hold the per-key lock the way
        // the first requester would.
        let leader_lock = Arc::new(tokio::sync::Mutex::new(()));
        fs.in_flight
            .lock()
            .unwrap()
            .insert(key.clone(), leader_lock.clone());
        let leader_guard = leader_lock.clone().lock_owned().await;

        // A concurrent request must now block on the in-flight lock...
        let fs2 = fs.clone();
        let mut follower = tokio::spawn(async move {
            fs2.serve("/big.txt", None, Some("gzip"))
                .await
                .unwrap()
                .unwrap()
        });
        tokio::select! {
            _ = &mut follower => panic!("follower completed while compression was still in flight"),
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
        }

        // ...until the leader publishes its result to the cache and
        // releases the lock.
        let compressed = FileServer::compress_with(&vec![b'a'; 4096], "gzip")
            .await
            .unwrap();
        fs.compress_cache
            .lock()
            .unwrap()
            .insert(key.clone(), Arc::new(compressed.clone()));
        drop(leader_guard);

        let served = tokio::time::timeout(std::time::Duration::from_secs(5), &mut follower)
            .await
            .expect("follower never unblocked after the leader finished")
            .unwrap();
        assert_eq!(
            served.content, compressed,
            "follower must serve the leader's shared result"
        );
        assert_eq!(served.content_encoding.as_deref(), Some("gzip"));

        // The in-flight bookkeeping must not leak: both the leader's slot
        // (removed by the follower on its coalesced hit) is gone.
        assert!(
            fs.in_flight.lock().unwrap().is_empty(),
            "in-flight entry must be removed after use"
        );
    }
}

#[cfg(test)]
mod browse_limit_tests {
    use super::*;

    #[tokio::test]
    async fn browse_listing_honors_the_entry_limit() {
        let dir = tempfile::tempdir().unwrap();
        for index in 0..5 {
            std::fs::write(dir.path().join(format!("f{index}.txt")), "x").unwrap();
        }
        let fs = FileServer::new(FileServerConfig {
            root: dir.path().to_path_buf(),
            browse: true,
            browse_limit: Some(2),
            ..Default::default()
        });
        let listing = fs.generate_listing(dir.path(), "/").await.unwrap();
        assert_eq!(
            listing.matches("<a href=").count(),
            2,
            "listing must be capped at the configured limit: {listing}"
        );
    }
}
