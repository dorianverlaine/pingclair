// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! File server implementation

use arc_swap::ArcSwap;
use pingclair_core::error::Result;
use std::collections::{HashMap, VecDeque};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use http::HeaderValue;

/// Key for a cached compressed response: a file identity (path + mtime) plus
/// the content encoding. mtime is part of the key so editing a file naturally
/// invalidates its stale cached compression instead of serving old bytes.
#[derive(Clone, PartialEq, Eq, Hash)]
struct CompressKey {
    path: PathBuf,
    mtime_ns: u128,
    encoding: &'static str,
}

/// Prebuilt response metadata for one file identity: path, mtime, and size.
///
/// Every static response repeats the same header values (Content-Type,
/// Last-Modified, ETag, Content-Length) for the same file. Building them as
/// `HeaderValue`s once per file identity lets hot paths clone them for one
/// atomic reference-count increment instead of reformatting and copying
/// strings on every request — the dominant per-request header allocation on
/// the small-file benchmark path.
struct FileMeta {
    content_type: HeaderValue,
    last_modified: Option<HeaderValue>,
    etag: HeaderValue,
    content_length: HeaderValue,
}

/// Identity of one file's metadata, derived from a single `stat` per request.
#[derive(Clone, PartialEq, Eq, Hash)]
struct MetaKey {
    path: PathBuf,
    mtime_ns: u128,
    size: u64,
}

/// A small, byte-bounded LRU cache of already-compressed file bodies.
///
/// On-the-fly compression is expensive and, without this, was redone from
/// scratch on *every* request for the same file — under sustained concurrent
/// load against a large compressible file that turned a 20s benchmark into a
/// 16-minute one (see benchmarks/README.md). Caching the compressed output
/// keyed on (path, mtime, encoding) means a hot file is compressed once and
/// then served from memory. Bounded by total compressed bytes so the cache
/// can't grow without limit; least-recently-used entries are evicted first.
struct CompressCache {
    entries: HashMap<CompressKey, Arc<Vec<u8>>>,
    /// Recency order, front = least recently used.
    lru: VecDeque<CompressKey>,
    bytes: usize,
    budget: usize,
}

impl CompressCache {
    fn new(budget: usize) -> Self {
        Self {
            entries: HashMap::new(),
            lru: VecDeque::new(),
            bytes: 0,
            budget,
        }
    }

    fn touch(&mut self, key: &CompressKey) {
        if let Some(pos) = self.lru.iter().position(|k| k == key) {
            self.lru.remove(pos);
        }
        self.lru.push_back(key.clone());
    }

    fn get(&mut self, key: &CompressKey) -> Option<Arc<Vec<u8>>> {
        if let Some(v) = self.entries.get(key).cloned() {
            self.touch(key);
            Some(v)
        } else {
            None
        }
    }

    fn insert(&mut self, key: CompressKey, value: Arc<Vec<u8>>) {
        let size = value.len();
        // A single entry larger than the whole budget is never worth caching —
        // it would immediately evict everything including itself.
        if size > self.budget {
            return;
        }
        if let Some(old) = self.entries.insert(key.clone(), value) {
            self.bytes -= old.len();
            if let Some(pos) = self.lru.iter().position(|k| k == &key) {
                self.lru.remove(pos);
            }
        }
        self.bytes += size;
        self.lru.push_back(key);

        while self.bytes > self.budget {
            match self.lru.pop_front() {
                Some(evicted) => {
                    if let Some(v) = self.entries.remove(&evicted) {
                        self.bytes -= v.len();
                    }
                }
                None => break,
            }
        }
    }
}

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
    /// client that would have received gzip, and vice versa. Caddy sets the
    /// header on both variants for exactly this reason; Day 26 measured that
    /// we set it on neither of the uncompressed ones.
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

/// Streaming file response for zero-copy large file transfer
/// Use this for files larger than 5MB to avoid memory pressure
pub struct StreamingFile {
    /// Synchronous file handle. Synchronous I/O is intentional: reads of
    /// local regular files effectively never block (a page-cache hit is
    /// microseconds), which is why nginx reads/sends files directly on its
    /// event-loop threads. Routing every read through `tokio::fs` costs a
    /// `spawn_blocking` cross-thread round trip per chunk — several per
    /// request on this hot path.
    pub file: std::fs::File,
    /// Total file size in bytes
    pub file_size: u64,
    /// Chunk size for streaming (default 64KB)
    pub chunk_size: usize,
    /// Prebuilt Content-Type header value (clone is a shared-bytes bump).
    pub content_type: HeaderValue,
    /// Prebuilt Content-Length header value.
    pub content_length: HeaderValue,
    /// Path to the file
    pub path: PathBuf,
    /// Last-Modified header value
    pub last_modified: Option<HeaderValue>,
    /// ETag header value
    pub etag: Option<HeaderValue>,
    /// 🧊 See [`ServedFile::vary_accept_encoding`]. A streamed response is by
    /// definition the uncompressed variant, so this is exactly the case that
    /// used to reach a shared cache with no `Vary` at all.
    pub vary_accept_encoding: bool,
    /// Bytes read so far
    bytes_read: u64,
}

impl StreamingFile {
    /// Read the next chunk of data (synchronous — see the `file` field for
    /// why blocking I/O is deliberate here).
    /// Returns None when EOF is reached
    pub fn read_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        if self.bytes_read >= self.file_size {
            return Ok(None);
        }

        let remaining = (self.file_size - self.bytes_read) as usize;
        let to_read = remaining.min(self.chunk_size);

        let mut buf = vec![0u8; to_read];
        let n = self.file.read(&mut buf)?;

        if n == 0 {
            return Ok(None);
        }

        buf.truncate(n);
        self.bytes_read += n as u64;

        Ok(Some(buf))
    }

    /// Get progress as a fraction (0.0 - 1.0)
    pub fn progress(&self) -> f64 {
        if self.file_size == 0 {
            1.0
        } else {
            self.bytes_read as f64 / self.file_size as f64
        }
    }

    /// Check if streaming is complete
    pub fn is_complete(&self) -> bool {
        self.bytes_read >= self.file_size
    }

    /// Get Content-Length header value
    pub fn content_length(&self) -> u64 {
        self.file_size
    }
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

    /// Maximum number of file identities whose response metadata is cached.
    /// Each entry holds a handful of small `HeaderValue`s, so even a busy
    /// site with thousands of files stays well under a megabyte.
    const META_CACHE_CAP: usize = 4096;

    /// Return the prebuilt response metadata for `file_path`, building and
    /// caching it on the first request and on every mtime/size change.
    fn file_meta(&self, file_path: &Path, metadata: &std::fs::Metadata) -> Result<Arc<FileMeta>> {
        let size = metadata.len();
        let mtime_ns = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_nanos());

        // Files without a usable mtime are rebuilt per request: caching by
        // size alone could serve stale headers after a same-size overwrite.
        let Some(mtime_ns) = mtime_ns else {
            return Ok(Arc::new(Self::build_meta(file_path, metadata, size)));
        };

        let key = MetaKey {
            path: file_path.to_path_buf(),
            mtime_ns,
            size,
        };
        if let Some(meta) = self.meta_cache.load().get(&key) {
            return Ok(meta.clone());
        }

        let meta = Arc::new(Self::build_meta(file_path, metadata, size));
        let _guard = self.meta_write.lock().unwrap();
        // Whoever published first wins; the double-check avoids rebuilding
        // the map after a concurrent miss already inserted the entry.
        if let Some(meta) = self.meta_cache.load().get(&key) {
            return Ok(meta.clone());
        }
        let mut cache = (**self.meta_cache.load()).clone();
        if cache.len() >= Self::META_CACHE_CAP {
            cache.clear();
        }
        cache.insert(key, meta.clone());
        self.meta_cache.store(Arc::new(cache));
        Ok(meta)
    }

    /// Format one file's response metadata into reusable header values.
    fn build_meta(file_path: &Path, metadata: &std::fs::Metadata, size: u64) -> FileMeta {
        let mime_type = crate::mime::with_charset(
            mime_guess::from_path(file_path)
                .first_raw()
                .unwrap_or("application/octet-stream"),
        );
        let last_modified = metadata.modified().ok().map(httpdate::fmt_http_date);
        let modified_secs = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        let etag = format!("\"{size:x}-{modified_secs:x}\"");

        FileMeta {
            content_type: HeaderValue::from_str(&mime_type).unwrap(),
            last_modified: last_modified.map(|v| HeaderValue::from_str(&v).unwrap()),
            etag: HeaderValue::from_str(&etag).unwrap(),
            content_length: HeaderValue::from(size),
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

    /// 🧵 Size above which complete, uncompressed responses stream from disk.
    ///
    /// Files at or below this bound stay on the buffered fast path, where one
    /// read plus one write serves the body; anything larger streams in 64 KiB
    /// chunks so per-request memory stays bounded. The bound is deliberately
    /// small (256 KiB, four chunks): a 5 MiB bound meant 2,000 in-flight 1 MiB
    /// responses could buffer ~2 GiB and OOM a small host (observed on
    /// t3.small, see benchmarks/results/20260803_aws_h3perf/). Streaming
    /// never applies to Range or negotiated-compression responses, so the
    /// compression cache and byte-range behavior are unchanged.
    const STREAMING_THRESHOLD: u64 = 256 * 1024;

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

    /// Cheap pre-check for the streaming path, without any I/O: streaming
    /// is only ever possible for non-Range requests that won't be
    /// compressed. The caller uses this to skip the stat+open that
    /// `serve_streaming` would otherwise do on every request just to
    /// discover streaming doesn't apply (notably every compressed
    /// response — the hot path of the compression cache).
    pub fn could_stream(&self, range: Option<&str>, accept_encoding: Option<&str>) -> bool {
        range.is_none()
            && !(self.config.compress && Self::negotiate_encoding(accept_encoding).is_some())
    }

    /// 🧭 Whether a request for a file of `file_size` bytes should be
    /// answered by chunked streaming instead of the buffered+cached path:
    /// only complete (non-Range), uncompressed responses above
    /// [`Self::STREAMING_THRESHOLD`]. Compressed responses stay buffered so
    /// the compression cache keeps working regardless of file size.
    pub fn should_stream_response(
        &self,
        file_size: u64,
        range: Option<&str>,
        accept_encoding: Option<&str>,
    ) -> bool {
        self.could_stream(range, accept_encoding) && file_size > Self::STREAMING_THRESHOLD
    }

    /// 🌊 Serve a large file using zero-copy streaming.
    ///
    /// Returns a [`StreamingFile`] that can be used for chunked transfer.
    /// Use this for files above [`Self::STREAMING_THRESHOLD`] to keep
    /// per-request memory bounded under concurrency.
    pub async fn serve_streaming(&self, path: &str) -> Result<Option<StreamingFile>> {
        // Lexical docroot check (rejects `..` traversal; no syscalls)
        let file_path = match self.resolve_path(path) {
            Some(p) => p,
            None => return Ok(None),
        };

        // Check if file exists. `std::fs` on purpose: stat of a local file
        // is a cheap syscall, while `tokio::fs::metadata` would dispatch a
        // `spawn_blocking` cross-thread round trip per request.
        let metadata = match std::fs::metadata(&file_path) {
            Ok(m) if m.is_file() => m,
            _ => return Ok(None),
        };

        Ok(Some(Self::open_stream(self, file_path, &metadata)?))
    }

    /// Open `file_path` for chunked streaming, computing the response
    /// metadata (MIME, Last-Modified, ETag) from the already-fetched stat.
    fn open_stream(
        server: &FileServer,
        file_path: PathBuf,
        metadata: &std::fs::Metadata,
    ) -> Result<StreamingFile> {
        let file_size = metadata.len();

        // Open file handle (no reading yet - zero-copy preparation)
        let file = std::fs::File::open(&file_path)?;
        let meta = server.file_meta(&file_path, metadata)?;

        Ok(StreamingFile {
            file,
            file_size,
            chunk_size: 64 * 1024, // 64KB chunks
            content_type: meta.content_type.clone(),
            content_length: meta.content_length.clone(),
            path: file_path,
            last_modified: meta.last_modified.clone(),
            etag: Some(meta.etag.clone()),
            vary_accept_encoding: server.config.compress,
            bytes_read: 0,
        })
    }

    /// 📏 Check if a file should be served with streaming (based on size).
    pub async fn should_stream(&self, path: &str) -> Result<bool> {
        let file_path = self.config.root.join(path.trim_start_matches('/'));
        match std::fs::metadata(&file_path) {
            Ok(m) => Ok(m.len() > Self::STREAMING_THRESHOLD),
            Err(_) => Ok(false),
        }
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

    /// Read `length` bytes of `file_path` starting at `start`, then compress
    /// the body when `encoding` was negotiated. A compressible full-file
    /// result with a usable mtime is stored in `compress_cache` under
    /// (path, mtime, encoding) so later requests skip the read+compress.
    async fn read_and_maybe_compress(
        &self,
        file_path: &std::path::Path,
        start: u64,
        length: u64,
        encoding: Option<&'static str>,
        mtime_ns: Option<u128>,
    ) -> Result<(Vec<u8>, Option<String>)> {
        // Synchronous read, intentionally: a local regular-file read served
        // from the page cache effectively never blocks (the nginx model), so
        // paying a spawn_blocking round trip per request via tokio::fs only
        // adds cross-thread wakeups on this hot path.
        let mut file = std::fs::File::open(file_path)?;

        if start > 0 {
            file.seek(SeekFrom::Start(start))?;
        }

        let mut content = vec![0u8; length as usize];
        file.read_exact(&mut content)?;

        match encoding {
            Some(enc) => {
                let compressed = Arc::new(Self::compress_with(&content, enc).await?);
                if let Some(mtime_ns) = mtime_ns {
                    let key = CompressKey {
                        path: file_path.to_path_buf(),
                        mtime_ns,
                        encoding: enc,
                    };
                    self.compress_cache
                        .lock()
                        .unwrap()
                        .insert(key, compressed.clone());
                }
                Ok(((*compressed).clone(), Some(enc.to_string())))
            }
            None => Ok((content, None)),
        }
    }

    /// Remove the in-flight entry for `key`, but only if it is still the
    /// `lock` this request took — a newer request for the same key may have
    /// already replaced the entry, and we must never remove somebody else's.
    fn release_inflight(
        map: &Mutex<HashMap<CompressKey, Arc<tokio::sync::Mutex<()>>>>,
        key: &CompressKey,
        lock: &Arc<tokio::sync::Mutex<()>>,
    ) {
        let mut map = map.lock().unwrap();
        if map.get(key).is_some_and(|l| Arc::ptr_eq(l, lock)) {
            map.remove(key);
        }
    }

    /// Try to find and load a pre-compressed version of the file
    /// Checks for .br, .gz, .zst files in order of preference based on Accept-Encoding
    async fn try_precompressed(
        &self,
        original_path: &std::path::Path,
        accept_encoding: Option<&str>,
    ) -> Option<(Vec<u8>, &'static str)> {
        let accept = accept_encoding?;

        // Priority order based on compression ratio and modern support:
        // 1. Brotli (.br) - best for web
        // 2. Zstd (.zst) - fastest decompression
        // 3. Gzip (.gz) - widest support
        let candidates: Vec<(&'static str, &'static str)> =
            vec![("br", ".br"), ("zstd", ".zst"), ("gzip", ".gz")];

        for (encoding, ext) in candidates {
            if !accept.contains(encoding) {
                continue;
            }

            // Build precompressed path
            let mut precompressed_path = original_path.as_os_str().to_owned();
            precompressed_path.push(ext);
            let precompressed_path = std::path::PathBuf::from(precompressed_path);

            // Check if pre-compressed file exists and is readable
            // (synchronous read — same rationale as read_and_maybe_compress)
            if let Ok(content) = std::fs::read(&precompressed_path) {
                return Some((content, encoding));
            }
        }

        None
    }

    /// Pick a content encoding from an `Accept-Encoding` header.
    /// Priority: br > zstd > gzip. Returns `None` if the client accepts none
    /// of them (or sent no header), meaning "serve uncompressed".
    /// 🗜️ Codings this server will produce, in preference order.
    ///
    /// Brotli stays in the list even though the DSL refuses `encode br`,
    /// because a static file has been able to answer a brotli request for as
    /// long as this code existed and dropping it is a behaviour change that
    /// belongs in its own commit, not smuggled into a correctness fix. The
    /// inconsistency with the proxy path is recorded rather than papered over.
    const OFFERED: &'static [&'static str] = &["br", "zstd", "gzip"];

    /// Picks the coding for a response, honouring the client's quality values.
    ///
    /// This used to be `header.contains("gzip")`. Day 26 measured what that
    /// costs against Caddy 2.11.4: a client sending
    /// `Accept-Encoding: gzip;q=0` — an explicit refusal — was answered with a
    /// gzip body, because the refusal still contains the word. `contains` also
    /// matched substrings, so a token merely embedding a coding name selected
    /// it. Both are gone now that whole tokens and their `q` are read.
    fn negotiate_encoding(accept_header: Option<&str>) -> Option<&'static str> {
        pingclair_core::encoding::negotiate(accept_header?, Self::OFFERED)
    }

    /// Compress `input` with a specific, already-negotiated encoding.
    async fn compress_with(input: &[u8], encoding: &str) -> Result<Vec<u8>> {
        use async_compression::tokio::write::{BrotliEncoder, GzipEncoder, ZstdEncoder};
        use tokio::io::AsyncWriteExt;

        let out = match encoding {
            "br" => {
                let mut e = BrotliEncoder::new(Vec::new());
                e.write_all(input).await?;
                e.shutdown().await?;
                e.into_inner()
            }
            "zstd" => {
                let mut e = ZstdEncoder::new(Vec::new());
                e.write_all(input).await?;
                e.shutdown().await?;
                e.into_inner()
            }
            "gzip" => {
                let mut e = GzipEncoder::new(Vec::new());
                e.write_all(input).await?;
                e.shutdown().await?;
                e.into_inner()
            }
            _ => input.to_vec(),
        };
        Ok(out)
    }

    /// Negotiate + compress in one step (used for small, uncached bodies like
    /// directory listings). Returns the body and the chosen encoding, if any.
    async fn compress_content(
        &self,
        input: &[u8],
        accept_header: Option<&str>,
    ) -> Result<(Vec<u8>, Option<String>)> {
        match Self::negotiate_encoding(accept_header) {
            Some(enc) => Ok((
                Self::compress_with(input, enc).await?,
                Some(enc.to_string()),
            )),
            None => Ok((input.to_vec(), None)),
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
mod compress_cache_tests {
    use super::*;

    fn key(path: &str, mtime: u128, enc: &'static str) -> CompressKey {
        CompressKey {
            path: PathBuf::from(path),
            mtime_ns: mtime,
            encoding: enc,
        }
    }

    #[test]
    fn hit_and_miss() {
        let mut c = CompressCache::new(1024);
        let k = key("/a", 1, "gzip");
        assert!(c.get(&k).is_none(), "empty cache must miss");
        c.insert(k.clone(), Arc::new(vec![0u8; 10]));
        assert_eq!(
            c.get(&k).map(|v| v.len()),
            Some(10),
            "must hit after insert"
        );
    }

    #[test]
    fn distinct_encodings_and_mtimes_are_distinct_entries() {
        let mut c = CompressCache::new(1024);
        c.insert(key("/a", 1, "gzip"), Arc::new(vec![1u8; 4]));
        c.insert(key("/a", 1, "br"), Arc::new(vec![2u8; 6]));
        // A newer mtime is a different key — the old compression is stale and
        // must not be served for the new one.
        assert!(
            c.get(&key("/a", 2, "gzip")).is_none(),
            "changed mtime must miss"
        );
        assert_eq!(c.get(&key("/a", 1, "gzip")).map(|v| v[0]), Some(1));
        assert_eq!(c.get(&key("/a", 1, "br")).map(|v| v[0]), Some(2));
    }

    #[test]
    fn evicts_least_recently_used_when_over_budget() {
        let mut c = CompressCache::new(30); // room for ~3x 10-byte entries
        c.insert(key("/a", 1, "gzip"), Arc::new(vec![0u8; 10]));
        c.insert(key("/b", 1, "gzip"), Arc::new(vec![0u8; 10]));
        c.insert(key("/c", 1, "gzip"), Arc::new(vec![0u8; 10]));
        // Touch /a so /b becomes the least-recently-used.
        assert!(c.get(&key("/a", 1, "gzip")).is_some());
        // Insert a 4th entry, forcing one eviction.
        c.insert(key("/d", 1, "gzip"), Arc::new(vec![0u8; 10]));
        assert!(
            c.get(&key("/b", 1, "gzip")).is_none(),
            "LRU entry /b should be evicted"
        );
        assert!(
            c.get(&key("/a", 1, "gzip")).is_some(),
            "recently-touched /a should survive"
        );
        assert!(c.get(&key("/c", 1, "gzip")).is_some());
        assert!(c.get(&key("/d", 1, "gzip")).is_some());
    }

    #[test]
    fn total_bytes_never_exceed_budget() {
        let mut c = CompressCache::new(100);
        for i in 0..50 {
            c.insert(key("/f", i, "gzip"), Arc::new(vec![0u8; 25]));
            assert!(
                c.bytes <= 100,
                "budget exceeded at iteration {i}: {} bytes",
                c.bytes
            );
        }
    }

    #[test]
    fn reinsert_same_key_does_not_double_count_bytes() {
        let mut c = CompressCache::new(1000);
        let k = key("/a", 1, "gzip");
        c.insert(k.clone(), Arc::new(vec![0u8; 10]));
        c.insert(k.clone(), Arc::new(vec![0u8; 40]));
        assert_eq!(c.bytes, 40, "re-insert must replace, not accumulate");
        assert_eq!(c.get(&k).map(|v| v.len()), Some(40));
    }

    #[test]
    fn entry_larger_than_budget_is_not_cached() {
        let mut c = CompressCache::new(100);
        c.insert(key("/big", 1, "gzip"), Arc::new(vec![0u8; 200]));
        assert!(c.get(&key("/big", 1, "gzip")).is_none());
        assert_eq!(c.bytes, 0);
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
mod serve_auto_tests {
    use super::*;

    fn server(root: &std::path::Path, compress: bool) -> FileServer {
        FileServer::new(FileServerConfig {
            root: root.to_path_buf(),
            index: vec![],
            browse: false,
            browse_limit: None,
            compress,
            precompressed: false,
        })
    }

    #[tokio::test]
    async fn large_uncompressed_file_streams_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        // 6MB, well over the streaming threshold; non-repeating so gzip
        // wouldn't trivially shrink it (not used here anyway).
        let body: Vec<u8> = (0..6 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
        tokio::fs::write(dir.path().join("big.bin"), &body)
            .await
            .unwrap();

        let fs = server(dir.path(), false);
        match fs
            .serve_auto("/big.bin", None, None)
            .await
            .unwrap()
            .unwrap()
        {
            ServedResponse::Stream(mut stream) => {
                assert_eq!(stream.file_size, body.len() as u64);
                let mut got = Vec::new();
                while let Some(chunk) = stream.read_chunk().unwrap() {
                    got.extend_from_slice(&chunk);
                }
                assert_eq!(got, body, "streamed bytes must equal the file");
            }
            ServedResponse::Buffered(_) => panic!("6MB uncompressed response must stream"),
            ServedResponse::Redirect(_) => panic!("a regular file must not redirect"),
        }
    }

    #[tokio::test]
    async fn one_mib_file_streams_so_concurrency_cannot_buffer_gibibytes() {
        // 🧠 Regression for the AWS run: with a 5 MiB threshold, 2,000
        // in-flight 1 MiB responses buffered ~2 GiB and OOM-killed the host.
        // A 1 MiB file must now take the streaming path.
        let dir = tempfile::tempdir().unwrap();
        let body = vec![0x5au8; 1024 * 1024];
        tokio::fs::write(dir.path().join("one.bin"), &body)
            .await
            .unwrap();

        let fs = server(dir.path(), false);
        match fs
            .serve_auto("/one.bin", None, None)
            .await
            .unwrap()
            .unwrap()
        {
            ServedResponse::Stream(mut stream) => {
                assert_eq!(stream.file_size, body.len() as u64);
                let mut got = Vec::new();
                while let Some(chunk) = stream.read_chunk().unwrap() {
                    got.extend_from_slice(&chunk);
                }
                assert_eq!(got, body, "streamed bytes must equal the file");
            }
            ServedResponse::Buffered(_) => panic!("1 MiB uncompressed response must stream"),
            ServedResponse::Redirect(_) => panic!("a regular file must not redirect"),
        }
    }

    #[tokio::test]
    async fn large_file_stays_buffered_when_compression_is_negotiated() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("big.txt"), &vec![b'a'; 6 * 1024 * 1024])
            .await
            .unwrap();

        let fs = server(dir.path(), true);
        match fs
            .serve_auto("/big.txt", None, Some("gzip"))
            .await
            .unwrap()
            .unwrap()
        {
            ServedResponse::Buffered(file) => {
                assert_eq!(file.content_encoding.as_deref(), Some("gzip"));
            }
            ServedResponse::Stream(_) => {
                panic!("compressed responses must stay buffered for the cache")
            }
            ServedResponse::Redirect(_) => panic!("a regular file must not redirect"),
        }
    }

    #[tokio::test]
    async fn serve_wrapper_buffers_a_stream_for_compat_callers() {
        let dir = tempfile::tempdir().unwrap();
        let body = vec![b'x'; 6 * 1024 * 1024];
        tokio::fs::write(dir.path().join("big.bin"), &body)
            .await
            .unwrap();

        let fs = server(dir.path(), false);
        let served = fs.serve("/big.bin", None, None).await.unwrap().unwrap();
        assert_eq!(
            served.content, body,
            "serve() must return the full body even for streamed files"
        );
    }
}

#[cfg(test)]
mod stream_decision_tests {
    use super::*;

    fn server(compress: bool) -> FileServer {
        FileServer::new(FileServerConfig {
            compress,
            ..Default::default()
        })
    }

    const BIG: u64 = 6 * 1024 * 1024; // well over the streaming threshold
    const ONE_MIB: u64 = 1024 * 1024; // the OOM regression size from the AWS run
    const THRESHOLD: u64 = 256 * 1024; // exactly at the streaming boundary
    const SMALL: u64 = 1024;

    #[test]
    fn large_plain_response_streams() {
        assert!(server(true).should_stream_response(BIG, None, None));
        assert!(server(false).should_stream_response(BIG, None, None));
        assert!(
            server(false).should_stream_response(ONE_MIB, None, None),
            "1 MiB files must stream so high concurrency cannot buffer GiB"
        );
    }

    #[test]
    fn threshold_boundary_is_strictly_greater() {
        let fs = server(false);
        assert!(!fs.should_stream_response(THRESHOLD, None, None));
        assert!(fs.should_stream_response(THRESHOLD + 1, None, None));
    }

    #[test]
    fn small_range_or_compressed_responses_stay_buffered() {
        let fs = server(true);
        assert!(
            !fs.should_stream_response(SMALL, None, None),
            "below threshold"
        );
        assert!(
            !fs.should_stream_response(BIG, Some("bytes=0-99"), None),
            "range request"
        );
        assert!(
            !fs.should_stream_response(BIG, None, Some("gzip, br")),
            "compression negotiated"
        );
        // Compression disabled in config: nothing to cache, streaming is fine.
        assert!(server(false).should_stream_response(BIG, None, Some("gzip")));
        // Unsupported encodings don't count as negotiated.
        assert!(fs.should_stream_response(BIG, None, Some("identity")));
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

// MARK: - Response metadata cache

/// 🗂️ The per-file response metadata cache: what it must reuse, and what it
/// must never reuse. Every entry keys on path + mtime + size, so the
/// interesting cases are the ones where one of those changes underneath a
/// warm entry.
#[cfg(test)]
mod meta_cache_tests {
    use super::*;

    fn server(root: &std::path::Path) -> FileServer {
        FileServer::new(FileServerConfig {
            root: root.to_path_buf(),
            ..Default::default()
        })
    }

    fn meta_for(fs: &FileServer, path: &std::path::Path) -> Arc<FileMeta> {
        let metadata = std::fs::metadata(path).unwrap();
        fs.file_meta(path, &metadata).unwrap()
    }

    fn header_text(value: &HeaderValue) -> String {
        value.to_str().unwrap().to_string()
    }

    #[test]
    fn a_repeat_request_reuses_the_same_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.txt");
        std::fs::write(&path, b"hello").unwrap();

        let fs = server(dir.path());
        let first = meta_for(&fs, &path);
        let second = meta_for(&fs, &path);

        // 🎯 The point of the cache: the second request must not rebuild the
        // values, so both handles are the same allocation.
        assert!(
            Arc::ptr_eq(&first, &second),
            "an unchanged file must be served from one cached FileMeta"
        );
    }

    #[test]
    fn editing_a_file_invalidates_its_cached_etag_and_last_modified() {
        // 🚨 The correctness property. If the key missed a change, the server
        // would keep answering with the old ETag, and a client holding it
        // would be told 304 Not Modified for content that did change.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.txt");
        std::fs::write(&path, b"first").unwrap();

        let fs = server(dir.path());
        let before = meta_for(&fs, &path);
        let before_etag = header_text(&before.etag);

        // 🕰️ Filesystem timestamps are coarse enough that an immediate
        // rewrite can land on the same mtime; a longer body changes the size
        // too, so the key moves either way.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&path, b"second body, definitely longer").unwrap();

        let after = meta_for(&fs, &path);
        assert_ne!(
            before_etag,
            header_text(&after.etag),
            "an edited file must not keep its old ETag"
        );
        assert_eq!(
            header_text(&after.content_length),
            "30",
            "Content-Length must describe the new body"
        );
    }

    #[test]
    fn two_files_do_not_share_one_entry() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.html");
        std::fs::write(&a, b"aaaa").unwrap();
        std::fs::write(&b, b"bb").unwrap();

        let fs = server(dir.path());
        let meta_a = meta_for(&fs, &a);
        let meta_b = meta_for(&fs, &b);

        assert_ne!(header_text(&meta_a.etag), header_text(&meta_b.etag));
        assert_eq!(header_text(&meta_a.content_length), "4");
        assert_eq!(header_text(&meta_b.content_length), "2");
        // 📄 Content-Type is derived per path, so the extension must survive.
        assert!(
            header_text(&meta_b.content_type).starts_with("text/html"),
            "expected text/html for .html, got {}",
            header_text(&meta_b.content_type)
        );
    }

    #[test]
    fn the_cache_stays_bounded_and_still_answers_correctly_after_eviction() {
        // 🧹 Eviction here is a whole-map `clear()`, not an LRU: once the cap
        // is reached every entry goes. That is a deliberate simplicity
        // trade-off, but it must never turn into a wrong answer — a request
        // arriving right after a wipe has to rebuild, not serve nothing.
        let dir = tempfile::tempdir().unwrap();
        let fs = server(dir.path());

        let mut paths = Vec::new();
        for index in 0..(FileServer::META_CACHE_CAP + 8) {
            let path = dir.path().join(format!("f{index}.txt"));
            std::fs::write(&path, format!("body-{index}")).unwrap();
            let _ = meta_for(&fs, &path);
            paths.push(path);
        }

        assert!(
            fs.meta_cache.load().len() <= FileServer::META_CACHE_CAP,
            "the cache grew past its cap: {}",
            fs.meta_cache.load().len()
        );

        // 🔁 Every file must still resolve to metadata that matches the file
        // on disk, whether or not its entry survived the wipe.
        for (index, path) in paths.iter().enumerate() {
            let expected = format!("body-{index}").len().to_string();
            assert_eq!(
                header_text(&meta_for(&fs, path).content_length),
                expected,
                "{path:?} reported the wrong length after eviction"
            );
        }
    }

    #[test]
    fn a_rebuilt_entry_matches_what_the_cache_would_have_returned() {
        // 🧭 The uncached path (a file whose mtime cannot be read) must not be
        // a different answer, only a slower one. `build_meta` is what that
        // path calls, so it has to agree with a cache hit.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.json");
        std::fs::write(&path, b"{}").unwrap();

        let fs = server(dir.path());
        let metadata = std::fs::metadata(&path).unwrap();
        let cached = meta_for(&fs, &path);
        let rebuilt = FileServer::build_meta(&path, &metadata, metadata.len());

        assert_eq!(header_text(&cached.etag), header_text(&rebuilt.etag));
        assert_eq!(
            header_text(&cached.content_type),
            header_text(&rebuilt.content_type)
        );
        assert_eq!(
            header_text(&cached.content_length),
            header_text(&rebuilt.content_length)
        );
        assert_eq!(
            cached.last_modified.as_ref().map(header_text),
            rebuilt.last_modified.as_ref().map(header_text)
        );
    }
}
