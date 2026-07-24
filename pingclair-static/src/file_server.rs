//! File server implementation

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;
use pingclair_core::error::Result;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

/// Key for a cached compressed response: a file identity (path + mtime) plus
/// the content encoding. mtime is part of the key so editing a file naturally
/// invalidates its stale cached compression instead of serving old bytes.
#[derive(Clone, PartialEq, Eq, Hash)]
struct CompressKey {
    path: PathBuf,
    mtime_ns: u128,
    encoding: &'static str,
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
        Self { entries: HashMap::new(), lru: VecDeque::new(), bytes: 0, budget }
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
            compress: true,
            precompressed: true,  // Default to checking for pre-compressed files
        }
    }
}

/// Static file server
pub struct FileServer {
    config: FileServerConfig,
    /// Cache of already-compressed file bodies (see [`CompressCache`]).
    /// Behind a `Mutex` because `FileServer` is shared (`Arc`) across all
    /// worker threads; the lock is only ever held for a tiny map operation,
    /// never across an `.await`.
    compress_cache: Mutex<CompressCache>,
}

/// Response from file server
pub struct ServedFile {
    pub content: Vec<u8>,
    pub mime_type: String,
    pub path: PathBuf,
    pub status: u16,
    pub content_range: Option<String>,
    pub last_modified: Option<String>,
    pub etag: Option<String>,
    pub content_encoding: Option<String>,
}

/// Streaming file response for zero-copy large file transfer
/// Use this for files larger than 5MB to avoid memory pressure
pub struct StreamingFile {
    /// Tokio file handle for async reading
    pub file: tokio::fs::File,
    /// Total file size in bytes
    pub file_size: u64,
    /// Chunk size for streaming (default 64KB)
    pub chunk_size: usize,
    /// MIME type of the file
    pub mime_type: String,
    /// Path to the file
    pub path: PathBuf,
    /// Last-Modified header value
    pub last_modified: Option<String>,
    /// ETag header value
    pub etag: Option<String>,
    /// Bytes read so far
    bytes_read: u64,
}

impl StreamingFile {
    /// Read the next chunk of data
    /// Returns None when EOF is reached
    pub async fn read_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        if self.bytes_read >= self.file_size {
            return Ok(None);
        }
        
        let remaining = (self.file_size - self.bytes_read) as usize;
        let to_read = remaining.min(self.chunk_size);
        
        let mut buf = vec![0u8; to_read];
        let n = self.file.read(&mut buf).await?;
        
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
            compress_cache: Mutex::new(CompressCache::new(Self::COMPRESS_CACHE_BUDGET)),
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
    
    /// THRESHOLD for using streaming vs in-memory (5MB)
    const STREAMING_THRESHOLD: u64 = 5 * 1024 * 1024;
    
    /// Serve a large file using zero-copy streaming
    /// Returns a StreamingFile that can be used for chunked transfer
    /// Use this for files larger than 5MB to avoid memory pressure
    pub async fn serve_streaming(&self, path: &str) -> Result<Option<StreamingFile>> {
        let file_path = self.config.root.join(path.trim_start_matches('/'));
        
        // Prevent path traversal
        if !file_path.starts_with(&self.config.root) {
            return Ok(None);
        }
        
        // Check if file exists
        let metadata = match tokio::fs::metadata(&file_path).await {
            Ok(m) if m.is_file() => m,
            _ => return Ok(None),
        };
        
        let file_size = metadata.len();
        
        // Open file handle (no reading yet - zero-copy preparation)
        let file = tokio::fs::File::open(&file_path).await?;
        
        // Guess MIME type
        let mime_type = mime_guess::from_path(&file_path)
            .first_or_octet_stream()
            .to_string();
        
        // Calculate Last-Modified and ETag
        let last_modified = metadata.modified().ok()
            .map(|t| httpdate::fmt_http_date(t));
            
        let etag = format!("\"{:x}-{:x}\"", file_size, 
            metadata.modified().map(|t| t.elapsed().unwrap_or_default().as_secs()).unwrap_or(0));
        
        Ok(Some(StreamingFile {
            file,
            file_size,
            chunk_size: 64 * 1024,  // 64KB chunks
            mime_type,
            path: file_path,
            last_modified,
            etag: Some(etag),
            bytes_read: 0,
        }))
    }
    
    /// Check if a file should be served with streaming (based on size)
    pub async fn should_stream(&self, path: &str) -> Result<bool> {
        let file_path = self.config.root.join(path.trim_start_matches('/'));
        match tokio::fs::metadata(&file_path).await {
            Ok(m) => Ok(m.len() > Self::STREAMING_THRESHOLD),
            Err(_) => Ok(false),
        }
    }


    /// Serve a file request
    pub async fn serve(&self, path: &str, range_header: Option<&str>, accept_encoding: Option<&str>) -> Result<Option<ServedFile>> {
        let mut file_path = self.config.root.join(path.trim_start_matches('/'));
        
        // Prevent path traversal
        if !file_path.starts_with(&self.config.root) {
            return Ok(None);
        }

        tracing::debug!("📁 Serving request: {} -> {:?}", path, file_path);
        
        // Check if metadata exists
        let metadata = match tokio::fs::metadata(&file_path).await {
            Ok(m) => m,
            Err(_) => return Ok(None),
        };

        // Handle directory
        if metadata.is_dir() {
            // Try index files
            let mut index_found = false;
            for index in &self.config.index {
                let index_path = file_path.join(index);
                if tokio::fs::try_exists(&index_path).await.unwrap_or(false) {
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
                        self.compress_content(listing.as_bytes(), accept_encoding).await?
                    } else {
                        (listing.into_bytes(), None)
                    };

                    return Ok(Some(ServedFile {
                        content,
                        mime_type: "text/html; charset=utf-8".to_string(),
                        path: file_path,
                        status: 200,
                        content_range: None,
                        last_modified: None,
                        etag: None,
                        content_encoding: encoding,
                    }));
                } else {
                    return Ok(None);
                }
            }
        }

        // Get updated metadata for file (size, modified)
        let metadata = match tokio::fs::metadata(&file_path).await {
            Ok(m) => m,
            Err(_) => return Ok(None),
        };
        let file_size = metadata.len();
        
        // Calculate Last-Modified and ETag
        let last_modified = metadata.modified().ok()
            .map(|t| httpdate::fmt_http_date(t));
            
        let etag = format!("\"{:x}-{:x}\"", file_size, 
            metadata.modified().map(|t| t.elapsed().unwrap_or_default().as_secs()).unwrap_or(0));

        // Handle Range Request
        let mut status = 200;
        let mut content_range = None;
        let mut start = 0;
        let mut length = file_size;

        if let Some(range) = range_header {
            if let Some((s, e)) = self.parse_range(range, file_size) {
                start = s;
                length = e - s + 1;
                status = 206;
                content_range = Some(format!("bytes {}-{}/{}", s, e, file_size));
            }
        }
        
        // MIME type is path-based (no I/O) and needed by both the cache fast
        // path and every response below — compute it once, up front.
        let mime_type = mime_guess::from_path(&file_path)
            .first_or_octet_stream()
            .to_string();

        // Cache-key ingredients. Only full-file (200, non-range) responses
        // with compression enabled are cacheable; the negotiated encoding and
        // the file mtime (so an edit invalidates the stale entry) form the key.
        let cache_encoding = if self.config.compress && status == 200 {
            Self::negotiate_encoding(accept_encoding)
        } else {
            None
        };
        let mtime_ns = metadata.modified().ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_nanos());

        // Cache fast path: a hit returns the already-compressed body without
        // reading the file from disk or re-compressing it at all. This is the
        // whole point of the cache — a hot compressible file is compressed
        // once, then served from memory.
        if let (Some(enc), Some(mtime_ns)) = (cache_encoding, mtime_ns) {
            let key = CompressKey { path: file_path.clone(), mtime_ns, encoding: enc };
            if let Some(cached) = self.compress_cache.lock().unwrap().get(&key) {
                tracing::debug!("✅ Serving cached {} compression: {}", enc, file_path.display());
                return Ok(Some(ServedFile {
                    content: (*cached).clone(),
                    mime_type,
                    path: file_path,
                    status,
                    content_range,
                    last_modified,
                    etag: Some(etag),
                    content_encoding: Some(enc.to_string()),
                }));
            }
        }

        // Read file content (partial or full)
        let mut file = tokio::fs::File::open(&file_path).await?;

        if start > 0 {
            file.seek(std::io::SeekFrom::Start(start)).await?;
        }

        let mut content = vec![0u8; length as usize];
        file.read_exact(&mut content).await?;

        // Check for pre-compressed files first (much faster than on-the-fly compression)
        // Only for complete (non-range) requests
        if self.config.precompressed && status == 200 {
            if let Some((precompressed_content, encoding)) = self.try_precompressed(&file_path, accept_encoding).await {
                tracing::debug!("✅ Using pre-compressed file: {} ({})", file_path.display(), encoding);
                return Ok(Some(ServedFile {
                    content: precompressed_content,
                    mime_type,
                    path: file_path,
                    status,
                    content_range,
                    last_modified,
                    etag: Some(etag),
                    content_encoding: Some(encoding.to_string()),
                }));
            }
        }

        // Fall back to on-the-fly compression when the client accepts an
        // encoding. When we compress, store the result so subsequent requests
        // for the same (path, mtime, encoding) hit the fast path above and
        // skip the read+compress entirely. We still compress even if the file
        // has no usable mtime — we just can't safely cache that result.
        let (content, content_encoding) = match cache_encoding {
            Some(enc) => {
                let compressed = Arc::new(Self::compress_with(&content, enc).await?);
                if let Some(mtime_ns) = mtime_ns {
                    let key = CompressKey { path: file_path.clone(), mtime_ns, encoding: enc };
                    self.compress_cache.lock().unwrap().insert(key, compressed.clone());
                }
                ((*compressed).clone(), Some(enc.to_string()))
            }
            None => (content, None),
        };

        Ok(Some(ServedFile {
            content,
            mime_type,
            path: file_path,
            status,
            content_range,
            last_modified,
            etag: Some(etag),
            content_encoding,
        }))
    }

    /// Try to find and load a pre-compressed version of the file
    /// Checks for .br, .gz, .zst files in order of preference based on Accept-Encoding
    async fn try_precompressed(&self, original_path: &std::path::Path, accept_encoding: Option<&str>) -> Option<(Vec<u8>, &'static str)> {
        let accept = accept_encoding?;
        
        // Priority order based on compression ratio and modern support:
        // 1. Brotli (.br) - best for web
        // 2. Zstd (.zst) - fastest decompression
        // 3. Gzip (.gz) - widest support
        let candidates: Vec<(&'static str, &'static str)> = vec![
            ("br", ".br"),
            ("zstd", ".zst"),
            ("gzip", ".gz"),
        ];
        
        for (encoding, ext) in candidates {
            if !accept.contains(encoding) {
                continue;
            }
            
            // Build precompressed path
            let mut precompressed_path = original_path.as_os_str().to_owned();
            precompressed_path.push(ext);
            let precompressed_path = std::path::PathBuf::from(precompressed_path);
            
            // Check if pre-compressed file exists and is readable
            if let Ok(content) = tokio::fs::read(&precompressed_path).await {
                return Some((content, encoding));
            }
        }
        
        None
    }

    /// Pick a content encoding from an `Accept-Encoding` header.
    /// Priority: br > zstd > gzip. Returns `None` if the client accepts none
    /// of them (or sent no header), meaning "serve uncompressed".
    fn negotiate_encoding(accept_header: Option<&str>) -> Option<&'static str> {
        let header = accept_header?;
        if header.contains("br") {
            Some("br")
        } else if header.contains("zstd") {
            Some("zstd")
        } else if header.contains("gzip") {
            Some("gzip")
        } else {
            None
        }
    }

    /// Compress `input` with a specific, already-negotiated encoding.
    async fn compress_with(input: &[u8], encoding: &str) -> Result<Vec<u8>> {
        use async_compression::tokio::write::{GzipEncoder, BrotliEncoder, ZstdEncoder};
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
    async fn compress_content(&self, input: &[u8], accept_header: Option<&str>) -> Result<(Vec<u8>, Option<String>)> {
        match Self::negotiate_encoding(accept_header) {
            Some(enc) => Ok((Self::compress_with(input, enc).await?, Some(enc.to_string()))),
            None => Ok((input.to_vec(), None)),
        }
    }
    
    /// Generate HTML directory listing
    async fn generate_listing(&self, dir_path: &std::path::Path, req_path: &str) -> Result<String> {
        let mut entries = tokio::fs::read_dir(dir_path).await?;
        let mut html = format!(
            "<html><head><title>Index of {}</title></head><body><h1>Index of {}</h1><hr><pre>",
            req_path, req_path
        );
        
        // Parent link
        if req_path != "/" {
             html.push_str("<a href=\"..\">../</a>\n");
        }
        
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let is_dir = entry.file_type().await?.is_dir();
            let display_name = if is_dir { format!("{}/", name_str) } else { name_str.to_string() };
            
            html.push_str(&format!("<a href=\"{}\">{}</a>\n", display_name, display_name));
        }
        
        html.push_str("</pre><hr></body></html>");
        Ok(html)
    }
    
    /// Parse Range header (bytes=start-end)
    fn parse_range(&self, header: &str, file_size: u64) -> Option<(u64, u64)> {
        if !header.starts_with("bytes=") { return None; }
        let val = &header[6..];
        let parts: Vec<&str> = val.split('-').collect();
        if parts.len() != 2 { return None; }
        
        let start_str = parts[0];
        let end_str = parts[1];
        
        let start = start_str.parse::<u64>().ok().unwrap_or(0);
        let end = if end_str.is_empty() {
            file_size - 1
        } else {
            end_str.parse::<u64>().ok().unwrap_or(file_size - 1)
        };
        
        if start > end || start >= file_size { return None; }
        
        Some((start, std::cmp::min(end, file_size - 1)))
    }
}

#[cfg(test)]
mod compress_cache_tests {
    use super::*;

    fn key(path: &str, mtime: u128, enc: &'static str) -> CompressKey {
        CompressKey { path: PathBuf::from(path), mtime_ns: mtime, encoding: enc }
    }

    #[test]
    fn hit_and_miss() {
        let mut c = CompressCache::new(1024);
        let k = key("/a", 1, "gzip");
        assert!(c.get(&k).is_none(), "empty cache must miss");
        c.insert(k.clone(), Arc::new(vec![0u8; 10]));
        assert_eq!(c.get(&k).map(|v| v.len()), Some(10), "must hit after insert");
    }

    #[test]
    fn distinct_encodings_and_mtimes_are_distinct_entries() {
        let mut c = CompressCache::new(1024);
        c.insert(key("/a", 1, "gzip"), Arc::new(vec![1u8; 4]));
        c.insert(key("/a", 1, "br"), Arc::new(vec![2u8; 6]));
        // A newer mtime is a different key — the old compression is stale and
        // must not be served for the new one.
        assert!(c.get(&key("/a", 2, "gzip")).is_none(), "changed mtime must miss");
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
        assert!(c.get(&key("/b", 1, "gzip")).is_none(), "LRU entry /b should be evicted");
        assert!(c.get(&key("/a", 1, "gzip")).is_some(), "recently-touched /a should survive");
        assert!(c.get(&key("/c", 1, "gzip")).is_some());
        assert!(c.get(&key("/d", 1, "gzip")).is_some());
    }

    #[test]
    fn total_bytes_never_exceed_budget() {
        let mut c = CompressCache::new(100);
        for i in 0..50 {
            c.insert(key("/f", i, "gzip"), Arc::new(vec![0u8; 25]));
            assert!(c.bytes <= 100, "budget exceeded at iteration {i}: {} bytes", c.bytes);
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
            compress: true,
            precompressed: false, // force the on-the-fly path we're testing
        });

        // First request: cache miss, compresses and stores.
        let first = fs.serve("/big.txt", None, Some("gzip")).await.unwrap().unwrap();
        assert_eq!(first.content_encoding.as_deref(), Some("gzip"));
        assert!(first.content.len() < body.len(), "should be compressed");
        assert_eq!(fs.compress_cache.lock().unwrap().entries.len(), 1, "first request should populate the cache");

        // Second request: must hit the cache and return byte-identical output.
        let second = fs.serve("/big.txt", None, Some("gzip")).await.unwrap().unwrap();
        assert_eq!(second.content, first.content, "cached body must match freshly compressed body");

        // And the cached bytes must be valid gzip that round-trips.
        let mut d = flate2::read::GzDecoder::new(&second.content[..]);
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut d, &mut out).unwrap();
        assert_eq!(out, body, "cached gzip must decompress to the original file");
    }

    #[tokio::test]
    async fn editing_the_file_invalidates_the_cached_compression() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_file(dir.path(), "f.txt", &vec![b'a'; 4096]).await;

        let fs = FileServer::new(FileServerConfig {
            root: dir.path().to_path_buf(),
            index: vec![],
            browse: false,
            compress: true,
            precompressed: false,
        });

        let first = fs.serve("/f.txt", None, Some("gzip")).await.unwrap().unwrap();
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

        let second = fs.serve("/f.txt", None, Some("gzip")).await.unwrap().unwrap();
        let mut d2 = flate2::read::GzDecoder::new(&second.content[..]);
        let mut out2 = Vec::new();
        std::io::Read::read_to_end(&mut d2, &mut out2).unwrap();
        assert_eq!(out2, vec![b'z'; 8192], "must serve the NEW content, not the stale cached compression");
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
}
