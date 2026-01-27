//! File server implementation

use std::path::PathBuf;
use pingclair_core::error::Result;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

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

impl FileServer {
    /// Create a new file server
    pub fn new(config: FileServerConfig) -> Self {
        Self { config }
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
        
        // Read file content (partial or full)
        let mut file = tokio::fs::File::open(&file_path).await?;
        
        if start > 0 {
            file.seek(std::io::SeekFrom::Start(start)).await?;
        }
        
        let mut content = vec![0u8; length as usize];
        file.read_exact(&mut content).await?;

        // Guess MIME type
        let mime_type = mime_guess::from_path(&file_path)
            .first_or_octet_stream()
            .to_string();

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

        // Fall back to on-the-fly compression if:
        // 1. Configured
        // 2. Not a range request (partial content compression is complex)
        // 3. Client supports it
        // 4. No pre-compressed file was found
        let (content, content_encoding) = if self.config.compress && status == 200 {
            self.compress_content(&content, accept_encoding).await?
        } else {
            (content, None)
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

    async fn compress_content(&self, input: &[u8], accept_header: Option<&str>) -> Result<(Vec<u8>, Option<String>)> {
        use async_compression::tokio::write::{GzipEncoder, BrotliEncoder, ZstdEncoder};
        use tokio::io::AsyncWriteExt;

        let header = match accept_header {
            Some(h) => h,
            None => return Ok((input.to_vec(), None)),
        };

        // Poor man's content negotiation (prio: br > zstd > gzip)
        if header.contains("br") {
            let mut encoder = BrotliEncoder::new(Vec::new());
            encoder.write_all(input).await?;
            encoder.shutdown().await?;
            Ok((encoder.into_inner(), Some("br".to_string())))
        } else if header.contains("zstd") {
            let mut encoder = ZstdEncoder::new(Vec::new());
            encoder.write_all(input).await?;
            encoder.shutdown().await?;
            Ok((encoder.into_inner(), Some("zstd".to_string())))
        } else if header.contains("gzip") {
            let mut encoder = GzipEncoder::new(Vec::new());
            encoder.write_all(input).await?;
            encoder.shutdown().await?;
            Ok((encoder.into_inner(), Some("gzip".to_string())))
        } else {
            Ok((input.to_vec(), None))
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
