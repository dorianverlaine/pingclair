// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌊 The chunked response: its type, its threshold, and the decision to use it.
//!
//! A buffered response holds the whole body in memory before writing a byte of
//! it. That is the right trade for a small file and a catastrophic one for a
//! large file under load — 2,000 concurrent 1 MiB responses is ~2 GiB of
//! resident memory, which is how a t3.small was OOM-killed in the August 2026
//! AWS run. Above [`FileServer::STREAMING_THRESHOLD`] the body is instead read
//! and written in 64 KiB chunks, so per-request memory stops depending on file
//! size.
//!
//! The decision is deliberately split into a cheap I/O-free predicate and the
//! open itself, because the common case is discovering that streaming does
//! *not* apply — every compressed response takes that path — and finding that
//! out should not cost a stat.

use pingclair_core::error::Result;
use std::io::Read as _;
use std::path::PathBuf;

use http::HeaderValue;

use super::FileServer;
#[cfg(test)]
use super::{FileServerConfig, ServedResponse};

// MARK: - The streaming response

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

// MARK: - Deciding to stream

impl FileServer {
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
    pub(super) fn open_stream(
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
            ..FileServerConfig::default()
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
            .serve_auto("/big.bin", "/big.bin", None, None)
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
            .serve_auto("/one.bin", "/one.bin", None, None)
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
            .serve_auto("/big.txt", "/big.txt", None, Some("gzip"))
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
