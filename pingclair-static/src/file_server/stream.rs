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

/// 🌊 A response body read from disk in chunks rather than held in memory.
///
/// Carries a *window* of the file, not necessarily all of it: a `Range` request
/// streams `body_len` bytes from an offset, and the file handle has already been
/// seeked there. That is why the size field is called `body_len` and not
/// `file_size` — it is how many bytes this response sends, which for a complete
/// response happens to equal the file size and for a partial one does not.
///
/// It also carries the response metadata a partial or pre-compressed body needs
/// (`status`, `content_range`, `content_encoding`), because otherwise every
/// transport would have to reconstruct it and the two transports would drift.
pub struct StreamingFile {
    /// Synchronous file handle. Synchronous I/O is intentional: reads of
    /// local regular files effectively never block (a page-cache hit is
    /// microseconds), which is why nginx reads/sends files directly on its
    /// event-loop threads. Routing every read through `tokio::fs` costs a
    /// `spawn_blocking` cross-thread round trip per chunk — several per
    /// request on this hot path.
    pub file: std::fs::File,
    /// 🪟 Bytes this response body carries — the window, not the file.
    pub body_len: u64,
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
    /// 🔢 The status this body answers with: 200, 206 for a range, or a
    /// configured override such as the 503 a maintenance tree serves.
    pub status: u16,
    /// 🪟 `Content-Range`, present exactly when this is a partial response.
    pub content_range: Option<HeaderValue>,
    /// 🗜️ `Content-Encoding`, present when the bytes on disk are already
    /// compressed — a `.br`/`.gz`/`.zst` sidecar streamed as-is.
    pub content_encoding: Option<HeaderValue>,
    /// 🧊 See [`ServedFile::vary_accept_encoding`]. A streamed response is
    /// usually the uncompressed variant of a compressible resource, which is
    /// exactly the case that used to reach a shared cache with no `Vary`.
    pub vary_accept_encoding: bool,
    /// Bytes read so far
    bytes_read: u64,
}

impl StreamingFile {
    /// Read the next chunk of data (synchronous — see the `file` field for
    /// why blocking I/O is deliberate here).
    /// Returns None when the window has been sent.
    pub fn read_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        if self.bytes_read >= self.body_len {
            return Ok(None);
        }

        // 🪟 Bounded by what is left of the *window*, so a range response stops
        // at its end instead of running on to the end of the file.
        let remaining = (self.body_len - self.bytes_read) as usize;
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
        if self.body_len == 0 {
            1.0
        } else {
            self.bytes_read as f64 / self.body_len as f64
        }
    }

    /// Check if streaming is complete
    pub fn is_complete(&self) -> bool {
        self.bytes_read >= self.body_len
    }

    /// Get Content-Length header value
    pub fn content_length(&self) -> u64 {
        self.body_len
    }
}

/// 🪟 Which bytes of a file a stream should send, and how to describe them.
///
/// Exists so `open_stream_window` does not grow five positional arguments that
/// a caller can transpose. A complete, uncompressed 200 is
/// [`StreamWindow::whole_file`]; everything else says explicitly what it is.
pub(super) struct StreamWindow {
    /// 📍 Byte offset to seek to before the first read.
    pub start: u64,
    /// 📏 Bytes to send, or `None` for "to the end of the file".
    pub length: Option<u64>,
    /// 🔢 The status this body answers with.
    pub status: u16,
    /// 🪟 `Content-Range`, for a partial response.
    pub content_range: Option<HeaderValue>,
    /// 🗜️ `Content-Encoding`, when the bytes on disk are already compressed.
    pub content_encoding: Option<HeaderValue>,
}

impl StreamWindow {
    /// 📄 The whole file, uncompressed, answered 200.
    pub(super) fn whole_file() -> Self {
        Self {
            start: 0,
            length: None,
            status: 200,
            content_range: None,
            content_encoding: None,
        }
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
    pub(super) const STREAMING_THRESHOLD: u64 = 256 * 1024;

    /// 🗜️ Largest file this server will compress on the fly.
    ///
    /// Dynamic compression needs the whole body in memory — the compressor is
    /// fed a slice and returns a `Vec`, and the compressed-body cache wants a
    /// complete buffer to store. So the cost of compressing is proportional to
    /// the file, and until this bound existed it was proportional to the
    /// *largest file in the document root*, chosen by whichever client sent
    /// `Accept-Encoding: gzip`.
    ///
    /// 8 MiB, and deliberately below the 64 MiB compressed-body cache budget:
    /// the budget decided what to *keep* after the allocation had already
    /// happened, which is the wrong end of the decision. Above this bound the
    /// response streams uncompressed instead — worse on the wire, bounded in
    /// memory, and the kind of file (an archive, a video, an image) that
    /// compresses to about its own size anyway.
    ///
    /// 📌 A ceiling rather than streaming compression on purpose. Streaming
    /// compression would keep the encoding *and* the bound, but it means a
    /// compressor per in-flight response and a body whose length is unknown
    /// until it ends — a different design for the cache and the framing both.
    /// This is the conservative half of the fix; the other half is worth doing
    /// on its own terms, not smuggled in here.
    const MAX_COMPRESSIBLE: u64 = 8 * 1024 * 1024;

    /// 🗜️ The floor below which compressing is pure loss.
    ///
    /// 🤡 There was none, and every browser sends `Accept-Encoding`. Measured on
    /// 2026-08-11 against the real binary: an 80-byte JSON came back
    /// `Content-Encoding: gzip` with `Content-Length: 97` — **21% larger than the
    /// file**, having spent CPU to get there. Below the size where compression
    /// can win it loses on both axes at once.
    ///
    /// 512 bytes, matching upstream's `encode` `minimum_length`, which is the
    /// directive that does this job there. nginx uses 20 for `gzip_min_length`,
    /// but only ever with gzip explicitly turned on; 512 is the more careful of
    /// the two and this path is on by default.
    const MIN_COMPRESSIBLE: u64 = 512;

    /// 🗜️ Whether this response would be compressed on the fly.
    ///
    /// Reads the negotiation without doing I/O, so a caller can find out
    /// before deciding whether streaming is available.
    pub(super) fn would_compress(&self, file_size: u64, accept_encoding: Option<&str>) -> bool {
        self.config.compress
            && (Self::MIN_COMPRESSIBLE..=Self::MAX_COMPRESSIBLE).contains(&file_size)
            && Self::negotiate_encoding(accept_encoding).is_some()
    }

    /// Cheap pre-check for the streaming path, without any I/O.
    ///
    /// 🪟 A `Range` no longer disqualifies a response: the stream carries a
    /// window, so a partial response streams from an offset like any other. The
    /// one thing that still does is on-the-fly compression, because the
    /// compressor needs the whole body — and a file too large to compress is one
    /// this returns `true` for, which is the point.
    pub fn could_stream(&self, _range: Option<&str>, accept_encoding: Option<&str>) -> bool {
        // 📏 No size here, so assume the file is small enough to compress: this
        // predicate exists to answer "is streaming *impossible*", and a caller
        // with a size uses `should_stream_response` instead.
        !(self.config.compress && Self::negotiate_encoding(accept_encoding).is_some())
    }

    /// 🧭 Whether a response of `body_len` bytes should be streamed rather than
    /// buffered.
    ///
    /// `body_len` is the size of the body being sent — the range length for a
    /// partial response, the file size for a complete one — because that is what
    /// the memory cost is proportional to. Passing the file size for a range
    /// would stream a one-byte range out of a large file, which is the opposite
    /// of the intended trade.
    pub fn should_stream_response(
        &self,
        body_len: u64,
        file_size: u64,
        accept_encoding: Option<&str>,
    ) -> bool {
        !self.would_compress(file_size, accept_encoding) && body_len > Self::STREAMING_THRESHOLD
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
        Self::open_stream_window(server, file_path, metadata, StreamWindow::whole_file())
    }

    /// 🪟 Opens a stream over part of a file, with the response metadata that
    /// part needs.
    ///
    /// The window is what makes a `Range` streamable at all. Before this, any
    /// `Range` header disabled streaming outright, so `Range: bytes=0-` on a
    /// two-gigabyte file allocated two gigabytes — the request that costs the
    /// most was the one guaranteed to be buffered. Seeking once and bounding
    /// the reads costs one `lseek` and makes per-request memory the chunk size
    /// again, whatever the client asked for.
    pub(super) fn open_stream_window(
        server: &FileServer,
        file_path: PathBuf,
        metadata: &std::fs::Metadata,
        window: StreamWindow,
    ) -> Result<StreamingFile> {
        let body_len = window.length.unwrap_or(metadata.len());

        // Open file handle (no reading yet - zero-copy preparation)
        let mut file = std::fs::File::open(&file_path)?;
        if window.start > 0 {
            use std::io::Seek as _;
            file.seek(std::io::SeekFrom::Start(window.start))?;
        }
        let meta = server.file_meta(&file_path, metadata)?;

        Ok(StreamingFile {
            file,
            body_len,
            chunk_size: 64 * 1024, // 64KB chunks
            content_type: meta.content_type.clone(),
            // 🔢 The window's length, not the file's: `Content-Length` describes
            // the body being sent, and a range response that advertised the whole
            // file would hang the client waiting for bytes that never come.
            content_length: match window.length {
                Some(length) => HeaderValue::from(length),
                None => meta.content_length.clone(),
            },
            path: file_path,
            last_modified: meta.last_modified.clone(),
            etag: Some(meta.etag.clone()),
            status: window.status,
            content_range: window.content_range,
            content_encoding: window.content_encoding,
            vary_accept_encoding: server.config.varies_by_accept_encoding(),
            bytes_read: 0,
        })
    }

    /// 📏 Reports whether a request path names a file big enough to stream.
    ///
    /// 🛡️ Goes through `resolve_path` like every other entry point, so a
    /// `..` in the request cannot reach outside the document root. It used to
    /// join the path onto `config.root` directly — no caller in this
    /// workspace reached it, but it is a `pub` method on a `pub` type, which
    /// makes it reachable API and a trap for whoever wires up the next
    /// caller. A path outside the root now answers `false`, the same as a
    /// path that does not exist.
    pub async fn should_stream(&self, path: &str) -> Result<bool> {
        let Some(file_path) = self.resolve_path(path) else {
            return Ok(false);
        };
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
                assert_eq!(stream.body_len, body.len() as u64);
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
                assert_eq!(stream.body_len, body.len() as u64);
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
        assert!(server(true).should_stream_response(BIG, BIG, None));
        assert!(server(false).should_stream_response(BIG, BIG, None));
        assert!(
            server(false).should_stream_response(ONE_MIB, ONE_MIB, None),
            "1 MiB files must stream so high concurrency cannot buffer GiB"
        );
    }

    #[test]
    fn threshold_boundary_is_strictly_greater() {
        let fs = server(false);
        assert!(!fs.should_stream_response(THRESHOLD, THRESHOLD, None));
        assert!(fs.should_stream_response(THRESHOLD + 1, THRESHOLD + 1, None));
    }

    #[test]
    fn small_or_compressed_responses_stay_buffered() {
        let fs = server(true);
        assert!(
            !fs.should_stream_response(SMALL, SMALL, None),
            "below threshold"
        );
        assert!(
            !fs.should_stream_response(BIG, BIG, Some("gzip, br")),
            "compression negotiated"
        );
        // Compression disabled in config: nothing to cache, streaming is fine.
        assert!(server(false).should_stream_response(BIG, BIG, Some("gzip")));
        // Unsupported encodings don't count as negotiated.
        assert!(fs.should_stream_response(BIG, BIG, Some("identity")));
    }

    /// 🪟 A range decides on the size of the *range*, not of the file.
    ///
    /// Both directions matter. A large range out of a large file must stream —
    /// that is the case that used to allocate the whole window and is the reason
    /// `Range: bytes=0-` on a big file was the most expensive request this server
    /// could be asked for. A one-byte range out of the same file must not, because
    /// streaming a byte is pure overhead.
    #[test]
    fn a_range_is_judged_by_its_own_length() {
        let fs = server(true);
        assert!(
            fs.should_stream_response(BIG, BIG, Some("bytes=0-")),
            "a whole-file range must stream rather than allocate the file"
        );
        assert!(
            !fs.should_stream_response(SMALL, BIG, None),
            "a small range out of a large file has nothing to gain from streaming"
        );
    }

    /// 🗜️ A file too large to compress streams uncompressed instead of being
    /// buffered and compressed.
    ///
    /// This is the third of the buffering paths. Dynamic compression needs the
    /// whole body in memory, so its cost was proportional to the largest file in
    /// the document root — chosen by whichever client sent `Accept-Encoding`.
    /// Above the bound the answer is a bounded stream, which is also the right
    /// answer for the kind of file that is that large.
    #[test]
    fn a_file_too_large_to_compress_streams_instead() {
        let fs = server(true);
        const HUGE: u64 = 64 * 1024 * 1024;
        assert!(
            fs.should_stream_response(HUGE, HUGE, Some("gzip")),
            "a file past the compressible bound must stream, not buffer and compress"
        );
        // 🧭 And one inside the bound still compresses, so the assertion above is
        // about the size and not about compression having been switched off.
        const COMPRESSIBLE: u64 = 4 * 1024 * 1024;
        assert!(!fs.should_stream_response(COMPRESSIBLE, COMPRESSIBLE, Some("gzip")));
    }
}

#[cfg(test)]
mod should_stream_tests {
    use super::*;

    /// 🛡️ `should_stream` goes through the docroot check like everything else.
    ///
    /// It used to join the request path onto the root directly. No caller in
    /// this workspace reached it, but it is `pub` on a `pub` type — a trap for
    /// whoever wires up the next one.
    #[tokio::test]
    async fn should_stream_refuses_a_path_outside_the_document_root() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("root");
        std::fs::create_dir(&root).unwrap();
        // 📦 Large enough that a positive answer would be about the size
        // check rather than about the file merely existing.
        std::fs::write(base.path().join("secret.bin"), vec![0u8; 2 * 1024 * 1024]).unwrap();
        std::fs::write(root.join("public.bin"), vec![0u8; 2 * 1024 * 1024]).unwrap();

        let fs = FileServer::new(FileServerConfig {
            root: root.clone(),
            ..FileServerConfig::default()
        });

        assert!(
            fs.should_stream("/public.bin").await.unwrap(),
            "a large file inside the root must stream, or the control below proves nothing"
        );
        assert!(
            !fs.should_stream("/../secret.bin").await.unwrap(),
            "a traversal reached outside the document root"
        );
    }
}

#[cfg(test)]
mod bounded_memory_tests {
    use super::*;
    use std::io::Write as _;

    /// 📏 Sixteen mebibytes: over the streaming threshold, over the compressible
    /// bound, and small enough to write in a test without being slow.
    const LARGE: usize = 16 * 1024 * 1024;

    fn fixture(compress: bool, precompressed: bool) -> (tempfile::TempDir, FileServer) {
        let dir = tempfile::tempdir().unwrap();
        let mut file = std::fs::File::create(dir.path().join("big.bin")).unwrap();
        // 🗜️ Highly compressible on purpose: if a compression path is still
        // buffering, a body of zeroes makes the difference obvious rather than
        // hiding it behind an incompressible payload.
        file.write_all(&vec![0u8; LARGE]).unwrap();
        file.flush().unwrap();
        if precompressed {
            // 📦 A sidecar of the same size. Its contents do not have to be real
            // gzip — nothing in this test decompresses it, and what is being
            // measured is how many bytes reach memory.
            let mut sidecar = std::fs::File::create(dir.path().join("big.bin.gz")).unwrap();
            sidecar.write_all(&vec![0u8; LARGE]).unwrap();
            sidecar.flush().unwrap();
        }
        let server = FileServer::new(FileServerConfig {
            root: dir.path().to_path_buf(),
            index: vec![],
            browse: false,
            browse_limit: None,
            compress,
            precompressed: if precompressed {
                vec![super::super::PrecompressedFormat {
                    encoding: "gzip",
                    suffix: ".gz",
                }]
            } else {
                Vec::new()
            },
            ..FileServerConfig::default()
        });
        (dir, server)
    }

    /// 📏 The largest single allocation a response makes, measured by draining it.
    ///
    /// A streamed response reports its chunk size; a buffered one reports the
    /// whole body, because that is what it allocated. This is the number the
    /// finding asks about — it must not grow with the file.
    async fn largest_chunk(response: ServedResponse) -> usize {
        match response {
            ServedResponse::Stream(mut stream) => {
                let mut largest = 0;
                while let Some(chunk) = stream.read_chunk().unwrap() {
                    largest = largest.max(chunk.len());
                }
                largest
            }
            ServedResponse::Buffered(file) => file.content.len(),
            ServedResponse::Redirect(_) => 0,
        }
    }

    /// 🌊 None of the four ways to ask for a large file allocates it.
    ///
    /// One test over all four because the finding is one defect with four faces,
    /// and asserting them together is what stops a fix to one from being read as
    /// a fix to the class. The bound is the chunk size, which does not depend on
    /// the file: that is the whole property.
    #[tokio::test]
    async fn no_large_response_allocates_the_whole_body() {
        const CHUNK: usize = 64 * 1024;

        // 1️⃣ Identity — the case that already streamed, as the control.
        let (_dir, fs) = fixture(false, false);
        let response = fs
            .serve_auto("/big.bin", "/big.bin", None, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(largest_chunk(response).await, CHUNK, "identity");

        // 2️⃣ A whole-file Range — previously the most expensive request this
        // server could be asked for, because any Range disabled streaming.
        let (_dir, fs) = fixture(false, false);
        let response = fs
            .serve_auto("/big.bin", "/big.bin", Some("bytes=0-"), None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(largest_chunk(response).await, CHUNK, "whole-file range");

        // 3️⃣ Dynamic compression negotiated on a file past the compressible
        // bound: streams uncompressed rather than buffering and compressing.
        let (_dir, fs) = fixture(true, false);
        let response = fs
            .serve_auto("/big.bin", "/big.bin", None, Some("gzip"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(largest_chunk(response).await, CHUNK, "dynamic compression");

        // 4️⃣ A pre-compressed sidecar: its bytes on disk are already the body.
        let (_dir, fs) = fixture(true, true);
        let response = fs
            .serve_auto("/big.bin", "/big.bin", None, Some("gzip"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            largest_chunk(response).await,
            CHUNK,
            "precompressed sidecar"
        );
    }

    /// 🪟 A streamed range sends the right bytes and says so.
    ///
    /// Bounded memory is worthless if the body is wrong. The `Content-Range` and
    /// the 206 are asserted too, because a streamed range that answered 200 with
    /// no `Content-Range` would tell the client it had received the whole file —
    /// a correctness regression the memory fix could easily have introduced.
    #[tokio::test]
    async fn a_streamed_range_carries_the_right_bytes_and_headers() {
        let dir = tempfile::tempdir().unwrap();
        // 🔢 A recognisable pattern, so an off-by-one in the seek or the window
        // shows up as wrong bytes rather than as the right count of zeroes.
        let body: Vec<u8> = (0..LARGE).map(|i| (i % 251) as u8).collect();
        std::fs::write(dir.path().join("big.bin"), &body).unwrap();
        let fs = FileServer::new(FileServerConfig {
            root: dir.path().to_path_buf(),
            index: vec![],
            browse: false,
            browse_limit: None,
            compress: false,
            ..FileServerConfig::default()
        });

        let start = 1_000_000usize;
        let end = start + 5_000_000;
        let response = fs
            .serve_auto(
                "/big.bin",
                "/big.bin",
                Some(&format!("bytes={start}-{end}")),
                None,
            )
            .await
            .unwrap()
            .unwrap();

        let ServedResponse::Stream(mut stream) = response else {
            panic!("a 5 MB range must stream, not buffer");
        };
        assert_eq!(stream.status, 206);
        assert_eq!(
            stream.content_range.as_ref().map(|v| v.to_str().unwrap()),
            Some(format!("bytes {start}-{end}/{LARGE}").as_str())
        );
        assert_eq!(
            stream.content_length.to_str().unwrap(),
            (end - start + 1).to_string(),
            "Content-Length must describe the window, not the file"
        );

        let mut received = Vec::new();
        while let Some(chunk) = stream.read_chunk().unwrap() {
            received.extend_from_slice(&chunk);
        }
        assert_eq!(received.len(), end - start + 1);
        assert_eq!(
            received.as_slice(),
            &body[start..=end],
            "the streamed window is not the bytes that were asked for"
        );
    }

    /// 🧭 A small file is still buffered, and a small range still works.
    ///
    /// The control for the whole module: a change that streamed everything would
    /// satisfy every assertion above and add a syscall per small response, which
    /// is most of them.
    #[tokio::test]
    async fn small_responses_are_still_buffered() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("small.txt"), b"0123456789").unwrap();
        let fs = FileServer::new(FileServerConfig {
            root: dir.path().to_path_buf(),
            index: vec![],
            browse: false,
            browse_limit: None,
            compress: false,
            ..FileServerConfig::default()
        });

        let whole = fs
            .serve_auto("/small.txt", "/small.txt", None, None)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(whole, ServedResponse::Buffered(_)));

        let ranged = fs
            .serve_auto("/small.txt", "/small.txt", Some("bytes=2-5"), None)
            .await
            .unwrap()
            .unwrap();
        let ServedResponse::Buffered(file) = ranged else {
            panic!("a four-byte range must stay buffered");
        };
        assert_eq!(file.status, 206);
        assert_eq!(file.content, b"2345");
    }
}
