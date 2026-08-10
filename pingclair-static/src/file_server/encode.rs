// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🗜️ Choosing a content coding, and producing one.
//!
//! Three things live here, and the order matters: pick a coding the client
//! actually accepts, prefer a `.br`/`.zst`/`.gz` file somebody built ahead of
//! time, and only compress on the fly when neither of those answered. The
//! on-the-fly path is also the one that populates the compressed-body cache,
//! because it is the only one that produces bytes worth keeping.

use pingclair_core::error::Result;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::sync::Arc;

use super::FileServer;
use super::cache::CompressKey;

impl FileServer {
    // MARK: - Reading and compressing

    /// Read `length` bytes of `file_path` starting at `start`, then compress
    /// the body when `encoding` was negotiated. A compressible full-file
    /// result with a usable mtime is stored in `compress_cache` under
    /// (path, mtime, encoding) so later requests skip the read+compress.
    pub(super) async fn read_and_maybe_compress(
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

    // MARK: - Pre-compressed variants

    /// 🗜️ Finds and loads a sidecar for this file, if one is allowed and the
    /// client accepts its encoding.
    ///
    /// The order is the operator's, not ours: `precompressed zstd gzip` means
    /// zstd is preferred, and a build that guessed would serve the wrong one.
    /// Empty configuration never reaches here — the caller checks first, so a
    /// site that did not ask for sidecars pays nothing.
    pub(super) async fn try_precompressed(
        &self,
        original_path: &std::path::Path,
        accept_encoding: Option<&str>,
    ) -> Option<(Vec<u8>, &'static str)> {
        let accept = accept_encoding?;

        for format in &self.config.precompressed {
            if !accept.contains(format.encoding) {
                continue;
            }

            // 🗜️ Built by appending to the OS string rather than through
            // `with_extension`, which would replace `.js` instead of adding to
            // it and ask for `app.br`.
            let mut sidecar = original_path.as_os_str().to_owned();
            sidecar.push(format.suffix);
            let sidecar = std::path::PathBuf::from(sidecar);

            // 🙈 A hidden sidecar stays hidden. Without this, `hide *.gz`
            // would still serve the very file it was told to conceal.
            if self.config.hide.hides(&sidecar) {
                continue;
            }

            // (synchronous read — same rationale as read_and_maybe_compress)
            if let Ok(content) = std::fs::read(&sidecar) {
                return Some((content, format.encoding));
            }
        }

        None
    }

    // MARK: - Negotiation

    /// 🗜️ Codings this server will produce, in preference order.
    ///
    /// Brotli stays in the list even though the DSL refuses `encode br`,
    /// because a static file has been able to answer a brotli request for as
    /// long as this code existed and dropping it is a behaviour change that
    /// belongs in its own commit, not smuggled into a correctness fix. The
    /// inconsistency with the proxy path is recorded rather than papered over.
    const OFFERED: &'static [&'static str] = &["br", "zstd", "gzip"];

    /// 🗜️ Picks the coding for a response, honouring the client's quality
    /// values.
    ///
    /// `None` means "serve uncompressed" — the client accepted none of
    /// [`Self::OFFERED`], or sent no `Accept-Encoding` at all. It is an
    /// ordinary answer, not a failure.
    ///
    /// This used to be `header.contains("gzip")`. Day 26 measured what that
    /// costs: a client sending `Accept-Encoding: gzip;q=0` — an explicit
    /// refusal — was answered with a gzip body, because the refusal still
    /// contains the word. `contains` also matched substrings, so a token merely
    /// embedding a coding name selected it. Both are gone now that whole tokens
    /// and their `q` are read.
    pub(super) fn negotiate_encoding(accept_header: Option<&str>) -> Option<&'static str> {
        pingclair_core::encoding::negotiate(accept_header?, Self::OFFERED)
    }

    /// Compress `input` with a specific, already-negotiated encoding.
    pub(super) async fn compress_with(input: &[u8], encoding: &str) -> Result<Vec<u8>> {
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
    pub(super) async fn compress_content(
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
}
