// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🗜️ Choosing a content coding, and producing one.
//!
//! Three things live here, and the order matters: pick a coding the client
//! actually accepts, prefer a `.br`/`.zst`/`.gz` file somebody built ahead of
//! time, and only compress on the fly when neither of those answered. The
//! on-the-fly path is also the one that populates the compressed-body cache,
//! because it is the only one that produces bytes worth keeping.

use bytes::Bytes;
use pingclair_core::error::Result;
use std::io::{Read as _, Seek as _, SeekFrom};

use super::FileServer;
use super::cache::FileKey;

impl FileServer {
    /// 🎯 Preconditions and body selection must choose the same representation.
    pub(super) fn matches_file_encode(&self, status: u16, meta: &super::cache::FileMeta) -> bool {
        (self.config.encode.matcher.is_some()
            || pingclair_core::encoding::is_compressible_content_type(
                meta.content_type.to_str().unwrap_or(""),
                &self.config.gzip_types,
            ))
            && self.config.encode.matches(status, |name, patterns| {
                let value = if name.eq_ignore_ascii_case("content-type") {
                    meta.content_type.to_str().ok()
                } else if name.eq_ignore_ascii_case("content-length") {
                    meta.content_length.to_str().ok()
                } else if name.eq_ignore_ascii_case("accept-ranges") {
                    Some("bytes")
                } else if name.eq_ignore_ascii_case("etag") {
                    meta.etags.for_coding(None).to_str().ok()
                } else if name.eq_ignore_ascii_case("last-modified") {
                    meta.last_modified
                        .as_ref()
                        .and_then(|value| value.to_str().ok())
                } else {
                    None
                };
                value.is_some_and(|value| {
                    patterns.is_empty()
                        || patterns.iter().any(|pattern| {
                            pingclair_core::encoding::header_pattern_matches(value, pattern)
                        })
                })
            })
    }

    // MARK: - Reading and compressing

    /// Read `length` bytes of `file_path` starting at `start`, then compress
    /// the body when `encoding` was negotiated. A compressible full-file
    /// result with a usable mtime is stored in `compress_cache` under
    /// (path, mtime, encoding) so later requests skip the read+compress.
    ///
    /// A complete, uncompressed body is stored in `content_cache` under
    /// (path, mtime) instead, so a repeated request for the same small file
    /// skips the `open` + `read` + `close` as well. Only whole files are
    /// cached: a `Range` starts at a non-zero offset and is a different body,
    /// and the streaming path never reaches here at all.
    pub(super) async fn read_and_maybe_compress(
        &self,
        file_path: &std::path::Path,
        start: u64,
        length: u64,
        encoding: Option<&'static str>,
        mtime_ns: Option<u128>,
    ) -> Result<(Bytes, Option<String>)> {
        // 🗂️ A file at or below the streaming threshold enters user space
        // once. The cache returns shared `Bytes` after that first read, removing
        // both repeated syscalls and whole-body copies.
        //
        // Files without a usable mtime are never cached: there would be no key
        // for an edit to change, so a same-size overwrite could serve stale
        // bytes.
        let content_key = match (encoding, mtime_ns, start) {
            (None, Some(mtime_ns), 0) => Some(FileKey {
                path: file_path.to_path_buf(),
                mtime_ns,
                encoding: "",
                body_len: length,
            }),
            _ => None,
        };
        if let Some(key) = &content_key
            && let Some(cached) = self.content_cache.lock().unwrap().get(key)
        {
            return Ok((cached, None));
        }

        // 🗂️ Synchronous by design: a local regular-file read served from the
        // page cache finishes immediately in the measured workload. Paying a
        // blocking-pool round trip per request only adds cross-thread wakeups.
        let mut file = std::fs::File::open(file_path)?;

        if start > 0 {
            file.seek(SeekFrom::Start(start))?;
        }

        let mut content = vec![0u8; length as usize];
        file.read_exact(&mut content)?;
        let content = Bytes::from(content);

        match encoding {
            Some(enc) => {
                let compressed = Bytes::from(Self::compress_with(&content, enc).await?);
                if let Some(mtime_ns) = mtime_ns {
                    let key = FileKey {
                        path: file_path.to_path_buf(),
                        mtime_ns,
                        encoding: enc,
                        body_len: length,
                    };
                    self.compress_cache
                        .lock()
                        .unwrap()
                        .insert(key, compressed.clone());
                }
                Ok((compressed, Some(enc.to_string())))
            }
            None => {
                if let Some(key) = content_key {
                    self.content_cache
                        .lock()
                        .unwrap()
                        .insert(key, content.clone());
                }
                Ok((content, None))
            }
        }
    }

    // MARK: - Pre-compressed variants

    /// 🗜️ Finds and loads a sidecar for this file, if one is allowed and the
    /// client accepts its encoding.
    ///
    /// 🥇 The client's quality values choose first and the operator's order
    /// breaks ties: `precompressed zstd gzip` means zstd when the client does
    /// not care, but `zstd;q=0.1, gzip` gets the `.gz`. This used to be
    /// `accept.contains(encoding)`, which served the `.gz` to a client that
    /// sent `gzip;q=0` and served nothing to one that sent `*`. It now walks
    /// the same ranking live compression uses, so the two cannot drift again.
    ///
    /// 🔁 A missing sidecar falls through to the next-ranked coding rather
    /// than giving up. Empty configuration never reaches here — the caller
    /// checks first, so a site that did not ask for sidecars pays nothing.
    pub(super) async fn try_precompressed(
        &self,
        original_path: &std::path::Path,
        accept_encoding: Option<&str>,
    ) -> Option<(std::path::PathBuf, std::fs::Metadata, &'static str)> {
        let accept = accept_encoding?;

        for format in
            pingclair_core::encoding::ranked(accept, &self.config.precompressed, |f| f.encoding)
        {
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

            // 📏 Stat first so the caller can decide between streaming the
            // sidecar and buffering it. Reading it outright — which this used to
            // do — made a 500 MB `.br` a 500 MB allocation, and a sidecar is
            // exactly the case where the bytes on disk are already the response
            // body and never needed to be in memory at all.
            if let Ok(metadata) = std::fs::metadata(&sidecar)
                && metadata.is_file()
            {
                return Some((sidecar, metadata, format.encoding));
            }
        }

        None
    }

    /// 🗜️ Reads a sidecar whole, for the buffered path.
    ///
    /// Only reached for a sidecar small enough that buffering is the cheaper
    /// answer; the streaming threshold decides which.
    pub(super) fn read_precompressed(sidecar: &std::path::Path) -> Option<Vec<u8>> {
        // (synchronous read — same rationale as read_and_maybe_compress)
        std::fs::read(sidecar).ok()
    }

    // MARK: - Negotiation

    /// 🗜️ Both paths negotiate exactly the site's codings without allocating.
    pub(super) fn negotiate_encoding(&self, accept_header: Option<&str>) -> Option<&'static str> {
        pingclair_core::encoding::negotiate_by(accept_header?, &self.config.encodings, |coding| {
            coding.token()
        })
        .map(|coding| coding.token())
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
        match self.negotiate_encoding(accept_header) {
            Some(enc) => Ok((
                Self::compress_with(input, enc).await?,
                Some(enc.to_string()),
            )),
            None => Ok((input.to_vec(), None)),
        }
    }
}
