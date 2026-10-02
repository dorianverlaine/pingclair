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
    /// 🎯 Preconditions and body selection see the final response header policy.
    pub(super) fn matches_file_encode(
        &self,
        status: u16,
        meta: &super::cache::FileMeta,
        request: &super::FileRequest<'_>,
    ) -> bool {
        if self.config.encode.matcher.is_none() {
            return pingclair_core::encoding::is_compressible_content_type(
                meta.content_type.to_str().unwrap_or(""),
                &self.config.gzip_types,
            );
        }
        let mut headers = http::HeaderMap::with_capacity(6);
        headers.insert("content-type", meta.content_type.clone());
        headers.insert("content-length", meta.content_length.clone());
        headers.insert("accept-ranges", http::HeaderValue::from_static("bytes"));
        headers.insert("etag", meta.etags.for_coding(None).clone());
        if let Some(value) = &meta.last_modified {
            headers.insert("last-modified", value.clone());
        }
        self.matches_encode_headers(status, headers, request)
    }

    /// 🎯 Listings obey the same header policy as regular static files.
    pub(super) fn matches_listing_encode(
        &self,
        length: u64,
        request: &super::FileRequest<'_>,
    ) -> bool {
        if self.config.encode.matcher.is_none() {
            return pingclair_core::encoding::is_compressible_content_type(
                "text/html",
                &self.config.gzip_types,
            );
        }
        let mut headers = http::HeaderMap::with_capacity(3);
        headers.insert(
            "content-type",
            http::HeaderValue::from_static("text/html; charset=utf-8"),
        );
        headers.insert("content-length", http::HeaderValue::from(length));
        self.matches_encode_headers(200, headers, request)
    }

    /// 🧊 The matcher reads identity headers before encoding changes byte metadata.
    fn matches_encode_headers(
        &self,
        status: u16,
        mut headers: http::HeaderMap,
        request: &super::FileRequest<'_>,
    ) -> bool {
        headers.insert("vary", http::HeaderValue::from_static("Accept-Encoding"));
        if request
            .response_policy
            .is_some_and(|policy| !policy(status, &mut headers))
        {
            return false;
        }
        self.config.encode.matches(status, |name, patterns| {
            headers
                .get_all(name)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .any(|value| {
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
                let compressed = Bytes::from(self.compress_with(&content, enc).await?);
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
    /// sent `gzip;q=0`. Named coding acceptance now follows the same ranking
    /// as live compression; a positive wildcard alone keeps identity, as Caddy does.
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

    /// 🗜️ Both paths construct codecs with the site quality, rather than library defaults.
    pub(super) async fn compress_with(&self, input: &[u8], encoding: &str) -> Result<Vec<u8>> {
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
                let mut e = ZstdEncoder::with_quality(
                    Vec::new(),
                    async_compression::Level::Precise(pingclair_core::encoding::DEFAULT_ZSTD_LEVEL),
                );
                e.write_all(input).await?;
                e.shutdown().await?;
                e.into_inner()
            }
            "gzip" => {
                let mut e = GzipEncoder::with_quality(
                    Vec::new(),
                    async_compression::Level::Precise(self.config.encode.gzip_level as i32),
                );
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
            Some(enc) => Ok((self.compress_with(input, enc).await?, Some(enc.to_string()))),
            None => Ok((input.to_vec(), None)),
        }
    }
}
