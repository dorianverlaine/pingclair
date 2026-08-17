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
//! | [`listing`] | The browse page: what it may name, and how those names are encoded. |
//! | [`stream`] | The chunked response: its type, its threshold, and the decision to take it. |
//! | [`serve`] | The request handler, path resolution, and Range parsing. |
//!
//! This module keeps only what all five need: the configuration, the server
//! itself, and the two buffered response types.
//!
//! 🗺️ [`listing`] was the fifth to arrive, on 2026-08-17, and for the same
//! reason as the original split rather than for length: a browse page is the
//! only output this server builds out of bytes somebody else chose — filenames,
//! and the request path — so its encoding rules are security rules, and they
//! were sitting inside the request handler where nothing distinguished them
//! from formatting.

mod cache;
mod encode;
mod listing;
mod serve;
mod stream;

use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
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
    /// 🗜️ Encodings whose sidecar files may be served (`app.js.br`), in
    /// preference order. Empty means never look — a stale sidecar is a wrong
    /// answer, so hunting for one is opt-in, matching upstream.
    pub precompressed: Vec<PrecompressedFormat>,
    /// 🙈 What this server pretends does not exist, compiled once.
    pub hide: HidePolicy,
    /// 🔢 Overrides the status of a successful response.
    pub status: Option<u16>,
    /// 🔁 Redirect to the canonical trailing-slash form.
    pub canonical_uris: bool,
    /// 🏷️ Extensions of sidecar files holding a precomputed ETag.
    pub etag_file_extensions: Vec<String>,
}

/// 🗜️ One sidecar encoding, with the suffix and token resolved at load time so
/// a request never formats either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecompressedFormat {
    /// The `Content-Encoding` token, for example `br`.
    pub encoding: &'static str,
    /// The file suffix, for example `.br`.
    pub suffix: &'static str,
}

impl PrecompressedFormat {
    /// 🗜️ Resolves a configured name, or `None` if this build cannot read it.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "br" => Some(Self {
                encoding: "br",
                suffix: ".br",
            }),
            "zstd" => Some(Self {
                encoding: "zstd",
                suffix: ".zst",
            }),
            "gzip" => Some(Self {
                encoding: "gzip",
                suffix: ".gz",
            }),
            _ => None,
        }
    }
}

/// 🙈 The `hide` list, split once into the two ways it matches.
///
/// 🏎️ Upstream re-splits the filename and re-parses every pattern on every
/// request. Both halves of that are load-time work: the patterns compile here,
/// and the split into "component" and "prefix" rules happens here, so a
/// request walks two small slices and allocates nothing. The common case —
/// nothing hidden — is a single `is_empty` check.
#[derive(Debug, Default, Clone)]
pub struct HidePolicy {
    /// Patterns with no separator, matched against each path component.
    components: Vec<glob::Pattern>,
    /// Patterns containing a separator, matched as a path prefix.
    prefixes: Vec<PathBuf>,
}

impl HidePolicy {
    /// 🙈 Compiles the configured patterns.
    ///
    /// A pattern that will not compile is dropped with a warning rather than
    /// failing the load: the alternative is a server that refuses to start
    /// over a hide rule, and the rule that matters — the file stays visible —
    /// is the one an operator can see in the log.
    pub fn new(patterns: &[String], root: &Path) -> Self {
        let mut policy = Self::default();
        for pattern in patterns {
            if pattern.contains(std::path::MAIN_SEPARATOR) || pattern.contains('/') {
                // 📁 A relative prefix is resolved against the document root,
                // so `hide .git` and `hide /srv/.git` mean the same thing for
                // a site rooted at `/srv`.
                let path = Path::new(pattern);
                policy.prefixes.push(if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    root.join(path)
                });
                continue;
            }
            match glob::Pattern::new(pattern) {
                Ok(compiled) => policy.components.push(compiled),
                Err(error) => {
                    tracing::warn!(
                        "🙈 file_server hide pattern {:?} is not a valid glob and will not                          hide anything: {}",
                        pattern,
                        error
                    );
                }
            }
        }
        policy
    }

    /// 🙈 Reports whether this path must be treated as absent.
    pub fn hides(&self, path: &Path) -> bool {
        if self.components.is_empty() && self.prefixes.is_empty() {
            return false;
        }
        if self.prefixes.iter().any(|prefix| path.starts_with(prefix)) {
            return true;
        }
        path.components().any(|component| {
            let name = component.as_os_str();
            self.components
                .iter()
                .any(|pattern| pattern.matches_path(Path::new(name)))
        })
    }

    /// 🕳️ Whether anything is hidden at all.
    pub fn is_empty(&self) -> bool {
        self.components.is_empty() && self.prefixes.is_empty()
    }
}

impl FileServerConfig {
    /// 🧾 Builds the runtime configuration from what a `file_server` handler
    /// declared, resolving everything that a request would otherwise redo.
    ///
    /// One constructor rather than one per call site: this is built in five
    /// places across the H1/H2 and H3 paths, and a field added to only some of
    /// them is precisely how the two transports come to serve different bytes
    /// from the same configuration.
    #[allow(clippy::too_many_arguments)]
    pub fn from_handler(
        root: impl Into<PathBuf>,
        index: &[String],
        browse: bool,
        browse_limit: Option<usize>,
        compress: bool,
        precompressed: &[String],
        hide: &[String],
        status: Option<u16>,
        canonical_uris: bool,
        etag_file_extensions: &[String],
    ) -> Self {
        let root = root.into();
        Self {
            // 🙈 Compiled against this server's own root, so `hide .git` on a
            // site rooted at `/srv` means `/srv/.git` without a path join per
            // request.
            hide: HidePolicy::new(hide, &root),
            root,
            index: if index.is_empty() {
                vec!["index.html".to_string()]
            } else {
                index.to_vec()
            },
            browse,
            browse_limit,
            compress,
            // 🗜️ Resolved to suffixes here, and a name this build cannot read
            // is dropped now rather than tested on every request. The adapter
            // already refuses unknown names, so this only filters what the
            // Admin API could post.
            precompressed: precompressed
                .iter()
                .filter_map(|name| PrecompressedFormat::from_name(name))
                .collect(),
            status,
            canonical_uris,
            etag_file_extensions: etag_file_extensions.to_vec(),
        }
    }
}

impl Default for FileServerConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            index: vec!["index.html".to_string(), "index.htm".to_string()],
            browse: false,
            browse_limit: None,
            compress: true,
            // 🗜️ Off by default, like upstream. This server used to look for
            // sidecars unconditionally, so a stale `app.js.gz` was served in
            // place of a fresh `app.js` — the same configuration answering
            // with different bytes than upstream would.
            precompressed: Vec::new(),
            hide: HidePolicy::default(),
            status: None,
            canonical_uris: true,
            etag_file_extensions: Vec::new(),
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

#[cfg(test)]
mod subdirective_tests {
    use super::*;

    /// 🙈 The two ways `hide` matches, which upstream distinguishes by whether
    /// the pattern contains a separator.
    #[test]
    fn hide_matches_components_by_name_and_paths_by_prefix() {
        let root = Path::new("/srv");
        let policy = HidePolicy::new(&[".git".to_string(), "/srv/secret".to_string()], root);

        // 🏷️ No separator: any component of that name, at any depth.
        assert!(policy.hides(Path::new("/srv/.git")));
        assert!(policy.hides(Path::new("/srv/a/.git/config")));
        // 🚫 …but not a name that merely starts with it, which is the trap
        // upstream's own comment calls out with "barstool".
        assert!(!policy.hides(Path::new("/srv/.gitignore")));

        // 📁 With a separator: a path prefix.
        assert!(policy.hides(Path::new("/srv/secret/keys.pem")));
        assert!(!policy.hides(Path::new("/srv/public/index.html")));
    }

    /// 📁 A relative pattern with a separator is resolved against the document
    /// root, so `hide app/private` on a site rooted at `/srv` cannot
    /// accidentally hide `/app/private` on the host.
    #[test]
    fn a_relative_hide_prefix_is_rooted_at_the_document_root() {
        let policy = HidePolicy::new(&["app/private".to_string()], Path::new("/srv"));
        assert!(policy.hides(Path::new("/srv/app/private/notes.txt")));
        assert!(!policy.hides(Path::new("/app/private/notes.txt")));
    }

    /// ⭐ Glob patterns work on components, matching upstream's
    /// `filepath.Match`.
    #[test]
    fn hide_understands_globs() {
        let policy = HidePolicy::new(&["*.env".to_string()], Path::new("/srv"));
        assert!(policy.hides(Path::new("/srv/.production.env")));
        assert!(!policy.hides(Path::new("/srv/env.js")));
    }

    /// 🕳️ Nothing configured must cost nothing and hide nothing — this is the
    /// state almost every request is served in.
    #[test]
    fn an_empty_hide_policy_hides_nothing() {
        let policy = HidePolicy::new(&[], Path::new("/srv"));
        assert!(policy.is_empty());
        assert!(!policy.hides(Path::new("/srv/.git/config")));
    }

    /// 🧨 A pattern that will not compile must not take the server down, and
    /// must not silently look like it is hiding something.
    #[test]
    fn an_unparseable_pattern_is_dropped_rather_than_fatal() {
        let policy = HidePolicy::new(&["[".to_string()], Path::new("/srv"));
        assert!(policy.is_empty(), "a broken pattern was kept as a rule");
    }

    /// 🗜️ Sidecar suffixes are resolved once, and a name this build cannot
    /// read is not silently treated as some other encoding.
    #[test]
    fn precompressed_formats_resolve_to_their_suffixes() {
        assert_eq!(
            PrecompressedFormat::from_name("br").map(|f| f.suffix),
            Some(".br")
        );
        assert_eq!(
            PrecompressedFormat::from_name("zstd").map(|f| f.suffix),
            Some(".zst")
        );
        assert_eq!(
            PrecompressedFormat::from_name("gzip").map(|f| f.suffix),
            Some(".gz")
        );
        assert!(PrecompressedFormat::from_name("lz4").is_none());
    }

    /// 🗜️ Sidecar lookup is off unless asked for.
    ///
    /// This is a deliberate behaviour change: it used to be on, so a stale
    /// `app.js.gz` beside a fresh `app.js` was served in its place — the same
    /// configuration answering with different bytes than upstream would.
    #[test]
    fn sidecar_lookup_is_off_by_default() {
        assert!(FileServerConfig::default().precompressed.is_empty());
        assert!(FileServerConfig::default().canonical_uris);
    }

    /// 🧾 The one constructor both transports use, so a field cannot reach
    /// HTTP/1.1 and miss HTTP/3.
    #[test]
    fn from_handler_resolves_every_option() {
        let config = FileServerConfig::from_handler(
            "/srv",
            &[],
            false,
            None,
            true,
            &["gzip".to_string(), "lz4".to_string()],
            &[".git".to_string()],
            Some(503),
            false,
            &["etag".to_string()],
        );

        // 📄 An empty index list falls back to the default document.
        assert_eq!(config.index, vec!["index.html".to_string()]);
        // 🗜️ The unknown name is dropped, the known one kept, order preserved.
        assert_eq!(config.precompressed.len(), 1);
        assert_eq!(config.precompressed[0].suffix, ".gz");
        assert!(config.hide.hides(Path::new("/srv/.git/config")));
        assert_eq!(config.status, Some(503));
        assert!(!config.canonical_uris);
        assert_eq!(config.etag_file_extensions, vec!["etag".to_string()]);
    }
}
