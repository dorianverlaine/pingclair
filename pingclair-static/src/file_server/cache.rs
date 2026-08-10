// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🗂️ The two caches the file server keeps, and the keys that identify them.
//!
//! Both answer the same question — "have we already done this work for this
//! exact file?" — and both key on a file *identity* rather than a path, so an
//! edit invalidates the entry instead of being served stale. They differ in
//! what they protect: [`CompressCache`] protects CPU (compressing a hot file
//! once instead of per request), while the metadata cache protects allocation
//! (formatting one file's headers once instead of per request).

use pingclair_core::error::Result;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use http::HeaderValue;

use super::FileServer;
#[cfg(test)]
use super::FileServerConfig;

// MARK: - Keys

/// Key for a cached compressed response: a file identity (path + mtime) plus
/// the content encoding. mtime is part of the key so editing a file naturally
/// invalidates its stale cached compression instead of serving old bytes.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct CompressKey {
    pub(super) path: PathBuf,
    pub(super) mtime_ns: u128,
    pub(super) encoding: &'static str,
}

/// Prebuilt response metadata for one file identity: path, mtime, and size.
///
/// Every static response repeats the same header values (Content-Type,
/// Last-Modified, ETag, Content-Length) for the same file. Building them as
/// `HeaderValue`s once per file identity lets hot paths clone them for one
/// atomic reference-count increment instead of reformatting and copying
/// strings on every request — the dominant per-request header allocation on
/// the small-file benchmark path.
pub(super) struct FileMeta {
    pub(super) content_type: HeaderValue,
    pub(super) last_modified: Option<HeaderValue>,
    pub(super) etag: HeaderValue,
    pub(super) content_length: HeaderValue,
}

/// Identity of one file's metadata, derived from a single `stat` per request.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct MetaKey {
    path: PathBuf,
    mtime_ns: u128,
    size: u64,
}

// MARK: - Compressed body cache

/// A small, byte-bounded LRU cache of already-compressed file bodies.
///
/// On-the-fly compression is expensive and, without this, was redone from
/// scratch on *every* request for the same file — under sustained concurrent
/// load against a large compressible file that turned a 20s benchmark into a
/// 16-minute one (see benchmarks/README.md). Caching the compressed output
/// keyed on (path, mtime, encoding) means a hot file is compressed once and
/// then served from memory. Bounded by total compressed bytes so the cache
/// can't grow without limit; least-recently-used entries are evicted first.
pub(super) struct CompressCache {
    pub(super) entries: HashMap<CompressKey, Arc<Vec<u8>>>,
    /// Recency order, front = least recently used.
    lru: VecDeque<CompressKey>,
    bytes: usize,
    budget: usize,
}

impl CompressCache {
    pub(super) fn new(budget: usize) -> Self {
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

    pub(super) fn get(&mut self, key: &CompressKey) -> Option<Arc<Vec<u8>>> {
        if let Some(v) = self.entries.get(key).cloned() {
            self.touch(key);
            Some(v)
        } else {
            None
        }
    }

    pub(super) fn insert(&mut self, key: CompressKey, value: Arc<Vec<u8>>) {
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

// MARK: - Response metadata cache

impl FileServer {
    /// Maximum number of file identities whose response metadata is cached.
    /// Each entry holds a handful of small `HeaderValue`s, so even a busy
    /// site with thousands of files stays well under a megabyte.
    const META_CACHE_CAP: usize = 4096;

    /// Return the prebuilt response metadata for `file_path`, building and
    /// caching it on the first request and on every mtime/size change.
    pub(super) fn file_meta(
        &self,
        file_path: &Path,
        metadata: &std::fs::Metadata,
    ) -> Result<Arc<FileMeta>> {
        let size = metadata.len();
        let mtime_ns = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_nanos());

        // Files without a usable mtime are rebuilt per request: caching by
        // size alone could serve stale headers after a same-size overwrite.
        let Some(mtime_ns) = mtime_ns else {
            return Ok(Arc::new(Self::build_meta(
                file_path,
                metadata,
                size,
                &self.config.etag_file_extensions,
            )));
        };

        let key = MetaKey {
            path: file_path.to_path_buf(),
            mtime_ns,
            size,
        };
        if let Some(meta) = self.meta_cache.load().get(&key) {
            return Ok(meta.clone());
        }

        let meta = Arc::new(Self::build_meta(
            file_path,
            metadata,
            size,
            &self.config.etag_file_extensions,
        ));
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
    fn build_meta(
        file_path: &Path,
        metadata: &std::fs::Metadata,
        size: u64,
        etag_file_extensions: &[String],
    ) -> FileMeta {
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
        // 🏷️ A sidecar ETag wins when one exists. Build pipelines that hash
        // content write `app.js.etag` beside the file; deriving one from size
        // and mtime instead would change on every deploy that only touched
        // timestamps, and would *not* change when two builds produce the same
        // bytes — the opposite of what an ETag is for.
        //
        // Read here rather than per request: this runs on a cache miss, and
        // the value is cached against the same (path, mtime, size) identity as
        // everything else in `FileMeta`.
        let etag = read_sidecar_etag(file_path, etag_file_extensions)
            .unwrap_or_else(|| format!("\"{size:x}-{modified_secs:x}\""));

        FileMeta {
            content_type: HeaderValue::from_str(&mime_type).unwrap(),
            last_modified: last_modified.map(|v| HeaderValue::from_str(&v).unwrap()),
            etag: HeaderValue::from_str(&etag).unwrap(),
            content_length: HeaderValue::from(size),
        }
    }

    // MARK: - Sidecar ETags
}

/// 🏷️ Reads a precomputed ETag from a sidecar file, if the site names any.
///
/// The value is used as written after trimming, and quoted when it is not
/// already: an unquoted ETag is invalid per RFC 9110 and would be dropped by
/// caches without a word, which is the silent failure this avoids.
fn read_sidecar_etag(file_path: &Path, extensions: &[String]) -> Option<String> {
    // 🕳️ The overwhelmingly common case: nothing configured, no syscall.
    if extensions.is_empty() {
        return None;
    }
    for extension in extensions {
        let mut sidecar = file_path.as_os_str().to_owned();
        // 📄 Upstream takes the extension as written, dot included or not.
        if !extension.starts_with('.') {
            sidecar.push(".");
        }
        sidecar.push(extension);
        let Ok(contents) = std::fs::read_to_string(std::path::PathBuf::from(sidecar)) else {
            continue;
        };
        let value = contents.trim();
        // 🚫 An empty sidecar is not an ETag; fall through to the derived one
        // rather than emitting `""`, which every cache treats as a mismatch.
        if value.is_empty() {
            continue;
        }
        return Some(if value.starts_with('"') || value.starts_with("W/") {
            value.to_string()
        } else {
            format!("\"{value}\"")
        });
    }
    None
}

impl FileServer {
    // MARK: - In-flight coalescing

    /// Remove the in-flight entry for `key`, but only if it is still the
    /// `lock` this request took — a newer request for the same key may have
    /// already replaced the entry, and we must never remove somebody else's.
    pub(super) fn release_inflight(
        map: &Mutex<HashMap<CompressKey, Arc<tokio::sync::Mutex<()>>>>,
        key: &CompressKey,
        lock: &Arc<tokio::sync::Mutex<()>>,
    ) {
        let mut map = map.lock().unwrap();
        if map.get(key).is_some_and(|l| Arc::ptr_eq(l, lock)) {
            map.remove(key);
        }
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
        let rebuilt = FileServer::build_meta(&path, &metadata, metadata.len(), &[]);

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
