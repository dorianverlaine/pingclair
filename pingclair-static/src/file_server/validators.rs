// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🏷️ Validators: the values a client hands back to ask "is this still the
//! same thing I have?"
//!
//! An `ETag` sent without `W/` is a promise that two responses carrying it
//! have byte-for-byte identical bodies. That promise is what lets a client
//! stitch a `Range` response onto bytes it already holds. The file server used
//! to break it twice over: the tag was built from a whole-second mtime, so two
//! edits inside one second (same size) kept one tag; and the same tag went out
//! on the plain file, its `.gz` sidecar, and a live-compressed body — three
//! different byte sequences under one "identical bytes" promise.
//!
//! The fix keeps the tags strong and makes them honest instead of adding
//! `W/`: a weak tag can never satisfy the strong comparison `If-Range`
//! requires, so every resumed download would restart from zero.
//!
//! Everything here runs on a metadata-cache miss, never per request.

use http::HeaderValue;

/// 🏷️ One strong entity tag per representation of a file.
///
/// The encoded tags are the identity tag with the coding appended inside the
/// quotes, so `"1f-17a…"` becomes `"1f-17a…-gzip"`. Built once per file
/// identity; a request only picks one and clones it, which is a reference
/// count increment.
pub(super) struct EntityTags {
    identity: HeaderValue,
    br: HeaderValue,
    zstd: HeaderValue,
    gzip: HeaderValue,
}

impl EntityTags {
    /// 🏷️ Derives the tags from a file's size and nanosecond mtime, or from a
    /// sidecar-supplied tag when the site keeps one.
    ///
    /// Nanoseconds rather than seconds because the second is exactly the
    /// window in which a deploy can write a file twice; the content caches in
    /// this module already key on nanoseconds for the same reason.
    pub(super) fn derive(size: u64, mtime_ns: u128, sidecar: Option<String>) -> Self {
        let identity = sidecar.unwrap_or_else(|| format!("\"{size:x}-{mtime_ns:x}\""));
        Self {
            br: Self::coded(&identity, "br"),
            zstd: Self::coded(&identity, "zstd"),
            gzip: Self::coded(&identity, "gzip"),
            identity: HeaderValue::from_str(&identity).unwrap(),
        }
    }

    /// 🗜️ Appends the coding inside the closing quote, which keeps a sidecar's
    /// `W/` prefix (if the operator wrote one) and keeps the result a valid
    /// quoted entity tag.
    fn coded(identity: &str, coding: &str) -> HeaderValue {
        let tag = match identity.strip_suffix('"') {
            Some(stem) => format!("{stem}-{coding}\""),
            None => format!("{identity}-{coding}"),
        };
        HeaderValue::from_str(&tag).unwrap()
    }

    /// 🏷️ The tag for the body actually being sent: `None` is the file as it
    /// sits on disk.
    ///
    /// 📌 The codings are the closed set this crate produces — the live
    /// encoder offers `br`, `zstd`, and `gzip`, and the sidecar table names the
    /// same three — so the fallback arm is unreachable today. It answers with
    /// the identity tag rather than panicking; a new coding added without a
    /// tag here would show up in `representations_never_share_a_tag`.
    pub(super) fn for_coding(&self, coding: Option<&str>) -> &HeaderValue {
        match coding {
            None => &self.identity,
            Some("br") => &self.br,
            Some("zstd") => &self.zstd,
            Some("gzip") => &self.gzip,
            Some(_) => &self.identity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn representations_never_share_a_tag() {
        // 🎯 §8.8.1: a strong tag shared by the gzip and identity bodies is
        // not strong. Every coding this crate can emit must get its own.
        let tags = EntityTags::derive(0x1f, 0x17a, None);
        let all: Vec<&str> = [None, Some("br"), Some("zstd"), Some("gzip")]
            .into_iter()
            .map(|coding| tags.for_coding(coding).to_str().unwrap())
            .collect();
        assert_eq!(
            all,
            [
                "\"1f-17a\"",
                "\"1f-17a-br\"",
                "\"1f-17a-zstd\"",
                "\"1f-17a-gzip\""
            ]
        );
    }

    #[test]
    fn a_sidecar_tag_keeps_its_own_shape_per_coding() {
        let strong = EntityTags::derive(1, 1, Some("\"abc\"".to_string()));
        assert_eq!(strong.for_coding(Some("gzip")), "\"abc-gzip\"");
        let weak = EntityTags::derive(1, 1, Some("W/\"abc\"".to_string()));
        assert_eq!(weak.for_coding(Some("br")), "W/\"abc-br\"");
        assert_eq!(weak.for_coding(None), "W/\"abc\"");
    }
}
