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
//! Tag derivation runs on a metadata-cache miss, never per request. The
//! `If-Range` check does run per request, but only for the rare request that
//! carries a `Range`, and it compares bytes in place without allocating.

use std::time::{Duration, SystemTime};

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
    ///
    /// 🛡️ Every tag built here is a valid header value by construction: the
    /// derived one is quotes around hex digits and a hyphen, and a sidecar one
    /// has passed [`SidecarTag::parse`]. Appending `-br` and friends inside
    /// the quotes keeps both properties, which is why the conversions below
    /// cannot fail.
    pub(super) fn derive(size: u64, mtime_ns: u128, sidecar: Option<SidecarTag>) -> Self {
        let identity = sidecar.map_or_else(|| format!("\"{size:x}-{mtime_ns:x}\""), |tag| tag.0);
        Self {
            br: Self::coded(&identity, "br"),
            zstd: Self::coded(&identity, "zstd"),
            gzip: Self::coded(&identity, "gzip"),
            identity: Self::header(identity),
        }
    }

    /// 🗜️ Appends the coding inside the closing quote, which keeps a sidecar's
    /// `W/` prefix (if the operator wrote one) and keeps the result a valid
    /// quoted entity tag. Every identity reaching here ends in a quote.
    fn coded(identity: &str, coding: &str) -> HeaderValue {
        let stem = identity.strip_suffix('"').unwrap_or(identity);
        Self::header(format!("{stem}-{coding}\""))
    }

    /// 🛡️ Converts a tag already known to be a valid entity tag.
    fn header(tag: String) -> HeaderValue {
        HeaderValue::try_from(tag).expect("an entity tag is always a valid header value")
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

// MARK: - Sidecar tags

/// 🏷️ An entity tag read from a sidecar file, checked against the RFC 9110
/// §8.8.3 grammar before anything uses it.
///
/// The file is written by whoever can write into the document root, so its
/// contents are untrusted. The only way to build one is [`SidecarTag::parse`],
/// which is what lets [`EntityTags::derive`] treat the tag as a valid header.
pub(super) struct SidecarTag(String);

impl SidecarTag {
    /// 🚫 Accepts `[W/]"<etagc>*"`, where `etagc` is any visible ASCII byte
    /// other than `"`, or a non-ASCII byte (`obs-text`). Anything else, such
    /// as an embedded line break, answers `None`.
    pub(super) fn parse(tag: String) -> Option<Self> {
        let opaque = tag.strip_prefix("W/").unwrap_or(&tag);
        let inner = opaque.strip_prefix('"')?.strip_suffix('"')?;
        inner
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x7e).contains(&b) || b >= 0x80)
            .then_some(Self(tag))
    }
}

// MARK: - If-Range

/// 🪟 A byte-range request as the client sent it: the `Range` value, and the
/// `If-Range` validator that says which version of the file the range is
/// meant to extend.
///
/// The two travel together because `Range` alone is not safe to honour. A
/// client resuming a download holds the first half of *some* version of the
/// file; `If-Range` names that version, and when the file has changed since,
/// splicing today's second half onto yesterday's first produces a corrupt
/// file that no checksum in HTTP will catch.
#[derive(Clone, Copy, Debug)]
pub struct RangeRequest<'a> {
    /// 📐 The `Range` header value, such as `bytes=0-499`.
    pub range: &'a str,
    /// 🏷️ The `If-Range` header value, when the client sent one.
    pub if_range: Option<&'a str>,
}

/// 🏷️ Evaluates `If-Range` (RFC 9110 §13.1.5): `true` means honour `Range`,
/// `false` means ignore it and send the whole file with 200.
///
/// - No `If-Range` at all is unconditional, so the range is honoured.
/// - An entity tag must match `etag` under the *strong* comparison: byte for
///   byte, and neither side weak. A `W/` tag never matches.
/// - An HTTP date must equal the `Last-Modified` value exactly, and must be a
///   strong validator. A one-second date is strong only if the file cannot
///   have changed twice within that second; the file's current mtime is the
///   only evidence available, so a date is trusted once `now` is at least one
///   second past it. A file edited in the last second answers 200 — the safe
///   side, since a full body is always correct.
///
/// 📌 Uncertain residue, stated plainly: a client that fetched the file in the
/// very second it was edited, then edited again inside that same second, and
/// later resumed with the date, would be trusted. RFC 9110 forbids that client
/// from sending such a date (its `Date` and `Last-Modified` were within one
/// second, so the date was never strong), and the entity tag — which every
/// response here carries — has no such gap.
pub(super) fn if_range_holds(
    if_range: Option<&str>,
    etag: &HeaderValue,
    last_modified: Option<&HeaderValue>,
    modified: Option<SystemTime>,
    now: SystemTime,
) -> bool {
    let Some(value) = if_range.map(str::trim) else {
        return true;
    };
    if value.starts_with("W/") {
        return false;
    }
    if value.starts_with('"') {
        let etag = etag.as_bytes();
        return !etag.starts_with(b"W/") && etag == value.as_bytes();
    }
    let (Some(last_modified), Some(modified)) = (last_modified, modified) else {
        return false;
    };
    last_modified.as_bytes() == value.as_bytes()
        && now
            .duration_since(modified)
            .is_ok_and(|age| age >= Duration::from_secs(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATE: &str = "Tue, 22 Sep 2026 10:00:00 GMT";

    fn holds(if_range: Option<&str>, etag: &str, age: Duration) -> bool {
        let modified = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        if_range_holds(
            if_range,
            &HeaderValue::from_str(etag).unwrap(),
            Some(&HeaderValue::from_static(DATE)),
            Some(modified),
            modified + age,
        )
    }

    #[test]
    fn if_range_uses_strong_comparison_and_strong_dates_only() {
        let old = Duration::from_secs(5);
        // 🎯 Each row is one clause of §13.1.5.
        let cases = [
            (None, "\"a\"", old, true),
            (Some("\"a\""), "\"a\"", old, true),
            (Some("\"b\""), "\"a\"", old, false),
            (Some("W/\"a\""), "\"a\"", old, false),
            (Some("W/\"a\""), "W/\"a\"", old, false),
            (Some("\"a\""), "W/\"a\"", old, false),
            (Some(DATE), "\"a\"", old, true),
            (Some("Tue, 22 Sep 2026 10:00:01 GMT"), "\"a\"", old, false),
            (Some(DATE), "\"a\"", Duration::from_millis(300), false),
        ];
        let got: Vec<_> = cases
            .iter()
            .map(|&(if_range, etag, age, _)| holds(if_range, etag, age))
            .collect();
        let want: Vec<_> = cases.iter().map(|case| case.3).collect();
        assert_eq!(got, want);
    }

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

    /// 🕰️ Two writes inside the same second must not share a tag.
    ///
    /// 🤡 The mtime component used to be whole seconds, so a deploy that wrote
    /// the same file twice within one second left the second version with the
    /// first one's validator: an `If-None-Match` from a client that had already
    /// fetched the old bytes answered `304`, and the client kept the stale copy
    /// for as long as the tag held. Nanoseconds are what buys the distinction,
    /// and this is the assertion of that property rather than of the string
    /// format.
    #[test]
    fn a_second_write_inside_the_same_second_gets_a_different_tag() {
        // 🔢 Same size, same whole second, one nanosecond apart: this is the
        // pair whole-second resolution could not tell apart, and the pair a
        // deploy that writes a file twice in quick succession produces.
        let first = EntityTags::derive(0x1f, 1_700_000_000_000_000_000, None);
        let next_nanosecond = EntityTags::derive(0x1f, 1_700_000_000_000_000_001, None);
        assert_eq!(
            first.for_coding(None).to_str().unwrap().split('-').next(),
            next_nanosecond
                .for_coding(None)
                .to_str()
                .unwrap()
                .split('-')
                .next(),
            "the size half is the same, so only the time half can distinguish these"
        );
        assert_ne!(
            first.for_coding(None),
            next_nanosecond.for_coding(None),
            "a same-size edit inside one second must change the validator"
        );

        // 📌 And a later second still differs, so the fix was not bought by
        // dropping the time component out of the tag.
        let next_second = EntityTags::derive(0x1f, 1_700_000_001_000_000_000, None);
        assert_ne!(first.for_coding(None), next_second.for_coding(None));
    }

    #[test]
    fn a_sidecar_tag_keeps_its_own_shape_per_coding() {
        let strong = EntityTags::derive(1, 1, SidecarTag::parse("\"abc\"".to_string()));
        assert_eq!(strong.for_coding(Some("gzip")), "\"abc-gzip\"");
        let weak = EntityTags::derive(1, 1, SidecarTag::parse("W/\"abc\"".to_string()));
        assert_eq!(weak.for_coding(Some("br")), "W/\"abc-br\"");
        assert_eq!(weak.for_coding(None), "W/\"abc\"");
    }

    #[test]
    fn a_sidecar_tag_must_be_an_entity_tag() {
        // 🎯 §8.8.3: a quoted run of visible bytes, optionally weak.
        let cases = [
            ("\"abc\"", true),
            ("W/\"abc\"", true),
            ("\"\"", true),
            ("\"caf\u{e9}\"", true),
            ("\"abc\"\n\"def\"", false),
            ("\"a\rb\"", false),
            ("\"a b\"", false),
            ("\"a\"b\"", false),
            ("\"abc", false),
            ("abc", false),
        ];
        let got: Vec<_> = cases
            .iter()
            .map(|&(tag, _)| (tag, SidecarTag::parse(tag.to_string()).is_some()))
            .collect();
        assert_eq!(got, cases);
    }
}
