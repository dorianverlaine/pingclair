// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🏷️ Conditional requests (RFC 9110 §13): the client says "only do this if
//! the file is (or is not) still the version I know", and the server keeps
//! that promise before it sends a single byte.
//!
//! Two jobs depend on it. A browser revalidating its cache sends
//! `If-None-Match` with the `ETag` it holds, and a `304 Not Modified` saves
//! re-downloading a file it already has. An editor saving over a file sends
//! `If-Match`, and a `412 Precondition Failed` is what stops it overwriting
//! someone else's newer edit. Sending validators without ever reading them
//! back, which this server used to do, gives clients neither.
//!
//! Evaluation happens once per conditional request, after the file's metadata
//! is known and before any body is read. A request without any `If-*` field,
//! which is nearly all of them, costs one map lookup per field and nothing
//! else.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use http::header::{self, HeaderName};
use http::{HeaderMap, HeaderValue, Method};

use super::cache::FileMeta;
use super::serve::RangeDecision;
use super::validators;
use super::{FileServer, NotModified, ServedResponse};

// MARK: - Request

/// 📨 What the file server reads from a request: its method, and its header
/// fields (`Range`, `If-Range`, and the four preconditions).
///
/// Borrowed as a whole rather than copied field by field, because a
/// precondition can arrive on several header lines (a cache revalidating
/// three stored variants sends three tags), and only the full map keeps all
/// of them. Both transports hand over the map they already hold, so building
/// this costs nothing.
#[derive(Clone, Copy, Debug)]
pub struct FileRequest<'a> {
    /// 🧭 The request method: `GET` and `HEAD` get `304`, others `412`.
    pub method: &'a Method,
    /// 📋 The request header fields.
    pub headers: &'a HeaderMap,
}

impl<'a> FileRequest<'a> {
    /// 📨 A request for `method` carrying `headers`.
    pub fn new(method: &'a Method, headers: &'a HeaderMap) -> Self {
        Self { method, headers }
    }

    /// 🧪 A plain `GET` with no header fields, for tests that are not about
    /// conditions or ranges.
    #[cfg(test)]
    pub(super) fn plain() -> FileRequest<'static> {
        static EMPTY: std::sync::LazyLock<HeaderMap> = std::sync::LazyLock::new(HeaderMap::new);
        FileRequest::new(&Method::GET, &EMPTY)
    }

    /// 📋 The first line of a field, when it is text.
    fn field(&self, name: HeaderName) -> Option<&'a str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    /// 📐 The `Range` value, such as `bytes=0-499`.
    pub(super) fn range(&self) -> Option<&'a str> {
        self.field(header::RANGE)
    }

    /// 🪟 The `If-Range` validator that says which version of the file a
    /// range is meant to extend.
    pub(super) fn if_range(&self) -> Option<&'a str> {
        self.field(header::IF_RANGE)
    }

    /// 🏷️ Whether evaluating this request needs the entity tag of the
    /// representation that would be sent. Only `If-Match` and
    /// `If-None-Match` compare tags; the date fields do not.
    pub(super) fn compares_entity_tags(&self) -> bool {
        self.headers.contains_key(header::IF_MATCH)
            || self.headers.contains_key(header::IF_NONE_MATCH)
    }

    /// 🧭 `GET` and `HEAD`: the methods a file is served to, and the ones for
    /// which a failed `If-None-Match` means "you already have it" rather than
    /// "refused".
    pub(super) fn is_retrieval(&self) -> bool {
        matches!(*self.method, Method::GET | Method::HEAD)
    }

    /// 🕳️ Whether the request carries any precondition at all.
    fn has_preconditions(&self) -> bool {
        [
            header::IF_MATCH,
            header::IF_NONE_MATCH,
            header::IF_MODIFIED_SINCE,
            header::IF_UNMODIFIED_SINCE,
        ]
        .iter()
        .any(|name| self.headers.contains_key(name))
    }
}

// MARK: - Answering

impl FileServer {
    /// 🏷️ Answers a conditional request with `304` or `412`, or `None` to
    /// serve it normally.
    pub(super) async fn evaluate_preconditions(
        &self,
        request: &FileRequest<'_>,
        file_path: &Path,
        file_size: u64,
        meta: &FileMeta,
        accept_encoding: Option<&str>,
    ) -> Option<ServedResponse> {
        // 🕳️ The overwhelmingly common case: nothing to evaluate.
        if !request.has_preconditions() {
            return None;
        }
        let coding = if request.compares_entity_tags() {
            self.selected_coding(request, file_path, file_size, meta, accept_encoding)
                .await
        } else {
            None
        };
        let etag = meta.etags.for_coding(coding);
        match evaluate(request, etag, meta.modified) {
            Precondition::Proceed => None,
            Precondition::NotModified => Some(ServedResponse::NotModified(NotModified {
                etag: etag.clone(),
                last_modified: meta.last_modified.clone(),
                vary_accept_encoding: self.config.varies_by_accept_encoding(),
            })),
            Precondition::Failed => Some(ServedResponse::PreconditionFailed),
        }
    }

    /// 🗜️ The content coding of the body this request would receive, which
    /// decides the tag its conditions are compared with: each coding has its
    /// own strong tag, and a cache revalidating its gzip copy must be matched
    /// against the gzip tag, not the identity one.
    ///
    /// Mirrors the order `serve_auto` serves in: a range that will be honoured
    /// is always identity, then a precompressed sidecar, then on-the-fly
    /// compression. 📌 The sidecar probe repeats a `stat` that `serve_auto`
    /// makes again when the answer is 200. It only runs for a request that
    /// sent a tag condition, and the usual outcome there is a 304 that reads
    /// no body at all, so the extra `stat` buys skipping the whole read.
    async fn selected_coding(
        &self,
        request: &FileRequest<'_>,
        file_path: &Path,
        file_size: u64,
        meta: &FileMeta,
        accept_encoding: Option<&str>,
    ) -> Option<&'static str> {
        if let Some(range) = request.range()
            && validators::if_range_holds(
                request.if_range(),
                meta.etags.for_coding(None),
                meta.last_modified.as_ref(),
                meta.modified,
                SystemTime::now(),
            )
            && matches!(
                self.parse_range(range, file_size),
                RangeDecision::Satisfied { .. }
            )
        {
            return None;
        }
        if !self.config.precompressed.is_empty()
            && let Some((_, _, encoding)) = self.try_precompressed(file_path, accept_encoding).await
        {
            return Some(encoding);
        }
        if self.would_compress(file_size, accept_encoding) {
            return Self::negotiate_encoding(accept_encoding);
        }
        None
    }
}

// MARK: - Evaluation

/// 🏷️ What the preconditions decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Precondition {
    /// 👍 Every condition held, or none was sent: serve normally.
    Proceed,
    /// 🧊 The client already has this version: answer `304`.
    NotModified,
    /// 🚫 The client's condition failed: answer `412`.
    Failed,
}

/// 🏷️ Evaluates the preconditions in RFC 9110 §13.2.2's order against the
/// representation that would be sent.
///
/// - `If-Match` uses the strong comparison, because it guards a change: a
///   weak tag only promises "equivalent", not "the bytes you are about to
///   overwrite". Without `If-Match`, `If-Unmodified-Since` stands in for it.
/// - `If-None-Match` uses the weak comparison, because it guards a cached
///   copy, and an equivalent copy is good enough to keep. It answers `304` to
///   `GET` and `HEAD` and `412` to anything else. Without it,
///   `If-Modified-Since` stands in, for `GET` and `HEAD` only (§13.1.3).
///
/// A date that does not parse is ignored, as §13.1.3 and §13.1.4 require: a
/// malformed condition is not a failed one. Dates compare at whole seconds,
/// the resolution `Last-Modified` was sent with.
pub(super) fn evaluate(
    request: &FileRequest<'_>,
    etag: &HeaderValue,
    modified: Option<SystemTime>,
) -> Precondition {
    let headers = request.headers;
    // 🔢 Step 1 and 2: the conditions that guard a change.
    if headers.contains_key(header::IF_MATCH) {
        if !any_tag_matches(headers, header::IF_MATCH, etag, Comparison::Strong) {
            return Precondition::Failed;
        }
    } else if let Some(since) = date_field(request, header::IF_UNMODIFIED_SINCE)
        && modified.is_some_and(|modified| seconds(modified) > since)
    {
        return Precondition::Failed;
    }
    // 🔢 Step 3 and 4: the conditions that guard a cached copy.
    if headers.contains_key(header::IF_NONE_MATCH) {
        if any_tag_matches(headers, header::IF_NONE_MATCH, etag, Comparison::Weak) {
            return if request.is_retrieval() {
                Precondition::NotModified
            } else {
                Precondition::Failed
            };
        }
    } else if request.is_retrieval()
        && let Some(since) = date_field(request, header::IF_MODIFIED_SINCE)
        && modified.is_some_and(|modified| seconds(modified) <= since)
    {
        return Precondition::NotModified;
    }
    Precondition::Proceed
}

/// 🕰️ A date condition as whole seconds since the epoch, or `None` when it is
/// absent or not an HTTP date.
fn date_field(request: &FileRequest<'_>, name: HeaderName) -> Option<u64> {
    let value = request.field(name)?;
    httpdate::parse_http_date(value.trim()).ok().map(seconds)
}

/// 🕰️ Whole seconds since the epoch; a time before it counts as zero.
fn seconds(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

// MARK: - Entity-tag lists

/// 🏷️ The two ways RFC 9110 §8.8.3.2 compares entity tags.
#[derive(Clone, Copy)]
enum Comparison {
    /// 🛡️ Byte-for-byte, and neither tag weak.
    Strong,
    /// 🧊 Same opaque value; `W/` on either side is ignored.
    Weak,
}

/// 🏷️ Whether any tag on any line of `name` matches `etag`, or the field is
/// `*`, which matches any current representation, and there is one here.
///
/// Scans the bytes in place rather than splitting on commas: a comma is a
/// legal byte inside an entity tag, so `"a,b"` is one tag, not two.
fn any_tag_matches(
    headers: &HeaderMap,
    name: HeaderName,
    etag: &HeaderValue,
    comparison: Comparison,
) -> bool {
    let (current_weak, current) = split_weak(etag.as_bytes());
    headers.get_all(name).iter().any(|line| {
        let mut rest = line.as_bytes();
        if rest.trim_ascii() == b"*" {
            return true;
        }
        loop {
            rest = rest.trim_ascii_start();
            rest = rest.strip_prefix(b",").unwrap_or(rest).trim_ascii_start();
            let (weak, tail) = split_weak(rest);
            // 🚫 Anything that is not a quoted tag ends the scan: a malformed
            // list cannot be trusted to say which tags it meant.
            let Some(end) = tail
                .strip_prefix(b"\"")
                .and_then(|inner| inner.iter().position(|&b| b == b'"'))
            else {
                return false;
            };
            let opaque = &tail[..end + 2];
            let matched = match comparison {
                Comparison::Strong => !weak && !current_weak && opaque == current,
                Comparison::Weak => opaque == current,
            };
            if matched {
                return true;
            }
            rest = &tail[end + 2..];
        }
    })
}

/// 🏷️ Splits a tag into whether it is weak and its quoted opaque part.
fn split_weak(tag: &[u8]) -> (bool, &[u8]) {
    match tag.strip_prefix(b"W/") {
        Some(opaque) => (true, opaque),
        None => (false, tag),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const MODIFIED: &str = "Tue, 22 Sep 2026 10:00:00 GMT";
    const EARLIER: &str = "Tue, 22 Sep 2026 09:59:59 GMT";

    /// 🧪 A method, its fields, and the outcome they must produce.
    type Case = (
        Method,
        &'static [(&'static str, &'static str)],
        Precondition,
    );

    fn outcome(method: Method, fields: &[(&'static str, &str)]) -> Precondition {
        let mut headers = HeaderMap::new();
        for &(name, value) in fields {
            headers.append(name, HeaderValue::from_str(value).unwrap());
        }
        // 🕰️ Sub-second precision the one-second dates cannot see.
        let modified = httpdate::parse_http_date(MODIFIED).unwrap() + Duration::from_millis(700);
        evaluate(
            &FileRequest::new(&method, &headers),
            &HeaderValue::from_static("\"v1\""),
            Some(modified),
        )
    }

    #[test]
    fn preconditions_follow_the_section_13_2_2_order() {
        use Precondition::{Failed, NotModified, Proceed};
        // 🎯 Each row is one clause of §13.1 or one step of §13.2.2.
        let cases: [Case; 20] = [
            (Method::GET, &[], Proceed),
            (Method::GET, &[("if-match", "\"v1\"")], Proceed),
            (Method::GET, &[("if-match", "\"v0\", \"v1\"")], Proceed),
            (Method::GET, &[("if-match", "*")], Proceed),
            (Method::GET, &[("if-match", "W/\"v1\"")], Failed),
            (Method::GET, &[("if-match", "\"v0\"")], Failed),
            (Method::GET, &[("if-unmodified-since", MODIFIED)], Proceed),
            (Method::GET, &[("if-unmodified-since", EARLIER)], Failed),
            (
                Method::GET,
                &[("if-unmodified-since", "not a date")],
                Proceed,
            ),
            // 🔢 If-Match present: If-Unmodified-Since is not consulted.
            (
                Method::GET,
                &[("if-match", "\"v1\""), ("if-unmodified-since", EARLIER)],
                Proceed,
            ),
            (Method::GET, &[("if-none-match", "W/\"v1\"")], NotModified),
            (
                Method::HEAD,
                &[("if-none-match", "\"v0\", \"v1\"")],
                NotModified,
            ),
            (
                Method::GET,
                &[("if-none-match", "\"v0\""), ("if-none-match", "\"v1\"")],
                NotModified,
            ),
            (Method::POST, &[("if-none-match", "*")], Failed),
            (Method::GET, &[("if-none-match", "\"v0\"")], Proceed),
            (Method::GET, &[("if-modified-since", MODIFIED)], NotModified),
            (Method::GET, &[("if-modified-since", EARLIER)], Proceed),
            (Method::POST, &[("if-modified-since", MODIFIED)], Proceed),
            // 🔢 §13.1.3: If-None-Match replaces If-Modified-Since entirely.
            (
                Method::GET,
                &[("if-none-match", "\"v0\""), ("if-modified-since", MODIFIED)],
                Proceed,
            ),
            // 🔢 A failed If-Match wins over a matching If-None-Match.
            (
                Method::GET,
                &[("if-match", "\"v0\""), ("if-none-match", "\"v1\"")],
                Failed,
            ),
        ];
        let got: Vec<_> = cases
            .iter()
            .map(|(method, fields, _)| outcome(method.clone(), fields))
            .collect();
        let want: Vec<_> = cases.iter().map(|case| case.2).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn a_comma_inside_a_tag_does_not_split_it() {
        let mut headers = HeaderMap::new();
        headers.insert("if-none-match", HeaderValue::from_static("\"a,b\""));
        let tag = HeaderValue::from_static("\"a,b\"");
        assert!(any_tag_matches(
            &headers,
            header::IF_NONE_MATCH,
            &tag,
            Comparison::Weak
        ));
        let other = HeaderValue::from_static("\"a\"");
        assert!(!any_tag_matches(
            &headers,
            header::IF_NONE_MATCH,
            &other,
            Comparison::Weak
        ));
    }
}
