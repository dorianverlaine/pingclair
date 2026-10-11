// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 `Accept`-based negotiation for the file server.
//!
//! The server decides between two representations of a *page*: the HTML the
//! path names, and the sibling Markdown file (`X.md`, or `X/index.md`). The
//! comparison is RFC 9110 §12.5.1's: each representation's quality is the q
//! of the most specific media range that matches it, a member whose q is
//! malformed is ignored, and a type no range matches has quality 0 — which is
//! what makes `text/markdown;q=0, */*;q=1` forbid Markdown while a browser's
//! `*/*;q=0.8` leaves both representations equal and HTML the default.

use http::HeaderValue;

/// 📝 One quality value, in thousandths, so the comparison is exact.
pub(crate) type Quality = u16;

/// 🧭 What one `Accept` header says about the two page representations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PagePreference {
    /// 📝 The quality of `text/markdown`; `None` when no `Accept` was sent.
    pub(crate) markdown: Option<Quality>,
    /// 🌐 The quality of `text/html`; `None` when no `Accept` was sent.
    pub(crate) html: Option<Quality>,
}

impl PagePreference {
    /// 🧭 Reads the header fields once per request.
    pub(crate) fn from_headers(headers: &http::HeaderMap) -> Self {
        let accept = headers
            .get(http::header::ACCEPT)
            .and_then(|value: &HeaderValue| value.to_str().ok())
            // 📌 An empty field carries no ranges at all; reading it as "every
            // representation is refused" would answer 406 to a client that
            // said nothing usable, so it is treated like a missing header.
            .map(str::trim)
            .filter(|value| !value.is_empty());
        Self {
            markdown: quality(accept, "text", "markdown"),
            html: quality(accept, "text", "html"),
        }
    }

    /// 📝 Markdown is served when the client prefers it *strictly*: no
    /// `Accept` at all, or equal quality, keeps the HTML — a tie is a browser
    /// that mentioned neither type by name, and its `*/*` fallback says so.
    pub(crate) fn prefers_markdown(&self) -> bool {
        matches!((self.markdown, self.html), (Some(md), Some(html)) if md > html)
    }

    /// 🚫 Whether the client refused the HTML representation outright.
    pub(crate) fn refuses_html(&self) -> bool {
        self.html == Some(0)
    }
}

/// 📏 The quality this header assigns to `type/subtype`, in thousandths.
///
/// `None` means the request carried no `Accept` header — every representation
/// is then acceptable, and the default applies. A value of 0 means the
/// representation was refused, either by `q=0` or by matching no range.
fn quality(accept: Option<&str>, type_: &str, subtype: &str) -> Option<Quality> {
    let accept = accept?;
    let mut best: Option<(u8, Quality)> = None;
    for member in accept.split(',') {
        let member = member.trim();
        if member.is_empty() {
            continue;
        }
        let mut parts = member.split(';');
        let range = parts.next().unwrap_or("").trim();
        // 🚫 A malformed q makes the whole member unusable, and RFC 9110 says
        // to ignore it rather than guess.
        let Some(member_quality) = member_quality(parts) else {
            continue;
        };
        let Some((range_type, range_subtype)) = range.split_once('/') else {
            continue;
        };
        // 🎯 Most specific reference wins: the exact type, then `type/*`,
        // then `*/*`. Equal specificity keeps the first member.
        let specificity = match (range_type.trim(), range_subtype.trim()) {
            (kind, sub)
                if kind.eq_ignore_ascii_case(type_) && sub.eq_ignore_ascii_case(subtype) =>
            {
                1
            }
            (kind, "*") if kind.eq_ignore_ascii_case(type_) => 2,
            ("*", "*") => 3,
            _ => continue,
        };
        if best.is_none_or(|(known, _)| specificity < known) {
            best = Some((specificity, member_quality));
        }
    }
    Some(best.map_or(0, |(_, quality)| quality))
}

/// 🔢 The `q` parameter of one member, or 1 when it carries none.
fn member_quality<'a>(parameters: impl Iterator<Item = &'a str>) -> Option<Quality> {
    for parameter in parameters {
        let Some((name, value)) = parameter.split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("q") {
            continue;
        }
        return parse_qvalue(value.trim());
    }
    Some(1000)
}

/// 🔢 RFC 9110 §12.4.2's `qvalue`: `0`, `1`, or a decimal with at most three
/// digits below 1. Anything else is refused by the caller.
fn parse_qvalue(text: &str) -> Option<Quality> {
    let (integer, fraction) = text.split_once('.').unwrap_or((text, ""));
    if integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > 3
    {
        return None;
    }
    match integer {
        "1" => {
            if fraction.bytes().all(|byte| byte == b'0') {
                Some(1000)
            } else {
                None
            }
        }
        "0" => {
            let mut digits = fraction.to_string();
            while digits.len() < 3 {
                digits.push('0');
            }
            digits.parse().ok()
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preference(accept: &str) -> PagePreference {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::ACCEPT, HeaderValue::from_str(accept).unwrap());
        PagePreference::from_headers(&headers)
    }

    #[test]
    fn no_accept_header_keeps_html() {
        let preference = PagePreference::from_headers(&http::HeaderMap::new());
        assert_eq!(
            preference,
            PagePreference {
                markdown: None,
                html: None
            }
        );
        assert!(!preference.prefers_markdown());
        assert!(!preference.refuses_html());
    }

    #[test]
    fn a_browser_quality_tie_keeps_html() {
        let preference =
            preference("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        assert_eq!(preference.html, Some(1000));
        // 📌 `*/*;q=0.8` matches text/markdown too — equal is not preferred.
        assert_eq!(preference.markdown, Some(800));
        assert!(!preference.prefers_markdown());
    }

    #[test]
    fn an_explicit_markdown_preference_wins() {
        let preference = preference("text/markdown, text/html;q=0.5");
        assert!(preference.prefers_markdown());
        assert!(!preference.refuses_html());
    }

    #[test]
    fn q_zero_refuses_and_most_specific_range_wins() {
        let refused = preference("text/markdown;q=0, */*;q=1");
        assert_eq!(refused.markdown, Some(0));
        assert_eq!(refused.html, Some(1000));
        assert!(!refused.prefers_markdown());
        let specific = preference("text/*;q=0.2, text/markdown;q=0.9, text/html;q=0.3");
        assert!(specific.prefers_markdown());
        let type_wildcard = preference("text/*;q=0.9, text/html;q=0.4");
        assert_eq!(type_wildcard.markdown, Some(900));
        assert!(type_wildcard.prefers_markdown());
    }

    #[test]
    fn malformed_members_are_ignored() {
        let preference = preference("text/markdown;q=2, text/html;q=bogus, text/markdown");
        assert_eq!(preference.markdown, Some(1000));
        assert_eq!(preference.html, Some(0));
        assert!(preference.prefers_markdown());
    }

    #[test]
    fn an_empty_accept_field_reads_like_a_missing_one() {
        let preference = preference("  ");
        assert_eq!(
            preference,
            PagePreference {
                markdown: None,
                html: None
            }
        );
        assert!(!preference.refuses_html());
    }
}
