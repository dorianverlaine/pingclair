// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧾 The `max_headers` and `max_header_bytes` check, shared by both
//! transports.
//!
//! Both limits are totals, so the check sums every field line. RFC 6585 §5
//! separates two reasons for a 431: the fields together are too large, or one
//! field alone is. In the second case the response should say which field, so
//! the client knows what to shrink. The same pass that sums the sizes also
//! remembers the largest single line; only when that one line exceeds the
//! byte limit on its own is it named. A total that no single field accounts
//! for names nothing, because any name chosen there would be a guess.
//!
//! 🏎️ One pass, no allocation: this runs on every request of a site that
//! configured a limit. The field name is copied only when a 431 is sent.

use std::borrow::Cow;

use pingclair_core::config::ResourceLimitsConfig;

/// 🚫 Why a request's header section was refused.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HeaderLimitBreach<'a> {
    /// More field lines than `max_headers` allows.
    TooMany,
    /// The fields together exceed `max_header_bytes`, and no single one does.
    TooLarge,
    /// This one field line alone exceeds `max_header_bytes`.
    FieldTooLarge(&'a str),
}

/// ✂️ The longest field name a response body will repeat. Longer names are
/// cut, so a client cannot make the 431 body as large as its own request.
const MAX_NAMED_FIELD: usize = 64;

impl HeaderLimitBreach<'_> {
    /// 💬 A sentence naming the field at fault, for the 431 body, or `None`
    /// when no single field is.
    ///
    /// 🛡️ Only the name is repeated, never the value, and only when every byte
    /// of it is an RFC 9110 token character: a name that is not a token cannot
    /// be a field name, and echoing it could put markup or control bytes into
    /// the response.
    pub(crate) fn detail(&self) -> Option<Cow<'static, str>> {
        let Self::FieldTooLarge(name) = self else {
            return None;
        };
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return None;
        }
        let shown = &name[..name.len().min(MAX_NAMED_FIELD)];
        let ellipsis = if shown.len() < name.len() { "..." } else { "" };
        Some(Cow::Owned(format!(
            "the {shown}{ellipsis} field alone exceeds the header size limit"
        )))
    }
}

/// 🧾 Checks one request's field lines against the site's limits.
///
/// `fields` yields each field line's name and value length; `count` is the
/// number of lines, which both callers know without iterating.
pub(crate) fn check<'a>(
    limits: &ResourceLimitsConfig,
    count: usize,
    fields: impl Iterator<Item = (&'a str, usize)>,
) -> Option<HeaderLimitBreach<'a>> {
    if limits.max_header_count.is_some_and(|limit| count > limit) {
        return Some(HeaderLimitBreach::TooMany);
    }
    let limit = limits.max_header_bytes?;
    let (total, largest) = fields.fold(
        (0usize, None::<(&str, usize)>),
        |(total, largest), (name, value_len)| {
            let size = name.len().saturating_add(value_len);
            let largest = match largest {
                Some((_, biggest)) if biggest >= size => largest,
                _ => Some((name, size)),
            };
            (total.saturating_add(size), largest)
        },
    );
    if total <= limit {
        return None;
    }
    Some(match largest {
        Some((name, size)) if size > limit => HeaderLimitBreach::FieldTooLarge(name),
        _ => HeaderLimitBreach::TooLarge,
    })
}

/// 🔤 RFC 9110 §5.6.2 `tchar`.
fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(count: Option<usize>, bytes: Option<usize>) -> ResourceLimitsConfig {
        ResourceLimitsConfig {
            max_header_count: count,
            max_header_bytes: bytes,
            ..Default::default()
        }
    }

    fn run<'a>(
        limits: &ResourceLimitsConfig,
        fields: &[(&'a str, usize)],
    ) -> Option<HeaderLimitBreach<'a>> {
        check(limits, fields.len(), fields.iter().copied())
    }

    #[test]
    fn names_a_field_only_when_it_alone_exceeds_the_limit() {
        let limits = limits(None, Some(100));
        assert_eq!(
            run(&limits, &[("host", 10), ("x-big", 200)]),
            Some(HeaderLimitBreach::FieldTooLarge("x-big"))
        );
        // 🎯 Three fields of 60: the total is over, no single field is.
        assert_eq!(
            run(&limits, &[("a", 59), ("b", 59), ("c", 59)]),
            Some(HeaderLimitBreach::TooLarge)
        );
        assert_eq!(run(&limits, &[("host", 10)]), None);
    }

    #[test]
    fn count_is_checked_before_size() {
        let limits = limits(Some(1), Some(10));
        assert_eq!(
            run(&limits, &[("a", 100), ("b", 1)]),
            Some(HeaderLimitBreach::TooMany)
        );
    }

    #[test]
    fn detail_names_only_token_names_and_caps_their_length() {
        assert_eq!(
            HeaderLimitBreach::FieldTooLarge("x-big")
                .detail()
                .as_deref(),
            Some("the x-big field alone exceeds the header size limit")
        );
        assert_eq!(HeaderLimitBreach::FieldTooLarge("<b>").detail(), None);
        assert_eq!(HeaderLimitBreach::TooLarge.detail(), None);
        let long = "x".repeat(200);
        let detail = HeaderLimitBreach::FieldTooLarge(&long).detail().unwrap();
        assert!(
            detail.starts_with(&format!("the {}... field", "x".repeat(64))),
            "{detail}"
        );
    }
}
