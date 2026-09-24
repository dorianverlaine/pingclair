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

/// 📏 What HTTP/2 and HTTP/3 count per field line beyond its name and value
/// (RFC 7541 §4.1, RFC 9114 §4.2.2). This check does not count it, so the
/// protocol libraries' idea of a section's size is always the larger one.
const PROTOCOL_FIELD_OVERHEAD: usize = 32;

/// 🔢 The most field lines a site may allow (`max_headers`, validated in the
/// compiler). Used as the field count when a site sets none.
const MAX_CONFIGURABLE_FIELDS: usize = 256;

/// 🧮 The header-list size to hand the HTTP/2 and HTTP/3 libraries, given the
/// listener's `max_header_bytes`.
///
/// Both libraries refuse an oversized section themselves, before this proxy
/// sees the request: h2 with a bodiless 431, quiche by closing the whole
/// connection with H3_EXCESSIVE_LOAD, taking every other request on it down
/// too. Neither can say which field was at fault. So the libraries get a
/// looser limit and [`check`] makes the real decision, answering 431 on the
/// one request with the field named.
///
/// 🛡️ Looser is still bounded. The allowance is twice the configured limit,
/// which is enough for [`check`] to see and name a field that overshoots it,
/// plus the libraries' 32-byte per-field overhead for as many fields as the
/// site may send. Past that a peer is refused by the library as before, so
/// no client can make the proxy buffer an unbounded header section. With
/// the compiler's ceilings (1 MiB, 256 fields) the result is under 2.1 MiB.
///
/// 📌 Computed once per listener at startup, never per request.
pub fn protocol_header_list_limit(limits: &ResourceLimitsConfig) -> Option<usize> {
    let fields = limits
        .max_header_count
        .unwrap_or(MAX_CONFIGURABLE_FIELDS)
        .min(MAX_CONFIGURABLE_FIELDS);
    limits.max_header_bytes.map(|limit| {
        limit
            .saturating_mul(2)
            .saturating_add(fields.saturating_mul(PROTOCOL_FIELD_OVERHEAD))
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
    fn protocol_limit_leaves_room_for_the_check_to_answer() {
        // 🎯 1024 bytes and 10 fields: twice the limit, plus 32 per field.
        assert_eq!(
            protocol_header_list_limit(&limits(Some(10), Some(1024))),
            Some(2048 + 320)
        );
        // 📌 No field count configured: the compiler's ceiling of 256 fields.
        assert_eq!(
            protocol_header_list_limit(&limits(None, Some(1024))),
            Some(2048 + 256 * 32)
        );
        assert_eq!(protocol_header_list_limit(&limits(Some(10), None)), None);
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
