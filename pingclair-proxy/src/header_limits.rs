// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧾 The `max_headers` and `max_header_bytes` check, shared by both
//! transports.
//!
//! Both limits are totals, so the check sums the whole head: the field lines
//! **and** the bytes outside them — the HTTP/1 request line, or the HTTP/2 and
//! HTTP/3 pseudo-headers (`:method`, `:target`, `:authority`, `:scheme`), which
//! the field iterator never sees. Before the head was counted, a 256 KiB
//! request-target was admitted with `200` while `max_header_bytes` reported
//! nothing (#326); the request line is now bounded by the same option and
//! answered `414` on its own (the recorded reference reading agrees).
//!
//! RFC 6585 §5 separates two reasons for a 431: the fields together are too
//! large, or one field alone is. In the second case the response should say
//! which field, so the client knows what to shrink. The same pass that sums the
//! sizes also remembers the largest single line; only when that one line
//! exceeds the byte limit on its own is it named. A total that no single field
//! accounts for names nothing, because any name chosen there would be a guess.
//!
//! 🚦 The head bytes decide the status on their own: over the budget before a
//! single field is read is `414`, which is what the request-target deserves
//! (RFC 9112 §3), while an over-budget total that is mostly fields stays `431`.
//!
//! 🏎️ One pass, no allocation: this runs on every request of a site that
//! configured a limit. The field name is copied only when a 431 is sent.
//!
//! 📏 A site that configures nothing now runs under the reference's own
//! defaults — `large_client_header_buffers 4 8k` is 32 KiB of head, and
//! `max_headers` is 1000 fields — so the pass above happens on every request.
//! An explicit `0` means "no bound", which is this project's spelling for off
//! everywhere else; the reference refuses every field at `max_headers 0`
//! instead, a difference recorded in the engineering memory (#58).

use std::borrow::Cow;

use pingclair_core::config::ResourceLimitsConfig;

/// 🧾 The one record a header-limit refusal writes, on every transport.
///
/// The H1/H2 refusal happens inside Pingora's early filter, so the only trace
/// of it was Pingora's own incidental line — and the H3 path builds its
/// refusal itself and left no trace at all, so an operator scraping logs saw
/// every refusal except the QUIC ones (#308). This is the stable record: the
/// transport is a field rather than a different message, and the text matches
/// the sentence H1/H2 already carried, so an existing search keeps working.
pub fn log_refusal(transport: &'static str, status: u16, detail: Option<&str>) {
    tracing::warn!(
        transport,
        status,
        detail = detail.unwrap_or_default(),
        "⛔ request headers exceed configured limits"
    );
}

/// 🚫 Why a request's header section was refused.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HeaderLimitBreach<'a> {
    /// The bytes outside the field lines — the HTTP/1 request line, or the
    /// HTTP/2 and HTTP/3 pseudo-headers — exceed `max_header_bytes` on their
    /// own. Answering 431 here would tell a client to shrink a field it never
    /// sent, so this case is `414`, the status RFC 9112 §3 points at for a
    /// request-target the server will not parse.
    RequestLineTooLarge,
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

/// 📏 The head budget when the site names none: the reference's
/// `large_client_header_buffers` default of four 8 KiB buffers.
pub(crate) const DEFAULT_MAX_HEADER_BYTES: usize = 4 * 8 * 1024;

/// 🔢 The field ceiling when the site names none: the reference's
/// `max_headers` default.
pub(crate) const DEFAULT_MAX_HEADER_COUNT: usize = 1000;

/// 📏 The byte budget this check enforces.
///
/// `Some(0)` is the explicit "no bound"; `None` is the site saying nothing,
/// which now means the reference's default rather than no limit at all.
fn byte_budget(limits: &ResourceLimitsConfig) -> Option<usize> {
    match limits.max_header_bytes {
        Some(0) => None,
        Some(value) => Some(value),
        None => Some(DEFAULT_MAX_HEADER_BYTES),
    }
}

/// 🔢 The field ceiling this check enforces, with the same three states.
fn field_ceiling(limits: &ResourceLimitsConfig) -> Option<usize> {
    match limits.max_header_count {
        Some(0) => None,
        Some(value) => Some(value),
        None => Some(DEFAULT_MAX_HEADER_COUNT),
    }
}

impl HeaderLimitBreach<'_> {
    /// 🚦 The status this breach is answered with.
    pub(crate) fn status(&self) -> u16 {
        match self {
            Self::RequestLineTooLarge => 414,
            Self::TooMany | Self::TooLarge | Self::FieldTooLarge(_) => 431,
        }
    }

    /// 💬 A sentence naming the field at fault, for the 431 body, or `None`
    /// when no single field is.
    ///
    /// 🛡️ Only the name is repeated, never the value, and only when every byte
    /// of it is an RFC 9110 token character: a name that is not a token cannot
    /// be a field name, and echoing it could put markup or control bytes into
    /// the response.
    pub(crate) fn detail(&self) -> Option<Cow<'static, str>> {
        if matches!(self, Self::RequestLineTooLarge) {
            return Some(Cow::Borrowed(
                "the request line alone exceeds the header size limit",
            ));
        }
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
/// `head` is the size of the bytes that are not field lines (the HTTP/1 request
/// line, or the pseudo-headers on HTTP/2 and HTTP/3); `fields` yields each field
/// line's name and value length, and `count` is the number of lines, which both
/// callers know without iterating. The order is the order a server reads them
/// in: the request line first, then the fields.
pub(crate) fn check<'a>(
    limits: &ResourceLimitsConfig,
    head: usize,
    count: usize,
    fields: impl Iterator<Item = (&'a str, usize)>,
) -> Option<HeaderLimitBreach<'a>> {
    let byte_limit = byte_budget(limits);
    // 🚦 With a byte budget, the request line is read before the fields and
    // decides first.
    if let Some(limit) = byte_limit
        && head > limit
    {
        return Some(HeaderLimitBreach::RequestLineTooLarge);
    }
    if field_ceiling(limits).is_some_and(|limit| count > limit) {
        return Some(HeaderLimitBreach::TooMany);
    }
    // 🧾 Either limit stands alone: a site may set the count and nothing else,
    // in which case the count above was the whole check (#328).
    let limit = byte_limit?;
    let (total, largest) = fields.fold(
        (head, None::<(&str, usize)>),
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
/// compiler). Used as the field count when a site switches the ceiling off.
const MAX_CONFIGURABLE_FIELDS: usize = 4096;

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
    let fields = field_ceiling(limits)
        .unwrap_or(MAX_CONFIGURABLE_FIELDS)
        .min(MAX_CONFIGURABLE_FIELDS)
        // 📇 The pseudo-headers are fields to the protocol library even though
        // they are not field lines to us: `:method`, `:scheme`, `:authority`,
        // `:path`, so the section it measures is four overheads larger.
        .saturating_add(PSEUDO_HEADERS);
    byte_budget(limits).map(|limit| {
        limit
            .saturating_mul(2)
            .saturating_add(fields.saturating_mul(PROTOCOL_FIELD_OVERHEAD))
    })
}

/// 📇 The pseudo-headers HTTP/2 and HTTP/3 count (RFC 9113 §8.3, RFC 9114 §4.3).
const PSEUDO_HEADERS: usize = 4;

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
        check(limits, 0, fields.len(), fields.iter().copied())
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
        // 🎯 1024 bytes and 10 fields: twice the limit, plus 32 for each of the
        // ten fields and the four pseudo-headers the library also counts.
        assert_eq!(
            protocol_header_list_limit(&limits(Some(10), Some(1024))),
            Some(2048 + 14 * 32)
        );
        // 📌 No field count configured: the reference's default of 1000.
        assert_eq!(
            protocol_header_list_limit(&limits(None, Some(1024))),
            Some(2048 + 1004 * 32)
        );
        // 📏 No byte budget configured: the reference's 32 KiB applies.
        assert_eq!(
            protocol_header_list_limit(&limits(Some(10), None)),
            Some(2 * 32 * 1024 + 14 * 32)
        );
        // 🔌 An explicit zero switches both bounds off.
        assert_eq!(protocol_header_list_limit(&limits(Some(0), Some(0))), None);
    }

    /// 📏 The reference's defaults apply until the site says otherwise.
    #[test]
    fn the_reference_defaults_apply_until_the_site_says_otherwise() {
        assert_eq!(byte_budget(&limits(None, None)), Some(32 * 1024));
        assert_eq!(field_ceiling(&limits(None, None)), Some(1000));
        assert_eq!(byte_budget(&limits(Some(0), Some(0))), None);
        assert_eq!(field_ceiling(&limits(Some(0), Some(0))), None);
        assert_eq!(byte_budget(&limits(Some(7), Some(4096))), Some(4096));
        assert_eq!(field_ceiling(&limits(Some(7), Some(4096))), Some(7));
    }

    #[test]
    fn a_head_over_the_budget_alone_is_414_and_comes_first() {
        let limits = limits(Some(1), Some(100));
        // 🚦 The request line is read before the fields, so it decides first —
        // even when the field count is also over.
        assert_eq!(
            check(&limits, 200, 5, [("a", 1), ("b", 1)].into_iter()),
            Some(HeaderLimitBreach::RequestLineTooLarge)
        );
        assert_eq!(HeaderLimitBreach::RequestLineTooLarge.status(), 414);
        assert_eq!(
            HeaderLimitBreach::RequestLineTooLarge.detail().as_deref(),
            Some("the request line alone exceeds the header size limit")
        );
        // 📌 Under the budget the head still counts toward the total.
        assert_eq!(
            check(&limits, 80, 1, [("a", 30)].into_iter()),
            Some(HeaderLimitBreach::TooLarge)
        );
        assert_eq!(check(&limits, 60, 1, [("a", 30)].into_iter()), None);
    }

    #[test]
    fn count_is_checked_before_size() {
        let limits = limits(Some(1), Some(10));
        assert_eq!(
            run(&limits, &[("a", 100), ("b", 1)]),
            Some(HeaderLimitBreach::TooMany)
        );
    }

    /// 🔢 A field-count ceiling works on its own.
    ///
    /// Count once sat behind the byte budget's early return, so a site that set
    /// only `max_headers` silently lost the ceiling on every transport (#328).
    #[test]
    fn a_count_budget_alone_is_still_enforced() {
        let count_only = limits(Some(10), None);
        assert_eq!(
            check(&count_only, 40, 11, std::iter::empty()),
            Some(HeaderLimitBreach::TooMany)
        );
        assert_eq!(check(&count_only, 40, 10, std::iter::empty()), None);
        // 📌 Neither budget set is still a no-op.
        assert_eq!(
            check(&limits(None, None), 40, 1_000, std::iter::empty()),
            None
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
