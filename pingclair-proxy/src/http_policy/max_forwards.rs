// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 `TRACE` and `Max-Forwards`: which requests this hop must answer itself.
//!
//! RFC 9110 §7.6.2 lets a client ask "how far does this request get?" by
//! sending `TRACE` or `OPTIONS` with a hop budget in `Max-Forwards`. Every
//! intermediary spends one unit, and the hop that receives zero answers
//! instead of forwarding. Both transports ask the same two questions here, so
//! HTTP/1.1, HTTP/2 and HTTP/3 cannot drift apart.
//!
//! `TRACE` is refused outright rather than reflected. A reflected `TRACE`
//! echoes the request's `Cookie` and `Authorization` back in a response body,
//! which is how cross-site tracing read cookies a script was not allowed to.
//!
//! 🔌 `CONNECT` stops here too. It asks this hop to become a blind tunnel to
//! another host (RFC 9110 §9.3.6), which is a forward proxy's job; this server
//! is a reverse proxy and never opens one. The method is understood and simply
//! not offered, so the answer is 405 with `Allow` on every transport rather
//! than a 404 from routing or a 501 on one protocol only.

use http::{HeaderMap, Method, header::MAX_FORWARDS};

/// 🧭 The methods a locally answered `OPTIONS` or refused `TRACE` advertises.
///
/// 📌 This is the general-purpose set rather than a per-route answer: the hop
/// that answers has not dispatched to a handler, so it cannot know which
/// methods the resource behind it takes. It never includes `TRACE`.
pub(crate) const ALLOWED_METHODS: &str = "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS";

/// 🧭 A request this hop answers itself instead of routing or forwarding it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalHopAnswer {
    /// 🚫 `TRACE`, whatever its `Max-Forwards`: 405 with `Allow`.
    TraceRefused,
    /// 🧭 `OPTIONS` with `Max-Forwards: 0`: this hop is the final recipient
    /// and answers 200 with `Allow`.
    OptionsFinalRecipient,
    /// 🔌 `CONNECT`: this server opens no tunnels, so 405 with `Allow`.
    ConnectRefused,
}

impl LocalHopAnswer {
    /// 🧭 The status code the local answer carries.
    pub(crate) fn status(self) -> u16 {
        match self {
            Self::TraceRefused | Self::ConnectRefused => 405,
            Self::OptionsFinalRecipient => 200,
        }
    }
}

/// 🧭 Whether this request stops here. `None` means route it as usual.
pub(crate) fn local_hop_answer(method: &Method, headers: &HeaderMap) -> Option<LocalHopAnswer> {
    if method == Method::TRACE {
        return Some(LocalHopAnswer::TraceRefused);
    }
    if method == Method::CONNECT {
        return Some(LocalHopAnswer::ConnectRefused);
    }
    if method == Method::OPTIONS && max_forwards(headers) == Some(0) {
        return Some(LocalHopAnswer::OptionsFinalRecipient);
    }
    None
}

/// 🧭 The `Max-Forwards` value an `OPTIONS` request leaves with, one less than
/// it arrived with. `None` means leave the field as received: another method,
/// no field, or a value that is not a number.
///
/// Zero never reaches this point because [`local_hop_answer`] already
/// answered it, but it maps to `None` rather than underflowing regardless.
pub(crate) fn forwarded_max_forwards(method: &Method, headers: &HeaderMap) -> Option<u64> {
    if method != Method::OPTIONS {
        return None;
    }
    max_forwards(headers)?.checked_sub(1)
}

/// 🧭 Reads `Max-Forwards` as `1*DIGIT` straight from the field bytes.
///
/// ⚡ No `to_str()` and no `parse()`: the digits are folded in place, and a
/// value too large for `u64` saturates, since any budget that large is
/// already more hops than a request will ever take.
fn max_forwards(headers: &HeaderMap) -> Option<u64> {
    let bytes = headers.get(MAX_FORWARDS)?.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0u64, |total, &byte| {
        byte.is_ascii_digit().then(|| {
            total
                .saturating_mul(10)
                .saturating_add(u64::from(byte - b'0'))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(max_forwards: Option<&'static str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(value) = max_forwards {
            headers.insert(MAX_FORWARDS, value.parse().unwrap());
        }
        headers
    }

    /// 🚫 `TRACE` stops here with any budget, including none.
    #[test]
    fn trace_is_always_refused() {
        for value in [None, Some("0"), Some("5")] {
            assert_eq!(
                local_hop_answer(&Method::TRACE, &headers(value)),
                Some(LocalHopAnswer::TraceRefused),
                "{value:?}"
            );
        }
    }

    /// 🔌 `CONNECT` stops here whatever else the request carries.
    #[test]
    fn connect_is_always_refused() {
        assert_eq!(
            local_hop_answer(&Method::CONNECT, &headers(Some("5"))),
            Some(LocalHopAnswer::ConnectRefused)
        );
        assert_eq!(LocalHopAnswer::ConnectRefused.status(), 405);
    }

    /// 🧭 Only a zero budget makes this hop the final recipient of `OPTIONS`,
    /// and every other budget leaves one smaller.
    #[test]
    fn options_budget_is_spent_or_answered() {
        let cases = [
            (None, None, None),
            (Some("0"), Some(LocalHopAnswer::OptionsFinalRecipient), None),
            (Some("1"), None, Some(0)),
            (Some("10"), None, Some(9)),
            (Some("99999999999999999999999"), None, Some(u64::MAX - 1)),
            (Some("-1"), None, None),
            (Some("1 "), None, None),
            (Some(""), None, None),
        ];
        for (value, answer, forwarded) in cases {
            let headers = headers(value);
            assert_eq!(
                (
                    local_hop_answer(&Method::OPTIONS, &headers),
                    forwarded_max_forwards(&Method::OPTIONS, &headers),
                ),
                (answer, forwarded),
                "{value:?}"
            );
        }
    }

    /// 🧭 Other methods keep whatever `Max-Forwards` they carried.
    #[test]
    fn other_methods_are_untouched() {
        let headers = headers(Some("0"));
        assert_eq!(
            (
                local_hop_answer(&Method::GET, &headers),
                forwarded_max_forwards(&Method::GET, &headers),
            ),
            (None, None)
        );
    }
}
