// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🗄️ What the response cache may store, and for how long.
//!
//! The H1/H2 proxy is a shared cache: one stored response is replayed to every
//! later visitor. The rules here decide which upstream responses are safe to
//! share and how long each stays fresh. They are pure functions of a response
//! header, kept apart from the Pingora lifecycle in `server.rs` so the policy
//! can be read, and tested, in one place. H3 has no response cache, so nothing
//! here has a second transport to stay in parity with.

use std::time::Duration;

use http::StatusCode;
use pingora_cache::cache_control::CacheControl;
use pingora_cache::meta::CacheMetaDefaults;
use pingora_http::ResponseHeader;

use crate::server::is_streaming_content_type;

/// 🩹 How long a not-found stays stored when the origin says nothing.
///
/// A shock absorber, not a cache of failure: long enough that a stampede of
/// clients asking for a missing page reaches the origin once, short enough
/// that publishing the page is visible almost at once.
const NEGATIVE_LIFETIME: Duration = Duration::from_secs(10);

/// 🗄️ Tells Pingora which statuses may be stored without an origin lifetime.
///
/// Only whether an entry exists matters here; the durations are replaced by
/// [`heuristic_lifetime`], which also knows the route's `ttl`. Both must list
/// the same statuses, which is why the numbers come from the same place.
///
/// A status absent from this table is stored only when the origin states a
/// lifetime for it. Server errors are absent on purpose (RFC 9111 §4.2.2
/// allows heuristic freshness only for heuristically cacheable statuses):
/// holding an unannounced 503 would pin one upstream hiccup in the cache.
pub(crate) fn cache_defaults() -> &'static CacheMetaDefaults {
    static DEFAULTS: CacheMetaDefaults = CacheMetaDefaults::new(
        |status| match status.as_u16() {
            // 📄 A placeholder: `heuristic_lifetime` substitutes the route's `ttl`.
            200 => Some(Duration::from_secs(60)),
            404 | 410 => Some(NEGATIVE_LIFETIME),
            _ => None,
        },
        0,
        0,
    );
    &DEFAULTS
}

/// ⏳ How long a response stays fresh when the origin stated no lifetime.
///
/// The route's `ttl` is the operator's answer for successful content, so a
/// 200 lives exactly that long. A not-found keeps its short negative lifetime,
/// capped by the `ttl` so a route asking for one second never holds anything
/// for ten. Every other status gets `None`: the origin did not say, and
/// guessing is how a 503 used to be stored for the route's whole `ttl`.
pub(crate) fn heuristic_lifetime(status: StatusCode, route_ttl: Duration) -> Option<Duration> {
    match status.as_u16() {
        200 => Some(route_ttl),
        404 | 410 => Some(NEGATIVE_LIFETIME.min(route_ttl)),
        _ => None,
    }
}

/// 🚫 Names the reason a response must not be stored, or `None` if it may be.
///
/// Deliberately a small, explicit list rather than full RFC 9111 evaluation.
/// Each entry answers "would a shared copy of this be wrong or useless?", and
/// anything not understood is refused by the caller's status check rather than
/// guessed at.
pub(crate) fn uncacheable_response_reason(response: &ResponseHeader) -> Option<&'static str> {
    // 🚫 The status decides first, before any freshness directive is read.
    // Pingora's `resp_cacheable` never looks at the status: one
    // `Cache-Control: max-age=300` on a 429 was enough to store the "too many
    // requests" page and replay it to every visitor for five minutes, turning
    // one rate-limited moment into a site-wide outage. RFC 6585 says 428, 429,
    // 431 and 511 "MUST NOT be stored by a cache", whatever they claim about
    // their own freshness.
    if !status_may_be_stored(response.status.as_u16()) {
        return Some("status is never stored");
    }

    // 🍪 A response that sets a cookie is establishing per-client state. Storing
    // it hands the same cookie to everyone who follows. RFC 9111 permits a
    // shared cache to store it; doing so safely means stripping the field, and
    // a cache that silently edits responses is worse than one that declines.
    if response.headers.contains_key("set-cookie") {
        return Some("response sets a cookie");
    }

    // 🌊 A streaming media type is consumed as it arrives and never ends on a
    // useful boundary. Storing it means holding the whole thing in memory —
    // the exact shape of the bug this project shipped twice, once for static
    // gzip and once for reverse-proxy SSE.
    if response
        .headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(is_streaming_content_type)
    {
        return Some("response is a stream");
    }

    // 🔀 `Vary: *` says no two requests are interchangeable, so no stored copy
    // can ever be reused. Named fields are handled by `cache_vary_filter`.
    if response
        .headers
        .get_all("vary")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.split(',').any(|name| name.trim() == "*"))
    {
        return Some("response varies on everything");
    }

    // 🗜️ An origin that encoded the body itself produced one specific coding.
    // Serving that stored copy to a client which did not ask for it hands over
    // bytes it cannot decode, and the cache key alone cannot tell them apart —
    // only a `Vary: Accept-Encoding` from the origin makes the variants
    // distinguishable. Our own compression is not affected: it runs after the
    // cache stores the original, so every client is encoded on the way out.
    if response.headers.contains_key("content-encoding")
        && !response
            .headers
            .get_all("vary")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|value| {
                value
                    .split(',')
                    .any(|name| name.trim().eq_ignore_ascii_case("accept-encoding"))
            })
    {
        return Some("origin-encoded response without Vary: Accept-Encoding");
    }

    None
}

/// 🛡️ Lists the statuses this cache may store at all.
///
/// An allowlist rather than a list of forbidden codes, because the dangerous
/// statuses are the ones nobody thought of: a new code added to the protocol,
/// or an origin inventing one, should be refused until someone decides what a
/// shared copy of it means. The list is RFC 9110 §15.1's heuristically
/// cacheable codes, plus the temporary redirects and gateway errors that may
/// be stored when the origin states a lifetime for them.
///
/// 🧩 206 is absent on purpose: this cache does not assemble ranges, so a
/// stored fragment would be served as if it were the whole body. So are 428,
/// 429, 431 and 511 (RFC 6585 forbids storing them) and every 1xx.
fn status_may_be_stored(status: u16) -> bool {
    matches!(
        status,
        200 | 203
            | 204
            | 300
            | 301
            | 302
            | 307
            | 308
            | 404
            | 405
            | 410
            | 414
            | 500
            | 501
            | 502
            | 503
            | 504
    )
}

/// ⏳ Reports whether the origin declared how long its response stays fresh.
///
/// Only then does the origin's lifetime take precedence over the route's `ttl`.
/// `Age` alone does not count: it says how long a response has already been
/// held, not how long it remains valid.
pub(crate) fn origin_stated_its_own_freshness(
    cache_control: Option<&CacheControl>,
    response: &ResponseHeader,
) -> bool {
    if let Some(cache_control) = cache_control
        && (cache_control.has_key("max-age")
            || cache_control.has_key("s-maxage")
            || cache_control.no_cache())
    {
        return true;
    }
    response.headers.contains_key("expires")
}
