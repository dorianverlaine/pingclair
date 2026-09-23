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

use pingora_cache::cache_control::CacheControl;
use pingora_cache::meta::CacheMetaDefaults;
use pingora_http::ResponseHeader;

use crate::server::is_streaming_content_type;

/// 🗄️ Default freshness per status, used when the origin states none.
///
/// The negative entries are the point. An origin that starts failing gets
/// hammered by every client at once precisely when it can least afford it,
/// so a not-found or a server error is worth holding briefly — long enough
/// to absorb a stampede, short enough that a fix is visible almost at once.
/// Ten and five seconds are deliberately small: this is a shock absorber,
/// not a cache of failure.
///
/// A status absent from this table is never stored by default. That is why
/// redirects, 206 and everything else fall through rather than being listed
/// with a guessed lifetime.
pub(crate) fn cache_defaults() -> &'static CacheMetaDefaults {
    static DEFAULTS: CacheMetaDefaults = CacheMetaDefaults::new(
        |status| match status.as_u16() {
            // 📄 Success uses a placeholder; the route's `ttl` replaces it
            // whenever the origin did not state a lifetime of its own.
            200 => Some(Duration::from_secs(60)),
            404 | 410 => Some(Duration::from_secs(10)),
            500 | 502 | 503 | 504 => Some(Duration::from_secs(5)),
            _ => None,
        },
        0,
        0,
    );
    &DEFAULTS
}

/// 🚫 Names the reason a response must not be stored, or `None` if it may be.
///
/// Deliberately a small, explicit list rather than full RFC 9111 evaluation.
/// Each entry answers "would a shared copy of this be wrong or useless?", and
/// anything not understood is refused by the caller's status check rather than
/// guessed at.
pub(crate) fn uncacheable_response_reason(response: &ResponseHeader) -> Option<&'static str> {
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
