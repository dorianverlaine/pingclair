// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ⏱️ How long a request header may take to arrive, start to finish, on every
//! transport.
//!
//! A client that sends its request header a byte at a time and never finishes
//! holds whatever the server set aside for that request for as long as it keeps
//! trickling. HTTP/1 and HTTP/2 enforce this bound in the binary's connection
//! guard; HTTP/3 enforces it per request stream in `quic.rs`. Both read the
//! value from here, so `limits { header_timeout }` means the same thing on all
//! of them.

use std::time::Duration;

use pingclair_core::config::ResourceLimitsConfig;

/// ⏱️ How long a request header may take when `limits { header_timeout }` is
/// not set.
///
/// One minute, as Caddy's `defaultReadHeaderTimeout` (`modules/caddyhttp/app.go`,
/// v2.x, recalled from memory on 2026-10-02 rather than re-read) and nginx's
/// `client_header_timeout`. A header is usually under a kilobyte, so a minute
/// is generous even for a very slow link, while still letting go of a client
/// that never finishes.
pub const DEFAULT_HEADER_TIMEOUT: Duration = Duration::from_secs(60);

/// ⏱️ The header deadline a listener with these limits enforces: the configured
/// `header_timeout`, or [`DEFAULT_HEADER_TIMEOUT`] when there is none.
///
/// 📌 Called once per listener or per connection, never per request.
pub fn resolve(limits: &ResourceLimitsConfig) -> Duration {
    limits
        .header_timeout_ms
        .map_or(DEFAULT_HEADER_TIMEOUT, Duration::from_millis)
}
