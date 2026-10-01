// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ⏱️ How long a request body may stall when nothing configures it, on both
//! transports.
//!
//! A client can announce `Content-Length: 999999999999` and then send nothing.
//! A `respond` route reads the announced body before it answers, and with no
//! `body_timeout`, `idle_timeout` or `request_body { read_timeout }` that read
//! had no deadline at all: the client got no response and the connection was
//! held for as long as the client cared to keep it. There used to be a 1 MiB
//! body ceiling by default, which refused that request on its header alone;
//! removing it to match Caddy left nothing else in the way.
//!
//! 📌 This bounds the pause between two pieces of body, not the whole upload,
//! so a large upload over a slow link still finishes as long as it keeps
//! moving. A client that stops is answered 408.

use std::time::Duration;

/// ⏱️ One minute, as nginx's `client_body_timeout` defaults to, with the same
/// meaning: the longest wait between two successive reads.
///
/// 📌 Caddy, recalled from memory on 2026-10-02 (`modules/caddyhttp/app.go`,
/// v2.x), sets no default for `read_body`, so its body reads are bounded only
/// by a `ReadTimeout` the operator writes. Caddy does not wait on the body
/// before a `respond` handler answers, though, so it never hung on this
/// request; this server does read first, which is why it needs a bound Caddy
/// can do without.
pub(crate) const DEFAULT_BODY_TIMEOUT: Duration = Duration::from_secs(60);
