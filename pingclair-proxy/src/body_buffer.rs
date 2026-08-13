// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧱 Explicit request and response body buffering, with a memory ceiling.
//!
//! `reverse_proxy { request_buffers <size> }` asks this proxy to read the
//! body into memory before handing it on, instead of streaming it through.
//! Operators reach for it when a backend cannot cope with a trickling client:
//! buffering means the upstream connection is only written to once the whole
//! body has arrived, so one slow client occupies this process rather than a
//! backend worker.
//!
//! # 🛡️ Why `unlimited` is not unlimited here
//!
//! The format this DSL follows spells the no-ceiling case `unlimited`, encodes
//! it as `-1`, and reads the whole body into memory — its own implementation
//! prints a warning at load that says, in as many words, that this can crash
//! the process out of memory. A proxy that OOMs because a client chose to send
//! a large body has handed an attacker the whole machine for the price of one
//! request, so `unlimited` here means "buffer as much as this server is
//! willing to hold", and past that point the body **keeps streaming** instead.
//!
//! Falling back to streaming, rather than rejecting, is deliberate: buffering
//! is a compatibility and latency knob, not a limit. The setting that rejects
//! oversized bodies is `request_body max_size`, and it fails closed on its own.
//! Turning a buffering hint into a request-killer would surprise an operator in
//! the expensive direction — 413s on traffic that used to work.
//!
//! # 🪤 Why nothing spills to a temporary file
//!
//! The obvious way to keep "buffer all of it" honest is to hold the first few
//! megabytes in memory and spill the rest to a private file. It does not work
//! on this proxy's HTTP/1.1 and HTTP/2 path, and the reason is worth writing
//! down so nobody re-derives it.
//!
//! Buffering happens inside Pingora's body filters, and a filter is handed one
//! chunk and may hand one chunk back. Releasing a body that was withheld means
//! returning it from the *last* filter call, because after the downstream body
//! is done — `pingora-proxy 0.8.1`, `proxy_h1.rs:411` feeding
//! `DownstreamStateMachine::maybe_finished` — the loop stops polling downstream
//! and the filter is never called again. So a spilled body would have to be
//! read back into one contiguous buffer to be released at all, and peak memory
//! would be exactly what it was without the file. The disk write would buy
//! nothing and cost a new file-descriptor and permissions surface.
//!
//! Checked against `pingora-proxy 0.8.1` and `pingora-core 0.8.1` on
//! 2026-08-13: `ProxyHttp::request_body_filter` / `upstream_response_body_filter`
//! (`proxy_trait.rs`) are the only body hooks, and neither can emit more than
//! one chunk per call. Writing directly to the session from inside a filter
//! was considered and rejected on the same day: the task pipeline in
//! `proxy_h1.rs:1209` (`response_duplex_vec` → `buffer_body_data`) owns the
//! downstream body writer's framing state, and interleaving a second writer
//! with it corrupts chunked framing in ways no test would catch reliably.
//!
//! # 🪤 The one that bites
//!
//! On the request side a filter withholds a chunk by handing back an **empty**
//! `Bytes`, never `None`. `proxy_h1.rs:774` recomputes end-of-body as
//! `end_of_body || data.is_none()` *after* the filter runs, so a `None` is read
//! as "the client is finished" and the upstream request body ends early — with
//! no error anywhere, and a truncated body at the backend. The response side
//! carries its own end-of-stream flag past the filter (`lib.rs:382`), so
//! `None` is safe there; this module hands back an empty `Bytes` on both sides
//! anyway, because a rule with an exception is a rule that gets misremembered.

use bytes::{Bytes, BytesMut};

use crate::upstream_failure::FailureLogThrottle;

// MARK: - Ceiling

/// 🛡️ The most this proxy will hold in memory for one buffered body.
///
/// Eight mebibytes is chosen to be generous for what buffering is actually
/// for — form posts, API payloads, JSON documents — while staying small
/// enough that a few thousand concurrent buffered requests cannot exhaust a
/// modest box. It is a constant rather than a setting because it is not a
/// per-site policy: it is this server's own promise that a configuration
/// cannot talk it into unbounded memory.
pub(crate) const MAX_BUFFERED_BODY_BYTES: usize = 8 * 1024 * 1024;

/// 🧭 Turns a configured ceiling into the number of bytes actually held.
///
/// `None` and `0` both mean "stream, do not buffer" — the same encoding the
/// format uses. `-1` is `unlimited`, which this server reads as its own
/// ceiling. A positive value larger than the ceiling is clamped, and the
/// clamp is reported at load time by [`describe_clamp`] rather than silently.
pub(crate) fn resolve_limit(configured: Option<i64>) -> Option<usize> {
    match configured {
        None | Some(0) => None,
        // 🧱 `unlimited` asks us to drop the operator's ceiling, not ours.
        Some(value) if value < 0 => Some(MAX_BUFFERED_BODY_BYTES),
        Some(value) => Some((value as u64).min(MAX_BUFFERED_BODY_BYTES as u64) as usize),
    }
}

/// 🧭 The load-time sentence for a ceiling this server will not honour in full,
/// or `None` when the configured value is used verbatim.
pub(crate) fn describe_clamp(configured: Option<i64>) -> Option<String> {
    match configured {
        Some(value) if value < 0 => Some(format!(
            "`unlimited` buffers up to {} bytes here and streams the rest; \
             this server does not read a whole body into memory on request",
            MAX_BUFFERED_BODY_BYTES
        )),
        Some(value) if value as u64 > MAX_BUFFERED_BODY_BYTES as u64 => Some(format!(
            "{value} bytes exceeds this server's {MAX_BUFFERED_BODY_BYTES}-byte \
             buffering ceiling; the remainder of a larger body streams"
        )),
        _ => None,
    }
}

/// 🧯 One line per second, process-wide, when a body outgrows its buffer.
///
/// Overflow is a property of traffic rather than of configuration, so it
/// cannot be reported at load time — but it changes what the operator asked
/// for, so it must not be invisible either.
static BUFFER_OVERFLOW_LOG: FailureLogThrottle = FailureLogThrottle::new();

/// 🧯 Reports, at most once a second, that a body has fallen back to streaming.
///
/// Called on the transition only. A body that overflows keeps streaming for
/// every later chunk, and a line per chunk would bury the one fact worth
/// reading: this route is configured to buffer and this traffic does not fit.
pub(crate) fn report_overflow(direction: &'static str, limit: usize) {
    if let Some(suppressed) = BUFFER_OVERFLOW_LOG.admit_now() {
        tracing::warn!(
            direction,
            buffer_bytes = limit,
            suppressed,
            "🧱 A body outgrew its buffer; the remainder is streaming"
        );
    }
}

// MARK: - The buffer

/// 🧱 Holds a body up to a ceiling, then gets out of the way.
///
/// The state machine has exactly two states and one transition. While
/// *holding*, every chunk offered is retained and nothing is emitted. The
/// moment the retained bytes reach the ceiling the buffer *releases*
/// everything it holds and never holds again, so the rest of the body streams
/// chunk by chunk exactly as if buffering had been off.
///
/// That transition is also what the format's own positive-size case does — a
/// `request_buffers 4KB` buffers the first four kilobytes and streams the
/// remainder — so one state machine covers both the sized case and the
/// ceiling this server imposes on `unlimited`.
pub(crate) struct BufferedBody {
    limit: usize,
    held: BytesMut,
    /// Once true, chunks pass straight through. Never returns to false: a body
    /// half-buffered and half-streamed must not start re-buffering later, or
    /// the bytes would arrive out of order.
    releasing: bool,
    overflowed: bool,
}

impl BufferedBody {
    /// 🧱 A buffer that holds up to `limit` bytes.
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            held: BytesMut::new(),
            releasing: false,
            overflowed: false,
        }
    }

    /// 📥 Offers one chunk; returns what should be forwarded now.
    ///
    /// `None` means the chunk is being held — the caller must forward nothing,
    /// and on Pingora's request path that means an empty `Bytes` rather than
    /// `None` (see the module header).
    ///
    /// The released chunk can exceed `limit` by up to one offered chunk. That
    /// is deliberate: splitting the buffer exactly at the ceiling would copy
    /// the remainder into a second allocation on a path whose whole purpose is
    /// to bound memory, and the bound that matters is "one ceiling plus one
    /// chunk", not "one ceiling exactly".
    pub(crate) fn offer(&mut self, chunk: Bytes) -> Option<Bytes> {
        if self.releasing {
            return Some(chunk);
        }
        self.held.extend_from_slice(&chunk);
        if self.held.len() >= self.limit {
            self.releasing = true;
            self.overflowed = true;
            return Some(self.held.split().freeze());
        }
        None
    }

    /// 📤 Everything still held, at end of stream.
    ///
    /// Returns `None` when there is nothing left, which is both the "body was
    /// empty" case and the "already released" case. Callers on the request
    /// path must still forward an empty `Bytes` in that case, never `None`.
    pub(crate) fn finish(&mut self) -> Option<Bytes> {
        self.releasing = true;
        if self.held.is_empty() {
            None
        } else {
            Some(self.held.split().freeze())
        }
    }

    /// 🧭 Whether this body outgrew the buffer and fell back to streaming.
    pub(crate) fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// 🧾 The ceiling this buffer was built with, for the overflow report.
    pub(crate) fn limit(&self) -> usize {
        self.limit
    }
}

// MARK: - Tests

#[cfg(test)]
mod tests {
    use super::*;

    /// 🎯 The security property in one assertion: a body far larger than the
    /// ceiling never leaves more than a ceiling's worth held.
    #[test]
    fn a_body_larger_than_the_ceiling_is_never_held_whole() {
        let mut buffer = BufferedBody::new(1024);
        let mut emitted = 0usize;
        let mut peak_held = 0usize;
        for _ in 0..2048 {
            let released = buffer.offer(Bytes::from_static(&[b'x'; 64]));
            peak_held = peak_held.max(buffer.held.len());
            emitted += released.map_or(0, |chunk| chunk.len());
        }
        emitted += buffer.finish().map_or(0, |chunk| chunk.len());
        assert_eq!(emitted, 2048 * 64, "every byte must still be forwarded");
        assert!(
            peak_held <= 1024,
            "held {peak_held} bytes, ceiling was 1024"
        );
        assert!(buffer.overflowed());
    }

    /// 🧱 A body that fits is emitted once, at the end, and not before.
    #[test]
    fn a_body_that_fits_is_withheld_until_the_stream_ends() {
        let mut buffer = BufferedBody::new(1024);
        assert!(buffer.offer(Bytes::from_static(b"hello ")).is_none());
        assert!(buffer.offer(Bytes::from_static(b"world")).is_none());
        assert_eq!(buffer.finish().as_deref(), Some(&b"hello world"[..]));
        assert!(!buffer.overflowed());
    }

    /// 🌊 Once streaming, every later chunk passes straight through — a buffer
    /// that started holding again would reorder the body.
    #[test]
    fn releasing_is_a_one_way_transition() {
        let mut buffer = BufferedBody::new(4);
        assert_eq!(
            buffer.offer(Bytes::from_static(b"abcd")).as_deref(),
            Some(&b"abcd"[..])
        );
        assert_eq!(
            buffer.offer(Bytes::from_static(b"e")).as_deref(),
            Some(&b"e"[..])
        );
        assert!(buffer.finish().is_none());
    }

    /// 🧭 An empty body holds nothing and releases nothing.
    #[test]
    fn an_empty_body_releases_nothing() {
        let mut buffer = BufferedBody::new(1024);
        assert!(buffer.finish().is_none());
        assert!(!buffer.overflowed());
    }

    /// 🛡️ `unlimited` resolves to this server's ceiling, not to no ceiling.
    #[test]
    fn unlimited_resolves_to_the_server_ceiling() {
        assert_eq!(resolve_limit(Some(-1)), Some(MAX_BUFFERED_BODY_BYTES));
        assert_eq!(resolve_limit(Some(i64::MAX)), Some(MAX_BUFFERED_BODY_BYTES));
        assert_eq!(resolve_limit(Some(4096)), Some(4096));
        assert_eq!(resolve_limit(Some(0)), None);
        assert_eq!(resolve_limit(None), None);
    }

    /// 🧾 Anything the server will not honour verbatim says so at load.
    #[test]
    fn a_clamped_ceiling_is_described() {
        assert!(describe_clamp(Some(-1)).is_some());
        assert!(describe_clamp(Some(i64::MAX)).is_some());
        assert!(describe_clamp(Some(4096)).is_none());
        assert!(describe_clamp(None).is_none());
    }
}
