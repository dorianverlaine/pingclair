// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ⏱️ The header deadline for HTTP/3 request streams.
//!
//! A client can open a request stream and send its HEADERS frame a byte at a
//! time, never finishing it. quiche holds the partial frame and reports
//! nothing until the last byte arrives, and QUIC's idle timer starts again
//! with every packet, so nothing ever let go of such a stream — or of the
//! connection under it, which can carry a hundred of them at once. HTTP/1
//! closes a connection whose header misses `limits { header_timeout }`; this
//! is the same bound for HTTP/3, applied per stream because one connection
//! carries many requests and only the unfinished one deserves to be cut.
//!
//! 🧭 Each request stream is recorded when the client opens it and settled
//! when its header arrives or the client resets it. A stream still unsettled
//! at its deadline is reset by the caller with H3_REQUEST_INCOMPLETE.
//!
//! 📌 The timeout is the same for every stream of a connection, so deadlines
//! are reached in the order streams were opened, and client stream ids only
//! grow. One queue ordered both ways replaces a map and a timer wheel: the
//! front is always the next deadline, and settling a stream is a binary search.

use std::collections::VecDeque;
use std::time::Duration;

use tokio::time::Instant;

/// 🧭 Client-initiated bidirectional stream ids are 0, 4, 8, … (RFC 9000
/// §2.1), and only those carry requests.
const CLIENT_BIDI_STEP: u64 = 4;

/// ⏱️ One connection's request streams whose header has not arrived yet.
pub(crate) struct PendingHeaders {
    /// ⏱️ How long a stream may wait for its whole header.
    timeout: Duration,
    /// 🧭 The lowest client request stream id not yet recorded.
    next_unseen: u64,
    /// ⏱️ Unsettled streams with their deadlines, ascending in both.
    waiting: VecDeque<(u64, Instant)>,
}

impl PendingHeaders {
    /// ⏱️ Starts a connection with nothing waiting.
    pub(crate) fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            next_unseen: 0,
            waiting: VecDeque::new(),
        }
    }

    /// 🧭 Records that the client has opened `stream_id`.
    ///
    /// Opening a stream opens every lower-numbered stream of the same kind
    /// with it (RFC 9000 §3.2), so those are recorded too: a client that sent
    /// stream 8 first must not leave 0 and 4 outside the deadline. quiche
    /// refuses an id past the stream limit it advertised, which is what bounds
    /// the loop and the queue.
    pub(crate) fn opened(&mut self, stream_id: u64) {
        if !stream_id.is_multiple_of(CLIENT_BIDI_STEP) || stream_id < self.next_unseen {
            return;
        }
        let deadline = Instant::now() + self.timeout;
        let mut id = self.next_unseen;
        while id <= stream_id {
            self.waiting.push_back((id, deadline));
            id += CLIENT_BIDI_STEP;
        }
        self.next_unseen = id;
    }

    /// 🎯 Takes `stream_id` off the clock: its header arrived, or the client
    /// reset it.
    ///
    /// 📌 Usually the stream is the newest one and sits at the back, so the
    /// removal moves nothing.
    pub(crate) fn settled(&mut self, stream_id: u64) {
        if let Ok(index) = self
            .waiting
            .binary_search_by_key(&stream_id, |entry| entry.0)
        {
            self.waiting.remove(index);
        }
    }

    /// ⏱️ When the next unsettled stream runs out of time, if any is waiting.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.waiting.front().map(|entry| entry.1)
    }

    /// 🚫 Removes and returns the next stream whose deadline has passed.
    pub(crate) fn pop_expired(&mut self, now: Instant) -> Option<u64> {
        let (stream_id, _) = self.waiting.front().filter(|entry| entry.1 <= now)?;
        let stream_id = *stream_id;
        self.waiting.pop_front();
        Some(stream_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🧭 Only client request streams are timed, a jump records the streams
    /// it opened implicitly, settled streams leave the clock, and expiry
    /// returns the rest in the order they were opened.
    #[test]
    fn tracks_request_streams_until_their_header_or_deadline() {
        let timeout = Duration::from_secs(60);
        let mut pending = PendingHeaders::new(timeout);
        // 📌 2 and 3 are unidirectional (control, QPACK); 1 is server-opened.
        for id in [2, 3, 1, 8, 4] {
            pending.opened(id);
        }
        pending.settled(4);
        assert_eq!(pending.pop_expired(Instant::now()), None);

        let later = Instant::now() + timeout;
        let expired: Vec<u64> = std::iter::from_fn(|| pending.pop_expired(later)).collect();
        assert_eq!((expired, pending.next_deadline()), (vec![0, 8], None));
    }
}
