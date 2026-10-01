// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ⏱️ One deadline for a whole HTTP/1 request header, however it is dribbled.
//!
//! A slowloris client opens a connection and sends its request header a byte
//! at a time, never quite finishing, so the connection is held open for as
//! long as it keeps trickling. Pingora's HTTP/1 reader cannot stop that on its
//! own: its timeout applies to each read separately
//! (`HttpSession::read_request_buf`, pingora-core 0.9.0,
//! `protocols/http/v1/server.rs`), and every byte that arrives starts the
//! clock again. A soak run held ten such clients for over 120 s.
//!
//! 🎯 So the header is read here first, under a single deadline that the
//! client's pace cannot move, and handed to Pingora complete through
//! `set_pipelined_prefix` — the entry point Pingora uses for bytes a previous
//! request already read off the socket. Pingora parses that prefix without
//! reading again, so the same bytes are not read twice; the extra work per
//! request is one scan for the blank line that ends the header.

use bytes::BytesMut;
use pingora_core::protocols::Stream;
use pingora_core::server::ShutdownWatch;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::time::Instant;

/// ⏱️ How long a request header may take when `limits { header_timeout }` is
/// not set.
///
/// One minute, as Caddy's `defaultReadHeaderTimeout` (`modules/caddyhttp/app.go`,
/// v2.x, recalled from memory on 2026-10-02 rather than re-read) and nginx's
/// `client_header_timeout`. A header is usually under a kilobyte, so a minute
/// is generous even for a very slow link, while still letting go of a client
/// that never finishes.
pub(crate) const DEFAULT_HEADER_TIMEOUT: Duration = Duration::from_secs(60);

/// 📏 The first allocation, the size Pingora's own reader starts with
/// (`INIT_HEADER_BUF_SIZE`, pingora-core 0.9.0), so a header read here costs
/// the allocation Pingora would otherwise have made itself.
const INITIAL_CAPACITY: usize = 4096;

/// 🛑 Past this many bytes the header is handed over unfinished, and Pingora
/// refuses it as too large (`MAX_HEADER_SIZE`, pingora-core 0.9.0). Reading on
/// here would only grow a buffer for a request that is already going to fail.
const HANDOFF_BYTES: usize = 1_048_575;

/// 🔎 Finds the blank line that ends a header section, one read at a time.
///
/// It remembers how far it has looked, so a header delivered in a thousand
/// one-byte reads is scanned once in total rather than once per read.
#[derive(Default)]
struct HeaderEnd {
    /// 🧭 Where the request line starts. RFC 9112 §2.2 lets a server skip
    /// empty lines before it, and Pingora's parser does; counting those as
    /// the end of the header would let a client escape the deadline by
    /// sending two newlines first.
    start: Option<usize>,
    /// 🔁 The next byte not yet examined.
    scanned: usize,
}

impl HeaderEnd {
    /// Whether `head` now holds a complete header section: a line feed
    /// followed by `\n` or `\r\n`, after the request line has begun.
    fn found(&mut self, head: &[u8]) -> bool {
        let start = match self.start {
            Some(start) => start,
            None => match head[self.scanned..]
                .iter()
                .position(|byte| !matches!(byte, b'\r' | b'\n'))
            {
                Some(offset) => *self.start.insert(self.scanned + offset),
                None => {
                    self.scanned = head.len();
                    return false;
                }
            },
        };
        // 🔁 A terminator can straddle two reads, so the last two bytes
        // already seen are looked at again.
        let mut cursor = self.scanned.saturating_sub(2).max(start);
        while let Some(offset) = head[cursor..].iter().position(|byte| *byte == b'\n') {
            let line_feed = cursor + offset;
            if matches!(
                head.get(line_feed + 1..),
                Some([b'\n', ..] | [b'\r', b'\n', ..])
            ) {
                return true;
            }
            cursor = line_feed + 1;
        }
        self.scanned = head.len();
        false
    }
}

/// ⏱️ Reads one request header off `stream`, finishing by `deadline`.
///
/// Returns the bytes read, which may also hold the start of the body, for the
/// caller to hand to Pingora. `None` means the connection should be dropped
/// without a response: the deadline passed, the server is shutting down, or
/// the socket failed. Dropping silently is what Pingora itself does when its
/// own read times out, and a client this slow is not waiting for an answer.
///
/// A client that closes early is not `None`: the partial bytes go to Pingora,
/// which closes the connection the same way it always has.
pub(crate) async fn read_request_head(
    stream: &mut Stream,
    deadline: Instant,
    shutdown: &mut ShutdownWatch,
) -> Option<BytesMut> {
    let mut head = BytesMut::with_capacity(INITIAL_CAPACITY);
    let mut end = HeaderEnd::default();
    loop {
        let read = tokio::select! {
            // 📌 Biased toward the read so bytes already in the socket are
            // taken before a shutdown is noticed, as Pingora's own reader does.
            biased;
            read = tokio::time::timeout_at(deadline, stream.read_buf(&mut head)) => read,
            // 🛑 A connection idling between keepalive requests must not hold
            // a graceful stop open for the rest of its header budget.
            _ = shutdown.changed() => return None,
        };
        match read {
            Err(_elapsed) => {
                tracing::debug!(
                    received = head.len(),
                    "⏱️ Dropping a connection whose request header missed its deadline"
                );
                return None;
            }
            Ok(Err(_)) => return None,
            Ok(Ok(0)) => return Some(head),
            Ok(Ok(_)) if end.found(&head) || head.len() > HANDOFF_BYTES => return Some(head),
            Ok(Ok(_)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HeaderEnd;

    /// 🔎 Feeds `chunks` one at a time and reports after which chunk, if any,
    /// the header was complete.
    fn completes_after(chunks: &[&[u8]]) -> Option<usize> {
        let mut head = Vec::new();
        let mut end = HeaderEnd::default();
        chunks.iter().enumerate().find_map(|(index, chunk)| {
            head.extend_from_slice(chunk);
            end.found(&head).then_some(index)
        })
    }

    #[test]
    fn a_header_ends_at_its_first_blank_line_however_it_is_split() {
        let request: &[u8] = b"GET / HTTP/1.1\r\nHost: a\r\n\r\nbody";
        let one_byte_reads: Vec<&[u8]> = request.chunks(1).collect();
        assert_eq!(
            [
                completes_after(&[request]),
                completes_after(&one_byte_reads),
                completes_after(&[b"GET / HTTP/1.1\nHost: a\n", b"\n"]),
                completes_after(&[b"GET / HTTP/1.1\r\nHost: a\r\n\r", b"\n"]),
                completes_after(&[b"GET / HTTP/1.1\r\nHost: a\r\n"]),
            ],
            [Some(0), Some(request.len() - 5), Some(1), Some(1), None],
        );
    }

    /// 🛡️ Blank lines before the request line are skipped, not taken as an
    /// end, or a client could open with `\r\n\r\n` and leave the deadline
    /// behind.
    #[test]
    fn leading_blank_lines_do_not_end_the_header() {
        assert_eq!(
            [
                completes_after(&[b"\r\n\r\n\n\n"]),
                completes_after(&[b"\r\n\r\n", b"GET / HTTP/1.1\r\n"]),
                completes_after(&[b"\r\n\r\n", b"GET / HTTP/1.1\r\n\r\n"]),
            ],
            [None, None, Some(1)],
        );
    }
}
