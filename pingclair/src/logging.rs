// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📝 Moving log output off the request path.
//!
//! The access log is emitted per request at `info`, and the default
//! `fmt::layer()` formats it and writes it *on the worker thread*. When stderr
//! is a systemd journal — the normal case for the packaged service — that write
//! is synchronous, so every request waits on the log before it can finish.
//! [`NonBlockingWriter`] hands each formatted record to a background thread
//! over a bounded channel and returns immediately.
//!
//! ⚠️ What this does and does not buy, measured on a 2-vCPU host with the same
//! binary and payload at 32 connections (median of three interleaved rounds):
//!
//! | | static | reverse proxy |
//! |---|---:|---:|
//! | synchronous writer | 12,043 rps | 4,406 rps |
//! | this writer | 12,556 rps | 4,650 rps |
//! | change | **+4.3 %** | **+5.5 %** |
//!
//! 📌 It is *not* the whole cost of logging. Suppressing the access log
//! entirely (`RUST_LOG=warn`) reaches **26,457 rps** — 2.2× the
//! logging-enabled figure — so roughly 55 % of throughput is still being paid
//! while this writer is in use. That remainder is the record being *built* on
//! the worker thread: ten fields formatted and allocated per request before the
//! writer ever sees them. Deferring the write moves the cheaper half. An
//! earlier version of this comment claimed the 55 % as the win, which confused
//! "turn logging off" with "make logging non-blocking"; they are not the same
//! measurement.
//!
//! 🛡️ Why the queue is bounded and drops instead of blocking. An unbounded
//! queue would turn a slow log consumer into unbounded memory growth, and a
//! *blocking* bounded queue would reintroduce exactly the stall this exists to
//! remove. Dropping under sustained back-pressure is the only option that keeps
//! the server's throughput independent of its logging, and the count of
//! dropped records is reported rather than swallowed — a log with a silent gap
//! is worse than one that says it has a gap.

use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};

/// Depth of the hand-off queue, in log records.
///
/// A few thousand records is a fraction of a second of access logs at the
/// rates this server reaches, which absorbs a journal hiccup without holding
/// meaningful memory.
const QUEUE_DEPTH: usize = 8192;

/// 📝 A `MakeWriter` that enqueues each record for a background writer thread.
///
/// Cloning shares one queue, which is what `fmt::layer` needs: it calls the
/// make-writer once per event.
#[derive(Clone)]
pub(crate) struct NonBlockingWriter {
    tx: SyncSender<Vec<u8>>,
    dropped: Arc<AtomicU64>,
}

impl NonBlockingWriter {
    /// Spawn the writer thread, returning the handle that logging feeds.
    ///
    /// The returned [`WriterGuard`] must be held for as long as logging should
    /// work: dropping it closes the queue and joins the thread, which is also
    /// how buffered records reach the journal on shutdown.
    pub(crate) fn spawn() -> (Self, WriterGuard) {
        let (tx, rx) = sync_channel::<Vec<u8>>(QUEUE_DEPTH);
        let dropped = Arc::new(AtomicU64::new(0));

        let thread = std::thread::Builder::new()
            .name("pingclair-log".to_string())
            .spawn(move || {
                let stderr = io::stderr();
                while let Ok(record) = rx.recv() {
                    // 🔐 One lock per record, not per byte: the escape
                    // sequences a formatter emits are only valid as a whole
                    // record, so records have to be written atomically relative
                    // to each other.
                    let mut out = stderr.lock();
                    let _ = out.write_all(&record);
                    let _ = out.flush();
                }
            })
            .expect("spawning the log writer thread");

        (
            Self {
                tx,
                dropped: Arc::clone(&dropped),
            },
            WriterGuard {
                dropped,
                thread: Some(thread),
            },
        )
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for NonBlockingWriter {
    type Writer = QueueWriter;

    /// One writer per event, which is what makes [`QueueWriter`] able to send a
    /// whole record as a single message without a lock.
    fn make_writer(&'a self) -> Self::Writer {
        QueueWriter {
            tx: self.tx.clone(),
            dropped: self.dropped.clone(),
            buf: Vec::new(),
        }
    }
}

/// 📝 The per-event handle: buffers one record, then hands it over whole.
///
/// A `fmt::layer` formats a record across several `write` calls, and several
/// worker threads format concurrently. Forwarding each call as its own message
/// would let two records interleave mid-line, so the bytes accumulate here and
/// are sent once when the layer drops the writer at the end of the event. That
/// costs one bounded copy per record and removes the need for a lock — which
/// matters, because the alternative is a mutex on the logging path this module
/// exists to keep off the request path.
pub(crate) struct QueueWriter {
    tx: SyncSender<Vec<u8>>,
    dropped: Arc<AtomicU64>,
    buf: Vec<u8>,
}

impl Write for QueueWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for QueueWriter {
    fn drop(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let record = std::mem::take(&mut self.buf);
        match self.tx.try_send(record) {
            Ok(()) => {}
            // 🛡️ Report and drop rather than block the caller.
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

/// 🧹 Keeps the writer thread alive, and flushes what is queued on shutdown.
pub(crate) struct WriterGuard {
    dropped: Arc<AtomicU64>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for WriterGuard {
    fn drop(&mut self) {
        // Dropping the sender is what ends the writer thread's `recv` loop.
        // The senders live in the subscriber, so the caller must drop the
        // subscriber first — which `tracing::subscriber::set_global_default`'s
        // owner does at process exit.
        if let Some(thread) = self.thread.take() {
            let dropped = self.dropped.load(Ordering::Relaxed);
            if dropped > 0 {
                eprintln!(
                    "📝 {dropped} log records were dropped: the log writer could not keep up"
                );
            }
            let _ = thread.join();
        }
    }
}
