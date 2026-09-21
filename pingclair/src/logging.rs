// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📝 Moving log output off the request path.
//!
//! The access log is emitted per request at `info`, and the default
//! `fmt::layer()` formats it and writes it *on the worker thread*. When stderr
//! is a service journal — the normal case for the packaged service — that write
//! is synchronous, so every request waits on the log before it can finish.
//! [`NonBlockingWriter`] hands each formatted record to a background thread
//! over a bounded channel and returns immediately.
//!
//! 🔍 Formatting still happens on the emitting thread. Its cost must be
//! measured separately from the destination: a journal receiver also consumes
//! CPU and performs work per line, even when the producer writes asynchronously.
//! Comparing only logging enabled versus disabled cannot attribute that cost.
//! For sustained access traffic, a configured file logger uses the dedicated
//! buffered writer in `pingclair_proxy::access_log`.
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
use std::time::{Duration, Instant};

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
    /// work. Dropping it asks the writer to finish and waits a bounded moment
    /// for the queue to drain — see [`WriterGuard::shutdown`] for why the wait
    /// is bounded rather than a plain `join`.
    pub(crate) fn spawn() -> (Self, WriterGuard) {
        let (tx, rx) = sync_channel::<Vec<u8>>(QUEUE_DEPTH);
        let tx_guard = tx.clone();
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
                tx: Some(tx_guard),
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

/// 🧹 Keeps the writer thread alive, and drains what is queued on shutdown.
///
/// ⚠️ Shutdown does **not** join the writer, and that is not a shortcut. The
/// subscriber is installed with `set_global_default`, which parks senders in a
/// `OnceLock` that is never dropped, so the channel does not disconnect on its
/// own. An earlier version joined unconditionally and hung every short-lived
/// run — `pingclair adapt` and `pingclair validate`, which is most of the CLI
/// test suite, sat there until the runner's timeout. A server that never exits
/// would never notice; a command that should exit immediately notices at once.
///
/// So the guard drops its own sender and waits a bounded moment for the writer
/// to drain, then stops waiting. Losing the tail of the log on an unclean exit
/// is strictly better than never exiting.
pub(crate) struct WriterGuard {
    dropped: Arc<AtomicU64>,
    tx: Option<SyncSender<Vec<u8>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl WriterGuard {
    /// How long to let the writer drain before giving up on it.
    const DRAIN_TIMEOUT: Duration = Duration::from_millis(250);

    /// Close this guard's sender and wait briefly for the queue to drain.
    pub(crate) fn shutdown(&mut self) {
        // Dropping our sender is what asks the writer to finish; the process's
        // exit removes the thread if the drain did not.
        drop(self.tx.take());

        if let Some(thread) = &self.thread {
            let deadline = Instant::now() + Self::DRAIN_TIMEOUT;
            while !thread.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        let dropped = self.dropped.load(Ordering::Relaxed);
        if dropped > 0 {
            eprintln!("📝 {dropped} log records were dropped: the log writer could not keep up");
        }
    }
}

impl Drop for WriterGuard {
    fn drop(&mut self) {
        self.shutdown();
    }
}
