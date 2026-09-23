// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📝 Moving log output off the request path.
//!
//! The access log is emitted per request at `info`, and the default
//! `fmt::layer()` formats it and writes it *on the worker thread*. When the
//! destination is a service journal — the normal case for the packaged service
//! — that write is synchronous, so every request waits on the log before it can
//! finish. [`NonBlockingWriter`] hands each formatted record to a background
//! thread over a bounded channel and returns immediately.
//!
//! 📌 Records keep going to **stdout**, which is where the default `fmt::layer()`
//! already sent them. Moving the hand-off off the request path is not a licence
//! to change the destination: whoever pipes or captures the server's streams
//! sees the same stream as before, and the integration tests that read back a
//! captured stream for reload and limit diagnostics keep working.
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Depth of the hand-off queue, in log records.
///
/// A few thousand records is a fraction of a second of access logs at the
/// rates this server reaches, which absorbs a journal hiccup without holding
/// meaningful memory.
const QUEUE_DEPTH: usize = 8192;

/// 🚿 A barrier acknowledges the records accepted before it, even though the
/// global subscriber keeps its sender alive for the lifetime of the process.
enum WriterMessage {
    Record(Vec<u8>),
    Flush(SyncSender<bool>),
}

/// 📝 A `MakeWriter` that enqueues each record for a background writer thread.
///
/// Cloning shares one queue, which is what `fmt::layer` needs: it calls the
/// make-writer once per event.
#[derive(Clone)]
pub(crate) struct NonBlockingWriter {
    tx: SyncSender<WriterMessage>,
    dropped: Arc<AtomicU64>,
}

impl NonBlockingWriter {
    /// Spawn the writer thread, returning the handle that logging feeds.
    ///
    /// The [`WriterGuard`] is kept by this module rather than handed back: the
    /// server leaves through `std::process::exit`, which runs no destructors,
    /// so a guard the caller had to remember to drop would be forgotten on
    /// exactly the path that carries the most records. [`drain`] waits for an
    /// acknowledged barrier without joining a thread whose sender is global.
    pub(crate) fn spawn() -> Self {
        let (tx, rx) = sync_channel::<WriterMessage>(QUEUE_DEPTH);
        let tx_guard = tx.clone();
        let dropped = Arc::new(AtomicU64::new(0));

        std::thread::Builder::new()
            .name("pingclair-log".to_string())
            .spawn(move || {
                let stdout = io::stdout();
                let mut healthy = true;
                while let Ok(message) = rx.recv() {
                    match message {
                        WriterMessage::Record(record) => {
                            // 🔐 One lock per record keeps concurrent stdout
                            // writers from splitting a formatted log line.
                            let mut out = stdout.lock();
                            if out.write_all(&record).and_then(|_| out.flush()).is_err() {
                                healthy = false;
                            }
                        }
                        WriterMessage::Flush(ack) => {
                            let _ = ack.send(healthy);
                        }
                    }
                }
            })
            .expect("spawning the log writer thread");

        *PARKED.lock().unwrap_or_else(|e| e.into_inner()) = Some(WriterGuard {
            dropped: Arc::clone(&dropped),
            tx: Some(tx_guard),
        });

        Self { tx, dropped }
    }
}

/// 🚿 The writer this process drains on the way out, parked for its lifetime.
///
/// A slot rather than a plain value so that draining can *take* the guard out
/// of it: a second drain is then a no-op, and the dropped-record count is
/// reported once.
static PARKED: Mutex<Option<WriterGuard>> = Mutex::new(None);

/// 🚿 Finishes the log writer from an exit path that runs no destructors.
///
/// [`WriterGuard`] sends a barrier and waits a bounded moment for its reply.
/// The server ends at `std::process::exit`, which skips `Drop`, so its shutdown
/// path calls this explicitly rather than abandoning queued records.
pub(crate) fn drain() {
    // 🧹 Taken out of the slot first. The wait inside is bounded at 250 ms, and
    // holding the lock across it would block a `spawn` for that long.
    let guard = PARKED.lock().unwrap_or_else(|e| e.into_inner()).take();
    drop(guard);
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
    tx: SyncSender<WriterMessage>,
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
        match self.tx.try_send(WriterMessage::Record(record)) {
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
/// ⚠️ The global subscriber retains senders in a `OnceLock`, so the worker
/// cannot finish merely because this guard drops its sender. A barrier reports
/// when preceding records have actually reached stdout; waiting for its reply
/// is bounded so a blocked sink cannot hang shutdown.
///
/// 📌 The guard lives in [`PARKED`] rather than in the caller's hand, so that
/// the drain is reachable from an exit that drops nothing — see [`drain`].
pub(crate) struct WriterGuard {
    dropped: Arc<AtomicU64>,
    tx: Option<SyncSender<WriterMessage>>,
}

impl WriterGuard {
    /// How long to let the writer drain before giving up on it.
    const DRAIN_TIMEOUT: Duration = Duration::from_millis(250);

    /// 🚿 Wait for accepted records to reach stdout, then close this sender.
    ///
    /// Named rather than inlined into `Drop` because it is the shutdown the
    /// documentation above is about, and because it is the whole reason the
    /// wait is bounded.
    fn shutdown(&mut self) {
        let deadline = Instant::now() + Self::DRAIN_TIMEOUT;
        let drained = if let Some(tx) = self.tx.as_ref() {
            let (ack, wait) = sync_channel(1);
            let mut message = WriterMessage::Flush(ack);
            let sent = loop {
                match tx.try_send(message) {
                    Ok(()) => break true,
                    Err(TrySendError::Full(returned)) => {
                        if Instant::now() >= deadline {
                            break false;
                        }
                        message = returned;
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(TrySendError::Disconnected(_)) => break false,
                }
            };
            sent && matches!(
                wait.recv_timeout(deadline.saturating_duration_since(Instant::now())),
                Ok(true)
            )
        } else {
            true
        };
        drop(self.tx.take());
        if !drained {
            eprintln!("⚠️ Trace log drain exceeded the shutdown budget or stdout failed");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blocked_log_sink_cannot_hold_shutdown_open() {
        let (tx, _receiver) = sync_channel(1);
        assert!(
            tx.try_send(WriterMessage::Record(vec![b'x'])).is_ok(),
            "the one queue slot accepts a record"
        );
        let mut guard = WriterGuard {
            dropped: Arc::new(AtomicU64::new(0)),
            tx: Some(tx),
        };

        let started = Instant::now();
        guard.shutdown();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "a blocked stdout must not hang shutdown"
        );
    }
}
