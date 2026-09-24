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
//! 📌 Records keep going to **stdout** unless a global `log { output … }` block
//! says otherwise, which is where the default `fmt::layer()` already sent them.
//! Moving the hand-off off the request path is not a licence to change the
//! destination: whoever pipes or captures the server's streams sees the same
//! stream as before, and the integration tests that read back a captured stream
//! for reload and limit diagnostics keep working.
//!
//! 🧭 Caddy's unnamed global `log` block configures the *default* logger — the
//! sink its own lifecycle messages go to — and that is what [`apply_process_log`]
//! honours: the destination, the format, and the level, applied when the
//! configuration is read and again on every reload. The block used to compile
//! and do nothing at all, which is the "silently ignored setting" this
//! repository fails closed on everywhere else.
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

use pingclair_core::config::{LogFormat, LogOutput, LoggingConfig};
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
    /// 🔀 Point the writer at a new sink.
    ///
    /// 📌 The sink arrives already open, so the caller — which has somewhere to
    /// report a failure to — is the one that discovers a path it cannot create.
    /// A `Redirect` that reached the writer thread with a path instead would
    /// have to report the failure from a thread that can only lose it.
    Redirect(Box<ProcessSink>),
}

/// 🔀 Where the process log is written.
///
/// 📌 This is the *process* sink — the server's own diagnostics — and not the
/// access log, which has its own writers and rotation in
/// `pingclair_proxy::access_log`. A global `log { output … }` block configures
/// this one: Caddy sends its lifecycle messages ("admin endpoint started",
/// "serving initial configuration") to the default logger, and the block is
/// how an operator points those at a file.
pub(crate) enum ProcessSink {
    Stdout(std::io::Stdout),
    Stderr(std::io::Stderr),
    File(std::fs::File),
}

impl ProcessSink {
    /// 📂 Opens the sink a `log` block asked for.
    ///
    /// 🧹 The directory is created if missing, and the file is created 0600 on
    /// first use — the modes Caddy uses for the same setting, and the right
    /// default for a file that carries client addresses and request paths.
    /// Applied after the open rather than through `OpenOptions::mode`, which
    /// only takes effect on creation and would leave an existing file at
    /// whatever permissions it already had.
    fn open(output: &LogOutput) -> io::Result<Self> {
        match output {
            LogOutput::Stdout => Ok(ProcessSink::Stdout(io::stdout())),
            LogOutput::Stderr => Ok(ProcessSink::Stderr(io::stderr())),
            LogOutput::File(path) => {
                if let Some(parent) = std::path::Path::new(path).parent()
                    && !parent.as_os_str().is_empty()
                {
                    std::fs::create_dir_all(parent)?;
                }
                // 📌 Creation, not existence, decides whether the mode is
                // narrowed: an operator who set up a shared log file with wider
                // permissions did it on purpose, and the same reasoning already
                // applies to the directory in `access_log`.
                let existed = std::path::Path::new(path).exists();
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?;
                if !existed {
                    restrict_mode_0600(path);
                }
                Ok(ProcessSink::File(file))
            }
        }
    }

    fn write_record(&mut self, record: &[u8]) -> io::Result<()> {
        match self {
            ProcessSink::Stdout(out) => {
                // 🔐 One lock per record keeps concurrent stdout writers from
                // splitting a formatted line.
                let mut handle = out.lock();
                handle.write_all(record).and_then(|_| handle.flush())
            }
            ProcessSink::Stderr(err) => {
                let mut handle = err.lock();
                handle.write_all(record).and_then(|_| handle.flush())
            }
            ProcessSink::File(file) => file.write_all(record).and_then(|_| file.flush()),
        }
    }
}

/// 🔐 Narrows a process-log file this process just created to owner-only.
///
/// 🔍 The mode is applied after the open rather than through `OpenOptions::mode`,
/// which only takes effect at creation — the same reason `access_log` sets its
/// file mode the same way.
#[cfg(unix)]
fn restrict_mode_0600(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_mode_0600(_path: &str) {}

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
                // 📌 The sink is owned by this thread and swapped in place, so a
                // `log { output … }` block takes effect without a second writer
                // and without a lock on the record path.
                let mut sink = ProcessSink::Stdout(io::stdout());
                let mut healthy = true;
                while let Ok(message) = rx.recv() {
                    match message {
                        WriterMessage::Record(record) => {
                            if sink.write_record(&record).is_err() {
                                healthy = false;
                            }
                        }
                        WriterMessage::Redirect(next) => {
                            sink = *next;
                            // 🔁 A sink that failed is not the new sink's fault.
                            healthy = true;
                        }
                        WriterMessage::Flush(ack) => {
                            let _ = ack.send(healthy);
                        }
                    }
                }
            })
            .expect("spawning the log writer thread");

        let _ = PROCESS_LOG.set(tx_guard.clone());
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

/// 🎛️ The queue every redirect and drain goes through.
///
/// 📌 A separate handle from [`PARKED`] because it outlives the guard's
/// lifetime concerns: a redirect is a request to the *running* writer, while
/// the guard is about shutting it down.
static PROCESS_LOG: std::sync::OnceLock<SyncSender<WriterMessage>> = std::sync::OnceLock::new();

/// 🔀 Points the process log at the sink a global `log { output … }` block
/// asked for.
///
/// 🧭 Caddy's default logger is exactly this: the sink its own lifecycle
/// messages go to, reconfigured by an unnamed global `log` block. Before this
/// existed the block compiled, validated, and wrote nothing anywhere — the one
/// shape this adapter accepted and then silently ignored.
///
/// 📌 The file is opened here, on the calling thread, so a path that cannot be
/// created is reported to whoever can act on it instead of vanishing into the
/// writer thread.
pub(crate) fn redirect_to(output: &LogOutput) -> io::Result<()> {
    let sink = Box::new(ProcessSink::open(output)?);
    let Some(tx) = PROCESS_LOG.get() else {
        // 🧪 No subscriber: a unit test, or a command that never started one.
        // The sink is still opened, so a caller that asked for a file finds out
        // now whether it can have one.
        return Ok(());
    };
    // 🛡️ `send` rather than `try_send`: a redirect that is dropped under
    // back-pressure leaves the process logging to the wrong place forever, and
    // this runs at startup or on reload, never on a request.
    tx.send(WriterMessage::Redirect(sink))
        .map_err(|_| io::Error::other("the log writer thread has stopped"))
}

/// 🔤 Whether process records are rendered as JSON.
///
/// 🔍 A flag rather than a formatter swap: the tracing layer's formatter is
/// chosen when the subscriber is built, which happens before the configuration
/// is read. The reader is the formatter itself, on the emitting thread.
static PROCESS_JSON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// 🔤 Whether process records are rendered as JSON right now.
pub(crate) fn json_enabled() -> bool {
    PROCESS_JSON.load(Ordering::Relaxed)
}

/// 🎨 Whether process records carry colour escapes.
///
/// 📌 On by default, because stdout and stderr have always carried them and a
/// terminal is where those usually land. A **file** sink turns them off:
/// escapes are zero-width in a terminal and pure noise in a file an operator
/// greps through, and every other file logger in this workspace writes plain
/// bytes. Caddy's file writer does the same.
static PROCESS_ANSI: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// 🎨 Whether process records carry colour escapes right now.
pub(crate) fn ansi_enabled() -> bool {
    PROCESS_ANSI.load(Ordering::Relaxed)
}

/// 🚦 The filter the process logger was built with, so a reload can put back
/// what a configuration took away.
static FILTER: Mutex<Option<FilterHandle>> = Mutex::new(None);

struct FilterHandle {
    /// 🚦 Replaces the process filter's directives; `false` when the subscriber
    /// is gone, which happens on the way out.
    ///
    /// 📌 A closure rather than the reload handle itself, because the handle's
    /// type names the whole layered subscriber — which `main.rs` builds and
    /// this module has no business knowing.
    apply: Box<dyn Fn(&str) -> bool + Send + Sync>,
    /// 🧾 The directives the process started with, from `RUST_LOG` or `--verbose`.
    base: String,
    /// 🌍 Whether the base came from the environment, which outranks a
    /// configuration file — see `main.rs`.
    from_env: bool,
}

/// 📌 Remembers how to change the process filter, so a `log { level … }` can
/// reach it.
pub(crate) fn remember_filter(
    apply: impl Fn(&str) -> bool + Send + Sync + 'static,
    base: String,
    from_env: bool,
) {
    *FILTER.lock().unwrap_or_else(|e| e.into_inner()) = Some(FilterHandle {
        apply: Box::new(apply),
        base,
        from_env,
    });
}

/// ⚙️ Applies the process-logging half of a configuration.
///
/// Called with the configuration the server is about to run, and again on
/// every reload, because Caddy re-provisions its loggers the same way: a
/// configuration that moves the process log to a file, and a later one that
/// moves it back, both have to take effect.
///
/// 📌 A configuration with no unnamed global `log` block restores the process
/// defaults — stdout, text, the directives from `RUST_LOG`/`--verbose` —
/// rather than leaving the previous configuration's sink in place. Otherwise a
/// reload could not undo a `log { output file … }`, and the file would keep
/// growing for a configuration that no longer mentions it.
pub(crate) fn apply_process_log(logging: &LoggingConfig) {
    let (output, format, level) = match &logging.default {
        Some(default) => (
            Some(&default.output),
            Some(&default.format),
            default.level.as_deref(),
        ),
        None => (None, None, None),
    };

    let target = match output {
        Some(output) => match redirect_to(output) {
            Ok(()) => describe(output),
            Err(error) => {
                // 🚫 Not fatal: the server runs fine without its log file, and
                // refusing to start over a log destination would trade a
                // degraded service for no service. Reported loudly instead.
                eprintln!(
                    "⚠️ Could not open the configured process log {}: {error}; \
                     continuing to {}",
                    describe(output),
                    active_sink()
                );
                return;
            }
        },
        None => {
            let _ = redirect_to(&LogOutput::Stdout);
            "stdout".to_string()
        }
    };

    PROCESS_JSON.store(matches!(format, Some(LogFormat::Json)), Ordering::Relaxed);
    PROCESS_ANSI.store(
        !matches!(output, Some(LogOutput::File(_))),
        Ordering::Relaxed,
    );
    apply_level(level);
    tracing::info!(sink = %target, "🔀 Process log destination");
}

/// 📝 The sink as an operator would name it in their own configuration.
fn describe(output: &LogOutput) -> String {
    match output {
        LogOutput::Stdout => "stdout".to_string(),
        LogOutput::Stderr => "stderr".to_string(),
        LogOutput::File(path) => format!("file {path}"),
    }
}

fn active_sink() -> String {
    "stdout".to_string()
}

/// 🚦 Points the process filter at the configured level, or back at the default.
fn apply_level(level: Option<&str>) {
    let guard = FILTER.lock().unwrap_or_else(|e| e.into_inner());
    let Some(filter) = guard.as_ref() else {
        return;
    };
    let (directives, source) = match level {
        Some(level) if filter.from_env => {
            // 🌍 `RUST_LOG` wins outright, which is what makes it usable to
            // quieten or widen one module without editing the configuration.
            tracing::warn!(
                configured = level,
                environment = %filter.base,
                "⚠️ RUST_LOG is set and outranks the configured log level"
            );
            return;
        }
        Some(level) => (level.to_string(), "the configuration"),
        None => (filter.base.clone(), "the process default"),
    };
    if (filter.apply)(&directives) {
        tracing::debug!(source, "🚦 Process log level applied");
    }
}

/// 🔤 Renders process records in the format the configuration asked for.
///
/// 🔍 A dispatcher rather than two subscribers: the subscriber is built before
/// the configuration is read, because the earliest messages — including the one
/// that reports a configuration that will not parse — have to be visible either
/// way. So the choice is made per record, from a flag the configuration sets.
///
/// 📌 Both branches are the library's own formatters. Reimplementing either one
/// would mean the unconfigured text output silently changed the day this was
/// added, and that output is what the integration tests read back.
pub(crate) struct ProcessLogFormat;

impl<S, N> tracing_subscriber::fmt::format::FormatEvent<S, N> for ProcessLogFormat
where
    S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
    N: for<'writer> tracing_subscriber::fmt::format::FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        use tracing_subscriber::fmt::format::Format;
        if json_enabled() {
            // 🚫 Escapes off: the JSON form is for a machine, and colour codes
            // inside a field are bytes the reader has to strip — Caddy's own
            // JSON records carry none.
            Format::default()
                .json()
                .with_ansi(false)
                .format_event(ctx, writer, event)
        } else {
            Format::default()
                .with_ansi(ansi_enabled())
                .format_event(ctx, writer, event)
        }
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
