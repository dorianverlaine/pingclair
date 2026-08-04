// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📝 Per-server access logging driven by each server's `LogConfig`.
//!
//! Before this module, `log { output stdout; format json }` compiled into a
//! `LogConfig` that nothing ever read: every server shared one process-wide
//! `tracing` subscriber, so per-server `output`/`format` were silently
//! ignored. This module makes that configuration actually decide where a
//! request line goes and how it is shaped.
//!
//! ⚠️ Scope note: this is the *routing and formatting* layer only. Rotation,
//! retention, compression and a bounded async writer are deliberately absent.
//! Writes are synchronous and serialized per sink — correct, but they block
//! the caller if the disk stalls, so a slow or full disk becomes back-pressure
//! on the request path rather than a dropped log line.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex, OnceLock};

use crate::metrics;

use pingclair_core::config::{LogConfig, LogFormat, LogOutput, LogRotation};

/// 🖊️ Where a formatted access line is written.
///
/// `File` holds a shared handle rather than reopening per request: opening a
/// file per line would both cost a syscall pair on every request and let two
/// servers configured with the same path interleave partial lines.
#[derive(Clone)]
enum LogSink {
    Stdout,
    Stderr,
    File(Arc<Mutex<File>>),
}

impl LogSink {
    /// ✍️ Writes one line to the underlying sink. Called only from the
    /// writer thread, never from a request.
    fn write_line(&self, line: &str) -> std::io::Result<()> {
        match self {
            LogSink::Stdout => {
                let stdout = std::io::stdout();
                let mut handle = stdout.lock();
                handle.write_all(line.as_bytes())?;
                handle.write_all(b"\n")?;
                handle.flush()
            }
            LogSink::Stderr => {
                let stderr = std::io::stderr();
                let mut handle = stderr.lock();
                handle.write_all(line.as_bytes())?;
                handle.write_all(b"\n")?;
                handle.flush()
            }
            LogSink::File(file) => {
                let mut guard = file.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                guard.write_all(line.as_bytes())?;
                guard.write_all(b"\n")?;
                guard.flush()
            }
        }
    }
}

/// 🗂️ Process-wide registry of open log files, keyed by canonical path.
///
/// Two servers pointing `output file /var/log/pingclair.log` at the same
/// path must share one handle and one lock, otherwise their writes can
/// interleave mid-line.
fn file_registry() -> &'static Mutex<HashMap<PathBuf, Arc<Mutex<File>>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<File>>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn open_shared_file(path: &str) -> std::io::Result<Arc<Mutex<File>>> {
    // Canonicalize the *parent* — the log file itself may not exist yet, so
    // canonicalizing the full path would fail on first run.
    let raw = Path::new(path);
    let key = match (raw.parent(), raw.file_name()) {
        (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => {
            match parent.canonicalize() {
                Ok(dir) => dir.join(name),
                Err(_) => raw.to_path_buf(),
            }
        }
        _ => raw.to_path_buf(),
    };

    let mut registry = file_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if let Some(existing) = registry.get(&key) {
        return Ok(existing.clone());
    }

    if let Some(parent) = raw.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let file = OpenOptions::new().create(true).append(true).open(raw)?;
    let handle = Arc::new(Mutex::new(file));
    registry.insert(key, handle.clone());
    Ok(handle)
}

/// 🔄 Points an already-shared handle at a freshly created file.
///
/// Rotation renames the active file aside, which leaves every holder of the
/// shared handle writing into a file that no longer has that name — the bytes
/// go to the renamed inode and the new `access.log` is never created.
///
/// The fix has to swap the `File` *inside* the mutex rather than hand back a
/// new `Arc`, because the sharing is the point: two servers configured with the
/// same path hold the same handle precisely so their writes cannot interleave.
/// Replacing the Arc would rotate one of them and leave the other writing to
/// the rotated file forever.
fn reopen_shared_file(handle: &Arc<Mutex<File>>, path: &Path) -> std::io::Result<()> {
    let fresh = OpenOptions::new().create(true).append(true).open(path)?;
    let mut guard = handle
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // 🚿 Flush what the old handle still holds before dropping it, or the tail
    // of the rotated file is lost.
    let _ = guard.flush();
    *guard = fresh;
    Ok(())
}

/// 📋 One access-log record.
///
/// Borrowed rather than owned so the hot path does not allocate a copy of
/// every field just to format one line.
pub struct AccessEntry<'a> {
    pub request_id: &'a str,
    pub method: &'a str,
    pub host: &'a str,
    pub path: &'a str,
    pub status: u16,
    pub bytes: u64,
    /// Wall time from request start to response completion.
    pub duration_ms: u128,
    /// Time to first byte, when the response actually produced one. `None`
    /// for responses that failed before any byte was written.
    pub ttfb_ms: Option<u128>,
    /// Client IP resolved through the trusted-proxy policy, not the raw
    /// socket peer — see `trusted_proxies`.
    pub client_ip: &'a str,
    /// Matched route pattern, e.g. `/api/*`. `None` when no route matched.
    pub route: Option<&'a str>,
    pub upstream: Option<&'a str>,
    pub user_agent: &'a str,
    pub referer: &'a str,
    pub protocol: &'a str,
    pub error: Option<&'a str>,

    /// 🏷️ Selected request and response headers, already lowercased and
    /// already masked where required. Empty unless the server asked for them.
    ///
    /// Masking happens at collection rather than here so this type cannot be
    /// handed an unmasked secret in the first place — a log formatter that
    /// *could* print a credential is one refactor away from doing it.
    pub request_headers: &'a [(String, String)],
    pub response_headers: &'a [(String, String)],

    /// 🔐 Negotiated TLS version and cipher, when the server asked for them
    /// and the connection had any.
    pub tls_version: Option<&'a str>,
    pub tls_cipher: Option<&'a str>,
}

/// 🙈 Collects the named headers, masking the ones that carry secrets.
///
/// Naming `authorization` here is deliberately safe: the field appears in the
/// log so an operator can see the request was authenticated, and the value is
/// replaced. That is the whole reason `is_sensitive_header` was written back on
/// Day 3 — this is its first caller.
pub fn collect_headers(wanted: &[String], headers: &http::HeaderMap) -> Vec<(String, String)> {
    if wanted.is_empty() {
        return Vec::new();
    }
    wanted
        .iter()
        .filter_map(|name| {
            let value = headers.get(name.as_str())?;
            let rendered = if crate::redaction::is_sensitive_header(name) {
                crate::redaction::REDACTED.to_string()
            } else {
                value.to_str().unwrap_or("<binary>").to_string()
            };
            Some((name.clone(), rendered))
        })
        .collect()
}

/// 🧾 A configured per-server access logger.
pub struct AccessLogger {
    format: LogFormat,
    /// Field names the config asked to drop (`format filter { fields { x delete } }`).
    exclude: HashSet<String>,
    /// 🚚 Hands finished lines to the writer thread.
    ///
    /// Bounded and never blocking. See [`LogWriter`] for why both matter.
    writer: Arc<LogWriter>,
    /// 🏷️ Header names to record, lowercased. Empty is the common case and
    /// costs nothing.
    request_headers: Vec<String>,
    response_headers: Vec<String>,
    /// 🔐 Whether to record the negotiated TLS version and cipher.
    include_tls: bool,
}

/// 🚚 Owns the sink and drains a bounded queue from a dedicated thread.
///
/// **Why the request path must not write the line itself.** Before this, every
/// access-log line was written and flushed inline, holding the sink's lock. A
/// full disk, an NFS mount that stalls, a log file on a device doing GC — any
/// of those blocked the thread that was serving a request, and a proxy that
/// stops proxying because logging is slow has failed at its actual job.
///
/// **Why the queue is bounded.** An unbounded queue does not remove the
/// problem, it converts it: instead of stalling, the process grows until it is
/// killed. A bound turns "we cannot keep up" into a decision — and the decision
/// this project makes is to drop the line and count it, because a proxy that
/// keeps serving with a gap in its logs is better than one that stops.
/// [`metrics::ACCESS_LOG_DROPPED_TOTAL`] is how an operator finds out.
pub struct LogWriter {
    queue: SyncSender<WriterMessage>,
    /// 🧮 Lines the queue could not accept. Mirrored into a metric, and kept
    /// here so a test can read it without scraping Prometheus.
    dropped: Arc<AtomicU64>,
}

enum WriterMessage {
    Line(String),
    /// 🚿 Drain everything queued and acknowledge, so a test (or a shutdown)
    /// can wait for the sink to catch up without sleeping and hoping.
    Flush(std::sync::mpsc::SyncSender<()>),
}

/// 📏 Current size of the active log file, or `None` if it cannot be read.
fn current_size(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().map(|m| m.len())
}

/// 🔄 Whether the active file has hit either rotation trigger.
fn should_rotate(rotation: &LogRotation, written: u64, opened_at: std::time::SystemTime) -> bool {
    let by_size = rotation
        .max_size_bytes
        .is_some_and(|limit| written >= limit);
    let by_age = rotation.max_age_secs.is_some_and(|max| {
        opened_at
            .elapsed()
            .is_ok_and(|elapsed| elapsed.as_secs() >= max)
    });
    by_size || by_age
}

/// 🔄 Renames the active file aside, reopens it, and applies retention.
///
/// Returns the fresh handle, or `None` when anything failed — in which case the
/// caller keeps writing to the file it already has. **Failing to rotate must
/// never mean failing to log**: a permission problem on the directory is not a
/// reason to start dropping lines.
fn rotate(handle: &Arc<Mutex<File>>, path: &Path, rotation: &LogRotation) -> Option<()> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let rotated = path.with_extension(format!(
        "{}.{stamp}",
        path.extension().and_then(|e| e.to_str()).unwrap_or("log")
    ));

    if let Err(error) = std::fs::rename(path, &rotated) {
        tracing::warn!(error = %error, path = %path.display(), "⚠️ Could not rotate access log");
        return None;
    }

    if rotation.compress {
        compress_rotated(&rotated);
    }
    apply_retention(path, rotation.keep);

    match reopen_shared_file(handle, path) {
        Ok(()) => Some(()),
        Err(error) => {
            tracing::error!(error = %error, "❌ Could not reopen access log after rotation");
            None
        }
    }
}

/// 🗜️ Gzips a rotated file in place, replacing it with a `.gz`.
///
/// Best effort: a failure leaves the uncompressed file, which is strictly
/// better than losing it.
fn compress_rotated(rotated: &Path) {
    let Ok(raw) = std::fs::read(rotated) else {
        return;
    };
    let target = rotated.with_extension(format!(
        "{}.gz",
        rotated
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("log")
    ));
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    if encoder.write_all(&raw).is_err() {
        return;
    }
    let Ok(compressed) = encoder.finish() else {
        return;
    };
    if std::fs::write(&target, compressed).is_ok() {
        let _ = std::fs::remove_file(rotated);
    }
}

/// 🗃️ Deletes the oldest rotated files beyond `keep`.
///
/// Rotation without retention only slows the disk filling up; this is the half
/// that actually prevents it. `None` keeps everything, deliberately — an
/// operator shipping logs off the box elsewhere may want exactly that.
fn apply_retention(active: &Path, keep: Option<usize>) {
    let Some(keep) = keep else { return };
    let Some(dir) = active.parent() else { return };
    let Some(stem) = active.file_name().and_then(|n| n.to_str()) else {
        return;
    };

    let mut rotated: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|candidate| {
            candidate
                .file_name()
                .and_then(|n| n.to_str())
                // 🎯 A rotated sibling starts with the active name and has more
                // after it; the active file itself must never be a candidate.
                .is_some_and(|name| name.starts_with(stem) && name != stem)
        })
        .collect();

    if rotated.len() <= keep {
        return;
    }
    // 🕰️ Names carry a unix timestamp, so lexical order is chronological.
    rotated.sort();
    let excess = rotated.len() - keep;
    for stale in rotated.into_iter().take(excess) {
        if let Err(error) = std::fs::remove_file(&stale) {
            tracing::warn!(error = %error, path = %stale.display(), "⚠️ Could not remove rotated log");
        }
    }
}

impl LogWriter {
    /// Spawns the writer thread for one sink.
    ///
    /// `capacity` is in lines, not bytes: the queue holds already-formatted
    /// strings, so a line is the unit an operator can reason about.
    #[cfg(test)]
    fn spawn(sink: LogSink, capacity: usize) -> Arc<Self> {
        Self::spawn_with_rotation(sink, capacity, LogRotation::default(), None)
    }

    /// Spawns the writer thread, optionally rotating a file sink.
    ///
    /// Rotation happens **on the writer thread**, between lines. That is the
    /// only place it can happen safely: renaming and reopening the file while a
    /// request thread held the handle would interleave a rename with a write,
    /// and gzipping a rotated file on the request path would be the same
    /// mistake as writing to it there.
    fn spawn_with_rotation(
        sink: LogSink,
        capacity: usize,
        rotation: LogRotation,
        path: Option<PathBuf>,
    ) -> Arc<Self> {
        let (queue, receiver) = std::sync::mpsc::sync_channel::<WriterMessage>(capacity);
        let dropped = Arc::new(AtomicU64::new(0));

        // 🧵 A plain OS thread rather than a Tokio task: the work is blocking
        // file I/O, and putting it on the runtime would occupy a worker that
        // requests need. It also keeps logging alive during shutdown, after
        // the runtime has stopped accepting new tasks.
        std::thread::Builder::new()
            .name("pingclair-access-log".into())
            .spawn(move || {
                // 🔄 `sink` is rebound on rotation, so the loop keeps writing
                // to whichever file is current without any shared state.
                // 🔄 Rotation state lives here, on the writer thread, so no
                // lock is needed to consult it.
                let mut written = if rotation.is_enabled() {
                    path.as_ref().and_then(|p| current_size(p)).unwrap_or(0)
                } else {
                    0
                };
                let mut opened_at = std::time::SystemTime::now();

                for message in receiver {
                    match message {
                        WriterMessage::Line(line) => {
                            if let (Some(path), LogSink::File(handle), true) =
                                (path.as_ref(), &sink, rotation.is_enabled())
                                && should_rotate(&rotation, written, opened_at)
                                && rotate(handle, path, &rotation).is_some()
                            {
                                written = 0;
                                opened_at = std::time::SystemTime::now();
                            }
                            written += line.len() as u64 + 1;
                            if let Err(error) = sink.write_line(&line) {
                                // 🚫 Reported once per failure and then
                                // dropped. Retrying a broken sink here would
                                // block the queue behind a device that is not
                                // coming back.
                                tracing::warn!(error = %error, "⚠️ Failed to write access log line");
                            }
                        }
                        WriterMessage::Flush(ack) => {
                            let _ = ack.send(());
                        }
                    }
                }
            })
            .expect("access log writer thread can be spawned");

        Arc::new(Self { queue, dropped })
    }

    /// 📤 Queues a line, or drops it. **Never blocks.**
    ///
    /// `try_send` is the whole point: `send` would block once the queue filled,
    /// which is exactly the stall this type exists to prevent.
    fn submit(&self, line: String) {
        if self.queue.try_send(WriterMessage::Line(line)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            metrics::ACCESS_LOG_DROPPED_TOTAL.inc();
        }
    }

    /// 🧮 How many lines have been dropped since start.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// 🚿 Blocks until everything queued so far has been written.
    ///
    /// For shutdown and for tests. Never called from the request path.
    pub fn flush(&self) {
        let (ack, wait) = std::sync::mpsc::sync_channel(0);
        if self.queue.send(WriterMessage::Flush(ack)).is_ok() {
            let _ = wait.recv();
        }
    }
}

impl AccessLogger {
    /// Build a logger from a server's `LogConfig`.
    ///
    /// Returns `Ok(None)` when the server has no `log` block, so callers keep
    /// the previous process-wide `tracing` behavior instead of silently
    /// losing lines.
    pub fn from_config(config: Option<&LogConfig>) -> std::io::Result<Option<Self>> {
        let Some(config) = config else {
            return Ok(None);
        };

        let sink = match &config.output {
            LogOutput::Stdout => LogSink::Stdout,
            LogOutput::Stderr => LogSink::Stderr,
            LogOutput::File(path) => LogSink::File(open_shared_file(path)?),
        };
        // 🔄 Rotation only applies to a file we own. Rotating stdout would mean
        // renaming whatever the service manager pointed it at.
        let rotate_path = match &config.output {
            LogOutput::File(path) if config.rotation.is_enabled() => Some(PathBuf::from(path)),
            _ => None,
        };

        Ok(Some(Self {
            format: config.format.clone(),
            exclude: config.exclude_fields.iter().cloned().collect(),
            // 📏 1024 lines. Big enough to absorb a burst that a healthy sink
            // drains in milliseconds, small enough that a stalled sink costs
            // bounded memory rather than growing until the box dies.
            writer: LogWriter::spawn_with_rotation(
                sink,
                1024,
                config.rotation.clone(),
                rotate_path,
            ),
            request_headers: config.request_headers.clone(),
            response_headers: config.response_headers.clone(),
            include_tls: config.include_tls,
        }))
    }

    /// 🏷️ Header names this server asked to record, if any.
    pub fn wanted_request_headers(&self) -> &[String] {
        &self.request_headers
    }

    pub fn wanted_response_headers(&self) -> &[String] {
        &self.response_headers
    }

    /// 🔐 Whether this server asked for TLS details in its access log.
    pub fn wants_tls(&self) -> bool {
        self.include_tls
    }

    fn included(&self, field: &str) -> bool {
        !self.exclude.contains(field)
    }

    /// Format and write one entry.
    ///
    /// Failures are reported through `tracing` and then dropped: a log sink
    /// that cannot be written must never take down the request that produced
    /// the line.
    pub fn log(&self, entry: &AccessEntry<'_>) {
        let line = match self.format {
            LogFormat::Json => self.format_json(entry),
            LogFormat::Text => self.format_text(entry),
        };

        // 🚦 Hand off and return. Whether the line reaches the disk is the
        // writer thread's problem; whether the request finishes is not.
        self.writer.submit(line);
    }

    /// 🚿 Blocks until queued lines have been written. Shutdown and tests only.
    pub fn flush(&self) {
        self.writer.flush();
    }

    /// 🧮 Lines dropped because the queue was full.
    pub fn dropped(&self) -> u64 {
        self.writer.dropped()
    }

    // The last field's macro expansion writes `first` without reading it
    // again — inherent to a comma-separating flag, not a bug.
    #[allow(unused_assignments)]
    fn format_json(&self, entry: &AccessEntry<'_>) -> String {
        let mut out = String::with_capacity(320);
        out.push('{');
        let mut first = true;

        macro_rules! raw_field {
            ($name:literal, $value:expr) => {
                if self.included($name) {
                    if !first {
                        out.push(',');
                    }
                    first = false;
                    out.push('"');
                    out.push_str($name);
                    out.push_str("\":");
                    out.push_str(&$value.to_string());
                }
            };
        }
        macro_rules! str_field {
            ($name:literal, $value:expr) => {
                if self.included($name) {
                    if !first {
                        out.push(',');
                    }
                    first = false;
                    out.push('"');
                    out.push_str($name);
                    out.push_str("\":\"");
                    escape_json_into(&mut out, $value);
                    out.push('"');
                }
            };
        }

        str_field!("request_id", entry.request_id);
        str_field!("method", entry.method);
        str_field!("host", entry.host);
        str_field!("path", entry.path);
        raw_field!("status", entry.status);
        raw_field!("bytes", entry.bytes);
        raw_field!("duration_ms", entry.duration_ms);
        if let Some(ttfb) = entry.ttfb_ms {
            raw_field!("ttfb_ms", ttfb);
        }
        str_field!("client_ip", entry.client_ip);
        if let Some(route) = entry.route {
            str_field!("route", route);
        }
        if let Some(upstream) = entry.upstream {
            str_field!("upstream", upstream);
        }
        str_field!("protocol", entry.protocol);
        str_field!("user_agent", entry.user_agent);
        str_field!("referer", entry.referer);
        if let Some(error) = entry.error {
            str_field!("error", error);
        }
        // 🔐 TLS details go in as ordinary fields; they are already strings
        // from the handshake and carry nothing client-controlled.
        if let Some(version) = entry.tls_version {
            str_field!("tls_version", version);
        }
        if let Some(cipher) = entry.tls_cipher {
            str_field!("tls_cipher", cipher);
        }

        // 🏷️ Headers are nested under one object per direction rather than
        // flattened, so a header called `status` cannot collide with the
        // status field and quietly overwrite it.
        for (label, headers) in [
            ("request_headers", entry.request_headers),
            ("response_headers", entry.response_headers),
        ] {
            if headers.is_empty() || !self.included(label) {
                continue;
            }
            if !first {
                out.push(',');
            }
            first = false;
            out.push('"');
            out.push_str(label);
            out.push_str("\":{");
            for (i, (name, value)) in headers.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                escape_json_into(&mut out, name);
                out.push_str("\":\"");
                escape_json_into(&mut out, value);
                out.push('"');
            }
            out.push('}');
        }

        out.push('}');
        out
    }

    fn format_text(&self, entry: &AccessEntry<'_>) -> String {
        let mut out = String::with_capacity(220);

        if self.included("client_ip") {
            out.push_str(entry.client_ip);
            out.push(' ');
        }
        if self.included("method") {
            out.push_str(entry.method);
            out.push(' ');
        }
        if self.included("host") {
            out.push_str(entry.host);
        }
        if self.included("path") {
            out.push_str(entry.path);
        }
        if self.included("protocol") {
            out.push(' ');
            out.push_str(entry.protocol);
        }
        if self.included("status") {
            out.push_str(&format!(" {}", entry.status));
        }
        if self.included("bytes") {
            out.push_str(&format!(" {}", entry.bytes));
        }
        if self.included("duration_ms") {
            out.push_str(&format!(" {}ms", entry.duration_ms));
        }
        if let Some(ttfb) = entry.ttfb_ms
            && self.included("ttfb_ms")
        {
            out.push_str(&format!(" ttfb={ttfb}ms"));
        }
        if let Some(route) = entry.route
            && self.included("route")
        {
            out.push_str(&format!(" route={route}"));
        }
        if let Some(upstream) = entry.upstream
            && self.included("upstream")
        {
            out.push_str(&format!(" upstream={upstream}"));
        }
        if self.included("request_id") {
            out.push_str(&format!(" id={}", entry.request_id));
        }
        if self.included("user_agent") {
            out.push_str(&format!(" ua=\"{}\"", entry.user_agent));
        }
        if self.included("referer") && entry.referer != "-" {
            out.push_str(&format!(" referer=\"{}\"", entry.referer));
        }
        if let Some(error) = entry.error {
            out.push_str(&format!(" error=\"{error}\""));
        }

        out
    }
}

/// Escape a string into a JSON string body (without the surrounding quotes).
///
/// A request path or User-Agent is attacker-controlled, so an unescaped
/// quote or control byte would let a client forge extra JSON fields in the
/// log — a log-injection bug, not just a formatting one.
fn escape_json_into(out: &mut String, value: &str) {
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn entry<'a>() -> AccessEntry<'a> {
        AccessEntry {
            request_id: "abc-1",
            method: "GET",
            host: "example.com",
            path: "/api/users",
            status: 200,
            bytes: 1234,
            duration_ms: 42,
            ttfb_ms: Some(7),
            client_ip: "203.0.113.9",
            route: Some("/api/*"),
            upstream: Some("10.0.0.2:8080"),
            user_agent: "curl/8",
            referer: "-",
            protocol: "HTTP/1.1",
            error: None,
            request_headers: &[],
            response_headers: &[],
            tls_version: None,
            tls_cipher: None,
        }
    }

    pub(super) fn logger(format: LogFormat, exclude: Vec<String>) -> AccessLogger {
        AccessLogger {
            format,
            exclude: exclude.into_iter().collect(),
            writer: LogWriter::spawn(LogSink::Stdout, 1024),
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            include_tls: false,
        }
    }

    #[test]
    fn json_contains_every_required_field() {
        let out = logger(LogFormat::Json, vec![]).format_json(&entry());
        for expected in [
            "\"request_id\":\"abc-1\"",
            "\"method\":\"GET\"",
            "\"status\":200",
            "\"bytes\":1234",
            "\"duration_ms\":42",
            "\"ttfb_ms\":7",
            "\"client_ip\":\"203.0.113.9\"",
            "\"route\":\"/api/*\"",
            "\"upstream\":\"10.0.0.2:8080\"",
        ] {
            assert!(out.contains(expected), "missing {expected} in {out}");
        }
        assert!(out.starts_with('{') && out.ends_with('}'));
    }

    #[test]
    fn json_is_parseable() {
        let out = logger(LogFormat::Json, vec![]).format_json(&entry());
        let parsed: serde_json::Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("emitted invalid JSON: {e}\n{out}"));
        assert_eq!(parsed["status"], 200);
        assert_eq!(parsed["route"], "/api/*");
    }

    /// A client-controlled field must not be able to forge extra JSON keys.
    #[test]
    fn json_escapes_client_controlled_fields() {
        let mut e = entry();
        e.path = "/x\",\"status\":999,\"injected\":\"";
        e.user_agent = "bad\nagent\twith\"quotes";
        let out = logger(LogFormat::Json, vec![]).format_json(&e);

        let parsed: serde_json::Value = serde_json::from_str(&out)
            .unwrap_or_else(|err| panic!("injection broke JSON: {err}\n{out}"));
        // status must still be the real one, not the injected 999.
        assert_eq!(parsed["status"], 200);
        assert!(parsed.get("injected").is_none(), "log injection succeeded");
        assert_eq!(parsed["user_agent"], "bad\nagent\twith\"quotes");
    }

    #[test]
    fn excluded_fields_are_dropped_in_both_formats() {
        let excl = vec!["user_agent".to_string(), "referer".to_string()];
        let json = logger(LogFormat::Json, excl.clone()).format_json(&entry());
        assert!(!json.contains("user_agent"), "{json}");

        let text = logger(LogFormat::Text, excl).format_text(&entry());
        assert!(!text.contains("ua="), "{text}");
    }

    #[test]
    fn text_format_is_single_line_and_has_key_fields() {
        let out = logger(LogFormat::Text, vec![]).format_text(&entry());
        assert!(!out.contains('\n'), "text line must not wrap: {out}");
        assert!(out.contains("203.0.113.9"));
        assert!(out.contains("GET"));
        assert!(out.contains(" 200 "));
        assert!(out.contains("ttfb=7ms"));
        assert!(out.contains("route=/api/*"));
    }

    #[test]
    fn missing_optional_fields_are_simply_absent() {
        let mut e = entry();
        e.ttfb_ms = None;
        e.route = None;
        e.upstream = None;
        let out = logger(LogFormat::Json, vec![]).format_json(&e);
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(parsed.get("ttfb_ms").is_none());
        assert!(parsed.get("route").is_none());
        assert!(parsed.get("upstream").is_none());
        // and the JSON is still well-formed with no dangling comma
        assert_eq!(parsed["status"], 200);
    }

    #[test]
    fn no_log_config_yields_no_logger() {
        assert!(AccessLogger::from_config(None).unwrap().is_none());
    }

    #[test]
    fn same_file_path_shares_one_handle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        let path_str = path.to_str().unwrap().to_string();

        let cfg = LogConfig {
            output: LogOutput::File(path_str.clone()),
            format: LogFormat::Json,
            level: None,
            exclude_fields: vec![],
            rotation: Default::default(),
            request_headers: vec![],
            response_headers: vec![],
            include_tls: false,
        };

        // 🗂️ Two servers configured with the same path must share one handle,
        // otherwise their writes can interleave mid-line. The registry is the
        // mechanism, so the assertion goes there directly — since the writer
        // thread took ownership of the sink, reaching through a built logger
        // would only re-test the plumbing that hands it over.
        let LogOutput::File(path) = &cfg.output else {
            panic!("expected a file output");
        };
        let first = open_shared_file(path).expect("open");
        let second = open_shared_file(path).expect("open again");
        assert!(
            Arc::ptr_eq(&first, &second),
            "same path must share one handle"
        );

        let a = AccessLogger::from_config(Some(&cfg)).unwrap().unwrap();
        let b = AccessLogger::from_config(Some(&cfg)).unwrap().unwrap();

        a.log(&entry());
        b.log(&entry());
        // 🚿 Writes are queued to a background thread since Day 23, so a test
        // that reads the file back has to wait for the sink to catch up.
        a.flush();
        b.flush();
        let contents = std::fs::read_to_string(path).unwrap();
        assert_eq!(contents.lines().count(), 2, "both lines should land");
        for line in contents.lines() {
            serde_json::from_str::<serde_json::Value>(line)
                .unwrap_or_else(|e| panic!("interleaved/corrupt line: {e}\n{line}"));
        }
    }

    #[test]
    fn file_sink_appends_rather_than_truncates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("append.log");
        std::fs::write(&path, "pre-existing\n").unwrap();

        let cfg = LogConfig {
            output: LogOutput::File(path.to_str().unwrap().to_string()),
            format: LogFormat::Json,
            level: None,
            exclude_fields: vec![],
            rotation: Default::default(),
            request_headers: vec![],
            response_headers: vec![],
            include_tls: false,
        };
        let logger = AccessLogger::from_config(Some(&cfg)).unwrap().unwrap();
        logger.log(&entry());
        // 🚿 Same reason as above: the line is queued, not yet written.
        logger.flush();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(
            contents.starts_with("pre-existing\n"),
            "must not truncate an existing log: {contents}"
        );
        assert_eq!(contents.lines().count(), 2);
    }
}

#[cfg(test)]
mod writer_backpressure_tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// 🧱 A sink that stops accepting writes, standing in for a full disk or a
    /// stalled network mount.
    ///
    /// A pipe whose read end is never drained: once the kernel buffer fills,
    /// `write` blocks. That is a real stall rather than a simulated one, and it
    /// needs no sleeps — the reader is simply held open and ignored.
    fn wedged_sink() -> (LogSink, std::io::PipeReader) {
        use std::os::fd::OwnedFd;
        let (reader, writer) = std::io::pipe().expect("pipe");
        let file = File::from(OwnedFd::from(writer));
        (LogSink::File(Arc::new(Mutex::new(file))), reader)
    }

    /// 🚦 **Day 23's completion criterion.**
    ///
    /// A writer that cannot keep up must not slow the caller down. The bound is
    /// deliberately generous — the assertion is not "logging is fast", it is
    /// "logging cannot hold a request hostage". Before the queue existed, this
    /// loop would have blocked on the first line and never returned.
    #[test]
    fn a_wedged_sink_does_not_block_the_caller() {
        // 🧊 `_reader` stays alive and unread for the whole test; dropping it
        // would turn the stall into EPIPE and quietly test nothing.
        let (sink, _reader) = wedged_sink();
        let writer = LogWriter::spawn(sink, 8);

        let started = Instant::now();
        for i in 0..10_000 {
            writer.submit(format!("line {i}"));
        }
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(2),
            "10,000 submissions against a wedged sink took {elapsed:?}; the request \
             path is waiting on the log writer"
        );
    }

    /// 🧮 The lines that could not be queued must be counted, not silently
    /// discarded. A gap in the log that nobody can detect is worse than a gap
    /// an operator can see and act on.
    #[test]
    fn dropped_lines_are_counted() {
        let (sink, _reader) = wedged_sink();
        let writer = LogWriter::spawn(sink, 8);
        for i in 0..5_000 {
            writer.submit(format!("line {i}"));
        }
        assert!(
            writer.dropped() > 0,
            "a queue of 8 accepted 5,000 lines against a wedged sink without \
             dropping any — the bound is not being enforced"
        );
    }

    /// 🎯 The mirror case: a healthy sink must lose nothing. Without this, a
    /// writer that dropped every line would pass both tests above.
    #[test]
    fn a_healthy_sink_loses_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("access.log");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("open");
        let writer = LogWriter::spawn(LogSink::File(Arc::new(Mutex::new(file))), 1024);

        for i in 0..500 {
            writer.submit(format!("line {i}"));
        }
        writer.flush();

        assert_eq!(writer.dropped(), 0, "a healthy sink must drop nothing");
        let written = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(
            written.lines().count(),
            500,
            "every submitted line must reach the file"
        );
    }
}

#[cfg(test)]
mod rotation_tests {
    use super::*;

    fn rotating_logger(dir: &Path, rotation: LogRotation) -> AccessLogger {
        let path = dir.join("access.log");
        let cfg = LogConfig {
            output: LogOutput::File(path.to_str().unwrap().to_string()),
            format: LogFormat::Json,
            level: None,
            exclude_fields: vec![],
            rotation,
            request_headers: vec![],
            response_headers: vec![],
            include_tls: false,
        };
        AccessLogger::from_config(Some(&cfg)).unwrap().unwrap()
    }

    fn siblings(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "access.log")
            .collect();
        names.sort();
        names
    }

    /// 🔄 A file that reaches the size trigger must be rolled aside, and the
    /// active file must start again from empty.
    ///
    /// Without this, "rotation is configured" and "rotation happens" are the
    /// same untested distinction that let the cache ceiling look enforced while
    /// 20 MiB streamed straight past it.
    #[test]
    fn reaching_the_size_limit_rolls_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let logger = rotating_logger(
            dir.path(),
            LogRotation {
                max_size_bytes: Some(512),
                ..Default::default()
            },
        );

        for _ in 0..200 {
            logger.log(&super::tests::entry());
        }
        logger.flush();

        assert!(
            !siblings(dir.path()).is_empty(),
            "200 JSON lines against a 512-byte limit produced no rotated file"
        );
        let active = std::fs::metadata(dir.path().join("access.log"))
            .unwrap()
            .len();
        assert!(
            active < 200 * 100,
            "the active file still holds everything ({active} bytes) — it was never rolled"
        );
    }

    /// 🗃️ Retention is the half that actually stops the disk filling. Rotation
    /// alone only slows it down.
    #[test]
    fn retention_deletes_the_oldest_rotated_files() {
        let dir = tempfile::tempdir().unwrap();
        let logger = rotating_logger(
            dir.path(),
            LogRotation {
                max_size_bytes: Some(256),
                keep: Some(2),
                ..Default::default()
            },
        );

        for _ in 0..400 {
            logger.log(&super::tests::entry());
        }
        logger.flush();

        let kept = siblings(dir.path());
        assert!(
            kept.len() <= 2,
            "keep=2 left {} rotated files behind: {kept:?}",
            kept.len()
        );
        assert!(
            !kept.is_empty(),
            "retention deleted everything, including what it should keep"
        );
    }

    /// 🗜️ Compressed rotation must produce `.gz` and remove the plain file,
    /// or the disk saving is imaginary.
    #[test]
    fn compressed_rotation_leaves_only_gzip() {
        let dir = tempfile::tempdir().unwrap();
        let logger = rotating_logger(
            dir.path(),
            LogRotation {
                max_size_bytes: Some(256),
                compress: true,
                ..Default::default()
            },
        );

        for _ in 0..300 {
            logger.log(&super::tests::entry());
        }
        logger.flush();

        let kept = siblings(dir.path());
        assert!(!kept.is_empty(), "nothing was rotated");
        assert!(
            kept.iter().all(|n| n.ends_with(".gz")),
            "compression left uncompressed files behind: {kept:?}"
        );
    }

    /// 🚫 A logger with no rotation configured must never touch the directory.
    /// This is the control: without it, a bug that rotated unconditionally
    /// would still satisfy every test above.
    #[test]
    fn without_a_trigger_nothing_is_rotated() {
        let dir = tempfile::tempdir().unwrap();
        let logger = rotating_logger(dir.path(), LogRotation::default());
        for _ in 0..500 {
            logger.log(&super::tests::entry());
        }
        logger.flush();
        assert!(
            siblings(dir.path()).is_empty(),
            "rotation happened without a trigger: {:?}",
            siblings(dir.path())
        );
    }
}

#[cfg(test)]
mod header_logging_tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                http::HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    /// 🙈 **The property that makes header logging safe to offer at all.**
    ///
    /// An operator naming `authorization` wants to know the request was
    /// authenticated, not to copy the credential into a file that gets shipped
    /// to a log aggregator. The field appears; the secret does not.
    #[test]
    fn sensitive_headers_are_recorded_as_present_but_masked() {
        let collected = collect_headers(
            &["authorization".to_string(), "cookie".to_string()],
            &headers(&[
                ("authorization", "Bearer super-secret-token"),
                ("cookie", "session=abc123"),
            ]),
        );

        assert_eq!(collected.len(), 2, "both headers must appear");
        for (name, value) in &collected {
            assert_eq!(value, crate::redaction::REDACTED, "{name} leaked its value");
        }
        let rendered = format!("{collected:?}");
        assert!(
            !rendered.contains("super-secret-token") && !rendered.contains("abc123"),
            "a secret survived masking: {rendered}"
        );
    }

    /// 🎯 The mirror case. Without it, a `collect_headers` that masked
    /// everything would pass the test above and make the feature useless.
    #[test]
    fn ordinary_headers_keep_their_values() {
        let collected = collect_headers(
            &["x-request-id".to_string()],
            &headers(&[("x-request-id", "abc-123")]),
        );
        assert_eq!(
            collected,
            vec![("x-request-id".to_string(), "abc-123".to_string())]
        );
    }

    /// 🚫 A header the server did not ask for must never be recorded, however
    /// harmless it looks — the allow list is the privacy boundary.
    #[test]
    fn unrequested_headers_are_not_recorded() {
        let collected = collect_headers(
            &["x-request-id".to_string()],
            &headers(&[("x-request-id", "abc"), ("x-secret-internal", "leak")]),
        );
        assert_eq!(collected.len(), 1);
        assert!(!format!("{collected:?}").contains("leak"));
    }

    /// 📭 Naming a header the request did not carry produces no field, rather
    /// than an empty one that reads as "the client sent nothing".
    #[test]
    fn absent_headers_produce_no_field() {
        let collected = collect_headers(&["x-missing".to_string()], &headers(&[]));
        assert!(collected.is_empty());
    }

    /// 🏷️ Headers are nested, so a header named after a log field cannot
    /// overwrite it.
    #[test]
    fn a_header_cannot_collide_with_a_log_field() {
        let logger = super::tests::logger(LogFormat::Json, vec![]);
        let request_headers = vec![("status".to_string(), "not-a-status".to_string())];
        let mut entry = super::tests::entry();
        entry.request_headers = &request_headers;

        let line = logger.format_json(&entry);
        let parsed: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(
            parsed["status"], 200,
            "a header called `status` overwrote the real status field: {line}"
        );
        assert_eq!(parsed["request_headers"]["status"], "not-a-status");
    }
}
