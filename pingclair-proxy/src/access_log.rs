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
//! Writes leave the request path immediately: [`LogWriter`] owns the sink and
//! drains a bounded queue from its own thread, so a stalled disk costs log
//! lines rather than requests. Size- and age-based rotation, gzip and
//! retention live here too.
//!
//! ⚠️ Scope note: [`LogTargets`] decides *which* destinations a request
//! reaches, from each logger's `hostnames`. The other two selection layers
//! Caddy has — `include`/`exclude` over logger namespaces, and `sampling` —
//! are not implemented yet and are refused rather than accepted, so no
//! configuration can quietly believe it is filtering.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

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

/// 🔢 Reads an octal permission string such as `0644`.
///
/// Returns `None` for anything unreadable; the caller then leaves the platform
/// default in place rather than guessing, because guessing at permissions on a
/// file full of request data is how a log ends up world-readable.
fn parse_octal_mode(value: &str) -> Option<u32> {
    let digits = value.trim().trim_start_matches("0o");
    u32::from_str_radix(digits, 8)
        .ok()
        .filter(|mode| *mode <= 0o7777)
}

/// 🔐 Applies a configured mode to a path that already exists.
///
/// Unix only: `mode` and `dir_mode` describe POSIX permission bits, and there
/// is no honest mapping onto Windows ACLs. Pretending otherwise would report
/// success for a restriction that was never applied.
#[cfg(unix)]
fn apply_mode(path: &Path, mode: Option<&String>) {
    use std::os::unix::fs::PermissionsExt;
    let Some(mode) = mode.and_then(|value| parse_octal_mode(value)) else {
        return;
    };
    if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        tracing::warn!(
            error = %error,
            path = %path.display(),
            "🔐 Could not apply the configured log file mode"
        );
    }
}

#[cfg(not(unix))]
fn apply_mode(_path: &Path, _mode: Option<&String>) {}

/// 📁 Whatever mode a newly created log directory should carry.
///
/// A directory needs execute wherever it has read, or its contents cannot be
/// listed — `0644` on a directory is unusable. `from_file` and `inherit` both
/// derive from something else and then normalise that way, which is why the
/// resolution happens here at open time rather than in the adapter: the answer
/// depends on the filesystem, not on what the configuration said.
#[cfg(unix)]
fn resolve_dir_mode(parent: &Path, rotation: &LogRotation) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;

    /// 🔁 Read implies traverse, the rule upstream applies to every derived
    /// directory mode: 0644 becomes 0755, 0600 becomes 0700.
    fn read_implies_execute(mode: u32) -> u32 {
        let mut mode = mode;
        for (read, execute) in [(0o400, 0o100), (0o040, 0o010), (0o004, 0o001)] {
            if mode & read != 0 {
                mode |= execute;
            }
        }
        mode
    }

    match rotation.dir_mode.as_deref()? {
        "from_file" => rotation
            .mode
            .as_deref()
            .and_then(parse_octal_mode)
            .map(read_implies_execute),
        // 🧭 The nearest existing ancestor, since the directory being created
        // has no permissions of its own to copy yet.
        "inherit" => {
            let mut ancestor = parent.parent();
            while let Some(candidate) = ancestor {
                if let Ok(metadata) = std::fs::metadata(candidate) {
                    return Some(read_implies_execute(metadata.permissions().mode() & 0o7777));
                }
                ancestor = candidate.parent();
            }
            None
        }
        explicit => parse_octal_mode(explicit),
    }
}

/// 📁 Applies the resolved directory mode, if one can be resolved.
#[cfg(unix)]
fn apply_resolved_dir_mode(parent: &Path, rotation: &LogRotation) {
    use std::os::unix::fs::PermissionsExt;
    let Some(mode) = resolve_dir_mode(parent, rotation) else {
        return;
    };
    if let Err(error) = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(mode)) {
        tracing::warn!(
            error = %error,
            path = %parent.display(),
            "🔐 Could not apply the configured log directory mode"
        );
    }
}

#[cfg(not(unix))]
fn apply_resolved_dir_mode(_parent: &Path, _rotation: &LogRotation) {}

fn open_shared_file(path: &str, rotation: &LogRotation) -> std::io::Result<Arc<Mutex<File>>> {
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
        let existed = parent.exists();
        std::fs::create_dir_all(parent)?;
        // 🔐 Only a directory this process created gets its mode set. Applying
        // `dir_mode` to a pre-existing directory would silently re-permission
        // something the operator may share with other services.
        if !existed {
            apply_resolved_dir_mode(parent, rotation);
        }
    }

    let file = OpenOptions::new().create(true).append(true).open(raw)?;
    // 🔐 A log file carries request paths, client addresses and any headers the
    // operator asked to record, so the default mode is not always the right
    // one. Applied after the open rather than through `OpenOptions::mode`,
    // which only takes effect on creation and would leave an existing file at
    // whatever permissions it already had.
    apply_mode(raw, rotation.mode.as_ref());
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
fn reopen_shared_file(
    handle: &Arc<Mutex<File>>,
    path: &Path,
    rotation: &LogRotation,
) -> std::io::Result<()> {
    let fresh = OpenOptions::new().create(true).append(true).open(path)?;
    // 🔐 The fresh file is a new inode, so it starts at the platform default
    // rather than inheriting the rotated file's permissions. Reapplying the
    // configured mode here is what stops rotation from quietly widening it.
    apply_mode(path, rotation.mode.as_ref());
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
    // 🌐 No list means every header, which is what Caddy does: its JSON access
    // log carries the whole `request.headers` map with `Authorization` and
    // `Cookie` replaced by `REDACTED`. Returning nothing here instead made the
    // masking untestable — Day 26 asserted "the secret is not in the log" and
    // it passed for the uninteresting reason that no header was there at all.
    // A named list is therefore a *narrowing*, not a switch that turns logging
    // on.
    let render = |name: &str, value: &http::HeaderValue| {
        if crate::redaction::is_sensitive_header(name) {
            crate::redaction::REDACTED.to_string()
        } else {
            value.to_str().unwrap_or("<binary>").to_string()
        }
    };

    if wanted.is_empty() {
        // 📌 `HeaderMap` has already lower-cased the names, so these read
        // `authorization` where Caddy echoes the sender's own capitalisation.
        // The set is identical; only the spelling differs.
        return headers
            .iter()
            .map(|(name, value)| {
                let name = name.as_str();
                (name.to_string(), render(name, value))
            })
            .collect();
    }

    wanted
        .iter()
        .filter_map(|name| {
            let value = headers.get(name.as_str())?;
            Some((name.clone(), render(name, value)))
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
    /// 🔌 Which log sources this destination subscribes to. Empty on both
    /// sides — the common case — admits everything and costs one length check.
    namespaces: NamespaceFilter,
    /// 🎲 Optional rate policy. `None` is the common case and costs one branch.
    sampling: Option<SamplingWindow>,
}

// MARK: - Host selection

/// 🏠 One entry of a logger's `hostnames` list, precompiled.
///
/// Upstream stores the pattern verbatim and, per request, walks the host's
/// labels replacing them with `*` one at a time **without restoring the
/// previous one**. For `a.b.c` that yields `*.b.c`, then `*.*.c`, then
/// `*.*.*` — so only a *leading run* of stars can ever match, and a pattern
/// like `a.*.c` is unreachable no matter what host arrives.
///
/// That quirk is copied deliberately. The obvious generalisation — same label
/// count, every non-star label equal — is strictly more permissive, and a
/// configuration that logs on one server and not the other is worse than one
/// that is uselessly strict in the same way on both.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HostPattern {
    /// 🔢 Labels the host must have, since upstream never changes the count.
    label_count: usize,
    /// ⭐ How many leading labels are `*`. Zero means an exact match.
    leading_stars: usize,
    /// 🏷️ The labels after the stars, which must match exactly.
    tail: Vec<String>,
}

impl HostPattern {
    /// 🧭 Compiles one configured pattern, or `None` if no host can match it.
    fn compile(pattern: &str) -> Option<Self> {
        let labels: Vec<&str> = pattern.split('.').collect();
        let leading_stars = labels.iter().take_while(|label| **label == "*").count();
        // 🚫 A star after a non-star label is unreachable upstream, so keeping
        // it would mean carrying a pattern that can never fire.
        if labels[leading_stars..].contains(&"*") {
            return None;
        }
        Some(Self {
            label_count: labels.len(),
            leading_stars,
            tail: labels[leading_stars..]
                .iter()
                .map(|label| label.to_ascii_lowercase())
                .collect(),
        })
    }

    /// 🎯 Whether a request host matches, without allocating.
    fn matches(&self, host: &str) -> bool {
        let mut labels = host.split('.');
        let count = host.split('.').count();
        if count != self.label_count {
            return false;
        }
        for _ in 0..self.leading_stars {
            if labels.next().is_none() {
                return false;
            }
        }
        self.tail
            .iter()
            .zip(labels)
            .all(|(expected, actual)| expected.eq_ignore_ascii_case(actual))
    }
}

// MARK: - Sampling

/// 🎲 Keeps a bounded share of entries inside a rolling window.
///
/// Sampling exists for the load where the log itself becomes the cost: the
/// first `first` entries of each window are kept, and after that one in every
/// `thereafter`. The window then resets, so a burst is represented rather than
/// recorded in full and a quiet period is unaffected.
///
/// 🚫 The lines this drops are **not** counted in
/// [`metrics::ACCESS_LOG_DROPPED_TOTAL`]. That metric means "the writer could
/// not keep up", which is a fault an operator should act on; a sampled line is
/// a line they asked not to have. One counter cannot mean both without making
/// the alerting useless.
struct SamplingWindow {
    /// ⏱️ Monotonic base, because an atomic cannot hold an `Instant` and the
    /// wall clock can step backwards.
    origin: Instant,
    interval_nanos: u64,
    first: u64,
    thereafter: u64,
    /// 🪟 Start of the current window, in nanoseconds since `origin`.
    window_start: AtomicU64,
    /// 🔢 Entries seen in the current window.
    count: AtomicU64,
}

impl SamplingWindow {
    /// 🧭 Builds a window, filling in upstream's defaults for anything unset.
    ///
    /// Zero means "not specified" in the configuration, and upstream substitutes
    /// one second and one hundred. Treating zero literally would mean a window
    /// that expires instantly or a `first` of none, both of which turn a tuning
    /// knob into an outage of the log.
    fn new(policy: pingclair_core::config::LogSampling) -> Self {
        let interval_secs = if policy.interval_secs == 0 {
            1
        } else {
            policy.interval_secs
        };
        Self {
            origin: Instant::now(),
            interval_nanos: interval_secs.saturating_mul(1_000_000_000),
            first: if policy.first == 0 {
                100
            } else {
                policy.first as u64
            },
            thereafter: policy.thereafter as u64,
            window_start: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// 🎯 Whether this entry survives sampling.
    ///
    /// Lock-free on purpose: this runs on the request path, and a mutex here
    /// would serialise every request behind whichever one is currently deciding
    /// whether to write a log line. The window handover uses one
    /// compare-exchange so exactly one thread resets the counter; a thread that
    /// increments across the boundary is off by one entry, which is the right
    /// trade for a mechanism whose whole purpose is approximation.
    fn admits(&self) -> bool {
        use std::sync::atomic::Ordering::{AcqRel, Acquire, Release};

        let now = self.origin.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        let start = self.window_start.load(Acquire);
        if now.saturating_sub(start) >= self.interval_nanos
            && self
                .window_start
                .compare_exchange(start, now, AcqRel, Acquire)
                .is_ok()
        {
            self.count.store(0, Release);
        }

        let seen = self.count.fetch_add(1, AcqRel) + 1;
        if seen <= self.first {
            return true;
        }
        // 📌 `thereafter 0` means nothing beyond the first entries is kept,
        // which is a meaningful setting rather than a division by zero.
        if self.thereafter == 0 {
            return false;
        }
        (seen - self.first).is_multiple_of(self.thereafter)
    }
}

// MARK: - Namespace selection

/// 🔌 Which log sources a destination subscribes to.
///
/// Upstream names every logger with a dotted namespace — a site's
/// `log access_json` emits under `http.log.access.access_json` — and a global
/// logger says which of those it wants with `include` and `exclude`. Both empty
/// means everything.
///
/// The matching rule is longest-prefix, and the trailing dot is not decoration:
/// without it `foo.b` would match `foo.bar`. `*` in `exclude` means every module
/// logger and `.` means the core's own, which is why they are checked before the
/// prefix walk rather than being treated as ordinary namespaces.
#[derive(Debug, Clone, Default)]
pub struct NamespaceFilter {
    include: Vec<String>,
    exclude: Vec<String>,
}

impl NamespaceFilter {
    pub fn new(include: Vec<String>, exclude: Vec<String>) -> Self {
        Self { include, exclude }
    }

    /// 🎯 Whether a log source may emit into this destination.
    pub fn admits(&self, source: &str) -> bool {
        if self.include.is_empty() && self.exclude.is_empty() {
            return true;
        }
        // 📌 The dot is appended once here and compared against `namespace + "."`
        // below, so an exact namespace and a parent namespace both match while a
        // shared prefix that stops mid-label does not.
        let dotted = if source.is_empty() || source == "*" || source == "." {
            source.to_string()
        } else {
            format!("{source}.")
        };

        let mut longest_accept = 0usize;
        let mut longest_reject = 0usize;

        if !self.include.is_empty() {
            for namespace in &self.include {
                if dotted.starts_with(&format!("{namespace}.")) && namespace.len() > longest_accept
                {
                    longest_accept = namespace.len();
                }
            }
            // 🚫 An `include` list is a requirement, not a hint: no match means
            // this destination did not ask for this source.
            if longest_accept == 0 {
                return false;
            }
        }

        if !self.exclude.is_empty() {
            for namespace in &self.exclude {
                if (namespace == "*" && dotted != ".") || (namespace == "." && dotted == ".") {
                    return false;
                }
                if dotted.starts_with(&format!("{namespace}.")) && namespace.len() > longest_reject
                {
                    longest_reject = namespace.len();
                }
            }
            if longest_reject > longest_accept {
                return false;
            }
        }

        longest_accept > longest_reject || (self.include.is_empty() && longest_reject == 0)
    }
}

/// 🪵 Which destinations a request reaches, resolved once at configuration time.
///
/// The request path used to hand every entry to every logger, which made
/// `hostnames` a field that compiled, serialised, and did nothing. Selection
/// now happens here, and the request path only walks a precomputed list — no
/// name lookups, no pattern parsing, no allocation.
#[derive(Default, Clone)]
pub struct LogTargets {
    /// 🌐 Destinations that take every request to this server, which is what a
    /// logger without `hostnames` means.
    unrestricted: Vec<Arc<AccessLogger>>,
    /// 🏠 Destinations restricted to particular hosts, most specific first.
    restricted: Vec<(HostPattern, Arc<AccessLogger>)>,
}

impl LogTargets {
    /// 🧭 Builds the selection, ordering restricted entries the way upstream
    /// resolves them: an exact hostname wins over `*.example.com`, which wins
    /// over `*.*.com`.
    pub fn new(entries: Vec<(Vec<String>, Arc<AccessLogger>)>) -> Self {
        let mut targets = Self::default();
        for (hostnames, logger) in entries {
            if hostnames.is_empty() {
                targets.unrestricted.push(logger);
                continue;
            }
            for hostname in &hostnames {
                match HostPattern::compile(hostname) {
                    Some(pattern) => targets.restricted.push((pattern, logger.clone())),
                    None => tracing::warn!(
                        hostname = %hostname,
                        "🚫 Ignoring a log hostname no request can match"
                    ),
                }
            }
        }
        targets
            .restricted
            .sort_by_key(|(pattern, _)| pattern.leading_stars);
        targets
    }

    /// 📮 Every destination this host's entries belong in.
    ///
    /// A host may reach several: upstream maps one hostname to a list, and a
    /// logger without `hostnames` covers the whole server alongside them.
    pub fn select(&self, host: &str) -> impl Iterator<Item = &Arc<AccessLogger>> {
        let host = host.split(':').next().unwrap_or(host);
        self.unrestricted.iter().chain(
            self.restricted
                .iter()
                .filter(move |(pattern, _)| pattern.matches(host))
                .map(|(_, logger)| logger),
        )
    }

    /// 🈳 Whether nothing at all is configured, so callers keep the previous
    /// process-wide `tracing` behaviour instead of silently dropping lines.
    pub fn is_empty(&self) -> bool {
        self.unrestricted.is_empty() && self.restricted.is_empty()
    }
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

/// 🪵 Process-wide registry of named channels, so several servers referencing
/// one channel share a single writer.
///
/// Sharing is the whole point. Two `AccessLogger`s on one file would each have
/// their own queue and their own thread; the file mutex would keep individual
/// lines intact, but the two queues would drain independently and a burst on
/// one server could sit behind a stall on the other. One channel, one queue.
fn channel_registry() -> &'static Mutex<HashMap<String, Arc<AccessLogger>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Arc<AccessLogger>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 🪵 Returns the shared logger for a named channel, building it once.
///
/// A reload that reuses the same channel name keeps the existing writer rather
/// than spawning a second one — otherwise every reload would leak a thread and
/// leave the old queue draining into the same file.
pub fn register_channels(channels: &std::collections::BTreeMap<String, LogConfig>) {
    let mut registry = channel_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for (name, config) in channels {
        // ♻️ A reload that names the same channel keeps the existing writer.
        // Rebuilding it would spawn a second thread writing the same file and
        // leak the first one, every reload, forever.
        if registry.contains_key(name) {
            continue;
        }
        match AccessLogger::from_config(Some(config)) {
            Ok(Some(logger)) => {
                registry.insert(name.clone(), Arc::new(logger));
            }
            Ok(None) => unreachable!("a channel always carries a config"),
            Err(error) => {
                // 🚫 Reported, not fatal. Losing one log destination must not
                // stop the server from starting and serving traffic.
                tracing::error!(error = %error, channel = %name, "❌ Could not open log channel");
            }
        }
    }
}

/// 🪵 Looks up an already-registered channel.
pub fn channel_logger(name: &str) -> Option<Arc<AccessLogger>> {
    channel_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(name)
        .cloned()
}

/// 🔌 Every registered channel that subscribes to a log source.
///
/// A site block writes to a global channel in two ways, and only one of them
/// used to work at runtime. Naming the channel directly (`log audit` where a
/// global `log audit { … }` exists) resolved by name. The other way — a global
/// logger saying `include http.log.access.audit` — passed validation and then
/// received nothing, because nothing ever consulted `include`.
pub fn channels_admitting(source: &str) -> Vec<Arc<AccessLogger>> {
    channel_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .values()
        .filter(|logger| logger.admits_source(source))
        .cloned()
        .collect()
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
    let by_interval = rotation.roll_interval_secs.is_some_and(|interval| {
        interval > 0
            && opened_at
                .elapsed()
                .is_ok_and(|elapsed| elapsed.as_secs() >= interval)
    });
    // 🕰️ Whichever trigger arrives first wins, so a file with both a size
    // limit and a nightly time rolls on whichever comes up — the operator
    // asked for both bounds, not for one to mask the other.
    by_size || by_age || by_interval || crossed_a_scheduled_time(rotation, opened_at)
}

/// 🕰️ Whether a `roll_at` or `roll_minutes` boundary has passed since the file
/// was opened.
///
/// Both are calendar triggers rather than durations: `roll_at 00:00` means
/// midnight, not "24 hours from whenever this file happened to open". The
/// question is therefore whether a scheduled instant falls in the half-open
/// window between the file's open time and now.
///
/// 📌 Like upstream, this is only consulted when a line arrives. An idle log
/// does not roll at midnight and then sit empty; it rolls when it next has
/// something to write, which is the point at which the boundary matters.
fn crossed_a_scheduled_time(rotation: &LogRotation, opened_at: std::time::SystemTime) -> bool {
    use chrono::{DateTime, Local, Timelike};

    if rotation.roll_at.is_none() && rotation.roll_minutes.is_none() {
        return false;
    }
    let opened: DateTime<Local> = DateTime::from(opened_at);
    let now = Local::now();
    if now <= opened {
        return false;
    }

    // 🕐 `roll_minutes 0 30` rolls at every xx:00 and xx:30. A boundary was
    // crossed when the count of elapsed boundaries differs between the two
    // instants, which avoids enumerating them.
    if let Some(minutes) = &rotation.roll_minutes {
        for minute in parse_minute_list(minutes) {
            let elapsed_hours = |at: &DateTime<Local>| {
                let reached = at.minute() >= minute;
                at.timestamp().div_euclid(3600) + i64::from(reached)
            };
            if elapsed_hours(&now) > elapsed_hours(&opened) {
                return true;
            }
        }
    }

    if let Some(times) = &rotation.roll_at {
        for (hour, minute) in parse_time_list(times) {
            let elapsed_days = |at: &DateTime<Local>| {
                let reached = (at.hour(), at.minute()) >= (hour, minute);
                at.timestamp().div_euclid(86_400) + i64::from(reached)
            };
            if elapsed_days(&now) > elapsed_days(&opened) {
                return true;
            }
        }
    }
    false
}

/// 🕰️ The timestamp a rotated file carries in its name.
///
/// Sortable and human-readable, because that name is what an operator greps
/// when asked which file covers a given hour. It used to be epoch seconds,
/// which is neither, and which made `roll_local_time` meaningless — a Unix
/// timestamp has no timezone to express.
///
/// Colons are avoided on purpose: they are legal on Unix and not on Windows,
/// and a rotated log that cannot be copied to another machine is a poor
/// archive.
fn rotation_stamp(local: bool) -> String {
    const FORMAT: &str = "%Y-%m-%dT%H-%M-%S%.3f";
    if local {
        chrono::Local::now().format(FORMAT).to_string()
    } else {
        chrono::Utc::now().format(FORMAT).to_string()
    }
}

/// 🗜️ How rotated files are compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RotationCompression {
    None,
    Gzip,
    Zstd,
}

/// 🗜️ Resolves the two spellings that can ask for compression.
///
/// The older boolean `compress` says whether, and Caddy's `roll_compression`
/// says which. When both are present the algorithm wins, because naming one is
/// the more specific statement — and an unknown name is refused at
/// configuration time, so it cannot arrive here and quietly become gzip.
fn rotation_compression(rotation: &LogRotation) -> RotationCompression {
    match rotation.roll_compression.as_deref() {
        Some("none") => RotationCompression::None,
        Some("gzip") => RotationCompression::Gzip,
        Some("zstd") => RotationCompression::Zstd,
        _ if rotation.compress => RotationCompression::Gzip,
        _ => RotationCompression::None,
    }
}

/// 🕐 Reads `roll_minutes 0 30` into minute-of-hour values.
///
/// An unreadable entry is skipped with a warning rather than failing the
/// writer, matching upstream — but the warning matters, because a silently
/// ignored `roll_minutes 61` is a rotation the operator believes is armed.
fn parse_minute_list(value: &str) -> Vec<u32> {
    value
        .split_whitespace()
        .filter_map(|token| match token.parse::<u32>() {
            Ok(minute) if minute < 60 => Some(minute),
            _ => {
                tracing::warn!(value = %token, "⚠️ Ignoring an out-of-range roll_minutes entry");
                None
            }
        })
        .collect()
}

/// 🕰️ Reads `roll_at 00:00 12:00` into hour and minute pairs.
fn parse_time_list(value: &str) -> Vec<(u32, u32)> {
    value
        .split_whitespace()
        .filter_map(|token| {
            let (hour, minute) = token.split_once(':')?;
            match (hour.parse::<u32>(), minute.parse::<u32>()) {
                (Ok(hour), Ok(minute)) if hour < 24 && minute < 60 => Some((hour, minute)),
                _ => {
                    tracing::warn!(value = %token, "⚠️ Ignoring an unreadable roll_at entry");
                    None
                }
            }
        })
        .collect()
}

/// 🔄 Renames the active file aside, reopens it, and applies retention.
///
/// Returns the fresh handle, or `None` when anything failed — in which case the
/// caller keeps writing to the file it already has. **Failing to rotate must
/// never mean failing to log**: a permission problem on the directory is not a
/// reason to start dropping lines.
fn rotate(handle: &Arc<Mutex<File>>, path: &Path, rotation: &LogRotation) -> Option<()> {
    let rotated = path.with_extension(format!(
        "{}.{}",
        path.extension().and_then(|e| e.to_str()).unwrap_or("log"),
        rotation_stamp(rotation.roll_local_time)
    ));

    if let Err(error) = std::fs::rename(path, &rotated) {
        tracing::warn!(error = %error, path = %path.display(), "⚠️ Could not rotate access log");
        return None;
    }

    compress_rotated(&rotated, rotation_compression(rotation));
    apply_retention(path, rotation.keep);

    match reopen_shared_file(handle, path, rotation) {
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
fn compress_rotated(rotated: &Path, algorithm: RotationCompression) {
    let Ok(raw) = std::fs::read(rotated) else {
        return;
    };
    let (suffix, compressed) = match algorithm {
        RotationCompression::None => return,
        RotationCompression::Gzip => {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            if encoder.write_all(&raw).is_err() {
                return;
            }
            let Ok(bytes) = encoder.finish() else {
                return;
            };
            ("gz", bytes)
        }
        RotationCompression::Zstd => {
            // 📏 Level 3 is zstd's own default: it is the point the algorithm
            // is tuned around, and a rotated log is written once and read
            // rarely, so spending more CPU here buys little.
            let Ok(bytes) = zstd::stream::encode_all(raw.as_slice(), 3) else {
                return;
            };
            ("zst", bytes)
        }
    };

    let target = rotated.with_extension(format!(
        "{}.{suffix}",
        rotated
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("log")
    ));
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
            LogOutput::File(path) => LogSink::File(open_shared_file(path, &config.rotation)?),
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
            namespaces: NamespaceFilter::new(config.include.clone(), config.exclude.clone()),
            sampling: config.sampling.map(SamplingWindow::new),
        }))
    }

    /// 🔌 Whether this destination subscribes to a given log source.
    pub fn admits_source(&self, source: &str) -> bool {
        self.namespaces.admits(source)
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
        // 🎲 Decided before the line is formatted, because formatting is the
        // expensive part and a sampled entry is one nobody will ever read.
        if let Some(sampling) = &self.sampling
            && !sampling.admits()
        {
            return;
        }
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
            namespaces: NamespaceFilter::default(),
            sampling: None,
        }
    }

    // MARK: - Sampling

    fn window(interval_secs: u64, first: usize, thereafter: usize) -> SamplingWindow {
        SamplingWindow::new(pingclair_core::config::LogSampling {
            interval_secs,
            first,
            thereafter,
        })
    }

    /// 🎲 The first `first` entries are kept, then one in every `thereafter`.
    #[test]
    fn the_first_entries_are_kept_then_one_in_every_thereafter() {
        let sampling = window(3600, 3, 4);
        // 🥇 The opening burst goes through untouched.
        assert!(sampling.admits());
        assert!(sampling.admits());
        assert!(sampling.admits());
        // 📉 Then entries 4, 5, 6 are dropped and 7 — the fourth after the
        // first three — is kept.
        assert!(!sampling.admits());
        assert!(!sampling.admits());
        assert!(!sampling.admits());
        assert!(sampling.admits());
        assert!(!sampling.admits());
    }

    /// 🚫 `thereafter 0` keeps only the opening entries, and is not a divide by zero.
    #[test]
    fn thereafter_zero_keeps_nothing_after_the_first() {
        let sampling = window(3600, 2, 0);
        assert!(sampling.admits());
        assert!(sampling.admits());
        for _ in 0..10 {
            assert!(!sampling.admits());
        }
    }

    /// 🪟 A new window restores the full allowance.
    #[test]
    fn the_allowance_returns_when_the_window_rolls() {
        // ⏱️ A window shorter than the test's own runtime, so the second call
        // is guaranteed to land in a fresh one.
        let sampling = window(0, 1, 0);
        assert!(sampling.admits(), "the first entry of the first window");
        assert!(!sampling.admits(), "the allowance is spent");

        std::thread::sleep(std::time::Duration::from_millis(1_100));
        assert!(
            sampling.admits(),
            "a fresh window must restore the allowance, not stay exhausted"
        );
    }

    /// 🧭 Zero means "unset", and takes upstream's defaults rather than
    /// being read literally.
    ///
    /// Read literally, `first: 0` would drop everything and `interval: 0`
    /// would expire the window on every entry — a tuning knob turned into an
    /// outage of the log.
    #[test]
    fn unset_sampling_fields_take_the_upstream_defaults() {
        let sampling = window(0, 0, 0);
        assert_eq!(sampling.first, 100);
        assert_eq!(sampling.interval_nanos, 1_000_000_000);
    }

    /// 🈳 A logger without a sampling policy keeps every line.
    #[test]
    fn no_policy_means_no_sampling() {
        let logger = logger(LogFormat::Json, Vec::new());
        assert!(logger.sampling.is_none());
    }

    // MARK: - Namespace selection

    /// 🈳 No lists at all is the common case and admits everything.
    #[test]
    fn an_empty_filter_admits_every_source() {
        let filter = NamespaceFilter::default();
        assert!(filter.admits("http.log.access.audit"));
        assert!(filter.admits("tls"));
    }

    /// 🔌 An `include` list is a requirement, and matches whole labels only.
    #[test]
    fn include_admits_the_namespace_and_everything_under_it() {
        let filter = NamespaceFilter::new(vec!["http.log.access".to_string()], Vec::new());
        assert!(filter.admits("http.log.access"), "the namespace itself");
        assert!(filter.admits("http.log.access.audit"), "and below it");
        assert!(
            !filter.admits("http.log.error"),
            "a sibling is not included"
        );
        assert!(!filter.admits("tls"), "an unrelated source is not included");
    }

    /// 📌 The trailing dot is what stops a shared prefix from matching.
    ///
    /// Without it `foo.b` would match a namespace of `foo.bar`, which is the
    /// bug the appended dot exists to prevent upstream.
    #[test]
    fn a_partial_label_is_not_a_match() {
        let filter = NamespaceFilter::new(vec!["foo.bar".to_string()], Vec::new());
        assert!(filter.admits("foo.bar.baz"));
        assert!(!filter.admits("foo.b"));
        assert!(!filter.admits("foo.barn"));
    }

    /// 🥇 When both lists match, the longer namespace wins.
    #[test]
    fn the_longest_matching_namespace_decides() {
        // 🎯 Include the whole access tree but carve one logger out of it.
        let filter = NamespaceFilter::new(
            vec!["http.log.access".to_string()],
            vec!["http.log.access.noisy".to_string()],
        );
        assert!(filter.admits("http.log.access.audit"));
        assert!(!filter.admits("http.log.access.noisy"));
        assert!(!filter.admits("http.log.access.noisy.deeper"));
    }

    /// ⭐ `*` excludes every module logger; `.` excludes the core's own.
    #[test]
    fn the_two_special_exclusions_are_not_ordinary_namespaces() {
        let everything = NamespaceFilter::new(Vec::new(), vec!["*".to_string()]);
        assert!(!everything.admits("http.log.access.audit"));
        assert!(everything.admits("."), "`*` does not cover the core");

        let core = NamespaceFilter::new(Vec::new(), vec![".".to_string()]);
        assert!(!core.admits("."));
        assert!(core.admits("http.log.access.audit"));
    }

    /// 🚫 Excluding without including admits everything else.
    #[test]
    fn exclude_alone_removes_only_what_it_names() {
        let filter = NamespaceFilter::new(Vec::new(), vec!["http.log.error".to_string()]);
        assert!(filter.admits("http.log.access.audit"));
        assert!(!filter.admits("http.log.error"));
        assert!(!filter.admits("http.log.error.detail"));
    }

    // MARK: - Host selection

    /// 🧪 Builds targets from `(hostnames, tag)` pairs, where the tag is
    /// recoverable afterwards through the logger's `exclude` set.
    fn targets(entries: &[(&[&str], &str)]) -> LogTargets {
        LogTargets::new(
            entries
                .iter()
                .map(|(hostnames, tag)| {
                    (
                        hostnames.iter().map(|host| host.to_string()).collect(),
                        Arc::new(logger(LogFormat::Json, vec![tag.to_string()])),
                    )
                })
                .collect(),
        )
    }

    /// 🔖 The tags of the destinations a host reaches, in selection order.
    fn selected(targets: &LogTargets, host: &str) -> Vec<String> {
        targets
            .select(host)
            .map(|logger| logger.exclude.iter().next().cloned().unwrap_or_default())
            .collect()
    }

    /// 🏠 A logger without `hostnames` takes everything; one with them does not.
    #[test]
    fn hostnames_restrict_a_logger_to_its_own_hosts() {
        let targets = targets(&[
            (&[][..], "everything"),
            (&["a.example.com"][..], "only-a"),
            (&["b.example.com"][..], "only-b"),
        ]);

        assert_eq!(
            selected(&targets, "a.example.com"),
            ["everything", "only-a"]
        );
        assert_eq!(
            selected(&targets, "b.example.com"),
            ["everything", "only-b"]
        );
        // 🎯 The whole point: before this, every destination saw every request,
        // so `only-a` received b.example.com's lines too.
        assert_eq!(selected(&targets, "c.example.com"), ["everything"]);
    }

    /// 🔌 A port on the request host must not defeat the match.
    #[test]
    fn the_port_is_stripped_before_matching() {
        let targets = targets(&[(&["a.example.com"][..], "only-a")]);
        assert_eq!(selected(&targets, "a.example.com:8443"), ["only-a"]);
    }

    /// ⭐ Wildcards match a leading run of labels, and only that.
    ///
    /// Upstream rewrites the host's labels to `*` one at a time without
    /// restoring the previous one, so `a.b.c` is looked up as `*.b.c`,
    /// `*.*.c`, `*.*.*`. A pattern with a star after a real label is therefore
    /// unreachable, and we reproduce that rather than being more generous.
    #[test]
    fn wildcards_match_only_a_leading_run_of_labels() {
        let targets = targets(&[
            (&["*.example.com"][..], "sub"),
            (&["*.*.com"][..], "two-deep"),
            (&["a.*.com"][..], "unreachable"),
        ]);

        assert_eq!(selected(&targets, "www.example.com"), ["sub", "two-deep"]);
        assert_eq!(selected(&targets, "a.other.com"), ["two-deep"]);
        // 🚫 Same label count, and the literal label agrees — still no match,
        // because upstream never generates this pattern.
        assert!(!selected(&targets, "a.other.com").contains(&"unreachable".to_string()));
        // 🔢 The label count has to agree; `*.example.com` is not a suffix rule.
        assert_eq!(
            selected(&targets, "deep.www.example.com"),
            Vec::<String>::new()
        );
        assert_eq!(selected(&targets, "example.com"), Vec::<String>::new());
    }

    /// 📶 An exact hostname is offered before a wildcard, and a narrower
    /// wildcard before a broader one.
    #[test]
    fn exact_hosts_are_selected_before_wildcards() {
        let targets = targets(&[
            (&["*.*.com"][..], "broad"),
            (&["*.example.com"][..], "narrow"),
            (&["www.example.com"][..], "exact"),
        ]);
        assert_eq!(
            selected(&targets, "www.example.com"),
            ["exact", "narrow", "broad"]
        );
    }

    /// 🈳 No configured destination means the caller keeps tracing output.
    #[test]
    fn no_destinations_is_reported_as_empty() {
        assert!(LogTargets::default().is_empty());
        assert!(!targets(&[(&[][..], "one")]).is_empty());
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
            hostnames: vec![],
            include: vec![],
            exclude: vec![],
            sampling: None,
        };

        // 🗂️ Two servers configured with the same path must share one handle,
        // otherwise their writes can interleave mid-line. The registry is the
        // mechanism, so the assertion goes there directly — since the writer
        // thread took ownership of the sink, reaching through a built logger
        // would only re-test the plumbing that hands it over.
        let LogOutput::File(path) = &cfg.output else {
            panic!("expected a file output");
        };
        let first = open_shared_file(path, &LogRotation::default()).expect("open");
        let second = open_shared_file(path, &LogRotation::default()).expect("open again");
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
            hostnames: vec![],
            include: vec![],
            exclude: vec![],
            sampling: None,
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

    /// ⏲️ A fixed interval is a trigger in its own right.
    ///
    /// It used to be neither read nor armed: `is_enabled` only counted size and
    /// age, so `roll_interval 12h` alone left rotation switched off entirely.
    #[test]
    fn an_interval_alone_arms_and_fires_rotation() {
        let rotation = LogRotation {
            roll_interval_secs: Some(60),
            ..Default::default()
        };
        assert!(rotation.is_enabled(), "an interval must arm rotation");

        let opened = std::time::SystemTime::now() - std::time::Duration::from_secs(61);
        assert!(should_rotate(&rotation, 0, opened));
        assert!(
            !should_rotate(&rotation, 0, std::time::SystemTime::now()),
            "a file opened just now has not reached its interval"
        );
    }

    /// 🕐 `roll_minutes` is a calendar boundary, not a duration.
    ///
    /// A file opened at 10:29 must roll at 10:30 — one minute later — rather
    /// than thirty minutes after it happened to open.
    #[test]
    fn a_minute_boundary_fires_when_it_is_crossed() {
        let rotation = LogRotation {
            // 🎯 Every minute, so the boundary is guaranteed to have been
            // crossed by a file opened two minutes ago whatever the wall clock
            // says when this runs.
            roll_minutes: Some((0..60).map(|m| m.to_string()).collect::<Vec<_>>().join(" ")),
            ..Default::default()
        };
        assert!(rotation.is_enabled());
        let opened = std::time::SystemTime::now() - std::time::Duration::from_secs(120);
        assert!(should_rotate(&rotation, 0, opened));
        assert!(!should_rotate(&rotation, 0, std::time::SystemTime::now()));
    }

    /// 🚫 An out-of-range entry is skipped rather than treated as a boundary.
    #[test]
    fn unreadable_schedule_entries_are_dropped() {
        assert_eq!(parse_minute_list("0 30 61 abc"), vec![0, 30]);
        assert_eq!(
            parse_time_list("00:00 24:00 12:30 nonsense"),
            vec![(0, 0), (12, 30)]
        );
    }

    /// 🕰️ The rotated name is sortable and carries no colons.
    ///
    /// Colons are legal on Unix and not on Windows, and a rotated log that
    /// cannot be copied to another machine is a poor archive.
    #[test]
    fn the_rotation_stamp_is_sortable_and_portable() {
        let stamp = rotation_stamp(false);
        assert!(!stamp.contains(':'), "{stamp}");
        assert!(stamp.starts_with("20"), "{stamp}");
        assert_eq!(stamp.matches('-').count(), 4, "{stamp}");
    }

    /// 🗜️ The named algorithm wins over the older boolean.
    #[test]
    fn roll_compression_decides_over_the_legacy_flag() {
        let with = |compress: bool, algorithm: Option<&str>| {
            rotation_compression(&LogRotation {
                compress,
                roll_compression: algorithm.map(str::to_string),
                ..Default::default()
            })
        };

        assert_eq!(with(true, Some("none")), RotationCompression::None);
        assert_eq!(with(false, Some("gzip")), RotationCompression::Gzip);
        assert_eq!(with(false, Some("zstd")), RotationCompression::Zstd);
        // 👍 With no algorithm named, the older spelling still decides.
        assert_eq!(with(true, None), RotationCompression::Gzip);
        assert_eq!(with(false, None), RotationCompression::None);
    }

    /// 🗜️ A zstd-rotated file is really zstd, and the plain one is gone.
    #[test]
    fn zstd_rotation_leaves_only_a_decodable_archive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        std::fs::write(&path, b"one line\n").unwrap();
        let rotation = LogRotation {
            max_size_bytes: Some(1),
            roll_compression: Some("zstd".to_string()),
            ..Default::default()
        };
        let handle = open_shared_file(path.to_str().unwrap(), &rotation).unwrap();
        rotate(&handle, &path, &rotation).expect("rotation succeeds");

        let archive = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|entry| entry.extension().is_some_and(|ext| ext == "zst"))
            .expect("a .zst archive is left behind");
        let raw = zstd::stream::decode_all(std::fs::read(&archive).unwrap().as_slice())
            .expect("the archive really is zstd");
        assert_eq!(raw, b"one line\n");
    }

    /// 📁 `from_file` derives the directory mode, adding traverse where read is.
    ///
    /// A directory at `0600` cannot be listed by its own owner's tools, so the
    /// read bits have to imply execute — `0600` becomes `0700`, `0644` becomes
    /// `0755`.
    #[cfg(unix)]
    #[test]
    fn from_file_derives_the_directory_mode_and_adds_traverse() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("access.log");
        let rotation = LogRotation {
            mode: Some("0640".to_string()),
            dir_mode: Some("from_file".to_string()),
            ..Default::default()
        };

        open_shared_file(path.to_str().unwrap(), &rotation).unwrap();
        let parent = path.parent().unwrap();
        assert_eq!(
            std::fs::metadata(parent).unwrap().permissions().mode() & 0o7777,
            0o750,
            "0640 must become 0750, not stay unreadable as a directory"
        );
    }

    /// 📁 `inherit` copies the nearest existing ancestor rather than guessing.
    #[cfg(unix)]
    #[test]
    fn inherit_copies_the_nearest_existing_ancestor() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o705)).unwrap();
        let path = dir.path().join("nested").join("access.log");
        let rotation = LogRotation {
            dir_mode: Some("inherit".to_string()),
            ..Default::default()
        };

        open_shared_file(path.to_str().unwrap(), &rotation).unwrap();
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o705,
            "the ancestor's mode already implies traverse where it reads"
        );
    }

    /// 🔐 The configured mode reaches the file, and survives a rotation.
    ///
    /// A log holds request paths, client addresses and any headers the operator
    /// asked to record. A rotation that quietly restored the default mode would
    /// widen that exposure at the exact moment nobody is watching.
    #[cfg(unix)]
    #[test]
    fn the_file_mode_is_applied_and_reapplied_after_rotation() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("access.log");
        let rotation = LogRotation {
            max_size_bytes: Some(1),
            mode: Some("0600".to_string()),
            dir_mode: Some("0700".to_string()),
            ..Default::default()
        };

        let handle = open_shared_file(path.to_str().unwrap(), &rotation).unwrap();
        let mode_of = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode_of(&path), 0o600, "the log file starts restricted");
        assert_eq!(
            mode_of(path.parent().unwrap()),
            0o700,
            "the directory this process created is restricted too"
        );

        rotate(&handle, &path, &rotation).expect("rotation succeeds");
        assert_eq!(
            mode_of(&path),
            0o600,
            "the fresh file must not fall back to the platform default"
        );
    }

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
            hostnames: vec![],
            include: vec![],
            exclude: vec![],
            sampling: None,
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

#[cfg(test)]
mod channel_sharing_tests {
    use super::*;

    fn channel_config(path: &Path) -> LogConfig {
        LogConfig {
            output: LogOutput::File(path.to_str().unwrap().to_string()),
            format: LogFormat::Json,
            level: None,
            exclude_fields: vec![],
            rotation: Default::default(),
            request_headers: vec![],
            response_headers: vec![],
            include_tls: false,
            hostnames: vec![],
            include: vec![],
            exclude: vec![],
            sampling: None,
        }
    }

    /// 🪵 **The reason named channels exist.**
    ///
    /// Two servers referencing one channel must share one writer — one queue,
    /// one thread. Give them a writer each and the file mutex still keeps
    /// individual lines intact, but the two queues drain independently, so a
    /// stall on one server can hold up lines the other already handed over.
    /// "The same channel" has to mean the same queue.
    #[test]
    fn one_channel_name_yields_one_shared_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared.log");
        let mut channels = std::collections::BTreeMap::new();
        channels.insert("shared".to_string(), channel_config(&path));

        register_channels(&channels);
        let first = channel_logger("shared").expect("registered");
        let second = channel_logger("shared").expect("still registered");

        assert!(
            Arc::ptr_eq(&first, &second),
            "two lookups of one channel produced two writers"
        );
    }

    /// ♻️ Re-registering the same name — which is what a reload does — must
    /// keep the existing writer rather than spawning a second thread onto the
    /// same file and leaking the first.
    #[test]
    fn re_registering_keeps_the_existing_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reload.log");
        let mut channels = std::collections::BTreeMap::new();
        channels.insert("reload".to_string(), channel_config(&path));

        register_channels(&channels);
        let before = channel_logger("reload").expect("registered");
        register_channels(&channels);
        let after = channel_logger("reload").expect("still registered");

        assert!(
            Arc::ptr_eq(&before, &after),
            "a reload replaced the writer, leaking the previous thread"
        );
    }

    /// 📭 An unregistered name resolves to nothing rather than to a default
    /// sink — a reference that silently logged somewhere else would be worse
    /// than one that logs nowhere, and `validate_config` already refuses it.
    #[test]
    fn an_unknown_channel_resolves_to_nothing() {
        assert!(channel_logger("never-declared-anywhere").is_none());
    }

    /// ✍️ Lines written through a channel actually reach its file.
    #[test]
    fn a_channel_writes_to_its_own_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("written.log");
        let mut channels = std::collections::BTreeMap::new();
        channels.insert("written".to_string(), channel_config(&path));

        register_channels(&channels);
        let logger = channel_logger("written").expect("registered");
        logger.log(&super::tests::entry());
        logger.flush();

        let contents = std::fs::read_to_string(&path).expect("channel file exists");
        assert_eq!(contents.lines().count(), 1);
        serde_json::from_str::<serde_json::Value>(contents.lines().next().unwrap())
            .expect("the channel wrote valid JSON");
    }
}
