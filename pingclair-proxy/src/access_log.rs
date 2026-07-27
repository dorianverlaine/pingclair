//! 📝 Per-server access logging driven by each server's `LogConfig`.
//!
//! Before this module, `log { output stdout; format json }` compiled into a
//! `LogConfig` that nothing ever read: every server shared one process-wide
//! `tracing` subscriber, so per-server `output`/`format` were silently
//! ignored. This module makes that configuration actually decide where a
//! request line goes and how it is shaped.
//!
//! Scope note: this is the *routing and formatting* layer only. Rotation,
//! retention, compression and a bounded async writer are deliberately not
//! here — see `docs/TODO.md` Day 21. Writes are synchronous and serialized
//! per sink, which is correct but will block the caller if the disk stalls;
//! that limitation is the reason Day 21 exists.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use pingclair_core::config::{LogConfig, LogFormat, LogOutput};

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
}

/// 🧾 A configured per-server access logger.
pub struct AccessLogger {
    sink: LogSink,
    format: LogFormat,
    /// Field names the config asked to drop (`format filter { fields { x delete } }`).
    exclude: HashSet<String>,
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

        Ok(Some(Self {
            sink,
            format: config.format.clone(),
            exclude: config.exclude_fields.iter().cloned().collect(),
        }))
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

        if let Err(e) = self.write_line(&line) {
            tracing::warn!(error = %e, "⚠️ Failed to write access log line");
        }
    }

    fn write_line(&self, line: &str) -> std::io::Result<()> {
        match &self.sink {
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

    fn entry<'a>() -> AccessEntry<'a> {
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
        }
    }

    fn logger(format: LogFormat, exclude: Vec<String>) -> AccessLogger {
        AccessLogger {
            sink: LogSink::Stdout,
            format,
            exclude: exclude.into_iter().collect(),
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
        };

        let a = AccessLogger::from_config(Some(&cfg)).unwrap().unwrap();
        let b = AccessLogger::from_config(Some(&cfg)).unwrap().unwrap();

        // Two servers configured with the same path must share one handle,
        // otherwise their writes can interleave mid-line.
        match (&a.sink, &b.sink) {
            (LogSink::File(fa), LogSink::File(fb)) => {
                assert!(Arc::ptr_eq(fa, fb), "same path must share one handle");
            }
            _ => panic!("expected file sinks"),
        }

        a.log(&entry());
        b.log(&entry());
        let contents = std::fs::read_to_string(&path).unwrap();
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
        };
        AccessLogger::from_config(Some(&cfg))
            .unwrap()
            .unwrap()
            .log(&entry());

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(
            contents.starts_with("pre-existing\n"),
            "must not truncate an existing log: {contents}"
        );
        assert_eq!(contents.lines().count(), 2);
    }
}
