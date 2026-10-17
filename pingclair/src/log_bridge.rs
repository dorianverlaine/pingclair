// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔁 Hands the `log` records Pingora writes to `tracing`, at the level the
//! event deserves rather than the level Pingora chose.
//!
//! Pingora logs through the `log` crate, and a stock `tracing_log::LogTracer`
//! forwards each record unchanged. That is right for almost every record, and
//! wrong for one: under ordinary concurrent load the upstream keepalive pool
//! sometimes hands out an idle connection while the task watching it has not
//! quite let go, and Pingora reports the miss as
//! `ERROR failed to acquire reusable stream`. The request is not affected —
//! the pool drops that connection and dials a new one — so a healthy server
//! logged a steady trickle of errors that no operator could act on. Observed in
//! the pre-0.2.0 soak run, and reproduced locally once in 51,200 proxied
//! requests at 256 concurrent clients.
//!
//! 📌 nginx treats the same event — a cached upstream keepalive connection
//! that cannot be used — as a `debug` message (`ngx_http_upstream_keepalive_module`,
//! from memory), because a reuse miss costs one extra connect and says nothing
//! about either side's health. This bridge does the same: such a record is
//! re-emitted at `DEBUG`, with its target, module, file and line kept, so
//! `log { level DEBUG }` still shows every miss and a rising rate stays
//! visible to whoever looks for it.
//!
//! 🏎️ The bridge only sees records that already passed `log`'s global level,
//! which at the default `INFO` means Pingora's warnings and errors — a handful
//! per minute, not per request. Each costs one target comparison, and a
//! second, borrowed comparison of a literal message only when the target
//! matches. Nothing is formatted or allocated to decide.

use tracing_log::AsLog;

use pingclair_proxy::metrics::{ACCEPT_ERRORS_TOTAL, DOWNSTREAM_HANDSHAKE_FAILURES_TOTAL};

/// 🎧 The Pingora listener emits the two client-caused failures this bridge
/// re-levels. Their messages are formatted, so they cannot live in the exact
/// table below; the target check keeps formatting off every other record.
const LISTENER_TARGET: &str = "pingora_core::services::listening";

/// 🗂️ Records known to describe routine operation, by `(target, message)`.
///
/// The message must be a literal in the emitting crate — that is what lets
/// `Arguments::as_str` compare it without formatting. Each entry says why it
/// is routine, because the next reader has to be able to tell when Pingora's
/// behaviour has changed enough that it no longer is.
const ROUTINE_RECORDS: &[(&str, &str, log::Level)] = &[
    // 🔁 `pingora-core 0.9.0`, `connectors/mod.rs:293`, read 2026-10-06:
    // `TransportConnector::reused_stream` found a pooled connection but could
    // not take sole ownership of it (`Arc::try_unwrap`), drops it and returns
    // `None`, and the caller connects afresh.
    (
        "pingora_core::connectors",
        "failed to acquire reusable stream",
        log::Level::Debug,
    ),
    // 🗜️ `pingora-cache 0.9.0`, `meta.rs:969`, read 2026-10-08: the header
    // serde warns, once per process, that no compression dictionary was
    // configured, and names the two `set_compression_dict_*` APIs that would
    // set one. The dictionary is an optional optimisation — without it the
    // same zstd frame is written, only with less shared context — and nothing
    // in a Pingclairfile can supply one, so the instruction cannot be
    // followed (#307). Re-levelled to `debug`: visible under `--verbose` or
    // `RUST_LOG` for anyone debugging the cache, absent from an operator's
    // log where it is noise they cannot act on.
    (
        "pingora_cache::meta",
        "no header compression dictionary loaded - use set_compression_dict_content() or set_compression_dict_path() to set one",
        log::Level::Debug,
    ),
];

/// 🔁 A `log::Log` that forwards to `tracing`, re-levelling routine records.
pub(crate) struct LogBridge {
    inner: tracing_log::LogTracer,
}

impl LogBridge {
    fn new() -> Self {
        Self {
            inner: tracing_log::LogTracer::new(),
        }
    }
}

impl log::Log for LogBridge {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        self.inner.enabled(metadata)
    }

    fn log(&self, record: &log::Record<'_>) {
        relevel(record, |record| self.inner.log(record));
    }

    fn flush(&self) {
        self.inner.flush();
    }
}

/// 🎚️ Hands `emit` the record as it should be logged: re-levelled when it is
/// one of [`ROUTINE_RECORDS`], untouched otherwise.
fn relevel(record: &log::Record<'_>, emit: impl FnOnce(&log::Record<'_>)) {
    let routine = ROUTINE_RECORDS
        .iter()
        .find(|(target, message, _)| {
            record.target() == *target && record.args().as_str() == Some(*message)
        })
        .map(|(_, _, level)| *level)
        .or_else(|| client_caused_listener_level(record));
    let Some(level) = routine else {
        emit(record);
        return;
    };
    emit(
        &log::Record::builder()
            .level(level)
            .target(record.target())
            .args(*record.args())
            .module_path(record.module_path())
            .file(record.file())
            .line(record.line())
            .build(),
    );
}

/// 🎚️ Re-levels the listener records caused by a client that went away.
///
/// Formatting the message happens only after the target matched, so an
/// ordinary process log costs one string comparison. These records arrive at
/// most once per failed connection, never per request.
fn client_caused_listener_level(record: &log::Record<'_>) -> Option<log::Level> {
    if record.target() != LISTENER_TARGET {
        return None;
    }
    let message = record.args().to_string();

    if message.starts_with("Downstream handshake error")
        || message.starts_with("Downstream handshake timeout")
    {
        DOWNSTREAM_HANDSHAKE_FAILURES_TOTAL.inc();
        return Some(log::Level::Debug);
    }

    if message.starts_with("Accept() failed") && is_client_abort(&message) {
        ACCEPT_ERRORS_TOTAL.inc();
        return Some(log::Level::Debug);
    }

    None
}

/// 🔌 Whether an accept/setup failure is the peer going away.
///
/// The `io::Error` display text is the only cross-platform signal Pingora
/// puts in the record. `EMFILE` says "Too many open files" and deliberately
/// stays an ERROR: the client did not cause it.
fn is_client_abort(message: &str) -> bool {
    message.contains("Connection reset by peer")
        || message.contains("Software caused connection abort")
        || message.contains("Connection aborted")
}

/// 🧭 Installs the bridge as the process's `log` logger, after the `tracing`
/// subscriber is in place.
///
/// The `log` crate's own level ceiling is set the way `tracing-subscriber`'s
/// `init` sets it, from the subscriber's current maximum, so a record the
/// subscriber would discard is dropped by `log` before reaching the bridge.
pub(crate) fn install() -> Result<(), log::SetLoggerError> {
    log::set_boxed_logger(Box::new(LogBridge::new()))?;
    log::set_max_level(tracing::level_filters::LevelFilter::current().as_log());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::Log;
    use std::sync::{Arc, Mutex};

    /// 🪣 Collects what a `fmt` subscriber writes, so a test can read the
    /// JSON record a `log` record became.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// 🧾 Sends one `log` record through the bridge into a JSON `tracing`
    /// subscriber that keeps everything, and returns the record it wrote
    /// without its timestamp.
    fn bridged(
        target: &str,
        level: log::Level,
        args: std::fmt::Arguments<'_>,
    ) -> serde_json::Value {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            LogBridge::new().log(
                &log::Record::builder()
                    .level(level)
                    .target(target)
                    .args(args)
                    .module_path_static(Some("pingora_core::connectors"))
                    .file_static(Some("src/connectors/mod.rs"))
                    .line(Some(293))
                    .build(),
            );
        });
        let written = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        let mut record: serde_json::Value =
            serde_json::from_str(written.trim()).expect("exactly one JSON record");
        record.as_object_mut().unwrap().remove("timestamp");
        record
    }

    /// 🔁 A keepalive reuse miss arrives at `DEBUG`, with every structured
    /// field the original record carried.
    #[test]
    fn a_keepalive_reuse_miss_is_logged_at_debug() {
        assert_eq!(
            bridged(
                "pingora_core::connectors",
                log::Level::Error,
                format_args!("failed to acquire reusable stream"),
            ),
            serde_json::json!({
                "level": "DEBUG",
                "target": "pingora_core::connectors",
                "fields": {
                    "message": "failed to acquire reusable stream",
                    "log.target": "pingora_core::connectors",
                    "log.module_path": "pingora_core::connectors",
                    "log.file": "src/connectors/mod.rs",
                    "log.line": 293,
                },
            })
        );
    }

    /// 🚨 Any other error from the same module keeps its level: only the
    /// named, understood record is re-levelled.
    #[test]
    fn other_records_keep_their_level() {
        let record = bridged(
            "pingora_core::connectors",
            log::Level::Error,
            format_args!("offload runtime failure"),
        );
        assert_eq!(record["level"], "ERROR");
    }

    /// 🔇 A client that leaves during the TLS handshake is routine, and the
    /// counter still makes a rising rate visible.
    #[test]
    fn a_client_caused_handshake_failure_is_debug_and_counted() {
        let before = DOWNSTREAM_HANDSHAKE_FAILURES_TOTAL.get();
        let record = bridged(
            "pingora_core::services::listening",
            log::Level::Error,
            format_args!(
                "Downstream handshake error from 203.0.113.9:43122: TLS handshake failure"
            ),
        );
        assert_eq!(record["level"], "DEBUG");
        assert!(
            DOWNSTREAM_HANDSHAKE_FAILURES_TOTAL.get() > before,
            "the handshake counter must move"
        );
    }

    /// 🔌 An accepted socket the client reset is DEBUG; a descriptor shortage
    /// is still the server's ERROR and must not be folded into the client count.
    #[test]
    fn client_aborted_accepts_are_debug_but_emfile_stays_error() {
        let before = ACCEPT_ERRORS_TOTAL.get();
        let reset = bridged(
            "pingora_core::services::listening",
            log::Level::Error,
            format_args!(
                "Accept() failed failed to set_nodelay cause: Connection reset by peer (os error 54)"
            ),
        );
        assert_eq!(reset["level"], "DEBUG");
        assert!(
            ACCEPT_ERRORS_TOTAL.get() > before,
            "the aborted-accept counter must move"
        );

        let counted = ACCEPT_ERRORS_TOTAL.get();
        let emfile = bridged(
            "pingora_core::services::listening",
            log::Level::Error,
            format_args!("Accept() failed Too many open files (os error 24)"),
        );
        assert_eq!(emfile["level"], "ERROR");
        assert_eq!(
            ACCEPT_ERRORS_TOTAL.get(),
            counted,
            "a server-side accept failure is not a client abort"
        );
    }

    /// 📊 Both counters are registered on the shared `/metrics` registry.
    #[test]
    fn listener_failure_counters_are_registered() {
        pingclair_proxy::metrics::init();
        let names: Vec<String> = pingclair_proxy::metrics::REGISTRY
            .gather()
            .iter()
            .map(|family| family.name().to_string())
            .collect();
        for name in [
            "pingclair_downstream_handshake_failures_total",
            "pingclair_accept_errors_total",
        ] {
            assert!(names.iter().any(|candidate| candidate == name), "{name}");
        }
    }
}
