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
        .map(|(_, _, level)| *level);
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
}
