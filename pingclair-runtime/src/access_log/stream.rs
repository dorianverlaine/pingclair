// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔌 Connection records share HTTP logging's bounded writer and destination policy.

use super::{AccessLogger, LogFormat, write_json_display};
use std::{fmt, fmt::Write, net::SocketAddr, time::Duration};

/// 🧾 One completed TCP session; byte counts describe successful socket I/O.
///
/// 🔐 This record deliberately contains no payload, SNI, or negotiated TLS fields.
pub struct StreamEntry<'a> {
    pub started_unix: f64,
    pub listener: &'a str,
    pub remote: SocketAddr,
    pub route: Option<usize>,
    pub outcome: &'a str,
    pub status: u16,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub session_time: Duration,
    pub upstream: Option<SocketAddr>,
    pub upstream_bytes_received: u64,
    pub upstream_bytes_sent: u64,
    pub upstream_connect_time: Option<Duration>,
}

impl AccessLogger {
    /// 📝 Queues one session record using the existing sampling and bounded writer.
    pub fn log_stream(&self, entry: &StreamEntry<'_>) {
        if !self.admits_source("layer4.log.access")
            || self
                .sampling
                .as_ref()
                .is_some_and(|sampling| !sampling.admits())
        {
            return;
        }
        self.writer.submit(self.format_stream(entry));
    }

    fn format_stream(&self, entry: &StreamEntry<'_>) -> String {
        let mut out = self.writer.take_buffer(512);
        let json = matches!(self.format, LogFormat::Json);
        if json {
            out.push('{');
        }
        let mut first = true;
        let mut field = |name: &str, value: fmt::Arguments<'_>, quoted: bool| {
            if !self.included(name) {
                return;
            }
            if !first {
                out.push(if json { ',' } else { ' ' });
            }
            first = false;
            if json {
                out.push('"');
            }
            out.push_str(name);
            out.push_str(if json { "\":" } else { "=" });
            if quoted {
                out.push('"');
                // 🛡️ Both formats escape control characters, so a value cannot forge a line.
                write_json_display(&mut out, value);
                out.push('"');
            } else {
                let _ = out.write_fmt(value);
            }
        };
        field("ts", format_args!("{}", entry.started_unix), false);
        field("protocol", format_args!("TCP"), true);
        field("listener", format_args!("{}", entry.listener), true);
        field(
            "remote_addr",
            format_args!("{}", entry.remote.ip().to_canonical()),
            true,
        );
        field(
            "remote_port",
            format_args!("{}", entry.remote.port()),
            false,
        );
        if let Some(route) = entry.route {
            field("route", format_args!("{}", route + 1), false);
        }
        field("outcome", format_args!("{}", entry.outcome), true);
        field("status", format_args!("{}", entry.status), false);
        field(
            "bytes_received",
            format_args!("{}", entry.bytes_received),
            false,
        );
        field("bytes_sent", format_args!("{}", entry.bytes_sent), false);
        field(
            "session_time",
            format_args!("{:.3}", entry.session_time.as_secs_f64()),
            false,
        );
        if let Some(upstream) = entry.upstream {
            field("upstream_addr", format_args!("{upstream}"), true);
        }
        field(
            "upstream_bytes_received",
            format_args!("{}", entry.upstream_bytes_received),
            false,
        );
        field(
            "upstream_bytes_sent",
            format_args!("{}", entry.upstream_bytes_sent),
            false,
        );
        if let Some(duration) = entry.upstream_connect_time {
            field(
                "upstream_connect_time",
                format_args!("{:.3}", duration.as_secs_f64()),
                false,
            );
        }
        if json {
            out.push('}');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> StreamEntry<'static> {
        StreamEntry {
            started_unix: 123.5,
            listener: "[::]:9443",
            remote: "[::ffff:127.0.0.1]:1234".parse().unwrap(),
            route: Some(0),
            outcome: "completed",
            status: 200,
            bytes_received: 13,
            bytes_sent: 7,
            session_time: Duration::from_millis(1200),
            upstream: Some("127.0.0.1:8443".parse().unwrap()),
            upstream_bytes_received: 7,
            upstream_bytes_sent: 13,
            upstream_connect_time: Some(Duration::from_millis(5)),
        }
    }

    #[test]
    fn json_records_use_stream_byte_and_duration_semantics() {
        let logger = super::super::tests::logger(LogFormat::Json, vec![]);
        let record: serde_json::Value =
            serde_json::from_str(&logger.format_stream(&entry())).unwrap();
        assert_eq!(
            record,
            serde_json::json!({"ts": 123.5, "protocol": "TCP", "listener": "[::]:9443",
            "remote_addr": "127.0.0.1", "remote_port": 1234, "route": 1, "outcome": "completed", "status": 200,
            "bytes_received": 13, "bytes_sent": 7, "session_time": 1.2, "upstream_addr": "127.0.0.1:8443",
            "upstream_bytes_received": 7, "upstream_bytes_sent": 13, "upstream_connect_time": 0.005})
        );
    }

    #[test]
    fn both_formats_escape_lines_and_honor_field_exclusion() {
        for format in [LogFormat::Json, LogFormat::Text] {
            let logger = super::super::tests::logger(format, vec!["remote_addr".into()]);
            let mut entry = entry();
            entry.listener = "untrusted\n\"value\t";
            let record = logger.format_stream(&entry);
            assert_eq!(record.lines().count(), 1);
            assert!(record.contains("untrusted\\n\\\"value\\t"));
            assert!(!record.contains("remote_addr"));
        }
    }
}
