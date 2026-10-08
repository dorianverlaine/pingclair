// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📊 The log option grammar: the process `Log`, an HTTP `.accessLog` and a
//! TCP `.sessionLog` describe one model, so they share one reader.

use super::*;
use pingclair_core::config::{LogRotation, LogSampling};

/// 🏷️ The settings an HTTP access log accepts.
pub(crate) const ACCESS_LOG_LABELS: &[&str] = &[
    "output",
    "format",
    "level",
    "headers",
    "hostnames",
    "include",
    "exclude",
    "excludeFields",
    "sampling",
    "rotation",
];

/// 🏷️ The settings a TCP session log accepts: no `headers:` and no
/// `hostnames:`, because a session has neither.
pub(crate) const SESSION_LOG_LABELS: &[&str] = &[
    "output",
    "format",
    "level",
    "include",
    "exclude",
    "excludeFields",
    "sampling",
    "rotation",
];

/// 🌐 Which log a declaration describes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum LogScope {
    HttpAccess,
    TcpSession,
}

/// 📊 Parses one log declaration into the shared `LogConfig`.
pub(super) fn parse_log(modifier: &Call, scope: LogScope) -> Result<LogConfig, Error> {
    if scope == LogScope::TcpSession {
        // 🚫 Named before the general label check, so the operator is told why
        // the setting does not apply instead of reading "unknown argument".
        for refused in ["headers", "hostnames"] {
            if modifier.get(refused).is_some() {
                return Err(modifier.at.error(format!(
                    ".sessionLog does not take {refused}: a TCP session has no header or host \
                     to record"
                )));
            }
        }
    }
    let labels = match scope {
        LogScope::HttpAccess => ACCESS_LOG_LABELS,
        LogScope::TcpSession => SESSION_LOG_LABELS,
    };
    modifier.leaf(labels)?;

    let output = match modifier.get("output") {
        Some(value) => log_output(value, modifier.at)?,
        None => LogOutput::Stdout,
    };
    let format = match modifier.get("format") {
        Some(value) => log_format(value, modifier.at)?,
        None => LogFormat::Text,
    };
    let level = match modifier.get("level") {
        Some(value) => Some(log_level(value, modifier.at)?.to_string()),
        None => None,
    };
    let mut request_headers = Vec::new();
    let mut response_headers = Vec::new();
    let mut include_tls = false;
    if let Some(headers) = modifier.get("headers") {
        parse_headers(
            headers,
            modifier.at,
            &mut request_headers,
            &mut response_headers,
            &mut include_tls,
        )?;
    }
    let list = |label: &str| -> Result<Vec<String>, Error> {
        match modifier.get(label) {
            Some(value) => string_list(value, label, modifier.at),
            None => Ok(Vec::new()),
        }
    };
    let hostnames = list("hostnames")?;
    let include = list("include")?;
    let exclude = list("exclude")?;
    let exclude_fields = list("excludeFields")?;
    let sampling = match modifier.get("sampling") {
        Some(value) => Some(parse_sampling(value, modifier.at)?),
        None => None,
    };
    let rotation = match modifier.get("rotation") {
        Some(value) => parse_rotation(value, modifier.at, &output)?,
        None => LogRotation::default(),
    };
    Ok(LogConfig {
        output,
        format,
        level,
        exclude_fields,
        rotation,
        request_headers,
        response_headers,
        include_tls,
        hostnames,
        include,
        exclude,
        sampling,
    })
}

/// 🪵 One log destination, shared with the process `Log(...)`.
pub(super) fn log_output(value: &Value, at: Position) -> Result<LogOutput, Error> {
    let Value::Typed(case) = value else {
        return Err(at.error("output takes .stdout, .stderr or .file(\"…\")"));
    };
    match case.name.as_str() {
        "stdout" => {
            expect_bare_case(case, ".stdout")?;
            Ok(LogOutput::Stdout)
        }
        "stderr" => {
            expect_bare_case(case, ".stderr")?;
            Ok(LogOutput::Stderr)
        }
        "file" => {
            if case.body.is_some() || !case.modifiers.is_empty() {
                return Err(case.at.error(".file does not take a block or modifiers"));
            }
            let [(None, Value::String(path))] = case.args.as_slice() else {
                return Err(case.at.error(".file takes one quoted path"));
            };
            if path.is_empty() {
                return Err(case.at.error(".file takes a non-empty path"));
            }
            Ok(LogOutput::File(path.clone()))
        }
        other => Err(case.at.error(format!(
            "unknown output `.{other}`; expected .stdout, .stderr or .file(\"…\")"
        ))),
    }
}

/// 🚦 One log level, shared with the process `Log(...)`.
pub(super) fn log_level(value: &Value, at: Position) -> Result<&'static str, Error> {
    let Value::Typed(case) = value else {
        return Err(at.error("level takes .trace, .debug, .info, .warn or .error"));
    };
    let level = match case.name.as_str() {
        "trace" => "trace",
        "debug" => "debug",
        "info" => "info",
        "warn" => "warn",
        "error" => "error",
        other => {
            return Err(case.at.error(format!(
                "unknown level `.{other}`; expected .trace, .debug, .info, .warn or .error"
            )));
        }
    };
    expect_bare_case(case, "a log level")?;
    Ok(level)
}

/// 🧾 One log encoder.
fn log_format(value: &Value, at: Position) -> Result<LogFormat, Error> {
    let Value::Typed(case) = value else {
        return Err(at.error("format takes .text or .json"));
    };
    match case.name.as_str() {
        "text" => {
            expect_bare_case(case, ".text")?;
            Ok(LogFormat::Text)
        }
        "json" => {
            expect_bare_case(case, ".json")?;
            Ok(LogFormat::Json)
        }
        // 🚩 Naming the old spelling is kinder than "unknown", and refusing it
        // rather than accepting both keeps one spelling per meaning.
        "console" => Err(case
            .at
            .error("`.console` was the old spelling of the text encoder; write `.text`")),
        other => Err(case.at.error(format!(
            "unknown format `.{other}`; expected .text or .json"
        ))),
    }
}

/// 🏷️ `headers: [.request("…"), .response("…"), .tls]` — what a record
/// carries beyond the fixed fields.
fn parse_headers(
    value: &Value,
    at: Position,
    request: &mut Vec<String>,
    response: &mut Vec<String>,
    include_tls: &mut bool,
) -> Result<(), Error> {
    let Value::Array(items) = value else {
        return Err(at.error("headers takes an array such as [.request(\"Authorization\"), .tls]"));
    };
    if items.is_empty() {
        return Err(at.error("headers must not be empty"));
    }
    for item in items {
        let Value::Typed(case) = item else {
            return Err(
                at.error("headers takes typed values such as .request(\"Authorization\") or .tls")
            );
        };
        match case.name.as_str() {
            side @ ("request" | "response") => {
                if case.body.is_some() || !case.modifiers.is_empty() {
                    return Err(case
                        .at
                        .error(format!(".{side} does not take a block or modifiers")));
                }
                let [(None, Value::String(name))] = case.args.as_slice() else {
                    return Err(case
                        .at
                        .error(format!(".{side} takes one quoted header name")));
                };
                if ::http::HeaderName::from_bytes(name.as_bytes()).is_err() {
                    return Err(case
                        .at
                        .error(format!("`{name}` is not a valid header name")));
                }
                // 📌 Lowercased like the Caddyfile adapter, because matching
                // and masking both compare lowercase names.
                if side == "request" {
                    request.push(name.to_ascii_lowercase());
                } else {
                    response.push(name.to_ascii_lowercase());
                }
            }
            "tls" => {
                expect_bare_case(case, ".tls")?;
                *include_tls = true;
            }
            other => {
                return Err(case.at.error(format!(
                    "unknown header capture `.{other}`; expected .request(\"…\"), \
                     .response(\"…\") or .tls"
                )));
            }
        }
    }
    Ok(())
}

/// 🎲 `sampling: .window(interval:, first:, thereafter:)`.
fn parse_sampling(value: &Value, at: Position) -> Result<LogSampling, Error> {
    let Value::Typed(case) = value else {
        return Err(at.error("sampling takes .window(interval:, first:, thereafter:)"));
    };
    if case.name != "window" {
        return Err(case.at.error(format!(
            "unknown sampling `.{name}`; expected .window(interval:, first:, thereafter:)",
            name = case.name
        )));
    }
    if case.body.is_some() {
        return Err(case.at.error(".window does not take a block"));
    }
    if !case.modifiers.is_empty() {
        return Err(case.at.error(".window does not take modifiers"));
    }
    let mut interval: Option<u64> = None;
    let mut first: Option<usize> = None;
    let mut thereafter: Option<usize> = None;
    for (label, value) in &case.args {
        match label.as_deref() {
            Some("interval") if interval.is_none() => {
                let seconds = duration_secs(value, "sampling interval", case.at)?;
                if seconds == 0 {
                    return Err(case.at.error("sampling interval must be non-zero"));
                }
                interval = Some(seconds);
            }
            Some("first") if first.is_none() => {
                let count = count_integer(value, "sampling first", case.at)?;
                if count == 0 {
                    return Err(case.at.error("sampling first must be at least 1"));
                }
                first = Some(count);
            }
            Some("thereafter") if thereafter.is_none() => {
                // 📌 Zero is meaningful: keep only the first entries.
                thereafter = Some(count_integer(value, "sampling thereafter", case.at)?);
            }
            Some(name @ ("interval" | "first" | "thereafter")) => {
                return Err(case
                    .at
                    .error(format!("sampling setting `{name}` is written twice")));
            }
            Some(name) => {
                return Err(case.at.error(format!(
                    "unknown sampling setting `{name}`; expected interval, first or thereafter"
                )));
            }
            None => {
                return Err(case.at.error(
                    "sampling settings are labeled, e.g. .window(interval: .minutes(5), \
                     first: 100, thereafter: 20)",
                ));
            }
        }
    }
    let missing = || {
        case.at
            .error("sampling needs interval:, first: and thereafter:")
    };
    Ok(LogSampling {
        interval_secs: interval.ok_or_else(missing)?,
        first: first.ok_or_else(missing)?,
        thereafter: thereafter.ok_or_else(missing)?,
    })
}

/// 🔄 `rotation: .roll(size:, age:, keep:, compress:, mode:, dirMode:,
/// localTime:, interval:, at:, minutes:, compression:)`.
fn parse_rotation(value: &Value, at: Position, output: &LogOutput) -> Result<LogRotation, Error> {
    let Value::Typed(case) = value else {
        return Err(at.error(
            "rotation takes .roll(size:, age:, keep:, compress:, mode:, dirMode:, localTime:, \
             interval:, at:, minutes:, compression:)",
        ));
    };
    if case.name != "roll" {
        return Err(case.at.error(format!(
            "unknown rotation `.{name}`; expected .roll(…)",
            name = case.name
        )));
    }
    if !matches!(output, LogOutput::File(_)) {
        return Err(at.error(
            "rotation applies only to .file output; a stream is rotated by whatever starts \
             the process",
        ));
    }
    if case.body.is_some() {
        return Err(case.at.error(".roll does not take a block"));
    }
    if !case.modifiers.is_empty() {
        return Err(case.at.error(".roll does not take modifiers"));
    }
    let mut rotation = LogRotation::default();
    let mut seen = std::collections::HashSet::new();
    for (label, value) in &case.args {
        let Some(label) = label.as_deref() else {
            return Err(case
                .at
                .error(".roll settings are labeled, e.g. .roll(size: .mebibytes(100), keep: 7)"));
        };
        if ![
            "size",
            "age",
            "keep",
            "compress",
            "mode",
            "dirMode",
            "localTime",
            "interval",
            "at",
            "minutes",
            "compression",
        ]
        .contains(&label)
        {
            return Err(case.at.error(format!(
                "unknown .roll setting `{label}`; expected size, age, keep, compress, mode, \
                 dirMode, localTime, interval, at, minutes or compression"
            )));
        }
        if !seen.insert(label) {
            return Err(case
                .at
                .error(format!(".roll setting `{label}` is written twice")));
        }
        match label {
            "size" => {
                let bytes = byte_size(value, case.at)?;
                if bytes == 0 {
                    return Err(case.at.error("size must not be zero"));
                }
                rotation.max_size_bytes = Some(bytes);
            }
            "age" => {
                let seconds = duration_secs(value, "age", case.at)?;
                if seconds == 0 {
                    return Err(case.at.error("age must be at least one second"));
                }
                rotation.max_age_secs = Some(seconds);
            }
            "keep" => {
                let keep = count_integer(value, "keep", case.at)?;
                if keep == 0 {
                    return Err(case.at.error("keep must be at least 1"));
                }
                rotation.keep = Some(keep);
            }
            "compress" => match value {
                Value::Bool(flag) => rotation.compress = *flag,
                _ => return Err(case.at.error("compress takes true or false")),
            },
            "mode" => rotation.mode = Some(permission_string(value, "mode", case.at)?),
            "dirMode" => {
                let Value::String(text) = value else {
                    return Err(case.at.error(
                        "dirMode takes a quoted octal permission or one of inherit, from_file",
                    ));
                };
                if text.is_empty() {
                    return Err(case.at.error("dirMode must not be empty"));
                }
                // 🧭 The two words are resolved at open time, not here: the
                // answer depends on the filesystem the file lands on.
                if !matches!(text.as_str(), "inherit" | "from_file") {
                    parse_octal_permission(text, case.at)?;
                }
                rotation.dir_mode = Some(text.clone());
            }
            "localTime" => match value {
                Value::Bool(flag) => rotation.roll_local_time = *flag,
                _ => return Err(case.at.error("localTime takes true or false")),
            },
            "interval" => {
                let seconds = duration_secs(value, "interval", case.at)?;
                if seconds == 0 {
                    return Err(case.at.error("interval must be non-zero"));
                }
                rotation.roll_interval_secs = Some(seconds);
            }
            "at" => {
                let times = string_list(value, "at", case.at)?;
                for time in &times {
                    validate_wall_clock(time, case.at)?;
                }
                rotation.roll_at = Some(times.join(" "));
            }
            "minutes" => {
                let minutes = string_list(value, "minutes", case.at)?;
                for minute in &minutes {
                    validate_minute_of_hour(minute, case.at)?;
                }
                rotation.roll_minutes = Some(minutes.join(" "));
            }
            "compression" => {
                let Value::Typed(codec) = value else {
                    return Err(case.at.error("compression takes .none, .gzip or .zstd"));
                };
                match codec.name.as_str() {
                    "none" | "gzip" | "zstd" => {
                        expect_bare_case(codec, "a compression codec")?;
                        rotation.roll_compression = Some(codec.name.clone());
                    }
                    other => {
                        return Err(codec.at.error(format!(
                            "unknown compression `.{other}`; expected .none, .gzip or .zstd"
                        )));
                    }
                }
            }
            _ => unreachable!(),
        }
    }
    // 📌 `keep` without a trigger is silently inert — nothing ever rolls, so
    // nothing is ever kept. The trigger list mirrors `LogRotation::is_enabled`.
    if rotation.keep.is_some() && !rotation.is_enabled() {
        return Err(case.at.error(
            "keep needs a rotation trigger: add size:, age:, interval:, at: or minutes:, or \
             nothing will ever be rotated to keep",
        ));
    }
    Ok(rotation)
}

/// 📏 A typed byte count (`.bytes`／`.kibibytes`／`.mebibytes`).
///
/// 📌 Taken exactly as written — unlike the Caddyfile adapter, which rounds a
/// `roll_size` up to a whole mebibyte. A typed byte count has no ambiguity to
/// resolve, and rounding it would change the limit the operator asked for.
fn byte_size(value: &Value, at: Position) -> Result<u64, Error> {
    let Value::Typed(unit) = value else {
        return Err(at.error("size takes an explicit byte unit such as .mebibytes(100)"));
    };
    if unit.body.is_some() {
        return Err(unit.at.error("size does not take a block"));
    }
    if !unit.modifiers.is_empty() {
        return Err(unit.at.error("size does not take modifiers"));
    }
    let [(None, Value::Number(number))] = unit.args.as_slice() else {
        return Err(unit
            .at
            .error("size takes one unsigned integer inside its unit"));
    };
    let factor: u64 = match unit.name.as_str() {
        "bytes" => 1,
        "kibibytes" => 1024,
        "mebibytes" => 1024 * 1024,
        other => {
            return Err(unit.at.error(format!(
                "unknown unit `.{other}`; expected .bytes, .kibibytes or .mebibytes"
            )));
        }
    };
    number
        .checked_mul(factor)
        .ok_or_else(|| unit.at.error("size exceeds the supported range"))
}

/// 🧷 A non-empty array of non-empty quoted strings.
fn string_list(value: &Value, label: &str, at: Position) -> Result<Vec<String>, Error> {
    let Value::Array(items) = value else {
        return Err(at.error(format!("{label} takes an array of quoted strings")));
    };
    if items.is_empty() {
        return Err(at.error(format!("{label} must not be empty")));
    }
    items
        .iter()
        .map(|item| match item {
            Value::String(text) if !text.is_empty() => Ok(text.clone()),
            _ => Err(at.error(format!(
                "{label} takes an array of non-empty quoted strings"
            ))),
        })
        .collect()
}

/// 🔢 An unsigned integer for one setting.
fn count_integer(value: &Value, what: &str, at: Position) -> Result<usize, Error> {
    match value {
        Value::Number(number) => usize::try_from(*number)
            .map_err(|_| at.error(format!("{what} exceeds the supported range"))),
        _ => Err(at.error(format!("{what} takes an unsigned integer"))),
    }
}

/// 🧱 An octal permission such as `0644` or `0o644`.
fn permission_string(value: &Value, what: &str, at: Position) -> Result<String, Error> {
    let Value::String(text) = value else {
        return Err(at.error(format!(
            "{what} takes a quoted octal permission such as \"0644\""
        )));
    };
    parse_octal_permission(text, at)?;
    Ok(text.clone())
}

/// 🧱 Validates one octal permission value.
fn parse_octal_permission(text: &str, at: Position) -> Result<(), Error> {
    let digits = text.trim().trim_start_matches("0o");
    if digits.is_empty()
        || u32::from_str_radix(digits, 8)
            .map(|mode| mode > 0o7777)
            .unwrap_or(true)
    {
        return Err(at.error(format!("`{text}` is not an octal permission such as 0644")));
    }
    Ok(())
}

/// 🕰️ `roll_at` entries look like `0:00` or `12:30`.
fn validate_wall_clock(text: &str, at: Position) -> Result<(), Error> {
    let Some((hour, minute)) = text.split_once(':') else {
        return Err(at.error(format!(
            "`{text}` is not a wall-clock time such as 0:00 or 12:30"
        )));
    };
    let hour: u32 = hour
        .parse()
        .map_err(|_| at.error(format!("`{text}` is not a wall-clock time such as 0:00")))?;
    let minute: u32 = minute
        .parse()
        .map_err(|_| at.error(format!("`{text}` is not a wall-clock time such as 0:00")))?;
    if hour > 23 || minute > 59 {
        return Err(at.error(format!(
            "`{text}` is outside a day; hours are 0–23 and minutes 0–59"
        )));
    }
    Ok(())
}

/// ⏱️ `roll_minutes` entries are minutes of the hour.
fn validate_minute_of_hour(text: &str, at: Position) -> Result<(), Error> {
    let minute: u32 = text
        .parse()
        .map_err(|_| at.error(format!("`{text}` is not a minute of the hour (0–59)")))?;
    if minute > 59 {
        return Err(at.error(format!("`{text}` is not a minute of the hour (0–59)")));
    }
    Ok(())
}
