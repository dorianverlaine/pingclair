// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧮 Argument helpers shared by the directive parsers.
//!
//! These say the same thing every time a directive is wrong about its own
//! arguments, which is the point: an operator who has seen one of these
//! messages has seen all of them. They live here rather than beside any one
//! directive because three layers reached for them — the global block, the
//! `log` block, and `reverse_proxy` — and a helper that three callers share
//! belongs to none of them.

use super::AdapterError;
use crate::parser::caddy_ast::Directive;

/// Parse the global `dns_refresh` argument into seconds.
///
/// `off`/`none` disable re-resolution. Everything else is a duration, and a
/// unit is mandatory: `parse_duration_ms` reads a bare number as
/// milliseconds, so accepting `dns_refresh 30` would silently install a
/// 30 ms lookup storm instead of the half-minute the operator meant. Sub-second
/// intervals are refused for the same reason rather than clamped, so the
/// mistake surfaces at load time instead of in production DNS traffic.
pub(super) fn parse_dns_refresh(value: &str) -> Result<u64, AdapterError> {
    if matches!(value.to_ascii_lowercase().as_str(), "off" | "none") {
        return Ok(0);
    }

    let invalid = || {
        AdapterError::InvalidArgument(
            "dns_refresh".into(),
            format!("expected `off` or a duration of at least 1s, got `{value}`"),
        )
    };

    let millis = parse_duration_ms(value).ok_or_else(invalid)?;
    if millis < 1_000 {
        return Err(invalid());
    }
    Ok(millis / 1_000)
}

/// 🚩 Accepts a bare flag directive, rejecting stray arguments instead of dropping them.
pub(super) fn expect_no_arguments(directive: &Directive) -> Result<(), AdapterError> {
    if directive.args.is_empty() {
        return Ok(());
    }
    Err(AdapterError::ArgumentCount(
        directive.name.clone(),
        0,
        directive.args.len(),
    ))
}

/// 🏷️ Reads exactly one argument, rejecting both none and extras.
pub(super) fn expect_one_argument(directive: &Directive) -> Result<&str, AdapterError> {
    if directive.args.len() != 1 {
        return Err(AdapterError::ArgumentCount(
            directive.name.clone(),
            1,
            directive.args.len(),
        ));
    }
    Ok(directive.args[0].as_str())
}

/// ⏱️ Parses one mandatory, positive duration argument without permissive fallback.
pub(super) fn parse_required_duration(directive: &Directive) -> Result<u64, AdapterError> {
    let value = directive.args.first().ok_or_else(|| {
        AdapterError::ArgumentCount(directive.name.clone(), 1, directive.args.len())
    })?;
    if directive.args.len() != 1 {
        return Err(AdapterError::ArgumentCount(
            directive.name.clone(),
            1,
            directive.args.len(),
        ));
    }
    parse_duration_ms(value)
        .filter(|millis| *millis > 0 && *millis <= 31_536_000_000)
        .ok_or_else(|| AdapterError::InvalidArgument(directive.name.clone(), value.clone()))
}

/// 🔢 Parses one mandatory positive `usize` argument.
pub(super) fn parse_positive_usize(directive: &Directive) -> Result<usize, AdapterError> {
    parse_positive_u64(directive).and_then(|value| {
        usize::try_from(value)
            .map_err(|_| AdapterError::InvalidArgument(directive.name.clone(), value.to_string()))
    })
}

/// 🔢 Parses one mandatory positive integer argument.
pub(super) fn parse_positive_u64(directive: &Directive) -> Result<u64, AdapterError> {
    let value = directive.args.first().ok_or_else(|| {
        AdapterError::ArgumentCount(directive.name.clone(), 1, directive.args.len())
    })?;
    if directive.args.len() != 1 {
        return Err(AdapterError::ArgumentCount(
            directive.name.clone(),
            1,
            directive.args.len(),
        ));
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|parsed| *parsed > 0)
        .ok_or_else(|| AdapterError::InvalidArgument(directive.name.clone(), value.clone()))
}

/// ⏱️ Parses Caddy durations into milliseconds.
///
/// Accepts the full Go-style unit set (`ns`, `us`/`µs`, `ms`, `s`, `m`,
/// `h`, `d`), fractional values (`1.5h`) and compound values (`2h45m`).
/// A bare number is rejected: `30` would silently mean 30 ms instead of the
/// 30 seconds the operator almost certainly meant.
pub(super) fn parse_duration_ms(s: &str) -> Option<u64> {
    const UNITS: [(&str, f64); 8] = [
        ("ns", 1e-6),
        ("us", 1e-3),
        ("µs", 1e-3),
        ("ms", 1.0),
        ("s", 1e3),
        ("m", 6e4),
        ("h", 3.6e6),
        ("d", 8.64e7),
    ];

    let mut rest = s.trim();
    if rest.is_empty() {
        return None;
    }
    let mut total_ms = 0.0f64;
    let mut consumed_any = false;
    while !rest.is_empty() {
        // 🧮 Read the numeric part (integer or decimal fraction).
        let number_end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        if number_end == 0 {
            return None;
        }
        let number: f64 = rest[..number_end].parse().ok()?;
        rest = &rest[number_end..];

        // 🧮 Read the unit that follows; without one the input is malformed.
        let unit = UNITS
            .iter()
            .find(|(name, _)| rest.starts_with(name))
            .map(|(name, multiplier)| (*name, *multiplier))?;
        total_ms += number * unit.1;
        rest = &rest[unit.0.len()..];
        consumed_any = true;
    }
    if !consumed_any {
        return None;
    }
    // ⚙️ Sub-millisecond durations cannot be represented in the internal
    // millisecond fields, so refuse them instead of silently truncating.
    if total_ms < 1.0 {
        return None;
    }
    Some(total_ms.round() as u64)
}
