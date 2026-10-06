// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚫 HTTP/1 header decisions before Pingora transforms or validates the bytes.

use bytes::BytesMut;
use pingora_core::protocols::http::authority::{RawTargetAuthority, raw_target_authority};

/// 🛡️ Pingora 0.9.0 repairs spaces and controls in a target while parsing
/// (`escape_illegal_request_line`). Reject them while the original bytes still
/// distinguish a malformed target from an explicitly percent-encoded one.
fn valid_request_line(head: &[u8]) -> bool {
    let start = head
        .iter()
        .position(|byte| !matches!(byte, b'\r' | b'\n'))
        .unwrap_or(head.len());
    let head = &head[start..];
    let Some(end) = head.iter().position(|byte| *byte == b'\n') else {
        return true;
    };
    let line = head[..end].strip_suffix(b"\r").unwrap_or(&head[..end]);
    let mut parts = line.split(|byte| *byte == b' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    !method.is_empty()
        && method
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte))
        && !target.is_empty()
        && !version.is_empty()
        && parts.next().is_none()
        && !target
            .iter()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
}

pub(crate) enum HeadRejection {
    BadRequest,
    UnsupportedVersion,
    UnsupportedTransferEncoding,
}

impl HeadRejection {
    pub(crate) fn response(&self) -> &'static [u8] {
        match self {
            Self::BadRequest => b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 15\r\nContent-Type: text/plain\r\n\r\n400 Bad Request",
            Self::UnsupportedVersion => b"HTTP/1.1 505 HTTP Version Not Supported\r\nConnection: close\r\nContent-Length: 30\r\nContent-Type: text/plain\r\n\r\n505 HTTP Version Not Supported",
            Self::UnsupportedTransferEncoding => b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 19\r\nContent-Type: text/plain\r\n\r\n501 Not Implemented",
        }
    }
}

/// 🧾 Preserve Go net/http's decisions before Pingora's more permissive parser
/// repairs targets or rejects unsupported versions and transfer codings as 400.
pub(crate) fn prepare_request_head(head: &mut BytesMut) -> Result<(), HeadRejection> {
    if matches!(head.first(), Some(b'\r' | b'\n')) || !valid_request_line(head) {
        return Err(HeadRejection::BadRequest);
    }
    let Some(line_end) = head.iter().position(|byte| *byte == b'\n') else {
        return Ok(());
    };
    let line = head[..line_end]
        .strip_suffix(b"\r")
        .unwrap_or(&head[..line_end]);
    let version = line.rsplit(|byte| *byte == b' ').next().unwrap();
    if version.len() != 8
        || !version.starts_with(b"HTTP/")
        || !version[5].is_ascii_digit()
        || version[6] != b'.'
        || !version[7].is_ascii_digit()
    {
        return Err(HeadRejection::BadRequest);
    }
    if version[5] != b'1' {
        return Err(HeadRejection::UnsupportedVersion);
    }
    let http10 = version[7] == b'0';
    if version[7] > b'1' {
        // 🧾 Go accepts HTTP/1.x and answers with HTTP/1.1 for every minor
        // version after zero; Pingora otherwise refuses these before routing.
        let minor = line.len() - 1;
        head[minor] = b'1';
    }
    unfold_headers(head, line_end + 1)?;
    let mut codings = 0;
    for line in head[line_end + 1..].split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.iter().position(|byte| *byte == b':')
            && line[..colon].eq_ignore_ascii_case(b"transfer-encoding")
            && !http10
        {
            codings += 1;
            if codings > 1 || !trim_ows(&line[colon + 1..]).eq_ignore_ascii_case(b"chunked") {
                return Err(HeadRejection::UnsupportedTransferEncoding);
            }
        }
    }
    normalize_absolute_host(head, line_end)
}

/// 🧾 Go's MIME reader replaces a folded header continuation with a space.
/// Compact only the header in place, in one pass, and retain every overread
/// body byte so neither folding nor an attacker can grow the body buffer.
fn unfold_headers(head: &mut BytesMut, start: usize) -> Result<(), HeadRejection> {
    let mut read = start;
    let mut write = start;
    let mut previous_header = false;
    let mut previous_ending = 0;
    while let Some(offset) = head[read..].iter().position(|byte| *byte == b'\n') {
        let end = read + offset + 1;
        let line = head[read..end - 1]
            .strip_suffix(b"\r")
            .unwrap_or(&head[read..end - 1]);
        if line.is_empty() {
            break;
        }
        let ending = end - read - line.len();
        let folded = matches!(line.first(), Some(b' ' | b'\t'));
        if folded {
            if !previous_header {
                return Err(HeadRejection::BadRequest);
            }
            let whitespace = line
                .iter()
                .take_while(|&&byte| matches!(byte, b' ' | b'\t'))
                .count();
            write -= previous_ending;
            head[write] = b' ';
            write += 1;
            read += whitespace;
        } else {
            previous_header = line.contains(&b':');
        }
        if write != read {
            head.copy_within(read..end, write);
        }
        write += end - read;
        read = end;
        previous_ending = ending;
    }
    if read != write {
        let tail = head.len() - read;
        head.copy_within(read.., write);
        head.truncate(write + tail);
    }
    Ok(())
}

/// 🏠 Go routes an absolute-form request by the URL's authority, ignoring a
/// different Host. Reconcile that one field before Pingora's consistency check,
/// after validating the original Host so malformed values cannot be hidden.
fn normalize_absolute_host(head: &mut BytesMut, line_end: usize) -> Result<(), HeadRejection> {
    let target = head[..line_end].split(|byte| *byte == b' ').nth(1).unwrap();
    let RawTargetAuthority::Absolute {
        scheme, authority, ..
    } = raw_target_authority(target)
    else {
        return Ok(());
    };
    if !(scheme.eq_ignore_ascii_case(b"http") || scheme.eq_ignore_ascii_case(b"https")) {
        return Ok(());
    }
    if !pingclair_proxy::request_host_is_valid(authority) {
        return Err(HeadRejection::BadRequest);
    }
    let mut cursor = line_end + 1;
    let mut host = None;
    for line in head[cursor..].split(|byte| *byte == b'\n') {
        let field = line.strip_suffix(b"\r").unwrap_or(line);
        if field.is_empty() {
            break;
        }
        if let Some(colon) = field.iter().position(|byte| *byte == b':')
            && field[..colon].eq_ignore_ascii_case(b"host")
        {
            if host.is_some() {
                return Err(HeadRejection::BadRequest);
            }
            let value = trim_ows(&field[colon + 1..]);
            if !value.is_empty() && !pingclair_proxy::request_host_is_valid(value) {
                return Err(HeadRejection::BadRequest);
            }
            host = Some(cursor + colon + 1..cursor + field.len());
        }
        cursor += line.len() + 1;
    }
    let Some(host) = host else {
        return Ok(());
    };
    if trim_ows(&head[host.clone()]) == authority {
        return Ok(());
    }
    // 📦 Only the uncommon absolute-form mismatch allocates. The input is
    // already bounded by the listener's header reader, including any overread.
    let mut reconciled = BytesMut::with_capacity(head.len() - host.len() + authority.len() + 1);
    reconciled.extend_from_slice(&head[..host.start]);
    reconciled.extend_from_slice(b" ");
    reconciled.extend_from_slice(authority);
    reconciled.extend_from_slice(&head[host.end..]);
    *head = reconciled;
    Ok(())
}

/// 🛡️ Only spaces and tabs are HTTP field padding. Trimming other controls
/// would hide a malformed original Host before absolute-form reconciliation.
fn trim_ows(mut raw: &[u8]) -> &[u8] {
    while matches!(raw.first(), Some(b' ' | b'\t')) {
        raw = &raw[1..];
    }
    while matches!(raw.last(), Some(b' ' | b'\t')) {
        raw = &raw[..raw.len() - 1];
    }
    raw
}
