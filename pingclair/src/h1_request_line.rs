// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚫 Validate the raw request line before Pingora can escape illegal target bytes.

/// 🛡️ Pingora 0.9.0 repairs spaces and controls in a target while parsing
/// (`escape_illegal_request_line`). Reject them while the original bytes still
/// distinguish a malformed target from an explicitly percent-encoded one.
pub(crate) fn valid_request_line(head: &[u8]) -> bool {
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
        && !target.is_empty()
        && !version.is_empty()
        && parts.next().is_none()
        && !target
            .iter()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
}
