// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚫 Placeholders this project once invented and has since retired.
//!
//! `{remote_ip}` was our own spelling, never Caddy's, and it had drifted into
//! meaning the opposite of the `remote_ip` matcher: the placeholder named the
//! verified client, the matcher names the socket peer. A header written as
//! `X-Real-IP {remote_ip}` could not be read correctly without knowing that
//! history. Rather than keep a name whose meaning depends on where it sits, a
//! configuration that uses it is refused at load, and the error names the two
//! spellings that say what they mean.
//!
//! 📌 This runs at configuration time only, so it favours clarity: the whole
//! document is serialized once and every string in it is searched. A reload
//! pays for one walk of the document; a request pays nothing.

use crate::compiler::{CompileError, CompileResult};
use pingclair_core::config::PingclairConfig;
use serde_json::Value;

/// 🚫 The retired spellings, with braces, as they would appear in a value.
const RETIRED: &[&str] = &["{remote_ip}"];

/// 🚫 Refuses a configuration that uses a retired placeholder anywhere.
///
/// Both the Pingclairfile and the JSON path reach this through
/// `validate_config`, so neither can carry the old spelling past it.
pub(crate) fn refuse_retired_placeholders(config: &PingclairConfig) -> CompileResult<()> {
    // 🧭 A config that fails to serialize is not this check's concern; every
    // other validation step still runs on the typed value.
    let Ok(document) = serde_json::to_value(config) else {
        return Ok(());
    };
    let mut location = String::new();
    match find(&document, &mut location) {
        Some((placeholder, at)) => Err(CompileError::InvalidServer {
            message: format!(
                "`{placeholder}` at `{at}` is not a placeholder: write `{{remote_host}}` for the \
                 connection's peer address, or `{{client_ip}}` for the client after \
                 `trusted_proxies`"
            ),
        }),
        None => Ok(()),
    }
}

/// 🔎 Depth-first search that returns the first retired placeholder and the
/// JSON-pointer location of the value or key that holds it.
fn find(value: &Value, location: &mut String) -> Option<(&'static str, String)> {
    match value {
        Value::String(text) => retired_in(text).map(|p| (p, pointer(location))),
        Value::Array(items) => items.iter().enumerate().find_map(|(index, item)| {
            descend(location, &index.to_string(), |location| {
                find(item, location)
            })
        }),
        Value::Object(fields) => fields.iter().find_map(|(key, item)| {
            descend(location, key, |location| {
                retired_in(key)
                    .map(|p| (p, pointer(location)))
                    .or_else(|| find(item, location))
            })
        }),
        Value::Null | Value::Bool(_) | Value::Number(_) => None,
    }
}

/// 🧭 Appends one pointer segment for the duration of `visit`, then removes it.
fn descend<T>(location: &mut String, segment: &str, visit: impl FnOnce(&mut String) -> T) -> T {
    let before = location.len();
    location.push('/');
    location.push_str(segment);
    let found = visit(location);
    location.truncate(before);
    found
}

fn pointer(location: &str) -> String {
    if location.is_empty() {
        "/".to_string()
    } else {
        location.to_string()
    }
}

fn retired_in(text: &str) -> Option<&'static str> {
    RETIRED
        .iter()
        .copied()
        .find(|placeholder| text.contains(placeholder))
}
