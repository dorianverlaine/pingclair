// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📣 Missing write paths name the parent the caller actually reached.

use crate::config_tree::TreeError;
use serde_json::Value;

pub(super) fn missing_path_message(
    document: &Value,
    segments: &[String],
    error: &TreeError,
) -> String {
    if *error != TreeError::NotFound {
        return error.message();
    }
    if segments.first().is_some_and(|segment| segment == "apps") {
        return format!(
            "{} — `apps` is the top level of Caddy's JSON; this API serves Pingclair's own shape. POST a Caddyfile (Content-Type: text/caddyfile), or read /config/.",
            error.message()
        );
    }
    let mut parent = document;
    for (depth, segment) in segments.iter().enumerate() {
        let next = match parent {
            Value::Object(map) => map.get(segment),
            Value::Array(items) => segment
                .parse::<usize>()
                .ok()
                .and_then(|index| items.get(index)),
            _ => None,
        };
        if let Some(next) = next {
            parent = next;
            continue;
        }
        let detail = match parent {
            Value::Object(map) => {
                let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
                keys.sort_unstable();
                format!("available keys are: {}", keys.join(", "))
            }
            Value::Array(items) => format!("array length is {}", items.len()),
            _ => "parent is a scalar".to_string(),
        };
        return format!(
            "{} at /config/{} — {detail}",
            error.message(),
            segments[..depth].join("/")
        );
    }
    error.message()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_tree;
    /// 📣 `apps` is the path that brings people here, and the answer must say
    /// why it is not in this document rather than that the path does not exist.
    #[test]
    fn a_missing_apps_path_is_explained_not_just_denied() {
        let document = serde_json::json!({
            "debug": false,
            "servers": [],
            "admin": null,
            "global": {},
            "logging": {}
        });
        let message = missing_path_message(
            &document,
            &["apps".to_string()],
            &config_tree::TreeError::NotFound,
        );
        assert!(
            message.contains("Caddy"),
            "must name whose shape this is: {message}"
        );
        assert!(
            message.contains("text/caddyfile"),
            "must point at the spelling this endpoint does take: {message}"
        );
    }

    /// 🧭 A missing root key names the available root keys.
    #[test]
    fn a_missing_root_path_names_the_available_keys() {
        let document = serde_json::json!({ "debug": false, "servers": [] });
        let message = missing_path_message(
            &document,
            &["nope".to_string()],
            &config_tree::TreeError::NotFound,
        );
        assert!(message.contains("debug, servers"), "{message}");
    }
    #[test]
    fn missing_nested_paths_name_the_nearest_parent() {
        let document = serde_json::json!({"servers": [{"routes": []}], "debug": false});
        for (segments, expected) in [
            (
                vec!["servers".into(), "0".into(), "nope".into()],
                "config path does not exist at /config/servers/0 — available keys are: routes",
            ),
            (
                vec!["servers".into(), "99".into()],
                "config path does not exist at /config/servers — array length is 1",
            ),
        ] {
            assert_eq!(
                missing_path_message(&document, &segments, &TreeError::NotFound),
                expected
            );
        }
    }
}
