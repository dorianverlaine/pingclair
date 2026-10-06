// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚫 Configured header fields must be fields HTTP can carry.
//!
//! RFC 9110 §5.5 calls a field value containing CR, LF or NUL "invalid and
//! dangerous": a recipient has to reject the message or blank the bytes out.
//! `header X-Inject "legit\r\nInjected-Header: pwned"` used to validate, and
//! then each transport did something different with it — HTTP/1 and HTTP/2
//! cancelled the response, while HTTP/3 put the bytes on the wire, where a
//! strict client killed the connection and a lenient one silently dropped the
//! field. None of those is the configuration the operator meant, so the value
//! is refused here, where `pingclair validate`, the Admin API, a reload and a
//! JSON document all see it. A field *name* that is not a token is refused for
//! the same reason.
//!
//! 📌 This checks what the configuration says. A placeholder that resolves to
//! such a byte at request time is a separate question for the transports.

use crate::compiler::{CompileError, CompileResult};
use pingclair_core::config::{HandlerConfig, HeaderReplacement};
use std::collections::BTreeMap;

/// 🚫 Walks a handler tree and refuses any header field it would emit that
/// HTTP cannot carry.
pub(crate) fn validate_header_fields(handler: &HandlerConfig) -> CompileResult<()> {
    match handler {
        HandlerConfig::Headers {
            set,
            add,
            replace,
            default_set,
            ..
        } => {
            for fields in [set, add, default_set] {
                check_fields(fields)?;
            }
            check_replacements(replace)
        }
        HandlerConfig::RequestHeaders {
            set, add, replace, ..
        } => {
            for fields in [set, add] {
                check_fields(fields)?;
            }
            check_replacements(replace)
        }
        HandlerConfig::Pipeline { handlers }
        | HandlerConfig::FirstMatch { handlers }
        | HandlerConfig::HandlePath { handlers, .. } => handlers
            .iter()
            .try_for_each(|element| validate_header_fields(&element.handler)),
        HandlerConfig::HandleErrors { errors } => errors
            .values()
            .flatten()
            .try_for_each(validate_header_fields),
        HandlerConfig::Intercept { handlers } => handlers
            .iter()
            .flat_map(|entry| &entry.handlers)
            .try_for_each(validate_header_fields),
        HandlerConfig::ReverseProxy(proxy) => {
            // 🧭 `header_up` and `header_down` write fields too; their names
            // carry the directive's own prefixes, so only values are checked.
            for fields in [
                &proxy.headers_up,
                &proxy.headers_down,
                &proxy.headers_down_add,
                &proxy.headers_down_default,
            ] {
                fields.values().try_for_each(|value| check_value(value))?;
            }
            for replacement in &proxy.headers_down_replace {
                check_value(&replacement.replace)?;
            }
            proxy
                .handle_response
                .iter()
                .flat_map(|entry| &entry.handlers)
                .try_for_each(validate_header_fields)
        }
        _ => Ok(()),
    }
}

/// 🏷️ Checks one map of field names to values.
fn check_fields(fields: &BTreeMap<String, String>) -> CompileResult<()> {
    for (name, value) in fields {
        check_name(name)?;
        check_value(value)?;
    }
    Ok(())
}

/// 🔁 Checks the field and the replacement text of each search-and-replace.
fn check_replacements(replacements: &[HeaderReplacement]) -> CompileResult<()> {
    for replacement in replacements {
        check_name(&replacement.field)?;
        check_value(&replacement.replace)?;
    }
    Ok(())
}

fn check_name(name: &str) -> CompileResult<()> {
    if http::HeaderName::from_bytes(name.as_bytes()).is_err() {
        return Err(CompileError::InvalidRoute {
            message: format!("`{name}` is not a valid header field name"),
        });
    }
    Ok(())
}

fn check_value(value: &str) -> CompileResult<()> {
    if value.contains(['\r', '\n', '\0']) {
        return Err(CompileError::InvalidRoute {
            message: format!(
                "header value {value:?} contains CR, LF or NUL, which no HTTP field \
                 value may carry (RFC 9110 §5.5)"
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(name: &str, value: &str) -> HandlerConfig {
        HandlerConfig::Headers {
            set: BTreeMap::from([(name.to_string(), value.to_string())]),
            add: BTreeMap::new(),
            remove: Vec::new(),
            replace: Vec::new(),
            default_set: BTreeMap::new(),
            require: None,
        }
    }

    /// 🎯 The issue's own Pingclairfile is refused, and so are its siblings on
    /// the request side and in `header_down`. Before the fix all of them
    /// compiled; a tab and a placeholder still do.
    #[test]
    fn a_configured_field_carrying_cr_or_lf_is_refused_at_load() {
        let compiles = [
            r#"header X-Inject "legit\r\nInjected-Header: pwned""#,
            r#"header "X Bad" "value""#,
            r#"request_header X-Inject "a\nb""#,
            "reverse_proxy 127.0.0.1:9000 {\n header_down X-Inject \"a\\rb\"\n}",
            r#"header X-Ok "{http.request.host}	tabbed""#,
        ]
        .map(|directive| {
            crate::compile(&format!(
                "http://example.com {{\n    {directive}\n    respond \"ok\"\n}}"
            ))
            .is_ok()
        });
        assert_eq!(compiles, [false, false, false, false, true]);
    }

    /// 🧾 A JSON document reaches the same rule: the check runs on the
    /// compiled handler, not on the DSL text.
    #[test]
    fn field_bytes_are_judged_by_the_field_grammar() {
        let verdicts = [
            ("X-Ok", "{http.request.host}\tand text"),
            ("X-Cr", "a\rb"),
            ("X-Lf", "a\nb"),
            ("X-Nul", "a\0b"),
            ("X Bad", "value"),
        ]
        .map(|(name, value)| validate_header_fields(&headers(name, value)).is_ok());
        assert_eq!(verdicts, [true, false, false, false, false]);
    }
}
