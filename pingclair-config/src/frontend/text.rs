// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 💬 Native text values: a literal string, `Format(…)`, or `from: <source>`.
//!
//! 📌 Strings stay literal — that contract is what `0189cb0` hardened — so a
//! dynamic value is spelled as a value: `Format("https://example.com{uri}",
//! uri: .uri)` compiles its pattern here, once, into the segment list the
//! runtime resolves. `Format` is a closed constructor, not a function: no
//! expressions, no nested formats, no unknown names, no unused parameters.

use crate::frontend::{Call, Error, Position, Value};
use pingclair_core::config::{ConfigText, TextSegment, TextSource};

/// 💬 Compiles one text value in a position that accepts dynamic text.
///
/// 📌 `at` is the position of the call that holds the value; a string, a
/// number and a boolean carry none of their own, and an error has to point at
/// the line the operator wrote.
pub(super) fn config_text(value: &Value, what: &str, at: Position) -> Result<ConfigText, Error> {
    match value {
        Value::String(text) => Ok(ConfigText::literal(text)),
        Value::Component(call) if call.name == "Format" => format_value(call),
        Value::Component(call) => Err(call.at.error(format!(
            "unknown text constructor `{}(…)`; a quoted string is literal, Format(…) mixes text \
             with sources, and from: names one source",
            call.name
        ))),
        _ => Err(unsupported(at, what)),
    }
}

/// 💬 One typed source, written as the case it is (`from: .clientIP`).
pub(super) fn source_value(value: &Value, what: &str, at: Position) -> Result<TextSource, Error> {
    let Value::Typed(case) = value else {
        return Err(at.error(format!(
            "{what} takes a text source such as .clientIP, .uri or .errorStatus"
        )));
    };
    if case.body.is_some() || !case.modifiers.is_empty() || !case.args.is_empty() {
        return Err(case.at.error("a text source takes no arguments"));
    }
    match case.name.as_str() {
        "clientIP" => Ok(TextSource::ClientIp),
        "remoteHost" => Ok(TextSource::RemoteHost),
        "remotePort" => Ok(TextSource::RemotePort),
        "scheme" => Ok(TextSource::Scheme),
        "host" => Ok(TextSource::Host),
        "path" => Ok(TextSource::Path),
        "method" => Ok(TextSource::Method),
        "uri" => Ok(TextSource::Uri),
        "errorStatus" => Ok(TextSource::ErrorStatus),
        "errorMessage" => Ok(TextSource::ErrorMessage),
        other => Err(case.at.error(format!(
            "unknown text source `.{other}`; expected .clientIP, .remoteHost, .remotePort, \
             .scheme, .host, .path, .method, .uri, .errorStatus or .errorMessage"
        ))),
    }
}

/// 💬 `Format("…{name}…", name: .source, …)` compiled into segments.
fn format_value(call: &Call) -> Result<ConfigText, Error> {
    if call.body.is_some() || !call.modifiers.is_empty() {
        return Err(call
            .at
            .error("Format takes a pattern and named sources on one line, nothing else"));
    }
    let Some((None, Value::String(pattern))) = call.args.first() else {
        return Err(call.at.error("Format takes a quoted pattern first"));
    };
    if call.args.len() == 1 {
        return Err(call
            .at
            .error("Format without named sources is just a string; drop the Format wrapper"));
    }

    let mut parameters: Vec<(String, TextSource)> = Vec::new();
    for (label, value) in &call.args[1..] {
        let Some(name) = label else {
            return Err(call
                .at
                .error("Format parameters need labels: Format(\"…{name}…\", name: <source>)"));
        };
        if parameters.iter().any(|(existing, _)| existing == name) {
            return Err(call
                .at
                .error(format!("Format parameter `{name}` is given twice")));
        }
        parameters.push((
            name.clone(),
            source_value(value, "a Format parameter", call.at)?,
        ));
    }

    let mut segments: Vec<TextSegment> = Vec::new();
    let mut literal = String::new();
    let mut used = vec![false; parameters.len()];
    let mut chars = pattern.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            // 📌 `{{` and `}}` are how a pattern carries a literal brace; a
            // lone one is a mistake in the pattern, not text.
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                literal.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                literal.push('}');
            }
            '{' => {
                let mut name = String::new();
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some(character) => name.push(character),
                        None => {
                            return Err(call.at.error(
                                "Format pattern has an unclosed `{`; write `{{` for a literal brace",
                            ));
                        }
                    }
                }
                let Some(index) = parameters
                    .iter()
                    .position(|(parameter, _)| parameter == &name)
                else {
                    return Err(call.at.error(format!(
                        "Format pattern names `{{{name}}}`, which has no parameter"
                    )));
                };
                used[index] = true;
                if !literal.is_empty() {
                    segments.push(TextSegment::Literal(std::mem::take(&mut literal)));
                }
                segments.push(TextSegment::Source(parameters[index].1));
            }
            '}' => {
                return Err(call
                    .at
                    .error("Format pattern has an unmatched `}`; write `}}` for a literal brace"));
            }
            character => literal.push(character),
        }
    }
    if !literal.is_empty() {
        segments.push(TextSegment::Literal(literal));
    }
    for (index, (name, _)) in parameters.iter().enumerate() {
        if !used[index] {
            return Err(call.at.error(format!(
                "Format parameter `{name}` never appears in the pattern"
            )));
        }
    }
    Ok(ConfigText::Segments { segments })
}

/// 🚫 The one message every text position shares for a value it cannot read.
fn unsupported(at: Position, what: &str) -> Error {
    at.error(format!(
        "{what} requires a quoted string, Format(…), or from: <source>"
    ))
}
