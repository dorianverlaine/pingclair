// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 Load-time lints: legal configurations that almost certainly are not what
//! the author meant.
//!
//! A lint never refuses and never changes behavior — it says one sentence and
//! the loader carries on. The first one exists because a native string is
//! literal text: `Redirect(to: "https://example.com{uri}")` sends `{uri}`
//! verbatim, and the author who meant the request target needs the pointer to
//! `Format(…)` before a deployment finds out (#330).

use pingclair_core::config::{ConfigText, HandlerConfig, PingclairConfig};

/// 🧭 Every lint this configuration carries, in walk order.
pub fn lints(config: &PingclairConfig) -> Vec<String> {
    let mut found = Vec::new();
    for server in &config.servers {
        for route in &server.routes {
            visit(
                &route.handler,
                &format!("route \"{}\"", route.path),
                &mut found,
            );
        }
        for route in &server.error_routes {
            for element in &route.handlers {
                visit(&element.handler, "an error route", &mut found);
            }
        }
    }
    found
}

/// 🚶 One handler, then everything it holds.
fn visit(handler: &HandlerConfig, at: &str, found: &mut Vec<String>) {
    match handler {
        HandlerConfig::Redirect {
            to: ConfigText::Literal { literal },
            ..
        } => {
            if let Some(placeholder) = placeholder_like(literal) {
                found.push(format!(
                    "{at}: a Redirect target contains `{placeholder}`, and a string is literal \
                     text — it would be sent exactly as written. Write \
                     `Format(\"…{placeholder}…\", …)` with a typed source (`.uri`, `.host`, …) \
                     to resolve it"
                ));
            }
        }
        HandlerConfig::Pipeline { handlers }
        | HandlerConfig::FirstMatch { handlers }
        | HandlerConfig::HandlePath { handlers, .. } => {
            for element in handlers {
                visit(&element.handler, at, found);
            }
        }
        HandlerConfig::Intercept { handlers } => {
            for entry in handlers {
                for element in &entry.handlers {
                    visit(element, at, found);
                }
            }
        }
        HandlerConfig::ReverseProxy(proxy) => {
            for entry in &proxy.handle_response {
                for element in &entry.handlers {
                    visit(element, at, found);
                }
            }
        }
        _ => {}
    }
}

/// 🧭 The first `{…}` that looks like a placeholder, for the sentence.
///
/// 🚫 A lone brace or a nested one is left alone: the lint points at the shape
/// the author almost certainly meant, it does not guess at text.
fn placeholder_like(text: &str) -> Option<&str> {
    let mut rest = text;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let close = after.find('}')?;
        let inner = &after[..close];
        if !inner.is_empty() && !inner.contains('{') {
            return Some(&rest[open..open + close + 2]);
        }
        rest = &after[close + 1..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native(source: &str) -> PingclairConfig {
        crate::compile(source).unwrap()
    }

    #[test]
    fn a_redirect_target_with_placeholder_braces_is_flagged() {
        let config = native(
            r#"HTTPListener(on: "127.0.0.1:18080") { Site(host: "*") {
                Route(when: .path(exact: "/old")) {
                    Redirect(to: "https://example.com{uri}", status: .permanentRedirect)
                }
            } }"#,
        );
        let found = lints(&config);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("route \"/old\""), "{}", found[0]);
        assert!(found[0].contains("{uri}"), "{}", found[0]);
    }

    #[test]
    fn the_typed_spelling_and_legacy_templates_are_not_flagged() {
        // 💬 `Format(…)` says what it means; a legacy template expands, so both
        // are exactly what their authors wrote.
        let typed = native(
            r#"HTTPListener(on: "127.0.0.1:18080") { Site(host: "*") {
                Route(when: .path(exact: "/old")) {
                    Redirect(to: Format("https://example.com{uri}", uri: .uri))
                }
            } }"#,
        );
        assert!(lints(&typed).is_empty());
        let legacy = crate::compile("http://:8080 {\n\tredir https://example.com{uri}\n}").unwrap();
        assert!(lints(&legacy).is_empty());
    }

    #[test]
    fn ordinary_literal_braces_elsewhere_are_not_redirect_lints() {
        let config = native(
            r#"HTTPListener(on: "127.0.0.1:18080") { Site(host: "*") {
                Fallback { Respond(body: "{not-a-placeholder}") }
            } }"#,
        );
        assert!(lints(&config).is_empty());
        // 🚫 A lone brace is text, not a placeholder.
        let lone = native(
            r#"HTTPListener(on: "127.0.0.1:18080") { Site(host: "*") {
                Route(when: .path(exact: "/old")) { Redirect(to: "https://example.com/a{b") }
            } }"#,
        );
        assert!(lints(&lone).is_empty());
    }
}
