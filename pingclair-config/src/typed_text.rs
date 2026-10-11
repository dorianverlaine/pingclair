// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 💬 Shared validation for compiled text segments.
//!
//! `Format(…)` and `from:` compile into a segment list at load time. Two
//! rules outlive the frontend that wrote them — a JSON document walks straight
//! past it — so they live with the shared validation, where `validate`, the
//! Admin `/load` endpoint, and a reload all pass through:
//!
//! 1. `.errorStatus` / `.errorMessage` describe a raised error and exist only
//!    inside an error route.
//! 2. A response subroute (`Intercept`, `handle_response`) is evaluated
//!    without a request in hand, so it refuses a segment list outright rather
//!    than writing text it cannot resolve.

use crate::compiler::{CompileError, CompileResult};
use pingclair_core::config::{ConfigText, HandlerConfig, PingclairConfig, TextSegment, TextSource};

/// 🧭 Where a handler sits, which decides what its text may say.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Ordinary routes: every source except the error ones.
    Route,
    /// Error routes: every source, including the error ones.
    ErrorRoute,
    /// Response subroutes: no request, so no dynamic text at all.
    Subroute,
}

/// 💬 Refuses segments that cannot resolve, and error sources that cannot
/// exist, wherever the configuration came from.
pub(crate) fn validate(config: &PingclairConfig) -> CompileResult<()> {
    for server in &config.servers {
        for route in &server.routes {
            walk(&route.handler, Stage::Route)?;
        }
        for route in &server.error_routes {
            for element in &route.handlers {
                walk(&element.handler, Stage::ErrorRoute)?;
            }
        }
    }
    Ok(())
}

/// 🚶 One handler, then everything it holds.
fn walk(handler: &HandlerConfig, stage: Stage) -> CompileResult<()> {
    match handler {
        HandlerConfig::Respond {
            body: Some(text), ..
        } => check(text, "a Respond body", stage)?,
        HandlerConfig::Redirect { to, .. } => check(to, "a redirect target", stage)?,
        HandlerConfig::Error {
            message: Some(text),
            ..
        } => check(text, "an error message", stage)?,
        HandlerConfig::Headers {
            set,
            add,
            default_set,
            ..
        } => {
            for value in set
                .values()
                .chain(add.values().flatten())
                .chain(default_set.values())
            {
                check(value, "a response header value", stage)?;
            }
        }
        HandlerConfig::RequestHeaders { set, add, .. } => {
            for value in set.values().chain(add.values().flatten()) {
                check(value, "a request header value", stage)?;
            }
        }
        HandlerConfig::ReverseProxy(proxy) => {
            for value in proxy
                .headers_up
                .values()
                .chain(proxy.headers_up_add.values().flatten())
            {
                check(value, "a header_up value", stage)?;
            }
            for value in proxy
                .headers_down
                .values()
                .chain(proxy.headers_down_add.values().flatten())
                .chain(proxy.headers_down_default.values())
            {
                check(value, "a header_down value", stage)?;
            }
            for entry in &proxy.handle_response {
                for element in &entry.handlers {
                    walk(element, Stage::Subroute)?;
                }
            }
        }
        HandlerConfig::Pipeline { handlers }
        | HandlerConfig::FirstMatch { handlers }
        | HandlerConfig::HandlePath { handlers, .. } => {
            for element in handlers {
                walk(&element.handler, stage)?;
            }
        }
        HandlerConfig::Intercept { handlers } => {
            for entry in handlers {
                for element in &entry.handlers {
                    walk(element, Stage::Subroute)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// 💬 One text value against the stage it sits in.
fn check(text: &ConfigText, what: &str, stage: Stage) -> CompileResult<()> {
    let Some(segments) = text.segments() else {
        return Ok(());
    };
    if stage == Stage::Subroute {
        return Err(CompileError::InvalidRoute {
            message: format!(
                "{what} cannot carry a `Format(…)` or `from:` value: a response subroute \
                 (`Intercept`, `handle_response`) is evaluated without a request to resolve \
                 it against"
            ),
        });
    }
    if stage == Stage::ErrorRoute {
        return Ok(());
    }
    for segment in segments {
        if let TextSegment::Source(source @ (TextSource::ErrorStatus | TextSource::ErrorMessage)) =
            segment
        {
            return Err(CompileError::InvalidRoute {
                message: format!(
                    "`{}` is only available inside an ErrorRoute; {} sits in an ordinary route",
                    source_name(*source),
                    what
                ),
            });
        }
    }
    Ok(())
}

/// 🏷️ The spelling an author wrote, for the refusal.
fn source_name(source: TextSource) -> &'static str {
    match source {
        TextSource::ErrorStatus => ".errorStatus",
        TextSource::ErrorMessage => ".errorMessage",
        TextSource::ClientIp => ".clientIP",
        TextSource::RemoteHost => ".remoteHost",
        TextSource::RemotePort => ".remotePort",
        TextSource::Scheme => ".scheme",
        TextSource::Host => ".host",
        TextSource::Path => ".path",
        TextSource::Method => ".method",
        TextSource::Uri => ".uri",
    }
}
