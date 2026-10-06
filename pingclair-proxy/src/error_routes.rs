// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚨 `handle_errors` routes, prepared once per configuration.
//!
//! An error route is a route body that runs after the handler chain raised a
//! status. Both transports run the same routes, so what they need from the
//! configuration is built here, at load, and shared through `ProxyState`:
//! the handler pipeline itself, its precompiled matchers, and the file server
//! a `file_server` inside the route serves its page from.
//!
//! 📌 The file server is the reason this module exists. An error route has no
//! route slot of its own, and both transports used to look its `file_server`
//! up in the slot of the route that *raised* the error — which, for a proxy
//! route, is empty. H1/H2 then sent the bare error text and HTTP/3 answered
//! `503 File Server Unavailable`, whatever the error route said.

use std::sync::Arc;

use pingclair_core::config::{HandlerConfig, ServerConfig};
use pingclair_core::server::MatcherPrecompile;

/// 🚨 One error route, ready to run on either transport.
pub(crate) struct PreparedErrorRoute {
    /// 🧭 The route body as one pipeline, built at load so answering an error
    /// does not deep-copy the handler tree each time.
    pub(crate) pipeline: HandlerConfig,
    /// 🎯 Matchers for `pipeline`, compiled once.
    pub(crate) precompile: MatcherPrecompile,
    /// 📂 The file server a `file_server` inside the route serves from, built
    /// from that handler's own configuration — root included.
    pub(crate) file_server: Option<Arc<pingclair_static::FileServer>>,
}

/// 🚨 Prepares every error route of one server, index-aligned with
/// `ServerConfig::error_routes`. The site's `encode` settings reach the
/// error routes' file servers as they reach every other.
pub(crate) fn prepare(site: &ServerConfig) -> Arc<[PreparedErrorRoute]> {
    site.error_routes
        .iter()
        .map(|route| {
            let pipeline = HandlerConfig::Pipeline {
                handlers: route.handlers.clone(),
            };
            PreparedErrorRoute {
                file_server: crate::server::build_file_server(&pipeline, site),
                precompile: pingclair_core::server::precompile_handler_list(&route.handlers),
                pipeline,
            }
        })
        .collect()
}

/// 🚨 The error an error route is answering: which route runs, and which
/// status the handler chain raised.
///
/// A `file_server` reads both. The route picks the file server, and the status
/// is the one the page goes out with — Caddy's file server, inside an error
/// route, answers with the error's status rather than `200` (from memory of
/// `staticfiles.go`, not re-read), so a client and a cache both still see
/// that the request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ErrorScope {
    /// Index into `ServerConfig::error_routes`.
    pub(crate) route: usize,
    /// The status raised by the handler chain.
    pub(crate) status: u16,
}

/// 📄 The method an error page is read with.
///
/// The page answers whatever request failed — a `POST` refused with `413`
/// included — so it is read as a `GET`, which is what the file server knows
/// how to answer; `HEAD` stays `HEAD` so its body is still left off. The
/// failed request's own header fields are not passed with it either: a
/// `Range` or `If-None-Match` aimed at the resource that failed says nothing
/// about the error page, and honouring one would turn the error into a `206`
/// or a `304`.
pub(crate) fn error_page_method(method: &http::Method) -> &'static http::Method {
    if method == http::Method::HEAD {
        &http::Method::HEAD
    } else {
        &http::Method::GET
    }
}

impl crate::server::ProxyState {
    /// 🚨 Whether any error route answers `status`.
    ///
    /// Asked on the failure paths that used to answer directly — a proxy that
    /// could not reach its upstream, a body over its limit — so that a site
    /// without a matching route keeps its error page and `Proxy-Status`
    /// exactly as before. At most one comparison per configured route.
    pub(crate) fn has_error_route_for(&self, status: u16) -> bool {
        self.config
            .error_routes
            .iter()
            .any(|route| route.matches(status))
    }
}
