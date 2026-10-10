// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔁 How many requests one downstream keepalive connection serves.
//!
//! Per-connection state accumulates for as long as a connection lives, so the
//! reference retires keepalive connections after 1000 requests
//! (`keepalive_requests`'s default, `ngx_http_core_module.c:3994`) and applies
//! the same number on HTTP/1, HTTP/2 and HTTP/3. Pingora carries the counter
//! for HTTP/1 only (`HttpServerOptions::keepalive_request_limit`,
//! `apps/mod.rs:85`); the HTTP/2 and HTTP/3 sessions have no equivalent while
//! the engineering memory tracks the gap (#58).
//!
//! 📌 Pingora's counter counts *reuses*, not requests: a connection serves one
//! request per reuse plus the first. The bound here is the reference's —
//! requests — so the counter handed to Pingora is one smaller, and the
//! integration test pins the pair.

use pingclair_core::config::ResourceLimitsConfig;

/// 🔁 Requests one keepalive connection serves when the configuration does
/// not name a number.
pub const DEFAULT_KEEPALIVE_REQUESTS: u32 = 1000;

/// 🔁 The reuse budget for a listener's HTTP/1 connections: the configured
/// `keepaliveRequests`, or the reference's default, expressed in the reuses
/// Pingora counts.
///
/// 📌 `Some(0)` cannot arrive from a compiled configuration — validation
/// refuses zero — and `saturating_sub` keeps a hand-built one from wrapping:
/// one request is the smallest meaningful bound.
pub fn resolve(limits: &ResourceLimitsConfig) -> Option<u32> {
    let requests = limits
        .keepalive_requests
        .unwrap_or(DEFAULT_KEEPALIVE_REQUESTS);
    Some(requests.saturating_sub(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(keepalive_requests: Option<u32>) -> ResourceLimitsConfig {
        ResourceLimitsConfig {
            keepalive_requests,
            ..Default::default()
        }
    }

    #[test]
    fn an_absent_bound_uses_the_references_default() {
        assert_eq!(resolve(&limits(None)), Some(999));
    }

    #[test]
    fn a_configured_bound_lands_one_reuse_smaller() {
        assert_eq!(resolve(&limits(Some(2))), Some(1));
        assert_eq!(resolve(&limits(Some(1))), Some(0));
    }
}
