// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📮 The downstream write timeout: a stalled reader is cut, a slow one is not.
//!
//! The reference's `send_timeout` — 60 seconds by default — is measured
//! *between two successive write operations*, not over the whole response. A
//! client that reads slowly is therefore never cut, while one that stops
//! reading stops paying: without a bound it holds the connection, its buffers
//! and its admission slot until it goes away on its own.
//!
//! 📌 `sendTimeout: .seconds(0)` disables the bound, which is the reference's
//! own spelling of "off" (`send_timeout 0`).
//!
//! 🔌 HTTP/3 does not go through this session: its writes are paced by QUIC
//! flow control, and the bound that plays this role there is the connection's
//! idle timeout (`longConnections.idleTimeout` / `limits.idleTimeout`), which
//! ends a peer that stops acknowledging. A per-write bound for the QUIC path
//! is not implemented; the measured need for one is tracked in the
//! engineering memory (issue 58).

use pingclair_core::config::ResourceLimitsConfig;
use std::time::Duration;

/// ⏱️ The write timeout a request runs under when the site configured none.
///
/// The reference's own default, so an unconfigured site behaves the way its
/// documentation says it should.
pub(crate) const DEFAULT_SEND_TIMEOUT: Duration = Duration::from_secs(60);

/// 📮 Maps one site's limits to the value handed to the session.
///
/// `None` from the configuration means the default applies; `Some(0)` means
/// the operator turned the bound off.
pub(crate) fn downstream_write_timeout(limits: &ResourceLimitsConfig) -> Option<Duration> {
    match limits.send_timeout_ms {
        Some(0) => None,
        Some(millis) => Some(Duration::from_millis(millis)),
        None => Some(DEFAULT_SEND_TIMEOUT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_applies_until_the_site_says_otherwise() {
        let mut limits = ResourceLimitsConfig::default();
        assert_eq!(
            downstream_write_timeout(&limits),
            Some(Duration::from_secs(60)),
            "an unconfigured site gets the reference's default"
        );
        limits.send_timeout_ms = Some(500);
        assert_eq!(
            downstream_write_timeout(&limits),
            Some(Duration::from_millis(500))
        );
        // 🔌 Zero is the reference's "off" spelling: no bound at all.
        limits.send_timeout_ms = Some(0);
        assert_eq!(downstream_write_timeout(&limits), None);
    }
}
