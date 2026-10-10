// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔌 How many downstream connections one listener admits at once.
//!
//! A configuration that never mentions connections still needs the ceiling
//! every server has: without one, an idle listener is bounded only by the
//! file-descriptor limit, and the symptom of exhausting it is far from the
//! cause. The reference carries the same bound without being asked —
//! `worker_connections` defaults to 512 connections per worker
//! (`ngx_event.c`'s `DEFAULT_CONNECTIONS`, read from the vendored source on
//! 2026-10-10) — so a listener with no `limits(maxConnections:)` admits 512
//! per worker thread — the same total the reference reaches under its
//! recommended `worker_processes auto`. The engineering memory records the
//! comparison (#58).
//!
//! 📌 One listener, one semaphore: the reference's pool is per worker and
//! shared by every listener that worker polls, while this project's budget is
//! per listener and shared by its threads. The number per thread is the same;
//! the scope is this project's and does not change with this default.

use pingclair_core::config::ResourceLimitsConfig;

/// 🔢 The downstream connections one worker thread admits when no
/// `limits(maxConnections:)` is configured.
pub const DEFAULT_CONNECTIONS_PER_THREAD: usize = 512;

/// 🔌 The ceiling a listener enforces: the configured `maxConnections`, or
/// [`DEFAULT_CONNECTIONS_PER_THREAD`] per worker thread when there is none.
///
/// 📌 The configured value has already been through validation, so a `0`
/// cannot arrive here; the thread count is clamped to at least one so a
/// misconfigured zero cannot turn the default into a listener that admits
/// nothing.
pub fn resolve(limits: &ResourceLimitsConfig, worker_threads: usize) -> usize {
    limits
        .max_connections
        .unwrap_or_else(|| default_for_worker_threads(worker_threads))
}

/// 🔌 [`DEFAULT_CONNECTIONS_PER_THREAD`] for a service running on
/// `worker_threads` threads.
pub fn default_for_worker_threads(worker_threads: usize) -> usize {
    DEFAULT_CONNECTIONS_PER_THREAD.saturating_mul(worker_threads.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(max_connections: Option<usize>) -> ResourceLimitsConfig {
        ResourceLimitsConfig {
            max_connections,
            ..Default::default()
        }
    }

    #[test]
    fn a_configured_ceiling_wins_over_the_default() {
        assert_eq!(resolve(&limits(Some(7)), 32), 7);
    }

    #[test]
    fn an_absent_ceiling_scales_with_the_worker_threads() {
        assert_eq!(resolve(&limits(None), 1), 512);
        assert_eq!(resolve(&limits(None), 8), 4096);
    }

    /// 🚫 A zero thread count must not produce a listener that admits
    /// nothing; the reference's number stands per thread that exists.
    #[test]
    fn a_zero_thread_count_keeps_one_workers_worth() {
        assert_eq!(resolve(&limits(None), 0), DEFAULT_CONNECTIONS_PER_THREAD);
    }
}
