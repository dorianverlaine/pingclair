// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚦 Whether this process is alive, and whether it can take traffic.
//!
//! These are two different questions and conflating them is the classic
//! orchestration bug. *Liveness* asks "is this process worth keeping?" — a
//! `no` means restart it. *Readiness* asks "should traffic go here right
//! now?" — a `no` means route around it and try again shortly.
//!
//! Answering readiness with "the process is up" is what makes a rolling deploy
//! drop requests: the new instance reports healthy, the load balancer sends it
//! traffic, and the listeners are still binding. So readiness here flips only
//! after the listeners are actually bound, and flips back off as soon as
//! shutdown begins — while liveness stays true throughout, because a process
//! draining connections is doing exactly what it should be and restarting it
//! would be the wrong response.

use std::sync::atomic::{AtomicU8, Ordering};

/// 🚦 The lifecycle states that change how a health check must answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Bootstrapping: configuration parsed, listeners not yet accepting.
    Starting,
    /// Listeners are bound and the router is published.
    Ready,
    /// Shutdown began. Existing connections are still being served, but no new
    /// traffic should be sent here.
    Draining,
}

impl Phase {
    fn as_u8(self) -> u8 {
        match self {
            Phase::Starting => 0,
            Phase::Ready => 1,
            Phase::Draining => 2,
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => Phase::Ready,
            2 => Phase::Draining,
            _ => Phase::Starting,
        }
    }

    /// 🩺 A process is live unless it is beyond saving. Draining is not.
    pub fn is_live(self) -> bool {
        true
    }

    /// 🚦 Only a fully started, not-yet-draining process should be sent traffic.
    pub fn is_ready(self) -> bool {
        matches!(self, Phase::Ready)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Starting => "starting",
            Phase::Ready => "ready",
            Phase::Draining => "draining",
        }
    }
}

/// 🚦 Process-wide lifecycle phase.
///
/// An atomic rather than a lock because health checks are polled continuously
/// by orchestrators and must never queue behind whatever else is happening.
static PHASE: AtomicU8 = AtomicU8::new(0);

/// 🚦 Reports the current phase.
pub fn phase() -> Phase {
    Phase::from_u8(PHASE.load(Ordering::Acquire))
}

/// ✅ Marks the process ready. Call **after** listeners are bound, never before.
///
/// The ordering is the whole point: announcing readiness while sockets are
/// still being created is the same as announcing it falsely.
pub fn mark_ready() {
    // 🚫 Once draining, nothing may claim readiness again — a late startup task
    // finishing after SIGTERM must not put the instance back into rotation.
    let _ = PHASE.compare_exchange(
        Phase::Starting.as_u8(),
        Phase::Ready.as_u8(),
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    crate::metrics::READY.set(i64::from(phase().is_ready()));
}

/// 🚰 Marks the process as draining. Idempotent, and irreversible by design.
pub fn mark_draining() {
    PHASE.store(Phase::Draining.as_u8(), Ordering::Release);
    crate::metrics::READY.set(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🚦 **Day 24's completion criterion.**
    ///
    /// A process that is up but not yet serving must report not-ready, or an
    /// orchestrator will send it traffic it cannot answer.
    #[test]
    fn a_starting_process_is_live_but_not_ready() {
        assert!(
            Phase::Starting.is_live(),
            "a starting process is worth keeping"
        );
        assert!(
            !Phase::Starting.is_ready(),
            "a starting process must not be sent traffic"
        );
    }

    /// 🚰 Draining is the mirror: still live, no longer ready. Reporting it
    /// dead would get it killed mid-drain, cutting the connections it is in the
    /// middle of finishing.
    #[test]
    fn a_draining_process_is_live_but_not_ready() {
        assert!(Phase::Draining.is_live());
        assert!(!Phase::Draining.is_ready());
    }

    #[test]
    fn only_the_ready_phase_takes_traffic() {
        assert!(Phase::Ready.is_ready());
    }
}
