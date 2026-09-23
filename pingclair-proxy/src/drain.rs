// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚰 How many requests are still running, so shutdown can wait for them.
//!
//! A graceful stop has to answer one question: "is anything still being
//! served?" Without the answer there are only two choices, and both are wrong.
//! Exit at once and every download in progress is cut mid-body. Sleep for the
//! whole grace period and every restart of an idle server costs thirty seconds
//! of nothing.
//!
//! So each request holds an [`InFlight`] token from the moment the transport
//! hands it over until its last byte is written or abandoned, and shutdown
//! waits in [`wait_idle`] until the count reaches zero or the grace period
//! runs out, whichever comes first.
//!
//! 🏎️ The count is one process-wide atomic, so every request pays two
//! uncontended-in-the-common-case read-modify-write operations on a shared
//! cache line. That is the same price as the request-id sequence already paid
//! per request, and it is the cheapest shape that can answer "zero?" without
//! walking every connection. Striping it per core would make the zero test a
//! sum over stripes that can never be read atomically.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Notify;

/// 🚰 Requests that have started and not yet finished, across both transports.
static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

/// 🔔 Wakes a shutdown waiting in [`wait_idle`] when the last request ends.
///
/// Only the transition to zero notifies, so a busy server never touches it.
static IDLE: Notify = Notify::const_new();

/// 🛑 Set once, when the process has stopped accepting and begins to drain.
///
/// Pingora tells its own listeners through its shutdown broadcast; this is the
/// same news for the transports Pingora does not own, which today means the
/// HTTP/3 server, so it can send `GOAWAY` on connections that stay open.
static STOPPING: AtomicBool = AtomicBool::new(false);

/// 🔔 Wakes everything waiting in [`stopping`] when [`begin_stopping`] runs.
static STOP: Notify = Notify::const_new();

/// 🛑 Announces that the process is draining. Idempotent.
pub fn begin_stopping() {
    STOPPING.store(true, Ordering::Release);
    STOP.notify_waiters();
}

/// 🛑 Whether [`begin_stopping`] has run.
pub fn is_stopping() -> bool {
    STOPPING.load(Ordering::Acquire)
}

/// 🛑 Resolves once the process is draining; at once if it already is.
pub async fn stopping() {
    let stop = STOP.notified();
    tokio::pin!(stop);
    // 🧷 Armed before the flag is read, for the same lost-wake-up reason as
    // in [`wait_idle`].
    stop.as_mut().enable();
    if is_stopping() {
        return;
    }
    stop.await;
}

/// 🎟️ Proof that one request is being served; dropping it ends the request.
///
/// Dropping rather than an explicit `finish()` call is deliberate: a request
/// can end through an error, a cancelled task, or a client that vanished, and
/// every one of those still drops the context that owns this token.
#[derive(Debug)]
pub struct InFlight(());

impl InFlight {
    /// 🎟️ Counts one request as started.
    pub fn enter() -> Self {
        // 📌 Relaxed is enough: the count orders nothing but itself, and the
        // waiter re-reads it after arming its notification.
        IN_FLIGHT.fetch_add(1, Ordering::Relaxed);
        Self(())
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if IN_FLIGHT.fetch_sub(1, Ordering::AcqRel) == 1 {
            // 🔔 `notify_waiters` stores no permit, so a server with nobody
            // waiting pays for nothing here beyond the check above.
            IDLE.notify_waiters();
        }
    }
}

/// 🚰 The number of requests currently being served.
pub fn in_flight() -> usize {
    IN_FLIGHT.load(Ordering::Acquire)
}

/// ⏳ Waits until no request is in flight, or until `grace` has passed.
///
/// Returns the number of requests still running when it stopped waiting, so
/// the caller can say how many it is about to cut off. Zero means everything
/// finished.
pub async fn wait_idle(grace: Duration) -> usize {
    let deadline = tokio::time::Instant::now() + grace;
    loop {
        // 🧷 Arm the notification *before* reading the count. The other order
        // loses a wake-up when the last request ends between the read and the
        // wait, and shutdown would then sit out the whole grace period.
        let idle = IDLE.notified();
        tokio::pin!(idle);
        idle.as_mut().enable();
        let remaining = in_flight();
        if remaining == 0 {
            return 0;
        }
        if tokio::time::timeout_at(deadline, idle).await.is_err() {
            return in_flight();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⏳ Shutdown leaves as soon as the last request ends, not at the deadline.
    ///
    /// One test rather than several because the counter is process-wide and
    /// the unit tests of this crate share one process.
    #[tokio::test]
    async fn waiting_ends_with_the_last_request_and_otherwise_at_the_deadline() {
        let token = InFlight::enter();
        let started = std::time::Instant::now();
        assert_eq!(
            wait_idle(Duration::from_millis(50)).await,
            1,
            "a request that never ends is reported when the grace period runs out"
        );

        let waiter = tokio::spawn(wait_idle(Duration::from_secs(30)));
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(token);
        assert_eq!(waiter.await.unwrap(), 0);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the wait must end when the request does, not at its deadline"
        );
    }
}
