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
//! 🔌 Then every connection still open has to be told it is over. A TCP
//! connection needs nothing from us: the kernel closes it when the process
//! exits, and the client sees the close at once. A QUIC connection lives only
//! in this process's memory, so if the process simply exits, the client is
//! never told and waits out its idle timeout with a request that will never
//! finish — about seventy seconds in the 2026-09-25 soak (#211). [`stop`]
//! therefore ends with [`close_connections`], and holds the exit until each
//! connection holding an [`OpenConnection`] token has put its close on the
//! wire.
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

/// ⏱️ How long the exit waits for open connections to send their close.
///
/// A close is one packet that each connection writes on its next turn, so
/// this is normally over in milliseconds. The bound exists for a connection
/// whose task never gets that turn: the exit must not hang on it, and every
/// millisecond here is a millisecond a restart refuses connections.
const CLOSE_BUDGET: Duration = Duration::from_millis(500);

// MARK: - Counting and announcing

/// 🧮 A process-wide count that a waiter can watch fall to zero.
struct Gauge {
    count: AtomicUsize,
    /// 🔔 Only the transition to zero notifies, so a busy server never
    /// touches it.
    zero: Notify,
}

impl Gauge {
    const fn new() -> Self {
        Self {
            count: AtomicUsize::new(0),
            zero: Notify::const_new(),
        }
    }

    fn enter(&self) {
        // 📌 Relaxed is enough: the count orders nothing but itself, and the
        // waiter re-reads it after arming its notification.
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    fn leave(&self) {
        if self.count.fetch_sub(1, Ordering::AcqRel) == 1 {
            // 🔔 `notify_waiters` stores no permit, so a server with nobody
            // waiting pays for nothing here beyond the check above.
            self.zero.notify_waiters();
        }
    }

    fn get(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    /// ⏳ Waits for zero or for `limit`; returns what is left.
    async fn wait_zero(&self, limit: Duration) -> usize {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            // 🧷 Arm the notification *before* reading the count. The other
            // order loses a wake-up when the last holder leaves between the
            // read and the wait, and shutdown would then sit out the whole
            // limit.
            let zero = self.zero.notified();
            tokio::pin!(zero);
            zero.as_mut().enable();
            if self.get() == 0 {
                return 0;
            }
            if tokio::time::timeout_at(deadline, zero).await.is_err() {
                return self.get();
            }
        }
    }
}

/// 📣 A one-way announcement: set once, never cleared, awaitable.
struct Latch {
    set: AtomicBool,
    notify: Notify,
}

impl Latch {
    const fn new() -> Self {
        Self {
            set: AtomicBool::new(false),
            notify: Notify::const_new(),
        }
    }

    fn set(&self) {
        self.set.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    fn is_set(&self) -> bool {
        self.set.load(Ordering::Acquire)
    }

    async fn wait(&self) {
        let notified = self.notify.notified();
        tokio::pin!(notified);
        // 🧷 Armed before the flag is read, for the same lost-wake-up reason
        // as in [`Gauge::wait_zero`].
        notified.as_mut().enable();
        if self.is_set() {
            return;
        }
        notified.await;
    }
}

/// 🚰 Requests that have started and not yet finished, across both transports.
static IN_FLIGHT: Gauge = Gauge::new();

/// 🔌 Established QUIC connections that have not yet sent their close.
static OPEN: Gauge = Gauge::new();

/// 🛑 Set once, when the process has stopped accepting and begins to drain.
///
/// Pingora tells its own listeners through its shutdown broadcast; this is the
/// same news for the transports Pingora does not own, which today means the
/// HTTP/3 server, so it can send `GOAWAY` on connections that stay open.
static STOPPING: Latch = Latch::new();

/// 🔌 Set once, when the drain is over and every connection must close now.
static CLOSING: Latch = Latch::new();

// MARK: - The stop, in order

/// 🛑 What a finished [`stop`] left behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stopped {
    /// 🔪 Requests still running when the grace period ran out.
    pub cut: usize,
    /// 🔌 Connections that had not sent their close when the budget ran out.
    pub unclosed: usize,
}

/// 🛑 Drains the process: announce, wait for requests, then close connections.
///
/// The three steps are one function so that the shutdown path and the tests
/// that pin its behavior cannot run them in different orders. It returns once
/// the process may exit without leaving a client waiting on a silent
/// connection, which takes at most `grace` plus [`CLOSE_BUDGET`].
pub async fn stop(grace: Duration) -> Stopped {
    begin_stopping();
    let cut = wait_idle(grace).await;
    close_connections();
    let unclosed = OPEN.wait_zero(CLOSE_BUDGET).await;
    Stopped { cut, unclosed }
}

/// 🛑 Announces that the process is draining. Idempotent.
pub fn begin_stopping() {
    STOPPING.set();
}

/// 🛑 Whether [`begin_stopping`] has run.
pub fn is_stopping() -> bool {
    STOPPING.is_set()
}

/// 🛑 Resolves once the process is draining; at once if it already is.
pub async fn stopping() {
    STOPPING.wait().await;
}

/// 🔌 Tells every open connection to close now, finished or not. Idempotent.
///
/// Closing implies stopping, so this also announces the drain: a connection
/// that is told to close must not first be waiting for a `GOAWAY` cue.
pub(crate) fn close_connections() {
    STOPPING.set();
    CLOSING.set();
}

/// 🔌 Whether [`close_connections`] has run.
pub(crate) fn is_closing() -> bool {
    CLOSING.is_set()
}

/// 🔌 Resolves once connections must close; at once if they already must.
pub(crate) async fn closing() {
    CLOSING.wait().await;
}

// MARK: - Tokens

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
        IN_FLIGHT.enter();
        Self(())
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        IN_FLIGHT.leave();
    }
}

/// 🔌 Proof that one connection still owes its client a close.
///
/// Held by a QUIC connection from its handshake until its close has left
/// the process, which is the moment the exit stops waiting for it. Dropping
/// covers every other ending too, so a connection the client closed first
/// is never waited for.
#[derive(Debug)]
pub(crate) struct OpenConnection(());

impl OpenConnection {
    /// 🔌 Counts one connection as open.
    pub(crate) fn enter() -> Self {
        OPEN.enter();
        Self(())
    }
}

impl Drop for OpenConnection {
    fn drop(&mut self) {
        OPEN.leave();
    }
}

/// 🚰 The number of requests currently being served.
pub fn in_flight() -> usize {
    IN_FLIGHT.get()
}

/// ⏳ Waits until no request is in flight, or until `grace` has passed.
///
/// Returns the number of requests still running when it stopped waiting, so
/// the caller can say how many it is about to cut off. Zero means everything
/// finished.
pub async fn wait_idle(grace: Duration) -> usize {
    IN_FLIGHT.wait_zero(grace).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⏳ Shutdown leaves as soon as the last request ends, not at the deadline.
    ///
    /// One test rather than several because the counters are process-wide and
    /// the unit tests of this crate share one process.
    #[tokio::test]
    async fn waiting_ends_with_the_last_holder_and_otherwise_at_the_deadline() {
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

        // 🔌 The close wait is the same gauge with its own count: an open
        // connection holds it, and letting go ends the wait at once.
        let connection = OpenConnection::enter();
        let waiter = tokio::spawn(async { OPEN.wait_zero(Duration::from_secs(30)).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(connection);
        assert_eq!(waiter.await.unwrap(), 0);
    }
}
