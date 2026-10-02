// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ⏱️ How long a request body may stall when nothing configures it, on both
//! transports, and how that bound reaches HTTP/2, where Pingora has none.
//!
//! A client can announce `Content-Length: 999999999999` and then send nothing.
//! A `respond` route reads the announced body before it answers, and with no
//! `body_timeout`, `idle_timeout` or `request_body { read_timeout }` that read
//! had no deadline at all: the client got no response and the connection was
//! held for as long as the client cared to keep it. There used to be a 1 MiB
//! body ceiling by default, which refused that request on its header alone;
//! removing it to match Caddy left nothing else in the way.
//!
//! 📌 This bounds the pause between two pieces of body, not the whole upload,
//! so a large upload over a slow link still finishes as long as it keeps
//! moving. A client that stops is answered 408.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;

/// ⏱️ One minute, as nginx's `client_body_timeout` defaults to, with the same
/// meaning: the longest wait between two successive reads.
///
/// 📌 Caddy, recalled from memory on 2026-10-02 (`modules/caddyhttp/app.go`,
/// v2.x), sets no default for `read_body`, so its body reads are bounded only
/// by a `ReadTimeout` the operator writes. Caddy does not wait on the body
/// before a `respond` handler answers, though, so it never hung on this
/// request; this server does read first, which is why it needs a bound Caddy
/// can do without.
pub(crate) const DEFAULT_BODY_TIMEOUT: Duration = Duration::from_secs(60);

/// ⏱️ Awaits one body read, failing it with `ReadTimedout` (answered 408) when
/// `pause` passes first. `None` awaits it untimed.
///
/// 📌 For the body reads this server makes itself — the local drain and
/// FastCGI — on HTTP/2, where Pingora's own per-read timer is a no-op
/// (pingora-core 0.9.0, `ServerSession::set_read_timeout`). HTTP/1 passes
/// `None`, because Pingora already times those reads from the same value.
pub(crate) async fn read_within<T>(
    pause: Option<Duration>,
    read: impl Future<Output = pingora_core::Result<T>>,
) -> pingora_core::Result<T> {
    match pause {
        Some(pause) => tokio::time::timeout(pause, read).await.or_else(|_| {
            pingora_core::Error::e_explain(
                pingora_core::ErrorType::ReadTimedout,
                "HTTP/2 request body paused past its timeout",
            )
        })?,
        None => read.await,
    }
}

// MARK: - HTTP/2 proxied bodies

/// ⏱️ The body-pause watch for one HTTP/2 stream whose body Pingora reads.
///
/// Pingora reads a proxied request body inside its own proxy loop, and on an
/// HTTP/2 stream that read has no timer at all: `set_read_timeout` is a no-op
/// there, and `HttpSession::read_body_bytes` carries a `TODO: timeout`
/// (pingora-core 0.9.0). An upload that stopped halfway therefore held its
/// stream and its upstream connection forever, configured `body_timeout` or
/// not. Nothing inside that loop can be given a timer, so the watch runs
/// beside it: the proxy arms it when the body starts going upstream, every
/// chunk that arrives pushes the deadline back, the end of the body disarms
/// it, and a pause past the deadline ends the stream from outside.
///
/// 🧵 One per HTTP/2 stream, shared between the task that serves the stream
/// (through a task-local) and the watchdog racing it. Atomics rather than a
/// lock, because the proxy touches it on every body chunk.
pub struct H2BodyWatch {
    /// ⏱️ The origin the two millisecond counters below are measured from.
    started: Instant,
    /// ⏱️ The longest allowed pause, in milliseconds; zero while disarmed.
    pause_ms: AtomicU64,
    /// ⏱️ When the body last moved, in milliseconds since `started`.
    moved_ms: AtomicU64,
    /// 🔔 Wakes the watchdog when the watch is armed, re-armed or disarmed.
    rearmed: Notify,
}

tokio::task_local! {
    /// 🧵 The watch of the HTTP/2 stream this task is serving, if any.
    static H2_BODY_WATCH: Arc<H2BodyWatch>;
}

impl H2BodyWatch {
    /// ⏱️ Milliseconds since `started`, saturating far beyond any deadline.
    fn now_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// ⏱️ Starts the clock with `pause`, or stops it with `None`.
    fn set(&self, pause: Option<Duration>) {
        let pause_ms = pause.map_or(0, |pause| {
            u64::try_from(pause.as_millis()).unwrap_or(u64::MAX).max(1)
        });
        self.moved_ms.store(self.now_ms(), Ordering::Release);
        self.pause_ms.store(pause_ms, Ordering::Release);
        self.rearmed.notify_one();
    }

    /// ⏱️ Resolves once the body has paused past the armed deadline.
    ///
    /// 📌 A chunk only ever moves the deadline later, so sleeping to the old
    /// one and looking again is enough; only arming can move it earlier, and
    /// arming wakes this.
    async fn stalled(&self) {
        loop {
            let pause_ms = self.pause_ms.load(Ordering::Acquire);
            if pause_ms == 0 {
                self.rearmed.notified().await;
                continue;
            }
            let due_ms = self
                .moved_ms
                .load(Ordering::Acquire)
                .saturating_add(pause_ms);
            if self.now_ms() >= due_ms {
                return;
            }
            let due = self.started + Duration::from_millis(due_ms);
            tokio::select! {
                () = tokio::time::sleep_until(due) => {}
                () = self.rearmed.notified() => {}
            }
        }
    }

    /// ⏱️ Arms the watch of the HTTP/2 stream this task serves with `pause`,
    /// or disarms it with `None`. A no-op outside one.
    pub(crate) fn arm(pause: Option<Duration>) {
        let _ = H2_BODY_WATCH.try_with(|watch| watch.set(pause));
    }

    /// 🌊 Gives an armed watch a new pause, `None` meaning none at all, when a
    /// request turns out to be a long connection. A disarmed watch stays
    /// disarmed: its body is finished, or not being read yet, and a clock
    /// started now would cut a quiet response stream.
    pub(crate) fn rearm(pause: Option<Duration>) {
        let _ = H2_BODY_WATCH.try_with(|watch| {
            if watch.pause_ms.load(Ordering::Acquire) != 0 {
                watch.set(pause);
            }
        });
    }

    /// ⏱️ Records that a body chunk arrived, pushing the deadline back.
    pub(crate) fn moved() {
        let _ = H2_BODY_WATCH.try_with(|watch| {
            watch.moved_ms.store(watch.now_ms(), Ordering::Release);
        });
    }

    /// ⏱️ Serves one HTTP/2 stream under a body watch, returning `None` when
    /// the watch ended it because its body stalled.
    ///
    /// Ending it means dropping `serve`, and with it the stream: h2 then sends
    /// `RST_STREAM(CANCEL)`, and the upstream connection, which holds half a
    /// request, is closed rather than reused. A `408` cannot be sent from
    /// here, because only the session inside `serve` can write a response.
    ///
    /// 📌 Costs one allocation per HTTP/2 stream; HTTP/1 never comes here.
    pub async fn serve<F: Future>(serve: F) -> Option<F::Output> {
        let watch = Arc::new(Self {
            started: Instant::now(),
            pause_ms: AtomicU64::new(0),
            moved_ms: AtomicU64::new(0),
            rearmed: Notify::new(),
        });
        let served = H2_BODY_WATCH.scope(Arc::clone(&watch), serve);
        tokio::select! {
            output = served => Some(output),
            () = watch.stalled() => {
                tracing::debug!("⏱️ An HTTP/2 request body paused past its timeout; resetting the stream");
                None
            }
        }
    }
}
