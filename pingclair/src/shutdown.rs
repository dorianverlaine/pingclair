// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛑 How the process stops: one order, every graceful path.
//!
//! A graceful stop happens in this order, and each step exists because
//! skipping it broke something:
//!
//! 1. **Stop being sent traffic.** `/ready` turns 503 and systemd hears
//!    `STOPPING=1`, so a load balancer routes around this instance.
//! 2. **Stop accepting.** Pingora's shutdown broadcast closes every listening
//!    socket, so a new connection is refused instead of half-served, and it
//!    sends HTTP/2 `GOAWAY` on open connections so clients retry elsewhere.
//! 3. **Let running requests finish**, for at most `grace_period`. The wait
//!    ends as soon as the last one does, so an idle server exits at once.
//! 4. **Close every HTTP/3 connection still open**, cutting what the grace
//!    period did not cover. TCP needs no step here because the kernel closes
//!    those sockets at exit; a QUIC client hears nothing unless this process
//!    tells it, and otherwise waits out its idle timeout (#211).
//! 5. **Flush the access log, then the tracing queue**, because
//!    `std::process::exit` runs no destructors and would lose both.
//! 6. **Exit.**
//!
//! Before this module, step 3 did not happen: the signal handler went
//! straight to step 4 and exited about a quarter of a second after SIGTERM,
//! cutting every in-flight request however long the configured grace was.
//!
//! 🏃 SIGQUIT is the exception on purpose. It exits immediately with status 2,
//! which is what Caddy does, and it is how an operator says "do not wait".

use std::time::Duration;

use pingora_core::server::ExecutionPhase;
#[cfg(unix)]
use pingora_core::server::{ShutdownSignal, ShutdownSignalWatch};
use tokio::sync::{broadcast, watch};

#[cfg(unix)]
use crate::systemd::notify_systemd_stopping;

/// ⏱️ How long a shutdown that served a request gives the transports to put
/// queued bytes on the wire before the process exits.
///
/// 📌 This waits for the *tail*, not for the response. The in-flight count
/// reaches zero when the proxy has handed the last chunk to its transport, so
/// what is left is whatever the HTTP/2 codec, TLS and the socket buffer are
/// still holding — hundreds of kilobytes, not the body. The bound is therefore
/// sized by "a few hundred kilobytes on a busy machine", which is why it is a
/// second rather than a scheduling round.
///
/// 🧭 It was 100 ms until the 2026-10-09 postmerge run on aarch64 (run
/// 37909489493), where a 4 MiB HTTP/2 response had 3 876 087 bytes delivered
/// and the rest cut. The same tail exists on a busy production host, and the
/// cost of being wrong here is a truncated response; the cost of the bound is
/// paid only by a shutdown that served something.
///
/// 🚫 It is deliberately not the configured grace period: that sleeps even
/// when nothing is left to do. A bound is not a proof: the transports never
/// tell us the tail is gone, so this is sized for a tail — a few hundred
/// kilobytes in the codec, TLS and the socket buffer — on a machine that is
/// busy with other work. The engineering memory records the deterministic
/// alternative (wait on the connection tasks, not on a clock) and why it is a
/// redesign rather than another number here.
const FLUSH_BUDGET: Duration = Duration::from_secs(1);

/// 🛑 Listens for every way to ask this process to stop, from startup on.
///
/// The signal handlers are installed here, on the background runtime, before
/// Pingora starts its services, because Pingora only asks [`SignalWatch`]
/// once its services are running. A SIGTERM that arrived in between would
/// otherwise hit the default action and kill the process without draining its
/// logs. Here it is recorded, and the graceful stop begins as soon as Pingora
/// looks.
///
/// Pingora's own watcher would treat SIGQUIT as "hand the sockets to a new
/// process" and SIGINT as "stop without waiting". Neither matches Caddy's
/// signal table, which this server follows, so SIGINT, SIGTERM, and the admin
/// API's `POST /stop` all become one graceful stop.
#[cfg(unix)]
pub(crate) async fn listen_for_stop(
    admin: std::sync::Arc<tokio::sync::Notify>,
    requested: watch::Sender<bool>,
) {
    use tokio::signal::unix::{SignalKind, signal};

    let (sigterm, sigquit) = (signal(SignalKind::terminate()), signal(SignalKind::quit()));
    // 🚧 A listener that could not be installed is reported and skipped, not
    // fatal: the other ways to stop still work.
    if let Err(e) = &sigterm {
        tracing::error!("❌ Failed to create SIGTERM listener: {}", e);
    }
    if let Err(e) = &sigquit {
        tracing::error!("❌ Failed to create SIGQUIT listener: {}", e);
    }
    let term = async {
        match sigterm {
            Ok(mut stream) => stream.recv().await,
            Err(_) => std::future::pending().await,
        }
    };
    let quit = async {
        match sigquit {
            Ok(mut stream) => stream.recv().await,
            Err(_) => std::future::pending().await,
        }
    };

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("🛑 Received SIGINT, shutting down");
        }
        _ = term => {
            tracing::info!("🛑 Received SIGTERM, shutting down");
        }
        _ = quit => {
            // 🏃 Caddy exits immediately on SIGQUIT (code 2) after cleaning
            // storage locks; Pingora has no equivalent lock step, so a prompt
            // exit is the faithful behavior.
            tracing::info!("🏃 Received SIGQUIT, forced exit");
            std::process::exit(2);
        }
        _ = admin.notified() => {
            tracing::info!("🛑 Admin API requested shutdown");
        }
    }
    // 🚰 Stop being sent new traffic before anything starts going away. A load
    // balancer polling /ready gets a 503 on its next check, so the requests
    // still running are the last this instance has to finish rather than the
    // first of a fresh wave.
    pingclair_proxy::readiness::mark_draining();
    notify_systemd_stopping();
    // 🧯 The receiver lives as long as Pingora's server does; a send can only
    // fail once nothing is left to stop.
    let _ = requested.send(true);
}

/// 🛑 Hands the stop request from [`listen_for_stop`] to Pingora.
///
/// 🧵 Pingora awaits [`ShutdownSignalWatch::recv`] once, on its own
/// single-thread runtime, and begins its shutdown broadcast the moment it
/// returns.
#[cfg(unix)]
pub(crate) struct SignalWatch {
    pub(crate) requested: watch::Receiver<bool>,
}

#[cfg(unix)]
#[async_trait::async_trait]
impl ShutdownSignalWatch for SignalWatch {
    async fn recv(&self) -> ShutdownSignal {
        let mut requested = self.requested.clone();
        // 🧯 A dropped sender means the listener task is gone, so no stop can
        // ever be requested again; waiting forever is then the honest answer.
        if requested.wait_for(|stop| *stop).await.is_err() {
            std::future::pending::<()>().await;
        }
        ShutdownSignal::GracefulTerminate
    }
}

/// ⏳ Waits out the running requests once Pingora has stopped accepting, then
/// leaves through [`shutdown_and_exit`].
///
/// This is what bounds the stop by the work left rather than by a clock.
/// Pingora's own grace period is an unconditional sleep, so an idle server
/// would otherwise take the whole `grace_period` to restart; this exits the
/// process as soon as the last request is done, and Pingora's sleep only
/// matters if this task is never scheduled.
pub(crate) async fn drain_then_exit(
    mut phases: broadcast::Receiver<ExecutionPhase>,
    grace: Duration,
    l4_dns: tokio::task::JoinHandle<()>,
) -> ! {
    loop {
        match phases.recv().await {
            // 📌 Pingora publishes this phase right after its shutdown
            // broadcast, so the listeners are already closing when it arrives.
            Ok(ExecutionPhase::GracefulTerminate) => break,
            Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => continue,
            // 🧯 The server object is gone without a graceful stop; nothing
            // is left to wait for.
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
    let running = pingclair_proxy::drain::in_flight();
    if running > 0 {
        tracing::info!(
            "🚰 Waiting up to {}s for {} running request(s)",
            grace.as_secs(),
            running
        );
    }
    // 📣 Pingora's broadcast reached only the transports it owns; the drain
    // tells the HTTP/3 server to send `GOAWAY`, waits for the running
    // requests, and then has every QUIC connection still open send its close,
    // because a QUIC client is not told when a process exits and would wait
    // out its idle timeout instead.
    let stopped = pingclair_proxy::drain::stop(grace).await;
    // 🧹 The coordinator cancels DNS and joins its transport scopes before process exit.
    if let Err(error) = l4_dns.await {
        tracing::error!(%error, "🚫 L4 DNS coordinator ended unexpectedly");
    }
    // 🧼 The count reaches zero when the proxy has *handed* the response to
    // its transport, which is not the same as the bytes being on the wire:
    // an HTTP/1 response is written synchronously, while the HTTP/2 codec
    // queues frames for its connection task to flush — and TLS buffers one
    // layer more. This process exits from a different runtime, so without
    // this the connection could close with the response still in userspace
    // (#313). A shutdown that served nothing pays nothing; one that did pays
    // this bound, far below any configured grace period.
    if running > 0 {
        // 📌 An operator who set the grace period to zero asked for an
        // immediate exit, so that is what they get: the bound never outlives
        // the period it exists inside.
        tokio::time::sleep(FLUSH_BUDGET.min(grace)).await;
    }
    if stopped.cut > 0 {
        tracing::warn!(
            "⏱️ Grace period of {}s ended with {} request(s) still running; they were cut",
            grace.as_secs(),
            stopped.cut
        );
    }
    if stopped.unclosed > 0 {
        tracing::warn!(
            "🔌 {} HTTP/3 connection(s) did not send their close in time; \
             their clients will wait for an idle timeout",
            stopped.unclosed
        );
    }
    shutdown_and_exit()
}

/// 🛑 The one graceful exit: drain both log paths, then leave.
///
/// `std::process::exit` runs no destructors, so neither queue can be left to a
/// `Drop` that will never run, and both drains are bounded rather than
/// unbounded: a blocked sink must not turn shutdown into a hang. Every
/// graceful exit comes through here, so a new one cannot skip the drains by
/// accident. The forced SIGQUIT exit deliberately does not: leaving
/// immediately is the Caddy behavior it reproduces.
pub(crate) fn shutdown_and_exit() -> ! {
    // 🚿 Access records first, because the warning below travels through the
    // tracing queue and would not survive the drain that follows it.
    if !pingclair_runtime::access_log::flush_all(Duration::from_millis(250)) {
        tracing::warn!("⚠️ Access log drain exceeded the shutdown budget");
    }
    // 🚿 Then the tracing queue itself — which is where the records about this
    // shutdown live, and the reason the queue is drained rather than abandoned.
    // A drain that could not finish reports what it dropped on stderr.
    crate::logging::drain();
    std::process::exit(0);
}
