// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧾 Cancellation-safe session accounting at the successful I/O boundary.

use crate::metrics::Metrics;
use prometheus::IntCounter;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

#[derive(Clone, Copy)]
pub(crate) enum Outcome {
    Completed,
    Blocked,
    PrereadEof,
    PrereadTimeout,
    PrereadOverflow,
    PrereadError,
    NoRoute,
    ConnectTimeout,
    ConnectError,
    RelayTimeout,
    RelayError,
    Cancelled,
}

impl Outcome {
    pub const ALL: [Self; 12] = [
        Self::Completed,
        Self::Blocked,
        Self::PrereadEof,
        Self::PrereadTimeout,
        Self::PrereadOverflow,
        Self::PrereadError,
        Self::NoRoute,
        Self::ConnectTimeout,
        Self::ConnectError,
        Self::RelayTimeout,
        Self::RelayError,
        Self::Cancelled,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Blocked => "blocked",
            Self::PrereadEof => "preread_eof",
            Self::PrereadTimeout => "preread_timeout",
            Self::PrereadOverflow => "preread_overflow",
            Self::PrereadError => "preread_error",
            Self::NoRoute => "no_route",
            Self::ConnectTimeout => "connect_timeout",
            Self::ConnectError => "connect_error",
            Self::RelayTimeout => "relay_timeout",
            Self::RelayError => "relay_error",
            Self::Cancelled => "cancelled",
        }
    }
}

pub(crate) enum Phase {
    Admission,
    Preread,
    Routing,
    Connect,
    Relay,
}

#[derive(Default)]
pub(crate) struct IoStats {
    pub read: u64,
    pub written: u64,
}

pub(crate) struct Observation<'a> {
    pub metrics: Option<&'a Metrics>,
    pub started: Instant,
    pub route: Option<usize>,
    pub phase: Phase,
    pub outcome: Option<Outcome>,
    pub downstream: IoStats,
    pub upstream: IoStats,
}

impl<'a> Observation<'a> {
    pub fn new(metrics: &'a Metrics) -> Self {
        // 🔁 Capture collection policy once so a reload cannot unbalance the active gauge.
        let metrics = pingclair_runtime::metrics::enabled().then_some(metrics);
        if let Some(metrics) = metrics {
            metrics.active.inc();
        }
        Self {
            metrics,
            started: Instant::now(),
            route: None,
            phase: Phase::Admission,
            outcome: None,
            downstream: IoStats::default(),
            upstream: IoStats::default(),
        }
    }
    pub fn finish(&mut self, result: &io::Result<()>) {
        if self.outcome.is_some() {
            return;
        }
        let timeout = result
            .as_ref()
            .is_err_and(|e| e.kind() == io::ErrorKind::TimedOut);
        self.outcome = Some(match result {
            Ok(()) => Outcome::Completed,
            Err(_) => match self.phase {
                Phase::Admission => Outcome::Blocked,
                Phase::Preread if timeout => Outcome::PrereadTimeout,
                Phase::Preread => Outcome::PrereadError,
                Phase::Routing => Outcome::NoRoute,
                Phase::Connect if timeout => Outcome::ConnectTimeout,
                Phase::Connect => Outcome::ConnectError,
                Phase::Relay if timeout => Outcome::RelayTimeout,
                Phase::Relay => Outcome::RelayError,
            },
        });
    }
}

impl Drop for Observation<'_> {
    fn drop(&mut self) {
        if let Some(metrics) = self.metrics {
            metrics.finish(
                self.route,
                self.outcome.unwrap_or(Outcome::Cancelled),
                self.started.elapsed().as_secs_f64(),
            );
        }
    }
}

pub(crate) struct Counted<'a, S> {
    pub inner: S,
    pub stats: &'a mut IoStats,
    pub written: Option<&'a IntCounter>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<'_, S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buffer);
        this.stats.read = this
            .stats
            .read
            .saturating_add((buffer.filled().len() - before) as u64);
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<'_, S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buffer);
        if let Poll::Ready(Ok(written)) = result {
            this.stats.written = this.stats.written.saturating_add(written as u64);
            if let Some(counter) = this.written {
                counter.inc_by(written as u64);
            }
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "observation_tests.rs"]
mod tests;
