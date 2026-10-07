// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌊 Two bounded buffers and one inactivity clock, driven by one task.

use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, sleep_until};

/// 🌊 Session policy compiled before any connection starts.
#[derive(Clone, Copy)]
pub struct RelayOptions {
    /// 📦 Maximum ordinary read size in each direction.
    pub buffer_size: usize,
    /// ⏱️ No successful read or write in either direction for this long ends the session.
    pub idle_timeout: Duration,
    /// 🔌 Propagates EOF independently instead of ending both directions.
    pub half_close: bool,
}

struct Direction {
    bytes: Vec<u8>,
    start: usize,
    end: usize,
    read_size: usize,
    eof: bool,
    closed: bool,
    flush: bool,
}

impl Direction {
    fn new(mut prefix: Vec<u8>, size: usize) -> io::Result<Self> {
        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero relay buffer",
            ));
        }
        let end = prefix.len();
        prefix
            .try_reserve_exact(size.saturating_sub(end))
            .map_err(io::Error::other)?;
        prefix.resize(size.max(end), 0);
        Ok(Self {
            bytes: prefix,
            start: 0,
            end,
            read_size: size,
            eof: false,
            closed: false,
            flush: false,
        })
    }

    fn drained(&self) -> bool {
        self.start == self.end && !self.flush
    }

    fn poll_io<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        read: &mut R,
        write: &mut W,
        half_close: bool,
        read_open: bool,
    ) -> io::Result<bool> {
        let mut progress = false;
        if self.start < self.end {
            match Pin::new(&mut *write).poll_write(cx, &self.bytes[self.start..self.end]) {
                Poll::Ready(Ok(0)) => return Err(io::ErrorKind::WriteZero.into()),
                Poll::Ready(Ok(n)) => {
                    self.start += n;
                    self.flush = true;
                    progress = true;
                }
                Poll::Ready(Err(error)) => return Err(error),
                Poll::Pending => {}
            }
        }
        if self.start == self.end && self.flush {
            match Pin::new(&mut *write).poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    self.flush = false;
                    progress = true;
                }
                Poll::Ready(Err(error)) => return Err(error),
                Poll::Pending => {}
            }
        }
        if self.drained() && !self.eof && read_open {
            let mut buffer = ReadBuf::new(&mut self.bytes[..self.read_size]);
            match Pin::new(read).poll_read(cx, &mut buffer) {
                Poll::Ready(Ok(())) => {
                    self.start = 0;
                    self.end = buffer.filled().len();
                    self.eof = self.end == 0;
                    progress = true;
                }
                Poll::Ready(Err(error)) => return Err(error),
                Poll::Pending => {}
            }
        }
        if self.eof && self.drained() && half_close && !self.closed {
            match Pin::new(write).poll_shutdown(cx) {
                Poll::Ready(Ok(())) => {
                    self.closed = true;
                    progress = true;
                }
                Poll::Ready(Err(error)) => return Err(error),
                Poll::Pending => {}
            }
        }
        Ok(progress)
    }
}

/// 🌊 Relays a connection, replaying the classified prefix exactly once.
///
/// 📦 Memory is bounded by the supplied prefix and two configured buffers.
/// The caller owns both sockets; cancelling this future releases both sides
/// when those owners leave scope. No lock, task, or allocation is added per I/O.
pub async fn relay<A: AsyncRead + AsyncWrite + Unpin, B: AsyncRead + AsyncWrite + Unpin>(
    downstream: &mut A,
    upstream: &mut B,
    prefix: Vec<u8>,
    options: RelayOptions,
) -> io::Result<()> {
    let mut forward = Direction::new(prefix, options.buffer_size)?;
    let mut reverse = Direction::new(Vec::new(), options.buffer_size)?;
    let deadline = || {
        Instant::now()
            .checked_add(options.idle_timeout)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "idle timeout overflow"))
    };
    let timer = sleep_until(deadline()?);
    tokio::pin!(timer);
    poll_fn(|cx| {
        // ⚖️ Cap work per poll so a continuously ready tunnel cannot monopolize its worker.
        for _ in 0..64 {
            if timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
            }
            let first = forward.poll_io(
                cx,
                downstream,
                upstream,
                options.half_close,
                options.half_close || !reverse.eof,
            )?;
            let second = reverse.poll_io(
                cx,
                upstream,
                downstream,
                options.half_close,
                options.half_close || !forward.eof,
            )?;
            let finished = if options.half_close {
                forward.closed && reverse.closed
            } else {
                (forward.eof || reverse.eof) && forward.drained() && reverse.drained()
            };
            if finished {
                return Poll::Ready(Ok(()));
            }
            if !first && !second {
                return Poll::Pending;
            }
            timer.as_mut().reset(deadline()?);
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    })
    .await
}

#[cfg(test)]
#[path = "relay_tests.rs"]
mod tests;
