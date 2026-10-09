// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚦 One process-wide warning window for failed local dial resources.

use std::io;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Limiter(AtomicU64);

impl Limiter {
    fn claim(&self, elapsed: Duration) -> bool {
        // ⏱️ Zero means no warning yet; timestamps use a monotonic process-relative clock.
        let now = u64::try_from(elapsed.as_millis())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let previous = self.0.load(Ordering::Relaxed);
        (previous == 0 || now.saturating_sub(previous) >= 30_000)
            && self
                .0
                .compare_exchange(previous, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
    }
}

static ALERTS: LazyLock<(Instant, Limiter)> =
    LazyLock::new(|| (Instant::now(), Limiter::default()));

fn reason(error: &io::Error) -> Option<&'static str> {
    #[cfg(unix)]
    match error.raw_os_error() {
        Some(libc::EMFILE | libc::ENFILE) => return Some("descriptor_limit"),
        Some(libc::ENOMEM | libc::ENOBUFS) => return Some("memory_or_buffers"),
        _ => {}
    }
    match error.kind() {
        io::ErrorKind::OutOfMemory => Some("memory_or_buffers"),
        io::ErrorKind::AddrNotAvailable => Some("local_address_unavailable"),
        _ => None,
    }
}

pub(super) fn warn_if_local(error: &io::Error) {
    let Some(reason) = reason(error) else {
        return;
    };
    let (start, limiter) = &*ALERTS;
    if limiter.claim(start.elapsed()) {
        tracing::warn!(
            reason,
            errno = error.raw_os_error(),
            "🚫 L4 upstream dial exhausted local resources"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn concurrent_errors_share_one_warning_window_and_later_errors_can_warn_again() {
        let limiter = Limiter::default();
        let granted = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..32 {
                scope.spawn(|| {
                    if limiter.claim(Duration::ZERO) {
                        granted.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(granted.load(Ordering::Relaxed), 1);
        assert!(!limiter.claim(Duration::from_millis(29_999)));
        assert!(limiter.claim(Duration::from_secs(30)));
        assert!(!limiter.claim(Duration::from_secs(30)));
        assert!(limiter.claim(Duration::from_secs(60)));
    }
}
