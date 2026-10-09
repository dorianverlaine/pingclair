// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔁 Bounded address selection and connection-only fallback.

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::time::{Instant, timeout_at};

#[path = "upstream/alerts.rs"]
mod alerts;

pub(crate) struct Upstream {
    addresses: Box<[SocketAddr]>,
    cursor: AtomicUsize,
}

impl Upstream {
    /// 🌐 Resolves once and bounds the compiled pool before publishing a route.
    pub fn prepare(address: &str) -> io::Result<Self> {
        Self::from_addresses(address.to_socket_addrs()?)
    }

    fn from_addresses(addresses: impl IntoIterator<Item = SocketAddr>) -> io::Result<Self> {
        let mut unique = Vec::new();
        for address in addresses {
            if unique.contains(&address) {
                continue;
            }
            if unique.len() == 64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "L4 upstream exceeds 64 addresses",
                ));
            }
            unique.push(address);
        }
        if unique.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "L4 upstream resolved to no addresses",
            ));
        }
        // 🔁 Stable ordering keeps the compiled pool deterministic across DNS answer permutations.
        unique.sort_unstable();
        Ok(Self {
            addresses: unique.into_boxed_slice(),
            cursor: AtomicUsize::new(0),
        })
    }

    /// 🔌 Returns at TCP establishment; relay errors never re-enter address selection.
    pub(crate) async fn connect_with<F, Fut, T>(&self, budget: Duration, dial: F) -> io::Result<T>
    where
        F: FnMut(SocketAddr) -> Fut,
        Fut: Future<Output = io::Result<T>>,
    {
        connect_with(&self.addresses, &self.cursor, budget, || true, dial).await
    }
}

/// 🔁 Both sources share connection-only fallback and the same total deadline.
pub(crate) async fn connect_with<F, Fut, T>(
    addresses: &[SocketAddr],
    cursor: &AtomicUsize,
    budget: Duration,
    available: impl Fn() -> bool,
    mut dial: F,
) -> io::Result<T>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    if addresses.is_empty() {
        return Err(io::ErrorKind::AddrNotAvailable.into());
    }
    let deadline = Instant::now() + budget;
    let count = addresses.len();
    // ⚡ A single upstream avoids shared cursor contention and keeps its original timeout.
    let start = if count == 1 {
        0
    } else {
        cursor.fetch_add(1, Ordering::Relaxed) % count
    };
    let attempt_budget = if count == 1 {
        budget
    } else {
        budget.min(Duration::from_secs(2))
    };
    let mut last = io::ErrorKind::TimedOut.into();
    for offset in 0..count.min(4) {
        if !available() {
            return Err(io::ErrorKind::AddrNotAvailable.into());
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let attempt_deadline = deadline.min(now + attempt_budget);
        match timeout_at(attempt_deadline, dial(addresses[(start + offset) % count])).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => {
                // 🛡️ Unknown or local resource errors must not amplify into more socket attempts.
                if !matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::NetworkUnreachable
                        | io::ErrorKind::HostUnreachable
                ) {
                    alerts::warn_if_local(&error);
                    return Err(error);
                }
                last = error;
            }
            Err(_) => last = io::ErrorKind::TimedOut.into(),
        }
    }
    Err(last)
}

#[cfg(test)]
#[path = "upstream_tests.rs"]
mod tests;
