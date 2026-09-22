// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🩺 Whose fault was a failed upstream connection?
//!
//! A reverse proxy learns about its backends by failing to reach them. When a
//! connection attempt fails, the proxy takes that backend out of rotation for a
//! while, and that is exactly right — the backend just proved it cannot serve.
//!
//! But not every failed connection attempt is evidence about the backend. If
//! this process has run out of file descriptors, `socket()` fails before a
//! single packet leaves the machine. The backend is healthy, idle, and has no
//! idea anything happened. Treating that as "the backend is down" takes a
//! working backend out of rotation because *we* ran out of something.
//!
//! On a route with one backend there is nothing to fail over to, so the whole
//! route stops answering for the length of the cooldown. That turns a
//! per-request local failure into a route-wide outage, and it is measurable:
//! on 2026-08-11, at commit `4ed66ec`, **five** local `socket()` failures
//! produced **139** rejected requests, and a single probe against a completely
//! healthy backend kept returning 502 for nine seconds after the load had
//! stopped and every descriptor had been returned.
//!
//! So this module answers one question — *did the failure come from the other
//! end of the wire, or from this machine?* — in one place, for every transport
//! and every upstream kind, because the alternative is four copies that drift.
//!
//! # 🪤 Why this is not a two-line match on the obvious error types
//!
//! The error type that names the real problem **does not survive the trip**.
//! `pingora-core` 0.9.0 (`connectors/l4.rs:184`) rewrites `SocketError` and
//! `BindError` into `InternalError` before returning, so by the time the error
//! reaches `fail_to_connect` the honest name is only in the cause chain:
//!
//! ```text
//! Upstream InternalError context: Fail to connect to addr: 127.0.0.1:19000
//!   cause: SocketError context: failed to create socket
//!   cause: Too many open files (os error 24)
//! ```
//!
//! A classifier written the obvious way — `SocketError | BindError => local` —
//! compiles, reviews cleanly, ships, and never matches anything. The
//! interesting type to match is `InternalError`.

use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Which side of the wire a failed connection attempt came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureOrigin {
    /// The backend refused, timed out, was unroutable, or failed its TLS
    /// handshake. This is evidence about the backend, so it belongs in the
    /// health map and should drive failover.
    Remote,
    /// This process ran out of something: descriptors, ephemeral ports,
    /// memory, permission. No packet reached the backend, so nothing was
    /// learned about it.
    Local,
}

impl FailureOrigin {
    /// Whether a failure of this origin is evidence that the backend is
    /// unhealthy, and may therefore take it out of rotation.
    ///
    /// This is the only question callers should ask. Naming it here rather
    /// than matching on the variant at each site keeps the policy in one
    /// reviewable place — which is the whole reason this module exists.
    pub fn implicates_backend(self) -> bool {
        matches!(self, Self::Remote)
    }
}

/// 🏷️ The deepest `ErrorType` in an error's cause chain.
///
/// The top-level type is often the *wrapper*, not the problem: Pingora rewrites
/// descriptor exhaustion (`SocketError`) and ephemeral-port exhaustion
/// (`BindError`) into `InternalError` on the way out of its connector, so a
/// metric labelled with `e.etype()` reports `InternalError` for both and
/// carries no information. The two need opposite operator actions — raise
/// `nofile`, or widen `net.ipv4.ip_local_port_range` and shorten TIME_WAIT —
/// and the name that distinguishes them is one link down.
///
/// The walk stops at the first link that is not a Pingora error, which is the
/// ordinary shape: the chain ends in the `std::io::Error` that actually failed,
/// and that has no `ErrorType` to contribute.
///
/// 🪤 **Pingora chains a `BError`, and `BError` is `Box<Error>` — which is
/// itself an `Error`, so the trait object in `cause` holds a *boxed* error.**
/// Its concrete type is `Box<Error>`, and a `downcast_ref::<Error>()` against
/// it returns `None`; a walk that only tries the unboxed type stops at the
/// wrapper and reports exactly the `InternalError` this function exists to see
/// past. Both shapes are tried, because a caller that hands over an unboxed
/// error produces the other one.
///
/// 📉 Cardinality stays bounded: `ErrorType` is an enum whose only
/// string-carrying variant takes a `&'static str`, so the label is bounded by
/// this binary's own code paths rather than by traffic.
pub fn deepest_error_type(error: &pingora_core::Error) -> &pingora_core::ErrorType {
    let mut deepest = error;
    while let Some(cause) = deepest.cause.as_deref() {
        let next = cause.downcast_ref::<pingora_core::Error>().or_else(|| {
            cause
                .downcast_ref::<Box<pingora_core::Error>>()
                .map(|boxed| &**boxed)
        });
        match next {
            Some(inner) => deepest = inner,
            None => break,
        };
    }
    deepest.etype()
}

/// Classifies a failure returned by Pingora's connector.
///
/// Every local failure traced through `pingora-core` 0.9.0 arrives as
/// `InternalError`: descriptor exhaustion and `setsockopt` faults come through
/// `SocketError`, ephemeral port exhaustion through `BindError`, and both are
/// collapsed by `connectors/l4.rs:184`. `wrap_os_connect_error` adds `EACCES`
/// and `EADDRINUSE` to the same bucket, and the BoringSSL connector reports
/// local TLS *configuration* faults — an unreadable cert store, an invalid
/// client key — the same way.
///
/// Everything else names a specific remote condition, so anything unrecognised
/// stays `Remote`. That is the conservative default: it preserves the failover
/// and retry behaviour this proxy already has, and the failure mode of getting
/// it wrong is a backend that stays in rotation slightly too long, not a
/// healthy backend evicted for something that was never its fault.
pub fn classify_connect_error(error: &pingora_core::Error) -> FailureOrigin {
    use pingora_core::ErrorType;

    match error.etype() {
        // 🔥 The one that actually fires. See the module header for why the
        // two obvious names below are not enough on their own.
        ErrorType::InternalError => FailureOrigin::Local,

        // 📌 Unreachable through Pingora 0.9.0's connector, and kept anyway.
        // Verified 2026-09-10 by reading `connectors/l4.rs:184`, which rewrites
        // both into `InternalError` on the way out. If a later version stops
        // collapsing them, this arm starts carrying real traffic and the
        // classification stays correct without anyone noticing it had to.
        ErrorType::SocketError | ErrorType::BindError => FailureOrigin::Local,

        // 🌐 `ConnectError` is the connector's catch-all for an OS error it did
        // not recognise. Calling it remote is a decision, not an oversight:
        // an unknown errno is more likely to be a peculiar network condition
        // than a resource limit, and every resource limit we know of is
        // already named above.
        _ => FailureOrigin::Remote,
    }
}

/// Classifies a raw dial failure, for the FastCGI path.
///
/// FastCGI does not go through Pingora's connector — it dials the responder
/// itself — so it holds the original [`std::io::Error`] with its errno intact
/// and needs no cause-chain archaeology. The answers still have to agree with
/// [`classify_connect_error`], because an operator reading the logs cannot be
/// expected to know which upstream kind rewrote their error on the way.
pub fn classify_dial_error(error: &std::io::Error) -> FailureOrigin {
    use std::io::ErrorKind;

    match error.kind() {
        ErrorKind::ConnectionRefused
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::TimedOut
        | ErrorKind::HostUnreachable
        | ErrorKind::NetworkUnreachable
        | ErrorKind::NetworkDown => FailureOrigin::Remote,

        ErrorKind::PermissionDenied
        | ErrorKind::AddrInUse
        | ErrorKind::AddrNotAvailable
        | ErrorKind::OutOfMemory => FailureOrigin::Local,

        // 🔢 The two errnos that matter most here have no stable `ErrorKind`:
        // `EMFILE` (this process is out of descriptors) and `ENFILE` (the
        // machine is) both land in `Uncategorized`, which cannot be matched on
        // stable Rust. `ENOBUFS`/`ENOMEM` are the kernel refusing to allocate
        // for the socket, which is the same category of problem.
        _ => match error.raw_os_error() {
            Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM) => {
                FailureOrigin::Local
            }
            _ => FailureOrigin::Remote,
        },
    }
}

/// 🔇 Admits at most one log line per second, and counts what it dropped.
///
/// Descriptor exhaustion does not fail one request. It fails every request
/// that arrives while the budget is empty, which at load is thousands per
/// second. A line per failure would bury the one event an operator needs to
/// see under its own repetitions — and on a machine that has just run out of
/// descriptors, writing those lines is not free either.
///
/// Dropping them silently would be worse than either, so the suppressed count
/// rides along on the next line that does get through. An operator who sees
/// `suppressed=4812` learns something a rate of one line per second cannot
/// tell them.
pub struct FailureLogThrottle {
    /// Whole seconds since process start when a line was last admitted.
    /// `u64::MAX` means "never", which is distinguishable from second zero.
    last_admitted_secs: AtomicU64,
    suppressed: AtomicU64,
}

impl FailureLogThrottle {
    pub const fn new() -> Self {
        Self {
            last_admitted_secs: AtomicU64::new(u64::MAX),
            suppressed: AtomicU64::new(0),
        }
    }

    /// Returns `Some(suppressed_since_last_line)` when the caller should log.
    ///
    /// Takes the timestamp rather than reading the clock so the behaviour can
    /// be tested without sleeping through it.
    pub fn admit(&self, elapsed_secs: u64) -> Option<u64> {
        let last = self.last_admitted_secs.load(Ordering::Relaxed);
        let fresh_second = last == u64::MAX || elapsed_secs > last;
        // 🏁 Two threads can reach this in the same second; the compare-exchange
        // decides which one writes the line. The loser counts itself as
        // suppressed rather than retrying, because a log line is not worth a
        // contended loop on a path that is already failing.
        if !fresh_second
            || self
                .last_admitted_secs
                .compare_exchange(last, elapsed_secs, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        Some(self.suppressed.swap(0, Ordering::Relaxed))
    }

    /// [`Self::admit`] against the process clock.
    pub fn admit_now(&self) -> Option<u64> {
        static START: LazyLock<Instant> = LazyLock::new(Instant::now);
        self.admit(START.elapsed().as_secs())
    }
}

impl Default for FailureLogThrottle {
    fn default() -> Self {
        Self::new()
    }
}

/// 🧯 Shared by every site that reports a local resource failure, so the rate
/// limit is a property of the process rather than of whichever transport
/// happened to notice first.
pub static LOCAL_FAILURE_LOG: FailureLogThrottle = FailureLogThrottle::new();

#[cfg(test)]
mod tests {
    use super::*;
    use pingora_core::{Error, ErrorType};

    /// 🎯 The regression test for the trap in the module header: this is the
    /// exact error shape Pingora hands us for `EMFILE`, reproduced from the
    /// observed log line on 2026-08-11. A classifier that matched only
    /// `SocketError`/`BindError` would let this through as `Remote` — which is
    /// the bug, and it would look like a correct fix while doing it.
    #[test]
    fn descriptor_exhaustion_arrives_as_internal_error_and_reads_as_local() {
        let cause = Error::because(
            ErrorType::SocketError,
            "failed to create socket",
            std::io::Error::from_raw_os_error(libc::EMFILE),
        );
        let error = Error::because(
            ErrorType::InternalError,
            "Fail to connect to addr: 127.0.0.1:19000",
            cause,
        );

        assert_eq!(classify_connect_error(&error), FailureOrigin::Local);
        assert!(!classify_connect_error(&error).implicates_backend());
    }

    /// 🏷️ The metric label must name the condition, not the wrapper it arrived
    /// in.
    ///
    /// Both of these are `InternalError` at the top and something useful one
    /// link down — and they are the two local failures that need *different*
    /// operator actions, which is the whole point of the label. Before this,
    /// `pingclair_upstream_errors_total` reported `InternalError` for both and
    /// the `reason` label carried nothing.
    #[test]
    fn the_deepest_type_names_the_condition_that_actually_failed() {
        let exhausted_descriptors = Error::because(
            ErrorType::InternalError,
            "Fail to connect to addr: 127.0.0.1:19000",
            Error::because(
                ErrorType::SocketError,
                "failed to create socket",
                std::io::Error::from_raw_os_error(libc::EMFILE),
            ),
        );
        let exhausted_ports = Error::because(
            ErrorType::InternalError,
            "Fail to connect to addr: 127.0.0.1:19000",
            Error::because(
                ErrorType::BindError,
                "failed to bind socket",
                std::io::Error::from_raw_os_error(libc::EADDRNOTAVAIL),
            ),
        );

        // 🪤 Both wrappers say the same thing; only the chain distinguishes them.
        assert_eq!(exhausted_descriptors.etype(), &ErrorType::InternalError);
        assert_eq!(exhausted_ports.etype(), &ErrorType::InternalError);
        assert_eq!(
            deepest_error_type(&exhausted_descriptors),
            &ErrorType::SocketError
        );
        assert_eq!(deepest_error_type(&exhausted_ports), &ErrorType::BindError);
    }

    /// 🧭 With nothing to walk, the error names itself — and the walk stops at
    /// the `io::Error` that has no `ErrorType` to contribute.
    #[test]
    fn a_bare_error_names_itself() {
        let refused = Error::explain(ErrorType::ConnectRefused, "backend said no");
        assert_eq!(deepest_error_type(&refused), &ErrorType::ConnectRefused);

        let io_leaf = Error::because(
            ErrorType::SocketError,
            "failed to create socket",
            std::io::Error::from_raw_os_error(libc::EMFILE),
        );
        assert_eq!(deepest_error_type(&io_leaf), &ErrorType::SocketError);
    }

    /// A backend that refuses is still the backend's problem, and must keep
    /// driving failover exactly as it did before this module existed.
    #[test]
    fn remote_connect_failures_still_implicate_the_backend() {
        for etype in [
            ErrorType::ConnectRefused,
            ErrorType::ConnectTimedout,
            ErrorType::ConnectNoRoute,
            ErrorType::TLSHandshakeFailure,
            ErrorType::TLSHandshakeTimedout,
            ErrorType::InvalidCert,
            ErrorType::HandshakeError,
            ErrorType::ConnectError,
        ] {
            let error = Error::explain(etype.clone(), "backend said no");
            assert_eq!(
                classify_connect_error(&error),
                FailureOrigin::Remote,
                "{etype:?} must stay remote"
            );
            assert!(classify_connect_error(&error).implicates_backend());
        }
    }

    /// The arms that Pingora 0.9.0 never produces. They are kept so a future
    /// version that stops collapsing them is still classified correctly, and
    /// this test is what says so out loud.
    #[test]
    fn uncollapsed_socket_errors_would_also_read_as_local() {
        for etype in [ErrorType::SocketError, ErrorType::BindError] {
            let error = Error::explain(etype.clone(), "hypothetical future shape");
            assert_eq!(classify_connect_error(&error), FailureOrigin::Local);
        }
    }

    #[test]
    fn fastcgi_dial_errors_agree_with_the_connector_classification() {
        let local = [
            libc::EMFILE,
            libc::ENFILE,
            libc::ENOBUFS,
            libc::ENOMEM,
            libc::EACCES,
            libc::EADDRNOTAVAIL,
            libc::EADDRINUSE,
        ];
        for errno in local {
            let error = std::io::Error::from_raw_os_error(errno);
            assert_eq!(
                classify_dial_error(&error),
                FailureOrigin::Local,
                "errno {errno} must read as local"
            );
        }

        let remote = [
            libc::ECONNREFUSED,
            libc::ETIMEDOUT,
            libc::ECONNRESET,
            libc::ENETUNREACH,
            libc::EHOSTUNREACH,
            // 📁 A Unix responder whose socket is not there is the responder's
            // problem, not ours.
            libc::ENOENT,
        ];
        for errno in remote {
            let error = std::io::Error::from_raw_os_error(errno);
            assert_eq!(
                classify_dial_error(&error),
                FailureOrigin::Remote,
                "errno {errno} must read as remote"
            );
        }
    }

    #[test]
    fn throttle_admits_once_per_second_and_reports_what_it_dropped() {
        let throttle = FailureLogThrottle::new();

        // The very first failure is always worth a line.
        assert_eq!(throttle.admit(0), Some(0));
        assert_eq!(throttle.admit(0), None);
        assert_eq!(throttle.admit(0), None);

        // The next second reports the two it swallowed.
        assert_eq!(throttle.admit(1), Some(2));
        assert_eq!(throttle.admit(1), None);

        // A quiet gap does not manufacture a backlog.
        assert_eq!(throttle.admit(9), Some(1));
        assert_eq!(throttle.admit(9), None);
        assert_eq!(throttle.admit(10), Some(1));
    }

    #[test]
    fn throttle_never_admits_twice_for_the_same_second_under_contention() {
        use std::sync::Arc;

        let throttle = Arc::new(FailureLogThrottle::new());
        let admitted = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let throttle = Arc::clone(&throttle);
            let admitted = Arc::clone(&admitted);
            handles.push(std::thread::spawn(move || {
                for _ in 0..500 {
                    if throttle.admit(7).is_some() {
                        admitted.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().expect("thread joins");
        }

        assert_eq!(
            admitted.load(Ordering::Relaxed),
            1,
            "one second admits exactly one line no matter how many threads race for it"
        );
    }
}
