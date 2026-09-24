// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📐 A startup estimate of the file descriptors the configuration reserves.
//!
//! Every idle upstream connection kept for reuse holds a file descriptor, and
//! the keepalive pool that keeps them is not one pool: each TCP listener gets
//! its own connector, and pingora-core 0.9.0 (`ConnectorOptions::
//! from_server_conf`, read 2026-09-24) sizes that connector at the configured
//! pool size times the worker threads. Each HTTP/3 port gets another connector
//! at the plain pool size. So `:80` + `:443` + HTTP/3 on a 4-core box allows
//! 512 × 4 × 2 + 512 = 4,608 idle upstream connections, against the 1,024
//! descriptors a container usually starts with. When the pools fill, accepts
//! and upstream connects start failing with `EMFILE`, far from the cause.
//!
//! 📌 This runs once at startup, so it favours plain arithmetic over speed.
//! It only warns: a high reservation is a capacity risk the operator may have
//! sized for deliberately, not a misconfiguration (issue #33).

/// 📐 The listener shape that decides how many descriptors can stay reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DescriptorReservation {
    /// 🔁 Idle connections one connector may keep, per worker thread.
    pub(crate) pool_size: usize,
    /// 🧵 Worker threads per service; TCP connectors scale with it.
    pub(crate) worker_threads: usize,
    /// 🔌 TCP listeners, each with its own connector and listening socket.
    pub(crate) tcp_listeners: usize,
    /// 🚀 HTTP/3 ports, each with its own connector and UDP socket.
    pub(crate) h3_ports: usize,
    /// 🔧 Whether the admin API holds a listening socket.
    pub(crate) admin_listener: bool,
}

impl DescriptorReservation {
    /// 🧮 The idle upstream connections every pool together may hold.
    pub(crate) fn idle_upstream_connections(&self) -> usize {
        let per_tcp_connector = self.pool_size.saturating_mul(self.worker_threads.max(1));
        per_tcp_connector
            .saturating_mul(self.tcp_listeners)
            .saturating_add(self.pool_size.saturating_mul(self.h3_ports))
    }

    /// 🧮 The descriptors held however little traffic arrives: the listening
    /// sockets, plus the three standard streams.
    pub(crate) fn fixed_descriptors(&self) -> usize {
        3 + self.tcp_listeners + self.h3_ports + usize::from(self.admin_listener)
    }

    /// 🧮 Everything above, before a single client connection is counted.
    pub(crate) fn total(&self) -> usize {
        self.idle_upstream_connections()
            .saturating_add(self.fixed_descriptors())
    }
}

/// 🔎 The process's soft `RLIMIT_NOFILE`, or `None` when it is unlimited or
/// cannot be read.
#[cfg(unix)]
fn soft_descriptor_limit() -> Option<u64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // 🛡️ `getrlimit` only writes into the struct it is handed.
    let status = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
    (status == 0 && limit.rlim_cur != libc::RLIM_INFINITY).then_some(limit.rlim_cur)
}

/// 📌 Elsewhere there is no `RLIMIT_NOFILE` to compare against.
#[cfg(not(unix))]
fn soft_descriptor_limit() -> Option<u64> {
    None
}

/// ⚠️ Warns when the reservation alone can exhaust the descriptor limit.
pub(crate) fn warn_if_over_limit(reservation: DescriptorReservation) {
    let Some(limit) = soft_descriptor_limit() else {
        return;
    };
    let reserved = reservation.total();
    if (reserved as u64) <= limit {
        return;
    }
    tracing::warn!(
        reserved,
        limit,
        idle_upstream_connections = reservation.idle_upstream_connections(),
        pool_size = reservation.pool_size,
        worker_threads = reservation.worker_threads,
        tcp_listeners = reservation.tcp_listeners,
        h3_ports = reservation.h3_ports,
        "⚠️ Upstream keepalive pools can hold more file descriptors than RLIMIT_NOFILE allows; \
         raise the limit (ulimit -n / LimitNOFILE) or lower `upstream_keepalive_pool_size`"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🎯 The case from issue #33: `:80`, `:443`, HTTP/3, admin on, 4 threads.
    #[test]
    fn two_listeners_and_h3_reserve_past_a_container_default() {
        let reservation = DescriptorReservation {
            pool_size: 512,
            worker_threads: 4,
            tcp_listeners: 2,
            h3_ports: 1,
            admin_listener: true,
        };
        assert_eq!(
            (
                reservation.idle_upstream_connections(),
                reservation.fixed_descriptors(),
                reservation.total(),
            ),
            (512 * 4 * 2 + 512, 3 + 2 + 1 + 1, 4_608 + 7),
        );
    }

    /// 🧵 Zero configured threads still means one, as Pingora treats it.
    #[test]
    fn zero_threads_count_as_one() {
        let reservation = DescriptorReservation {
            pool_size: 100,
            worker_threads: 0,
            tcp_listeners: 1,
            h3_ports: 0,
            admin_listener: false,
        };
        assert_eq!(reservation.total(), 100 + 4);
    }
}
