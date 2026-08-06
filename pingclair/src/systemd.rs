// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📣 The two sentences this process says to systemd, and nothing else.
//!
//! The whole protocol is one datagram to one socket named by `NOTIFY_SOCKET`,
//! which is why this is hand-written rather than a dependency: the crate would
//! be larger than the code. When the variable is unset — every other init
//! system, every local run, every platform that is not Linux — the functions
//! do nothing at all, so callers never have to ask where they are running.

/// 📣 Tells systemd this unit has finished starting.
///
/// Written by hand against the `sd_notify` protocol rather than pulling in a
/// crate: the protocol is one datagram to one socket, and the dependency would
/// be larger than the code. `NOTIFY_SOCKET` is unset unless the unit declares
/// `Type=notify`, so on every other platform and every other launch method
/// this is a no-op.
///
/// **Why it matters**: with `Type=simple` systemd considers the unit started
/// the moment the process is forked, so anything ordered `After=pingclair`
/// races against the listeners being bound. With `Type=notify` the unit is not
/// started until this datagram arrives — which happens after the listeners are
/// added, not after the config is parsed.
#[cfg(unix)]
fn notify_systemd(state: &str) {
    use std::os::unix::net::UnixDatagram;

    let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") else {
        return;
    };
    if socket_path.is_empty() {
        return;
    }
    // 🔌 A leading `@` means an abstract socket, which Rust spells with a NUL.
    let addr = if let Some(rest) = socket_path.strip_prefix('@') {
        format!("\0{rest}")
    } else {
        socket_path
    };

    match UnixDatagram::unbound().and_then(|socket| socket.send_to(state.as_bytes(), &addr)) {
        Ok(_) => tracing::debug!(state = %state, "📣 Notified systemd"),
        // 🚫 Never fatal. Failing to talk to systemd is not a reason to refuse
        // to serve traffic; the worst case is a unit that looks slower to
        // start than it is.
        Err(error) => tracing::debug!(error = %error, "📣 Could not notify systemd"),
    }
}

#[cfg(not(unix))]
fn notify_systemd(_state: &str) {}

pub(crate) fn notify_systemd_ready() {
    notify_systemd("READY=1\nSTATUS=Serving\n");
}

pub(crate) fn notify_systemd_stopping() {
    notify_systemd("STOPPING=1\nSTATUS=Draining\n");
}
