// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📊 A shared registry and collection switch for all transports.

use prometheus::Registry;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// 📚 Transports register their own collectors in this process-wide registry.
pub static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);
static ENABLED: AtomicBool = AtomicBool::new(false);

/// 🔁 Publishes whether the current configuration enables collection.
pub fn configure(enabled: bool) {
    ENABLED.store(enabled, Ordering::Release);
}

/// 🍃 Lets connection and request paths skip disabled metric collection.
#[inline]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}
