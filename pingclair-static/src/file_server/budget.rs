// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧮 Shared admission accounting keeps route count from multiplying cache limits.
//!
//! The limits themselves are one process-wide decision. [`CacheBudgets`] holds
//! what the caches may retain — sized from the machine's memory when the
//! runtime knows it, and never larger than the values this server has always
//! used. The runtime installs them once at startup, before the first file
//! server exists; a library user that never installs them gets the defaults.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

/// 🧮 What the static-file caches may retain, process-wide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheBudgets {
    /// 🗜️ Retained compressed bodies.
    pub compressed_bytes: usize,
    /// 📄 Retained raw bodies.
    pub content_bytes: usize,
    /// 🗂️ Retained response-metadata entries.
    pub metadata_entries: usize,
}

impl CacheBudgets {
    /// 📌 The ceilings this server has always used, and the answer when the
    /// machine's memory cannot be read.
    pub const DEFAULTS: Self = Self {
        compressed_bytes: 64 * 1024 * 1024,
        content_bytes: 16 * 1024 * 1024,
        metadata_entries: 4096,
    };

    /// 🧮 A budget set for a machine with `available` bytes to spare.
    ///
    /// The caches are a slice of the machine rather than a constant: a 4 GiB
    /// host keeps the historical ceilings, a 512 MiB container gets a
    /// sixteenth of them, and floors keep the caches working when memory is
    /// tiny. Nothing ever grows past [`CacheBudgets::DEFAULTS`] (#33).
    pub fn for_available_memory(available: Option<u64>) -> Self {
        let Some(available) = available else {
            return Self::DEFAULTS;
        };
        let share = |divisor: u64, floor: usize, ceiling: usize| {
            let share = available / divisor;
            let share = share.min(usize::MAX as u64) as usize;
            share.clamp(floor, ceiling)
        };
        Self {
            compressed_bytes: share(64, 4 * 1024 * 1024, Self::DEFAULTS.compressed_bytes),
            content_bytes: share(256, 1024 * 1024, Self::DEFAULTS.content_bytes),
            metadata_entries: share(512 * 1024, 256, Self::DEFAULTS.metadata_entries),
        }
    }
}

/// 📌 The installed budgets, if any. Set once, before the first file server.
static CONFIGURED: OnceLock<CacheBudgets> = OnceLock::new();

/// 📐 Installs the process's cache budgets; the first call wins, and later
/// calls report that they changed nothing.
pub fn configure_cache_budgets(budgets: CacheBudgets) -> bool {
    CONFIGURED.set(budgets).is_ok()
}

/// 🧮 The budgets in force: installed at startup, or the defaults.
pub(super) fn cache_budgets() -> CacheBudgets {
    *CONFIGURED.get().unwrap_or(&CacheBudgets::DEFAULTS)
}

pub(super) struct Budget {
    limit: usize,
    used: AtomicUsize,
}

impl Budget {
    pub(super) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicUsize::new(0),
        })
    }

    pub(super) fn limit(&self) -> usize {
        self.limit
    }

    pub(super) fn reserve(self: &Arc<Self>, amount: usize) -> Option<Reservation> {
        // 🧮 The counter grants capacity, not access to data; cache publication
        // supplies synchronization, so relaxed ordering is sufficient here.
        self.used
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(amount)
                    .filter(|total| *total <= self.limit)
            })
            .ok()?;
        Some(Reservation {
            budget: self.clone(),
            amount,
        })
    }
}

/// 🧹 Ownership returns capacity on eviction, replacement, or server teardown.
pub(super) struct Reservation {
    budget: Arc<Budget>,
    amount: usize,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.amount, Ordering::Relaxed);
    }
}
