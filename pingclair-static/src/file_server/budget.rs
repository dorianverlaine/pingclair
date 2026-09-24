// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧮 Shared admission accounting keeps route count from multiplying cache limits.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
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
