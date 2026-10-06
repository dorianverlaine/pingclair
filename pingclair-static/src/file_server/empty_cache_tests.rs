// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧮 Empty bodies still retain keys and LRU nodes across routes.

use super::budget::Budget;
use super::{BodyCache, FileKey};
use bytes::Bytes;
use std::path::PathBuf;

#[test]
fn empty_bodies_share_a_process_wide_entry_ceiling() {
    let mut first = BodyCache::new(Budget::new(1024));
    let mut second = BodyCache::new(Budget::new(1024));
    for index in 0..20_000 {
        let key = FileKey {
            path: PathBuf::from(format!("/empty-{index}")),
            mtime_ns: index,
            encoding: "",
            body_len: 0,
        };
        let cache = if index < 10_000 {
            &mut first
        } else {
            &mut second
        };
        cache.insert(key, Bytes::new());
    }
    assert!(
        first.entries.len() + second.entries.len() <= 16_384,
        "zero-byte bodies must pay for their retained entries"
    );
    assert!(
        !second.entries.is_empty(),
        "the cap must evict rather than disable empty-file caching"
    );
    drop(first);
    for index in 20_000..30_000 {
        second.insert(
            FileKey {
                path: PathBuf::from(format!("/empty-{index}")),
                mtime_ns: index,
                encoding: "",
                body_len: 0,
            },
            Bytes::new(),
        );
    }
    assert!(second.entries.len() <= 16_384);
    assert!(
        second.entries.len() > 10_000,
        "teardown must return shared slots"
    );
}
