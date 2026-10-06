// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🗄️ Response-cache admission and eviction stay within the configured ceiling,
//! and request Cache-Control is read across every field line.

use super::*;
use pingora_cache::eviction::{CacheEntryKey, CacheEntryKeyRef};
use pingora_cache::key::CacheKey;
use std::time::{Duration as StdDuration, SystemTime};

fn key(path: &str) -> pingora_cache::key::CompactCacheKey {
    CacheKey::new(crate::cache_key::primary(&[0; 16], "example.com", path), "").to_compact()
}

fn entry(path: &str) -> CacheEntryKey {
    CacheEntryKey::key_only(key(path))
}

fn fresh() -> SystemTime {
    SystemTime::now() + StdDuration::from_secs(3600)
}

/// 🚫 Only directive names request a bypass; values and extension names
/// must not turn an otherwise reusable response into an origin request.
#[test]
fn request_cache_control_matches_directive_names_across_field_lines() {
    let mut headers = http::HeaderMap::new();
    headers.append(
        "cache-control",
        "max-age=0, X-No-Cache-Foo".parse().unwrap(),
    );
    assert!(!request_cache_control_bypasses_cache(&headers));

    headers.append("cache-control", "  NO-StOrE  ".parse().unwrap());
    assert!(request_cache_control_bypasses_cache(&headers));

    headers.clear();
    headers.append("cache-control", "max-age=0".parse().unwrap());
    headers.append("cache-control", " No-CaChE=\"field\" ".parse().unwrap());
    assert!(request_cache_control_bypasses_cache(&headers));

    headers.clear();
    headers.append("cache-control", "extension=\"no-store\"".parse().unwrap());
    assert!(!request_cache_control_bypasses_cache(&headers));
}

/// 📏 The ceiling has to actually evict, not merely be recorded.
///
/// This is the completion test for the cache-limit work: before it, the
/// shared store had no ceiling at all and a route with `cache` enabled grew
/// the process until the machine ran out of memory. Asserting that the
/// limit *is configured* would prove nothing — the previous code also had
/// a number, in a comment.
#[test]
fn admitting_past_the_ceiling_evicts_the_least_recently_used() {
    let manager = simple_lru::Manager::new(300);

    assert!(
        manager.admit(entry("/a"), 100, fresh()).is_empty(),
        "the first entry fits under the ceiling"
    );
    assert!(manager.admit(entry("/b"), 100, fresh()).is_empty());
    assert!(manager.admit(entry("/c"), 100, fresh()).is_empty());
    assert_eq!(manager.total_size(), 300, "the store is exactly full");

    // 🧹 One more entry cannot fit, so something has to go — and it must be
    // the oldest, or the cache is evicting whatever it happens to reach
    // rather than what is least useful.
    let evicted = manager.admit(entry("/d"), 100, fresh());
    assert_eq!(
        evicted,
        vec![entry("/a")],
        "the oldest entry is the one dropped"
    );
    assert!(
        manager.total_size() <= 300,
        "the ceiling held: {} bytes stored against a 300-byte limit",
        manager.total_size()
    );
    assert_eq!(
        manager.evicted_size(),
        100,
        "the reclaimed bytes are counted"
    );
}

/// 🔥 A single response larger than the whole ceiling must not be allowed to
/// blow past it. This is the case that turns "bounded" back into
/// "unbounded" if the accounting only checks on admission of small items.
#[test]
fn an_entry_larger_than_the_ceiling_does_not_exceed_it() {
    let manager = simple_lru::Manager::new(300);
    manager.admit(entry("/small"), 50, fresh());
    manager.admit(entry("/huge"), 10_000, fresh());
    assert!(
        manager.total_size() <= 10_000,
        "an oversized entry must not accumulate on top of the existing ones"
    );
}

/// 🧮 Purging has to tell the eviction manager, or the size accounting
/// drifts upward forever and the ceiling starts evicting entries that were
/// already gone.
#[test]
fn removing_an_entry_returns_its_bytes_to_the_budget() {
    let manager = simple_lru::Manager::new(300);
    manager.admit(entry("/a"), 100, fresh());
    manager.admit(entry("/b"), 100, fresh());
    assert_eq!(manager.total_size(), 200);

    let key = key("/a");
    manager.remove(CacheEntryKeyRef::from_entry_id(&key, None));
    assert_eq!(
        manager.total_size(),
        100,
        "the purged entry's bytes are available again"
    );
}
