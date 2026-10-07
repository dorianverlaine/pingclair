// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧪 Independent servers must compete for capacity and return it on teardown.

use super::*;
use std::sync::Barrier;

fn key(name: &str) -> FileKey {
    FileKey {
        path: PathBuf::from(name),
        mtime_ns: 1,
        encoding: "",
        body_len: 1,
    }
}

fn assert_body_budget(compressed: bool) {
    let first = FileServer::new(FileServerConfig::default());
    let second = FileServer::new(FileServerConfig::default());
    let budgets = super::budget::cache_budgets();
    let (first_cache, second_cache, limit) = if compressed {
        (
            &first.compress_cache,
            &second.compress_cache,
            budgets.compressed_bytes,
        )
    } else {
        (
            &first.content_cache,
            &second.content_cache,
            budgets.content_bytes,
        )
    };
    let size = limit * 3 / 4;
    let body = Bytes::from(vec![7; size]);
    first_cache
        .lock()
        .unwrap()
        .insert(key("first"), body.clone());
    second_cache
        .lock()
        .unwrap()
        .insert(key("second"), body.clone());
    assert_eq!(
        first_cache
            .lock()
            .unwrap()
            .get(&key("first"))
            .map(|b| b.len()),
        Some(size)
    );
    assert!(second_cache.lock().unwrap().get(&key("second")).is_none());
    drop(first);
    second_cache.lock().unwrap().insert(key("second"), body);
    assert_eq!(
        second_cache
            .lock()
            .unwrap()
            .get(&key("second"))
            .map(|b| b.len()),
        Some(size)
    );
}

#[test]
fn content_budget_is_shared_across_servers() {
    assert_body_budget(false);
}

#[test]
fn compressed_budget_is_shared_across_servers() {
    assert_body_budget(true);
}

#[test]
fn metadata_budget_is_shared_and_readers_keep_their_slots() {
    let first = FileServer::new(FileServerConfig::default());
    let second = FileServer::new(FileServerConfig::default());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.txt");
    std::fs::write(&path, b"test").unwrap();
    let metadata = std::fs::metadata(&path).unwrap();
    let mut readers = Vec::new();
    for i in 0..super::budget::cache_budgets().metadata_entries {
        readers.push(
            first
                .file_meta(&dir.path().join(format!("{i}.txt")), &metadata)
                .unwrap(),
        );
    }
    let uncached = second.file_meta(&path, &metadata).unwrap();
    assert!(second.meta_cache.load().is_empty());
    drop(first);
    second.file_meta(&path, &metadata).unwrap();
    assert!(
        second.meta_cache.load().is_empty(),
        "readers still own all slots"
    );
    drop(readers);
    let cached = second.file_meta(&path, &metadata).unwrap();
    assert!(!Arc::ptr_eq(&uncached, &cached));
    assert!(Arc::ptr_eq(
        &cached,
        &second.file_meta(&path, &metadata).unwrap()
    ));
}

/// 🧮 A machine's memory sizes the caches without ever growing them.
#[test]
fn cache_budgets_follow_the_machines_memory_up_to_the_ceilings() {
    // 🫥 Nothing known: the values this server has always used.
    assert_eq!(
        CacheBudgets::for_available_memory(None),
        CacheBudgets::DEFAULTS
    );

    // 💻 A laptop or small server: exactly the ceilings.
    assert_eq!(
        CacheBudgets::for_available_memory(Some(4 * 1024 * 1024 * 1024)),
        CacheBudgets::DEFAULTS
    );

    // 📦 A large container: still the ceilings, never more.
    assert_eq!(
        CacheBudgets::for_available_memory(Some(64 * 1024 * 1024 * 1024)),
        CacheBudgets::DEFAULTS
    );

    // 🧯 A 512 MiB container: a sixteenth of the ceilings.
    assert_eq!(
        CacheBudgets::for_available_memory(Some(512 * 1024 * 1024)),
        CacheBudgets {
            compressed_bytes: 8 * 1024 * 1024,
            content_bytes: 2 * 1024 * 1024,
            metadata_entries: 1024,
        }
    );

    // 🪫 A tiny one still gets working caches, not zero.
    assert_eq!(
        CacheBudgets::for_available_memory(Some(64 * 1024 * 1024)),
        CacheBudgets {
            compressed_bytes: 4 * 1024 * 1024,
            content_bytes: 1024 * 1024,
            metadata_entries: 256,
        }
    );
}

#[test]
fn concurrent_admission_cannot_overbook_and_drop_returns_capacity() {
    let budget = Budget::new(7);
    let barrier = Barrier::new(16);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..16)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    let reservation = budget.reserve(1);
                    barrier.wait();
                    reservation
                })
            })
            .collect();
        let reservations: Vec<_> = handles
            .into_iter()
            .filter_map(|h| h.join().unwrap())
            .collect();
        assert_eq!(reservations.len(), 7);
        assert!(budget.reserve(1).is_none());
    });
    assert!(budget.reserve(7).is_some());
    assert!(budget.reserve(usize::MAX).is_none());
}

#[test]
fn replacement_and_eviction_return_body_capacity() {
    let budget = Budget::new(10);
    let mut first = BodyCache::new(budget.clone());
    let mut second = BodyCache::new(budget);
    first.insert(key("a"), Bytes::from_static(b"12345678"));
    first.insert(key("a"), Bytes::from_static(b"12"));
    second.insert(key("b"), Bytes::from_static(b"12345678"));
    assert_eq!(second.get(&key("b")).unwrap().len(), 8);
    first.insert(key("c"), Bytes::from_static(b"123"));
    assert!(first.get(&key("a")).is_none());
    assert!(first.get(&key("c")).is_none());
    drop(second);
    first.insert(key("c"), Bytes::from_static(b"1234567890"));
    assert_eq!(first.get(&key("c")).unwrap().len(), 10);
}
