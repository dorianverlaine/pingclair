// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌐 A single fair scheduler retains retired jobs until their transport tasks drain.

use super::{DnsRuntime, Failure, Pool, metrics::reason};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until};

struct Entry {
    pool: Arc<Pool>,
    next: Instant,
    last_start: Option<Instant>,
    cancel: Option<watch::Sender<bool>>,
    failures: u8,
    state: Option<Result<(), Failure>>,
    logged: Option<Instant>,
}

impl Entry {
    fn new(pool: Arc<Pool>) -> Self {
        let cancel = pool.cancel.lock().expect("DNS job cancellation").clone();
        let last_start = cancel.as_ref().map(|_| Instant::now());
        Self {
            pool,
            next: Instant::now(),
            last_start,
            cancel,
            failures: 0,
            state: None,
            logged: None,
        }
    }

    fn finish(
        &mut self,
        result: Result<super::Answer, Failure>,
        jitter: &mut u64,
    ) -> Result<(), Failure> {
        self.cancel = None;
        let result = self.pool.apply(result);
        let now = Instant::now();
        let deadline = match result {
            Ok(()) => {
                self.failures = 0;
                self.pool
                    .snapshot
                    .load()
                    .as_ref()
                    .expect("published DNS answer")
                    .fresh
            }
            Err(_) => {
                let seconds = 1u64 << self.failures.min(5);
                self.failures = self.failures.saturating_add(1);
                // 🔁 Deterministic jitter needs no entropy source or per-job RNG allocation.
                *jitter ^= *jitter << 13;
                *jitter ^= *jitter >> 7;
                *jitter ^= *jitter << 17;
                now + Duration::from_secs(seconds) + Duration::from_millis(*jitter % 1000)
            }
        };
        self.next =
            deadline.max(self.last_start.expect("started DNS job") + Duration::from_secs(1));
        if self.state != Some(result)
            && self
                .logged
                .is_none_or(|last| now.duration_since(last) >= Duration::from_secs(30))
        {
            let snapshot = self.pool.snapshot.load();
            tracing::info!(
                reason = reason(result),
                generation = snapshot.as_ref().map(|s| s.generation),
                age_seconds = snapshot.as_ref().map(|s| s.success.elapsed().as_secs()),
                "🌐 L4 DNS pool state changed"
            );
            self.logged = Some(now);
        }
        self.state = Some(result);
        result
    }
}

struct Shutdown<'a>(&'a DnsRuntime);

impl Drop for Shutdown<'_> {
    fn drop(&mut self) {
        let _publication = self.0.publication.lock().expect("DNS publication");
        for pool in self.0.active.load().iter() {
            pool.revoke();
            self.0.cancel(pool);
        }
        for binding in self.0.observers.load().iter() {
            binding.clear();
        }
    }
}

pub(super) async fn run(runtime: &DnsRuntime, stop: impl Future<Output = ()> + Send) {
    let shutdown = Shutdown(runtime);
    tokio::pin!(stop);
    let mut jobs = JoinSet::new();
    let mut entries: Vec<Entry> = Vec::new();
    let mut active = runtime.active.load_full();
    let mut cursor = 0usize;
    let mut jitter = 0x4c345f444e535f31u64;
    loop {
        let next = runtime.active.load_full();
        if !Arc::ptr_eq(&active, &next) || entries.len() != next.len() {
            entries.retain(|entry| {
                let retained = next.iter().any(|pool| Arc::ptr_eq(pool, &entry.pool));
                if !retained && let Some(cancel) = &entry.cancel {
                    let _ = cancel.send(true);
                }
                retained
            });
            for pool in next.iter() {
                if !entries.iter().any(|entry| Arc::ptr_eq(pool, &entry.pool)) {
                    entries.push(Entry::new(pool.clone()));
                }
            }
            active = next;
        }
        let metrics_deadline = runtime.metrics_deadline();
        let now = Instant::now();
        for offset in 0..entries.len() {
            let index = (cursor + offset) % entries.len();
            let entry = &mut entries[index];
            if jobs.len() == 8 {
                break;
            }
            if entry.cancel.is_none() && entry.next <= now {
                let _publication = runtime.publication.lock().expect("DNS publication");
                if !runtime
                    .active
                    .load()
                    .iter()
                    .any(|pool| Arc::ptr_eq(pool, &entry.pool))
                {
                    continue;
                }
                let (cancel, receiver) = watch::channel(false);
                *entry.pool.cancel.lock().expect("DNS job cancellation") = Some(cancel.clone());
                entry.cancel = Some(cancel);
                entry.last_start = Some(now);
                let pool = entry.pool.clone();
                jobs.spawn(async move {
                    let result = pool.resolver.lookup(receiver).await;
                    (pool, result)
                });
            }
        }
        if !entries.is_empty() {
            cursor = (cursor + 1) % entries.len();
        }
        let wake = if jobs.len() < 8 {
            entries
                .iter()
                .filter(|entry| entry.cancel.is_none())
                .map(|entry| entry.next)
                .min()
                .unwrap_or(now + Duration::from_secs(3600))
        } else {
            now + Duration::from_secs(3600)
        };
        let wake = metrics_deadline.map_or(wake, |deadline| wake.min(deadline));
        tokio::select! {
            biased;
            _ = &mut stop => break,
            _ = runtime.changed.notified() => {},
            job = jobs.join_next(), if !jobs.is_empty() => {
                match job {
                    Some(Ok((pool, result))) => {
                        let _publication = runtime.publication.lock().expect("DNS publication");
                        pool.cancel.lock().expect("DNS job cancellation").take();
                        if let Some(entry) = entries.iter_mut().find(|entry| Arc::ptr_eq(&pool, &entry.pool)) {
                            // ♻️ Publication may precede this completion event; check the current generation.
                            if runtime.active.load().iter().any(|active| Arc::ptr_eq(active, &pool)) {
                                let result = entry.finish(result, &mut jitter);
                                runtime.record_refresh(&pool, result);
                            }
                        }
                    }
                    Some(Err(error)) => {
                        tracing::error!(%error, "🚫 L4 DNS worker failed");
                        break;
                    }
                    None => {}
                }
            },
            _ = sleep_until(wake) => {},
        }
    }
    drop(shutdown);
    while let Some(result) = jobs.join_next().await {
        if let Ok((pool, _)) = result {
            pool.cancel.lock().expect("DNS job cancellation").take();
        }
    }
}
