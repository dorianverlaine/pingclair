// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌐 Immutable address snapshots and one bounded DNS coordinator across reloads.

mod policy;
mod resolver;
mod tasks;

use arc_swap::{ArcSwap, ArcSwapOption};
use pingclair_core::config::Layer4Dns;
use policy::Policy;
use resolver::{Answer, Failure, Resolver};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::Instant;

mod coordinator;

pub(super) struct Snapshot {
    addresses: Box<[SocketAddr]>,
    generation: u64,
    success: Instant,
    fresh: Instant,
    hard: Instant,
}

pub(super) struct Pool {
    config: Layer4Dns,
    own: Vec<SocketAddr>,
    resolver: Resolver,
    policy: Policy,
    snapshot: ArcSwapOption<Snapshot>,
    epoch: AtomicU64,
    next_generation: AtomicU64,
    cursor: AtomicUsize,
    cancel: Mutex<Option<tokio::sync::watch::Sender<bool>>>,
}

impl Pool {
    fn revoke(&self) {
        self.snapshot.store(None);
        self.epoch.fetch_add(1, Ordering::AcqRel);
    }

    fn apply(&self, result: Result<Answer, Failure>) -> Result<(), Failure> {
        match result {
            Ok(answer) => {
                if answer
                    .addresses
                    .iter()
                    .any(|address| !self.policy.permits(*address))
                {
                    self.revoke();
                    return Err(Failure::Invalid);
                }
                let success = Instant::now();
                let fresh = self
                    .config
                    .valid_ms
                    .map_or(answer.fresh, |valid| success + Duration::from_millis(valid));
                self.snapshot.store(Some(Arc::new(Snapshot {
                    addresses: answer.addresses.into_boxed_slice(),
                    generation: self.next_generation.fetch_add(1, Ordering::Relaxed),
                    success,
                    fresh,
                    hard: fresh + Duration::from_millis(self.config.stale_ms),
                })));
                Ok(())
            }
            Err(failure) => {
                match failure {
                    Failure::Empty | Failure::NxDomain | Failure::Invalid | Failure::Cancelled => {
                        self.revoke()
                    }
                    Failure::Transient | Failure::Timeout => {}
                }
                Err(failure)
            }
        }
    }

    fn available(&self, epoch: u64, hard: Instant) -> bool {
        Instant::now() < hard && self.epoch.load(Ordering::Acquire) == epoch
    }
}

/// 🌐 One compiled source; cloning shares the cursor and immutable snapshot.
#[derive(Clone)]
pub(crate) struct Source(Arc<Pool>);

impl Source {
    pub async fn connect(&self, budget: Duration) -> io::Result<tokio::net::TcpStream> {
        self.connect_with(budget, tokio::net::TcpStream::connect)
            .await
    }

    async fn connect_with<F, Fut, T>(&self, budget: Duration, dial: F) -> io::Result<T>
    where
        F: FnMut(SocketAddr) -> Fut,
        Fut: Future<Output = io::Result<T>>,
    {
        let epoch = self.0.epoch.load(Ordering::Acquire);
        // ⚡ One owned snapshot per connection; relay retains neither the pool nor its addresses.
        let snapshot = self
            .0
            .snapshot
            .load_full()
            .ok_or(io::ErrorKind::AddrNotAvailable)?;
        crate::upstream::connect_with(
            &snapshot.addresses,
            &self.0.cursor,
            budget,
            || self.0.available(epoch, snapshot.hard),
            dial,
        )
        .await
    }
}

/// 🏗️ A draft pool set. Preparing it cannot activate DNS or mutate published snapshots.
pub struct DnsPreparation {
    previous: Arc<Vec<Arc<Pool>>>,
    pools: Vec<Arc<Pool>>,
    own: Vec<SocketAddr>,
}

impl DnsPreparation {
    pub(crate) fn source(&mut self, config: &Layer4Dns) -> io::Result<Source> {
        if let Some(pool) = self.pools.iter().find(|pool| pool.config == *config) {
            return Ok(Source(pool.clone()));
        }
        if self.pools.len() == 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "L4 exceeds 256 dynamic pools",
            ));
        }
        let resolver = Resolver::prepare(config)?;
        if let Some(pool) = self.previous.iter().find(|pool| {
            pool.config == *config
                && pool.own == self.own
                && pool.resolver.endpoints == resolver.endpoints
        }) {
            self.pools.push(pool.clone());
            return Ok(Source(pool.clone()));
        }
        let policy = Policy::prepare(config.allow_ip.as_deref(), &self.own)?;
        let pool = Arc::new(Pool {
            config: config.clone(),
            own: self.own.clone(),
            resolver,
            policy,
            snapshot: ArcSwapOption::empty(),
            epoch: AtomicU64::new(0),
            next_generation: AtomicU64::new(1),
            cursor: AtomicUsize::new(0),
            cancel: Mutex::new(None),
        });
        self.pools.push(pool.clone());
        Ok(Source(pool))
    }
}

/// 🌐 Process-owned DNS state. The executable starts exactly one coordinator.
#[derive(Default)]
pub struct DnsRuntime {
    active: ArcSwap<Vec<Arc<Pool>>>,
    changed: Notify,
    started: AtomicBool,
    publication: Mutex<()>,
}

impl DnsRuntime {
    /// 🏗️ Captures the current pool set and all known local listener destinations.
    pub fn prepare(&self, mut own: Vec<SocketAddr>) -> DnsPreparation {
        for address in &mut own {
            *address = SocketAddr::new(address.ip().to_canonical(), address.port());
        }
        own.sort_unstable();
        own.dedup();
        DnsPreparation {
            previous: self.active.load_full(),
            pools: Vec::new(),
            own,
        }
    }

    /// ♻️ Activates a validated draft and immediately revokes removed pools.
    pub fn publish(&self, next: DnsPreparation) {
        let _publication = self.publication.lock().expect("DNS publication");
        let next = Arc::new(next.pools);
        let previous = self.active.swap(next.clone());
        for pool in previous
            .iter()
            .filter(|pool| !next.iter().any(|new| Arc::ptr_eq(pool, new)))
        {
            pool.revoke();
            if let Some(cancel) = pool.cancel.lock().expect("DNS job cancellation").as_ref() {
                let _ = cancel.send(true);
            }
        }
        self.changed.notify_one();
    }

    /// 🧹 Stops scheduling on shutdown and joins every retired DNS transport worker.
    /// One invocation is allowed over this runtime's lifetime, including cancellation.
    pub async fn run(&self, stop: impl Future<Output = ()> + Send) {
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        coordinator::run(self, stop).await;
    }
}

#[cfg(test)]
mod tests;
