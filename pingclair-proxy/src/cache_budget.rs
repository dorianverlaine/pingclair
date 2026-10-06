// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧮 One configuration-owned ceiling governs the process response store.

use pingclair_core::config::{HandlerConfig, ServerConfig};
use pingora_cache::eviction::{EvictionManager, lru};
use pingora_cache::storage::{PurgeTarget, PurgeType, Storage};
use std::sync::OnceLock;

pub(crate) static CACHE_EVICTION: OnceLock<lru::Manager<1>> = OnceLock::new();

/// 🧮 Publishes the ceiling that validation requires every caching route to share.
pub(crate) fn configure(servers: &[ServerConfig]) {
    fn limit(handler: &HandlerConfig) -> Option<usize> {
        match handler {
            HandlerConfig::ReverseProxy(proxy) if proxy.subrequest.is_none() => {
                proxy.cache.as_ref().map(|cache| cache.max_size_bytes)
            }
            HandlerConfig::Pipeline { handlers }
            | HandlerConfig::FirstMatch { handlers }
            | HandlerConfig::HandlePath { handlers, .. } => handlers
                .iter()
                .filter_map(|handler| limit(&handler.handler))
                .min(),
            _ => None,
        }
    }
    let limit = servers
        .iter()
        .flat_map(|server| &server.routes)
        .filter_map(|route| limit(&route.handler))
        .min();
    if limit.is_none() && CACHE_EVICTION.get().is_none() {
        return;
    }
    let limit = limit.unwrap_or(0);
    let manager = CACHE_EVICTION.get_or_init(|| lru::Manager::with_capacity(limit, 128));
    manager.set_weight_limit(limit);
    crate::metrics::CACHE_LIMIT_BYTES.set(limit as i64);
    // ♻️ Enforce a shrink now, even if every subsequent request is a cache hit.
    // 🧮 Pingora 0.9.0's lru::Manager exposes resizing but evicts on admission;
    // a zero-weight adjustment of an existing entry runs that eviction without a new key.
    if manager.total_size() > limit
        && let Some(key) = manager.peek_lru(0)
    {
        let evicted = manager.increment_weight(&key, 0, None);
        for entry in evicted {
            // 🧹 MemCache::purge contains no suspension; this config-only drain
            // can run synchronously without entering or blocking a Tokio runtime.
            futures::executor::block_on(Storage::purge(
                super::server::response_cache_storage(),
                PurgeTarget::Exact(&entry),
                PurgeType::Eviction,
                &pingora_cache::trace::Span::inactive().handle(),
            ))
            .expect("in-memory cache eviction is infallible");
        }
    }
    crate::metrics::CACHE_SIZE_BYTES.set(manager.total_size() as i64);
}
