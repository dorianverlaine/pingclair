// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔑 How a stored response is addressed in the shared cache.
//!
//! There is one cache store per process, so the key alone decides which
//! requests may be answered by which stored response. Host and URL are not
//! enough: two routes can serve the same URL from different upstreams — an
//! internal view guarded by `client_ip` and a public one, say — and a key that
//! cannot tell them apart serves whichever filled the entry first to both.
//!
//! So every key starts with the route's *scope*: a 16-byte digest of the whole
//! site configuration the route belongs to — names, listeners, site-level
//! `vars` and every route — and the route's position in it. Anything in the
//! site can change what the route sends upstream (`header_up
//! {http.vars.tenant}`), so all of it counts. It is computed once per
//! configuration load, so the request path only copies 16 bytes. A reload
//! that leaves a site unchanged keeps its warm entries; one that changes
//! anything in the site starts it cold, and the old entries age out of the LRU
//! because nothing can address them any more.
//!
//! A route whose dial is a placeholder adds one more step per request: the
//! upstream the dial resolves to becomes part of the entry's variant
//! ([`upstream_digest`], [`with_variance`]), because one route can then reach
//! several upstreams. A variant rather than the primary key, so a purge by URL
//! still reaches every upstream's copy.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use pingclair_core::config::{RouteConfig, ServerConfig};

use crate::upstream::UpstreamSpec;
use pingora_cache::key::{HashBinary, hash_key};
use serde::Serialize;

/// 🔑 The digest that separates one caching route's entries from every other's.
pub(crate) type CacheScope = HashBinary;

/// 🧾 Everything that makes one route's cached answer differ from another's.
///
/// Serialized only to be hashed. The configuration holds its maps as
/// `BTreeMap`s, so the same configuration always produces the same bytes and
/// therefore the same scope across reloads.
#[derive(Serialize)]
struct ScopeIdentity<'a> {
    site: &'a ServerConfig,
    route_index: usize,
}

/// 🔑 Computes the scope of each route in `config` that caches, parallel to
/// `config.routes`, and records it for [`known_scopes`].
///
/// 📌 Runs at configuration load, not per request, so it optimizes for being
/// obviously right: it serializes the route and hashes the bytes.
pub(crate) fn route_scopes(
    config: &ServerConfig,
    caches: impl Fn(&RouteConfig) -> bool,
) -> Vec<Option<CacheScope>> {
    let scopes: Vec<Option<CacheScope>> = config
        .routes
        .iter()
        .enumerate()
        .map(|(route_index, route)| {
            if !caches(route) {
                return None;
            }
            let identity = ScopeIdentity {
                site: config,
                route_index,
            };
            // 🛡️ A route whose identity cannot be serialized gets no scope,
            // and a route without a scope is never cached. Falling back to a
            // shared scope would bring back exactly the cross-route sharing
            // this module exists to prevent.
            match serde_json::to_vec(&identity) {
                Ok(bytes) => Some(hash_key(bytes)),
                Err(error) => {
                    tracing::error!(
                        route = route.path,
                        %error,
                        "🚫 Cache scope could not be computed; this route will not cache"
                    );
                    None
                }
            }
        })
        .collect();

    let mut registry = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    registry.extend(scopes.iter().flatten().copied());
    scopes
}

/// 🧹 Every scope any configuration loaded by this process has used, so the
/// purge endpoint can reach an entry whichever route stored it.
///
/// The set only grows: an entry stored under a scope from an earlier load can
/// still be in the cache, and purge must reach it. It grows by 16 bytes per
/// distinct caching route configuration ever loaded, which is bounded by what
/// operators write, not by traffic.
pub(crate) fn known_scopes() -> Vec<CacheScope> {
    registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .copied()
        .collect()
}

/// 🔒 A `Mutex` is enough: it is taken at configuration load and by the admin
/// purge endpoint, never on the request path.
fn registry() -> &'static Mutex<HashSet<CacheScope>> {
    static SCOPES: OnceLock<Mutex<HashSet<CacheScope>>> = OnceLock::new();
    SCOPES.get_or_init(|| Mutex::new(HashSet::new()))
}

/// 🧭 A digest of the upstream a placeholder dial resolved to.
///
/// Runs per request, but only on a caching route whose dial has placeholders;
/// the formatted dial is the one allocation it makes.
pub(crate) fn upstream_digest(upstream: &UpstreamSpec) -> HashBinary {
    hash_key(format!("{:?}://{}", upstream.scheme, upstream.authority()))
}

/// 🔀 Combines an upstream digest with the `Vary` variance, if any, into one
/// variant key. The marker byte keeps "no `Vary`" apart from a `Vary` whose
/// digest happens to be all zeroes.
pub(crate) fn with_variance(upstream: &HashBinary, vary: Option<HashBinary>) -> HashBinary {
    let mut bytes = [0u8; 33];
    bytes[..16].copy_from_slice(upstream);
    if let Some(vary) = vary {
        bytes[16] = 1;
        bytes[17..].copy_from_slice(&vary);
    }
    hash_key(bytes)
}

/// 🔑 Frames scope, host and request target into the single primary component
/// Pingora 0.9's cache-key API takes.
///
/// The scope is fixed-length; host and target are length-prefixed, so no two
/// different triples can produce the same bytes. The host is lowercased in
/// place in the buffer rather than through a temporary `String`.
pub(crate) fn primary(scope: &CacheScope, host: &str, path_and_query: &str) -> Vec<u8> {
    let mut primary = Vec::with_capacity(scope.len() + 16 + host.len() + path_and_query.len());
    primary.extend_from_slice(scope);
    primary.extend_from_slice(&(host.len() as u64).to_be_bytes());
    let host_start = primary.len();
    primary.extend_from_slice(host.as_bytes());
    primary[host_start..].make_ascii_lowercase();
    primary.extend_from_slice(&(path_and_query.len() as u64).to_be_bytes());
    primary.extend_from_slice(path_and_query.as_bytes());
    primary
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔐 Length prefixes keep host and target boundaries unambiguous.
    #[test]
    fn primary_does_not_conflate_adjacent_fields() {
        let scope = [0; 16];
        assert_ne!(primary(&scope, "ab", "c"), primary(&scope, "a", "bc"));
    }

    /// 🔑 Purge and the request path may differ in host case; the key may not.
    #[test]
    fn primary_ignores_host_case() {
        let scope = [7; 16];
        assert_eq!(
            primary(&scope, "EXAMPLE.com", "/a?b=1"),
            primary(&scope, "example.com", "/a?b=1")
        );
    }
}
