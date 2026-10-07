// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ♻️ One listener's routes and client-authentication policy, published as one value.
//!
//! A request needs two things from the configuration: which site answers a
//! host, and which client-certificate policy admitted its connection. When
//! those lived in separate snapshots, a reload had to swap them one after the
//! other, and a request that read one before the swap and the other after it
//! could be admitted under the old trust pool and routed by the new sites. The
//! old cure was to refuse every request while a reload was publishing, which
//! turned every reload into a burst of `503`s.
//!
//! A [`ListenerGeneration`] removes the in-between state instead. A reload
//! builds the whole next generation off to the side, then publishes it with a
//! single atomic pointer swap. A request loads one generation and answers
//! every question from it, so it sees either the old configuration or the new
//! one — never half of each — and nothing has to be refused.

use std::collections::HashMap;
use std::sync::Arc;

use crate::client_auth::ListenerSecuritySnapshot;
use crate::server::ProxyState;

/// 🗺️ The virtual hosts one listener serves, keyed by canonical host name.
#[derive(Default)]
pub struct RouteTable {
    pub(crate) hosts: HashMap<String, Arc<ProxyState>>,
    pub(crate) default: Option<Arc<ProxyState>>,
    /// 📝 Whether any site on this listener configured an access log.
    ///
    /// Caddy's `ServerLogConfig` belongs to the server, not to one site: a
    /// single site's `log` turns records on for the whole listener, and a
    /// server whose sites never mention `log` writes none. The answer is
    /// decided when the table is published (load and reload) rather than
    /// derived per request, because it cannot change while a generation is
    /// live (#213).
    pub(crate) access_logging: bool,
}

impl RouteTable {
    /// 📝 Whether this listener writes any access record at all.
    pub(crate) fn has_access_logging(&self) -> bool {
        self.access_logging
    }

    /// 🔁 Recomputes [`Self::has_access_logging`] from the sites present.
    ///
    /// Called once per load or reload, after the sites are registered — the
    /// only moment the answer can change.
    pub(crate) fn refresh_access_logging(&mut self) {
        let any = self.states().any(|state| !state.log_targets().is_empty());
        self.access_logging = any;
    }

    /// 🧭 Resolves a host to the site that answers it.
    ///
    /// Resolution order: the exact name, then a one-label wildcard such as
    /// `*.example.com`, then the catch-all site. The name is canonicalised
    /// here, at the one door to the map, because the client may send
    /// `EXAMPLE.com.` for a site the operator wrote as `example.com`.
    pub(crate) fn get(&self, host: &str) -> Option<Arc<ProxyState>> {
        let host = crate::http_policy::canonical_host(host);
        if let Some(state) = self.hosts.get(host.as_ref()) {
            return Some(Arc::clone(state));
        }
        for (pattern, state) in &self.hosts {
            if let Some(suffix) = pattern.strip_prefix("*.")
                && crate::http_policy::wildcard_host_matches(suffix, host.as_ref())
            {
                return Some(Arc::clone(state));
            }
        }
        self.default.clone()
    }

    /// 🏠 Iterates every site on the listener, the catch-all included.
    ///
    /// Public because the reload path reads each site's load balancers to
    /// retire `/metrics` health series the new generation no longer contains
    /// (#251).
    pub fn states(&self) -> impl Iterator<Item = &Arc<ProxyState>> {
        self.hosts.values().chain(self.default.iter())
    }
}

/// 📦 Everything a request on one listener reads from the configuration.
///
/// Immutable once built. The security half is shared with the TLS handshake
/// callbacks, which record its revision on each connection so a later request
/// can tell whether the trust pool changed underneath it.
pub struct ListenerGeneration {
    pub(crate) security: Arc<ListenerSecuritySnapshot>,
    pub(crate) routes: Arc<RouteTable>,
}

impl ListenerGeneration {
    /// 🔐 The client-authentication policy this generation enforces.
    pub fn security(&self) -> &ListenerSecuritySnapshot {
        &self.security
    }

    /// 🗺️ The sites this generation serves.
    ///
    /// Shared rather than borrowed so a reload that rotates only the trust
    /// pool can publish the same table again without rebuilding a site.
    pub fn routes(&self) -> &Arc<RouteTable> {
        &self.routes
    }

    /// 🪪 Reports whether any site on this listener asks for a client certificate.
    pub(crate) fn requires_client_auth(&self) -> bool {
        !self.security.client_auth().is_empty()
    }
}
