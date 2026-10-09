// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔌 Raw TCP services, immutable route generations, and process lifecycle integration.

use arc_swap::ArcSwap;
use pingclair_core::config::{PingclairConfig, covering_wildcard, normalize_listen_addr};
use pingclair_l4::{DnsPreparation, DnsRuntime, PreparedListener};
use pingclair_proxy::server::ConfigApplyError;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;

mod destinations;
mod listener;
pub(crate) use listener::register;

pub(crate) type Generation = HashMap<String, Arc<PreparedListener>>;

pub(crate) struct PreparedGeneration {
    listeners: Generation,
    dns: DnsPreparation,
}

/// 📦 New connections load one generation; established tunnels retain their own state.
pub(crate) struct Runtime(ArcSwap<Generation>, Arc<Semaphore>, DnsRuntime);

impl Default for Runtime {
    fn default() -> Self {
        Self(
            ArcSwap::default(),
            Arc::new(Semaphore::new(4096)),
            DnsRuntime::default(),
        )
    }
}

impl Runtime {
    pub(crate) fn publish(&self, next: PreparedGeneration) {
        self.0.store(Arc::new(next.listeners));
        self.2.publish(next.dns);
    }

    pub(crate) async fn run_dns(&self) {
        self.2.run(pingclair_proxy::drain::stopping()).await;
    }
}

/// 🛡️ Checks effective HTTP companions and Admin before resolving any upstream.
pub(crate) fn prepare(
    config: &PingclairConfig,
    current: &Runtime,
    http_addresses: impl Iterator<Item = String>,
) -> Result<PreparedGeneration, ConfigApplyError> {
    let mut occupied: Vec<SocketAddr> = http_addresses
        .filter_map(|address| address.parse().ok())
        .collect();
    if let Some(admin) = &config.admin
        && admin.enabled
        && let Some(address) = pingclair_core::config::parse_listen_addr(&admin.listen)
    {
        occupied.push(address);
    }
    for listener in &config.layer4 {
        let address = normalize_listen_addr(&listener.listen);
        let socket: SocketAddr = address
            .parse()
            .map_err(|error| ConfigApplyError::invalid(format!("invalid L4 address: {error}")))?;
        for other in &occupied {
            if socket == *other
                || (socket.ip().is_unspecified()
                    && covering_wildcard(&other.to_string(), &[socket]).is_some())
                || (other.ip().is_unspecified() && covering_wildcard(&address, &[*other]).is_some())
            {
                return Err(ConfigApplyError::invalid(format!(
                    "L4 listener {address} overlaps TCP listener {other}"
                )));
            }
        }
        occupied.push(socket);
    }
    let has_dynamic = config
        .layer4
        .iter()
        .flat_map(|listener| &listener.routes)
        .any(|route| route.dynamic.is_some());
    let own = if has_dynamic {
        destinations::known(&occupied).map_err(|error| {
            ConfigApplyError::invalid(format!("cannot prepare L4 local destinations: {error}"))
        })?
    } else {
        occupied
    };
    let mut dns = current.2.prepare(own);
    let previous = current.0.load();
    let mut next = HashMap::new();
    for listener in &config.layer4 {
        let address = normalize_listen_addr(&listener.listen);
        let prepared = PreparedListener::prepare_with_dns(
            listener,
            &config.global.blocked_ips,
            previous.get(&address).map(Arc::as_ref),
            &mut dns,
        )
        .map_err(|error| {
            ConfigApplyError::invalid(format!("cannot prepare L4 listener {address}: {error}"))
        })?;
        next.insert(address, Arc::new(prepared));
    }
    Ok(PreparedGeneration {
        listeners: next,
        dns,
    })
}

/// ♻️ Routes may change live; socket topology and listener limits require a restart.
pub(crate) fn ensure_hot_compatible(
    current: &PingclairConfig,
    next: &PingclairConfig,
) -> Result<(), ConfigApplyError> {
    let captured = |config: &PingclairConfig| {
        config
            .layer4
            .iter()
            .map(|listener| {
                let mut listener = listener.clone();
                listener.routes.clear();
                listener.log = None;
                listener.listen = normalize_listen_addr(&listener.listen);
                (listener.listen.clone(), listener)
            })
            .collect::<HashMap<_, _>>()
    };
    if captured(current) != captured(next) {
        return Err(ConfigApplyError::restart_required(
            "L4 listener topology or limits changed; restart Pingclair",
        ));
    }
    Ok(())
}
