// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚦 TCP acceptance with admission before session task allocation.

use super::Runtime;
use pingora_core::server::{ListenFds, ShutdownWatch};
use pingora_core::services::Service;
use std::{io, net::TcpListener, sync::Arc, time::Duration};
use tokio::sync::Semaphore;

/// 🔌 Reserves sockets before readiness and keeps quotas across route generations.
pub(crate) fn register(
    server: &mut pingora_core::server::Server,
    runtime: &Arc<Runtime>,
) -> io::Result<()> {
    for (address, prepared) in runtime.0.load().iter() {
        let socket = TcpListener::bind(address)?;
        socket.set_nonblocking(true)?;
        server.add_service(Listener {
            name: format!("L4 {address}"),
            address: address.clone(),
            runtime: runtime.clone(),
            quota: Arc::new(Semaphore::new(prepared.max_connections())),
            socket: Some(socket),
        });
        tracing::info!(listener = %address, "🔌 Reserved L4 TCP listener");
    }
    Ok(())
}

struct Listener {
    name: String,
    address: String,
    runtime: Arc<Runtime>,
    quota: Arc<Semaphore>,
    socket: Option<TcpListener>,
}

// 🔌 Pingora 0.9.0 requires async-trait for its external Service interface.
#[async_trait::async_trait]
impl Service for Listener {
    async fn start_service(
        &mut self,
        _fds: Option<ListenFds>,
        mut shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
    ) {
        let Some(socket) = self.socket.take() else {
            return;
        };
        let socket = tokio::net::TcpListener::from_std(socket)
            .expect("reserved L4 socket must attach to the service runtime");
        loop {
            if *shutdown.borrow() || pingclair_proxy::drain::is_stopping() {
                break;
            }
            let accepted = tokio::select! {
                biased;
                _ = pingclair_proxy::drain::stopping() => break,
                changed = shutdown.changed() => {
                    if changed.is_err() { break; }
                    continue;
                }
                accepted = socket.accept() => accepted,
            };
            let (stream, peer) = match accepted {
                Ok(pair) => pair,
                Err(error) => {
                    tracing::warn!(listener = %self.address, %error, "🔌 L4 accept failed");
                    // 🛡️ Resource exhaustion must not spin or flood logs; shutdown interrupts backoff.
                    tokio::select! {
                        _ = pingclair_proxy::drain::stopping() => break,
                        _ = shutdown.changed() => {}
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                    }
                    continue;
                }
            };
            let in_flight = pingclair_proxy::drain::InFlight::enter();
            if *shutdown.borrow() || pingclair_proxy::drain::is_stopping() {
                break;
            }
            let Some(prepared) = self.runtime.0.load().get(&self.address).cloned() else {
                continue;
            };
            let Ok(local) = self.quota.clone().try_acquire_owned() else {
                prepared.record_admission_rejection();
                continue;
            };
            let Ok(global) = self.runtime.1.clone().try_acquire_owned() else {
                prepared.record_admission_rejection();
                continue;
            };
            if let Err(error) = stream.set_nodelay(true) {
                tracing::debug!(%error, "🔌 Cannot configure L4 socket");
                continue;
            }
            // 🛑 Count accepted work before spawning so shutdown cannot miss a queued task.
            // ⚡ Preserve distribution across Pingora workers without work stealing.
            pingora_runtime::current_handle().spawn(async move {
                let _guards = (local, global, in_flight);
                if let Err(error) = prepared.serve(stream, peer).await {
                    tracing::debug!(%error, "🔌 L4 connection ended");
                }
            });
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn listen_addresses(&self) -> Option<Vec<String>> {
        Some(vec![self.address.clone()])
    }
}

#[cfg(test)]
#[path = "listener_tests.rs"]
mod tests;
