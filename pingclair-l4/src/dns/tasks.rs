// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧹 Owns and joins Hickory transport workers before a DNS job releases its slot.

use hickory_resolver::net::runtime::{RuntimeProvider, Spawn, TokioRuntimeProvider};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::JoinSet;

#[derive(Default)]
struct State {
    closed: bool,
    tasks: JoinSet<()>,
}

#[derive(Clone, Default)]
pub(super) struct Tasks(Arc<Mutex<State>>);

impl Tasks {
    fn close(&self) -> JoinSet<()> {
        let mut state = self.0.lock().expect("DNS task scope");
        state.closed = true;
        std::mem::take(&mut state.tasks)
    }

    pub fn guard(&self) -> Guard {
        Guard(self.clone())
    }

    pub async fn drain(self) {
        let mut tasks = self.close();
        tasks.shutdown().await;
    }
}

pub(super) struct Guard(Tasks);

impl Drop for Guard {
    fn drop(&mut self) {
        // 🧹 Even an aborted outer future must close its transport task scope.
        drop(self.0.close());
    }
}

impl Spawn for Tasks {
    fn spawn_bg(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        let mut state = self.0.lock().expect("DNS task scope");
        if !state.closed {
            state.tasks.spawn(future);
            while state.tasks.try_join_next().is_some() {}
        }
    }
}

/// 🧹 Hickory 0.26.3's RuntimeProvider delegates sockets and timers unchanged.
/// Its Spawn handle gives the coordinator an explicit join boundary on cancellation.
#[derive(Clone, Default)]
pub(super) struct Provider {
    pub tasks: Tasks,
    sockets: TokioRuntimeProvider,
}

impl RuntimeProvider for Provider {
    type Handle = Tasks;
    type Timer = <TokioRuntimeProvider as RuntimeProvider>::Timer;
    type Udp = <TokioRuntimeProvider as RuntimeProvider>::Udp;
    type Tcp = <TokioRuntimeProvider as RuntimeProvider>::Tcp;

    fn create_handle(&self) -> Self::Handle {
        self.tasks.clone()
    }

    fn connect_tcp(
        &self,
        server: SocketAddr,
        bind: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        self.sockets.connect_tcp(server, bind, timeout)
    }

    fn bind_udp(
        &self,
        local: SocketAddr,
        server: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        self.sockets.bind_udp(local, server)
    }
}
