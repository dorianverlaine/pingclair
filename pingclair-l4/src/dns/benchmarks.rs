// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ⚡ Shared snapshots, deadlines and cursors; the injected dial is immediately ready.

use super::*;
use crate::upstream::Upstream;
use divan::{Bencher, black_box};
use pingclair_core::config::Layer4IpVersions;
use std::future::{Future, ready};
use std::sync::LazyLock;
use std::task::{Context, Poll, Waker};

static STATIC: LazyLock<Upstream> =
    LazyLock::new(|| Upstream::prepare("203.0.113.10:443").unwrap());
static SINGLE: LazyLock<Source> = LazyLock::new(|| source(1));
static MULTIPLE: LazyLock<Source> = LazyLock::new(|| source(4));

fn source(count: u8) -> Source {
    let config = Layer4Dns {
        name: "benchmark.test".into(),
        port: 443,
        resolvers: Some(vec!["127.0.0.1:53".into()]),
        versions: Layer4IpVersions::Ipv4,
        valid_ms: None,
        stale_ms: 0,
        allow_ip: Some(vec!["203.0.113.0/24".into()]),
    };
    let source = DnsRuntime::default()
        .prepare(vec![])
        .source(&config)
        .unwrap();
    source
        .0
        .apply(Ok(Answer {
            addresses: (10..10 + count)
                .map(|last| SocketAddr::from(([203, 0, 113, last], 443)))
                .collect(),
            fresh: Instant::now() + Duration::from_secs(86_400),
        }))
        .unwrap();
    source
}

fn finish(future: impl Future<Output = io::Result<SocketAddr>>) -> SocketAddr {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Ok(address)) => black_box(address),
        Poll::Ready(Err(error)) => panic!("source benchmark failed: {error}"),
        Poll::Pending => panic!("benchmark dial unexpectedly suspended"),
    }
}

thread_local! {
    // ⚡ Each Divan worker has a time driver; entering it adds the same overhead to all sources.
    static RUNTIME: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time().build().unwrap();
}

fn measure<F, Fut>(bencher: Bencher<'_, '_>, operation: F)
where
    F: Fn() -> Fut + Sync,
    Fut: Future<Output = io::Result<SocketAddr>>,
{
    let run = || {
        RUNTIME.with(|runtime| {
            let _entered = runtime.enter();
            finish(operation())
        })
    };
    // ⚡ Input generation initializes each worker's runtime and ArcSwap slot before timing.
    bencher.with_inputs(&run).bench_values(|_| run());
}

#[divan::bench(threads = [1, 4, 8])]
fn static_single(bencher: Bencher<'_, '_>) {
    LazyLock::force(&STATIC);
    measure(bencher, || {
        STATIC.connect_with(Duration::from_secs(5), |address| {
            ready(Ok(black_box(address)))
        })
    });
}

#[divan::bench(threads = [1, 4, 8])]
fn dynamic_single(bencher: Bencher<'_, '_>) {
    LazyLock::force(&SINGLE);
    measure(bencher, || {
        SINGLE.connect_with(Duration::from_secs(5), |address| {
            ready(Ok(black_box(address)))
        })
    });
}

#[divan::bench(threads = [1, 4, 8])]
fn dynamic_four(bencher: Bencher<'_, '_>) {
    LazyLock::force(&MULTIPLE);
    measure(bencher, || {
        MULTIPLE.connect_with(Duration::from_secs(5), |address| {
            ready(Ok(black_box(address)))
        })
    });
}
