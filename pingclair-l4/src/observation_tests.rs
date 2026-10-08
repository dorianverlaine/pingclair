// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

#[tokio::test]
async fn partial_writes_and_cancellation_preserve_live_accounting() {
    pingclair_runtime::metrics::configure(true);
    let metrics = Metrics::prepare("cancel-test", 1);
    let (mut client, stream) = duplex(3);
    let mut observation = Observation::new(&metrics);
    assert_eq!(metrics.active.get(), 1);
    {
        let mut counted = Counted {
            inner: stream,
            stats: &mut observation.downstream,
            written: Some(&metrics.to_client),
        };
        assert_eq!(counted.write(b"longer than capacity").await.unwrap(), 3);
        assert_eq!(metrics.to_client.get(), 3);
        let mut got = [0; 3];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"lon");
        client.write_all(b"in").await.unwrap();
        counted.read_exact(&mut got[..2]).await.unwrap();
    }
    assert_eq!(
        (observation.downstream.read, observation.downstream.written),
        (2, 3)
    );
    // 🧹 Dropping before finish models a cancelled connection future.
    drop(observation);
    assert_eq!(metrics.active.get(), 0);
    assert_eq!(metrics.duration.get_sample_count(), 1);
    let families = pingclair_runtime::metrics::REGISTRY.gather();
    let family = families
        .iter()
        .find(|f| f.name() == "l4_connections_total")
        .unwrap();
    let cancelled = family
        .get_metric()
        .iter()
        .find(|m| {
            m.get_label()
                .iter()
                .any(|l| l.name() == "outcome" && l.value() == "cancelled")
                && m.get_label()
                    .iter()
                    .any(|l| l.name() == "route" && l.value() == "none")
        })
        .unwrap();
    assert_eq!(cancelled.get_counter().value(), 1.0);
}

#[test]
fn disabling_collection_does_not_unbalance_an_existing_session() {
    pingclair_runtime::metrics::configure(true);
    let metrics = Metrics::prepare("reload-test", 1);
    let active = Observation::new(&metrics);
    pingclair_runtime::metrics::configure(false);
    let disabled = Observation::new(&metrics);
    assert!(disabled.metrics.is_none());
    drop(disabled);
    assert_eq!(metrics.active.get(), 1);
    drop(active);
    assert_eq!(metrics.active.get(), 0);
    assert_eq!(metrics.duration.get_sample_count(), 1);
}
