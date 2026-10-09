// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;
use pingclair_core::config::{Layer4Matcher, Layer4Route, Layer4TlsMatcher};
use tokio::io::duplex;
use tokio::time::timeout;

#[tokio::test]
async fn cancellation_logs_once_and_unchanged_destinations_reuse_the_writer() {
    pingclair_runtime::metrics::configure(false);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("access.jsonl");
    let mut config = Layer4Server::new("127.0.0.1:9443".into());
    config.log = Some(
        serde_json::from_value(serde_json::json!({
            "output": {"file": path}, "format": "json", "level": null
        }))
        .unwrap(),
    );
    config.routes.push(Layer4Route {
        dynamic: None,
        upstream: "127.0.0.1:1".into(),
        matches: vec![Layer4Matcher {
            tls: Some(Layer4TlsMatcher::default()),
            remote_ip: vec![],
        }],
    });
    let first = Arc::new(PreparedListener::prepare(&config, &[]).unwrap());
    config.routes[0].upstream = "127.0.0.1:2".into();
    let next = PreparedListener::prepare_with_previous(&config, &[], Some(&first)).unwrap();
    assert!(Arc::ptr_eq(
        first.policy.logger.as_ref().unwrap(),
        next.policy.logger.as_ref().unwrap()
    ));
    let (_client, stream) = duplex(1);
    {
        let connection = first
            .clone()
            .serve(stream, "127.0.0.1:1234".parse().unwrap());
        tokio::pin!(connection);
        // ⏳ Poll the future into preread, then drop its owner to cancel it.
        assert!(
            timeout(Duration::from_millis(10), &mut connection)
                .await
                .is_err()
        );
    }
    first.policy.logger.as_ref().unwrap().flush();
    let contents = std::fs::read_to_string(path).unwrap();
    assert_eq!(contents.lines().count(), 1);
    let entry: serde_json::Value = serde_json::from_str(&contents).unwrap();
    assert_eq!(entry["outcome"], "cancelled");
    assert_eq!(entry["status"], 500);
    assert_eq!(entry["bytes_received"], 0);
    assert_eq!(entry["bytes_sent"], 0);
    assert!(entry.get("upstream_addr").is_none());
}
