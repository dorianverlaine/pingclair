// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ♻️ A reload must not cost a single request.
//!
//! Reloading used to close a gate on every listener while it swapped routing
//! and client-authentication snapshots one after another, and any request that
//! arrived in that window was answered `503 Configuration Reload In Progress`
//! and had its connection closed. The window was short, but a busy server
//! always has a request arriving, so every reload failed a few of them. These
//! tests keep traffic flowing through several reloads and count every answer
//! that was not a normal one.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use super::{TestServer, no_proxy_client};

/// 🏗️ Enough virtual hosts that building the next generation takes real work.
///
/// Each site compiles its own router and handler state on reload, so a few
/// dozen of them widen whatever window a reload opens from microseconds to
/// something concurrent clients reliably land in.
const SITES: usize = 64;

/// 🧾 One generation of the configuration, answering `body` on every site.
///
/// The readiness route lives only in the first generation's catch-all; the
/// later ones are written by the test after startup, when readiness no longer
/// matters.
fn generation(port: &str, body: &str, readiness: bool) -> String {
    let mut config = String::from("{\n    admin off\n}\n");
    config.push_str(&format!(":{port} {{\n"));
    if readiness {
        config.push_str(
            "    @readiness path __PINGCLAIR_TEST_READINESS_PATH__\n    \
             respond @readiness \"__PINGCLAIR_TEST_READINESS_TOKEN__\"\n",
        );
    }
    config.push_str(&format!("    respond \"{body}\"\n}}\n"));
    for site in 0..SITES {
        config.push_str(&format!(
            "http://site{site}.test:{port} {{\n    header X-Site {site}\n    respond \"{body}\"\n}}\n"
        ));
    }
    config
}

/// ♻️ Requests sent continuously across several signal reloads are all served.
///
/// Every answer must be a `200` from one complete generation. A `503`, a
/// dropped connection, or any other body fails the test, and the last
/// generation must be the one serving when it ends.
#[tokio::test]
async fn test_signal_reload_drops_no_request_under_steady_traffic() {
    let mut server =
        TestServer::new_pingclairfile(&generation("__PINGCLAIR_TEST_PORT__", "gen-0", true));
    assert!(server.wait_until_ready().await, "server failed to start");
    let port = server.address(0).port().to_string();
    let url = server.url(0, "/");
    let config_path = server._temp_dir.path().join("Pingclairfile");

    let stop = Arc::new(AtomicBool::new(false));
    let served = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();
    for worker in 0..8 {
        let stop = Arc::clone(&stop);
        let served = Arc::clone(&served);
        let url = url.clone();
        workers.push(tokio::spawn(async move {
            let client = no_proxy_client();
            let host = format!("site{}.test", worker * 7 % SITES);
            let mut failures = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                match client.get(&url).header("Host", &host).send().await {
                    Ok(response) => {
                        let status = response.status();
                        let body = response.text().await.unwrap_or_default();
                        if status == 200 && body.starts_with("gen-") {
                            served.fetch_add(1, Ordering::Relaxed);
                        } else {
                            failures.push(format!("{status}: {body}"));
                        }
                    }
                    Err(error) => failures.push(format!("transport error: {error}")),
                }
            }
            failures
        }));
    }

    // 🔁 Each reload is confirmed live before the next is sent, so the test
    // really crosses every publication rather than coalescing them.
    let probe = no_proxy_client();
    let reloads = 8;
    for reload in 1..=reloads {
        let body = format!("gen-{reload}");
        std::fs::write(&config_path, generation(&port, &body, false)).unwrap();
        let status = std::process::Command::new("kill")
            .args(["-USR1", &server.process.id().to_string()])
            .status()
            .expect("kill must run");
        assert!(status.success());

        let mut live = false;
        for _ in 0..100 {
            if let Ok(response) = probe.get(&url).header("Host", "site1.test").send().await
                && response.text().await.unwrap_or_default() == body
            {
                live = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(live, "reload {reload} never became live");
    }

    stop.store(true, Ordering::Relaxed);
    let mut failures = Vec::new();
    for worker in workers {
        failures.extend(worker.await.expect("worker task"));
    }
    let served = served.load(Ordering::Relaxed);
    assert!(
        failures.is_empty(),
        "{} of {} requests failed across {reloads} reloads; first few: {:?}",
        failures.len(),
        failures.len() + served,
        &failures[..failures.len().min(5)]
    );
    assert!(served > 0, "no request was served at all");

    // 🎯 The last generation is the one answering, on a named site and on
    // the catch-all alike.
    for host in ["site63.test", "unknown.test"] {
        let response = probe.get(&url).header("Host", host).send().await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), format!("gen-{reloads}"));
    }
}
