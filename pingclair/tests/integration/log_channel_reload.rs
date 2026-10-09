// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🪵 Reload must register new channels before sites resolve their destinations.

use super::{Duration, TestServer, no_proxy_client};
use std::process::Command;

enum ReloadMethod {
    Admin,
    #[cfg(unix)]
    Signal,
}

#[tokio::test]
async fn admin_reload_attaches_new_log_channels() {
    check_reload_channels(ReloadMethod::Admin).await;
}

#[cfg(unix)]
#[tokio::test]
async fn signal_reload_attaches_new_log_channels() {
    check_reload_channels(ReloadMethod::Signal).await;
}

async fn check_reload_channels(method: ReloadMethod) {
    let mut server = TestServer::new_pingclairfile(
        r#"
        {
            admin __PINGCLAIR_TEST_ADMIN_LISTEN__
        }
        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "before"
        }
        "#,
    );
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();
    let config_path = server._temp_dir.path().join("Pingclairfile");

    // 🔁 Both generations introduce a new destination; the second replaces an active one.
    for generation in 1..=2 {
        let log_path = server
            ._temp_dir
            .path()
            .join(format!("access-{generation}.log"));
        let marker = format!("generation-{generation}");
        std::fs::write(
            &config_path,
            format!(
                r#"
                {{
                    admin {admin}
                    log access{generation} {{
                        output file {log_path}
                        format json
                    }}
                }}
                http://{address} {{
                    log access{generation}
                    respond "{marker}"
                }}
                "#,
                admin = server.admin_address.unwrap(),
                log_path = log_path.display(),
                address = server.address(0),
            ),
        )
        .unwrap();
        let status = match method {
            ReloadMethod::Admin => Command::new(env!("CARGO_BIN_EXE_pingclair"))
                .args(["reload", "--config"])
                .arg(&config_path)
                .args(["--address", &server.admin_address.unwrap().to_string()])
                .status()
                .unwrap(),
            #[cfg(unix)]
            ReloadMethod::Signal => Command::new("kill")
                .args(["-USR1", &server.process.id().to_string()])
                .status()
                .unwrap(),
        };
        assert!(status.success(), "reload command failed");

        // ⏳ Observe the new route before sending the request whose log is asserted.
        let mut applied = false;
        for _ in 0..100 {
            let response = client
                .get(server.url(0, "/generation"))
                .send()
                .await
                .unwrap();
            if response.text().await.unwrap() == marker {
                applied = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(applied, "reload did not publish {marker}");
        let path = format!("/record-{generation}");
        let response = client.get(server.url(0, &path)).send().await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), marker);

        let mut recorded = String::new();
        for _ in 0..100 {
            recorded = std::fs::read_to_string(&log_path).unwrap_or_default();
            if recorded.contains(&path) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            recorded.lines().filter(|line| line.contains(&path)).count(),
            1,
            "the reloaded channel must record the request exactly once: {recorded:?}"
        );
    }
}
