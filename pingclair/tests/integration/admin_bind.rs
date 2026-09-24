// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔧 The admin API is bound at startup, or the process does not start.
//!
//! The admin listener used to be bound inside its own thread after startup had
//! already succeeded. A taken admin port became one log line on stdout, and the
//! server ran on without `/load`, `/config`, or `/metrics` while looking healthy.

use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// 🚫 A taken admin port stops startup, and the error names the address.
#[test]
fn test_startup_fails_when_the_admin_port_is_taken() {
    // 🧭 The test holds the admin port for its whole life, so the collision is
    // deliberate rather than a race with another fixture.
    let held = TcpListener::bind("127.0.0.1:0").expect("bind the admin port");
    let admin_address = held.local_addr().unwrap();
    let site = TcpListener::bind("127.0.0.1:0").unwrap();
    let site_port = site.local_addr().unwrap().port();
    drop(site);

    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("Pingclairfile");
    std::fs::write(
        &config_path,
        format!(
            r#"
            {{
                admin {admin_address}
            }}

            http://127.0.0.1:{site_port} {{
                respond "should-not-serve"
            }}
            "#,
        ),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_pingclair"))
        .arg("run")
        .arg(&config_path)
        .env("RUST_LOG", "info")
        .env("PINGCLAIR_TLS_STORE", dir.path().join("tls"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start pingclair");

    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("pingclair kept running although its admin port was taken");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut stderr = String::new();
    std::io::Read::read_to_string(child.stderr.as_mut().unwrap(), &mut stderr).unwrap();

    assert!(!status.success(), "startup reported success: {stderr}");
    assert!(
        stderr.contains(&format!("failed to bind admin API on {admin_address}")),
        "startup failed for some other reason: {stderr}"
    );
    drop(held);
}
