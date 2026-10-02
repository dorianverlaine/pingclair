// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧾 Real commands accept Caddy's path flags and honor explicit adapters.

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn cli_validate_accepts_config_flags_and_adapter_overrides() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.json");
    std::fs::write(dir.path().join("site"), ":8080 {\n respond hi\n}\n").unwrap();
    std::fs::write(&source, "import site\n").unwrap();
    let bin = env!("CARGO_BIN_EXE_pingclair");
    for flags in [vec!["--config"], vec!["-c"], vec![]] {
        let output = Command::new(bin)
            .arg("validate")
            .args(flags)
            .arg(&source)
            .args(["--adapter", "caddyfile"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let json = dir.path().join("extensionless");
    let dsl = dir.path().join("Pingclairfile");
    std::fs::write(&dsl, "import site\n").unwrap();
    let adapted = Command::new(bin)
        .args(["adapt", "-c"])
        .arg(&dsl)
        .output()
        .unwrap();
    assert!(adapted.status.success());
    std::fs::write(&json, adapted.stdout).unwrap();
    assert!(
        Command::new(bin)
            .args(["validate", "--adapter", "json", "-c"])
            .arg(&json)
            .status()
            .unwrap()
            .success()
    );
    let mut stdin = Command::new(bin)
        .args(["validate", "-c", "-", "--adapter", "json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    stdin
        .stdin
        .take()
        .unwrap()
        .write_all(&std::fs::read(&json).unwrap())
        .unwrap();
    assert!(stdin.wait_with_output().unwrap().status.success());
    std::fs::write(&json, r#"{"unknown":true}"#).unwrap();
    assert!(
        !Command::new(bin)
            .args(["validate", "--adapter", "json", "-c"])
            .arg(&json)
            .output()
            .unwrap()
            .status
            .success()
    );
    for command in ["run", "validate"] {
        let unknown = Command::new(bin)
            .args([command, "--adapter", "yaml"])
            .arg(&dsl)
            .output()
            .unwrap();
        assert!(!unknown.status.success());
        assert!(String::from_utf8_lossy(&unknown.stderr).contains("yaml"));
        let conflict = Command::new(bin)
            .arg(command)
            .arg(&dsl)
            .arg("--config")
            .arg(&dsl)
            .output()
            .unwrap();
        assert!(!conflict.status.success());
    }
}

struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn cli_run_accepts_config_flags_and_explicit_adapter() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source.json");
    let client = super::no_proxy_client();
    for (flags, adapter) in [
        (vec!["--config"], "caddyfile"),
        (vec!["-c"], "caddyfile"),
        (vec![], "caddyfile"),
        (vec!["--config"], "json"),
    ] {
        let port = super::free_port();
        let token = uuid::Uuid::new_v4().to_string();
        let source = |body: &str| {
            let dsl =
                format!("{{\n admin off\n}}\nhttp://127.0.0.1:{port} {{\n respond {body}\n}}\n");
            if adapter == "json" {
                // 🧾 This JSON fixture exercises the explicit JSON adapter feature.
                serde_json::to_string(&pingclair_config::compile(&dsl).unwrap()).unwrap()
            } else {
                dsl
            }
        };
        std::fs::write(&path, source(&token)).unwrap();
        let mut child = ChildGuard(
            Command::new(env!("CARGO_BIN_EXE_pingclair"))
                .arg("run")
                .args(flags)
                .arg(&path)
                .args(["--adapter", adapter, "--watch"])
                .env("PINGCLAIR_TLS_STORE", dir.path().join("store"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let url = format!("http://127.0.0.1:{port}/");
        let mut ready = false;
        for _ in 0..100 {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "run exited before readiness"
            );
            if let Ok(response) = client.get(&url).send().await
                && response.text().await.unwrap() == token
            {
                ready = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(ready, "run never served its unique readiness token");
        let updated = uuid::Uuid::new_v4().to_string();
        std::fs::write(&path, source(&updated)).unwrap();
        let mut reloaded = false;
        for _ in 0..100 {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "run exited during reload"
            );
            if let Ok(response) = client.get(&url).send().await
                && response.text().await.unwrap() == updated
            {
                reloaded = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(reloaded, "watch/signal reload lost the explicit adapter");
    }
}
