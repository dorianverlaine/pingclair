// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔒 Plaintext on the HTTPS port is refused on every entry point.
//!
//! The rule lives in `validate_config`, and a rule there is only as good as
//! the paths that reach it: the Admin API once skipped that function entirely.
//! So these tests go through the real interfaces — the `validate` command on a
//! Pingclairfile, and a JSON body posted to a running server's `/load`.
//!
//! 📌 The posted document is JSON because the Admin path is the subject: it is
//! the one entry that never passes through an adapter. The running server is
//! configured in the DSL.

use std::process::{Command, Stdio};

/// 🧹 Ends the child however the test ends.
struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// 🔒 `pingclair validate` refuses an `http://` site on the HTTPS port.
#[test]
fn test_validate_refuses_an_http_site_on_the_https_port() {
    let https_port = super::free_port();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("Pingclairfile");
    std::fs::write(
        &config_path,
        format!(
            "{{\n    https_port {https_port}\n}}\n\nhttp://localhost:{https_port} {{\n    \
             respond \"plaintext\"\n}}\n"
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_pingclair"))
        .arg("validate")
        .arg("--config")
        .arg(&config_path)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success() && stderr.contains("the HTTPS port"),
        "validate must refuse plaintext on the HTTPS port: {stderr}"
    );
}

/// 🛡️ An Admin `/load` that declares the HTTPS port plaintext is refused, and
/// nothing starts listening there.
#[tokio::test]
async fn test_admin_load_refuses_plaintext_on_the_https_port() {
    let admin_port = super::free_port();
    let https_port = super::free_port();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("Pingclairfile");
    std::fs::write(
        &config_path,
        format!("{{\n    admin 127.0.0.1:{admin_port}\n    https_port {https_port}\n}}\n"),
    )
    .unwrap();
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_pingclair"))
            .arg("run")
            .arg(&config_path)
            .env("PINGCLAIR_TLS_STORE", dir.path().join("tls"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let client = super::no_proxy_client();
    let config_url = format!("http://127.0.0.1:{admin_port}/config/");
    let mut document = None;
    for _ in 0..200 {
        assert!(child.0.try_wait().unwrap().is_none(), "pingclair exited");
        if let Ok(response) = client.get(&config_url).send().await
            && response.status().is_success()
        {
            document = Some(response.json::<serde_json::Value>().await.unwrap());
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let mut document = document.expect("the Admin API never answered");
    let address = format!("127.0.0.1:{https_port}");
    document["servers"] = serde_json::json!([{
        "listen": [address],
        "plaintext_listen": [address],
        "routes": [{
            "path": "/*",
            "handler": {"type": "respond", "status": 200, "body": "plaintext"}
        }]
    }]);
    let loaded = client
        .post(format!("http://127.0.0.1:{admin_port}/load"))
        .header("Content-Type", "application/json")
        .body(document.to_string())
        .send()
        .await
        .unwrap();
    let status = loaded.status().as_u16();
    let body = loaded.text().await.unwrap();

    // 🎯 A raw connect, so "refused" cannot be confused with an HTTP answer.
    let listening = tokio::net::TcpStream::connect(("127.0.0.1", https_port))
        .await
        .map(|_| ())
        .map_err(|error| error.kind());
    assert!(
        (400..500).contains(&status) && body.contains("the HTTPS port"),
        "load must be refused: {status} {body}"
    );
    assert_eq!(listening, Err(std::io::ErrorKind::ConnectionRefused));
}
