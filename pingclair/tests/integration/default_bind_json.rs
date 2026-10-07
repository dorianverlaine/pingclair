// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ `default_bind` holds for a JSON document posted to the Admin API.
//!
//! The Pingclairfile compiler copies `default_bind` into every site that named
//! no interface. A JSON document never passes through that compiler, so a site
//! loaded that way used to listen on every interface while the global option
//! said loopback.
//!
//! 📌 The posted document is JSON because JSON is the subject: the defect
//! lived only on the path the DSL never takes. The running server itself is
//! configured in the DSL, and the document posted is the one the Admin API
//! hands back, with one site added, so the global options are byte-for-byte
//! those the Pingclairfile produced.
//!
//! 🧭 The server starts with no site at all, so the posted site is a first
//! plaintext load, which the Admin API accepts without a restart. That is what
//! lets the test watch where the new listener lands.

use std::process::{Command, Stdio};

/// 🧹 Ends the child however the test ends.
struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// 🛡️ A JSON site with only a port lands on the `default_bind` interface.
#[tokio::test]
async fn test_admin_json_site_inherits_default_bind() {
    let admin_port = super::free_port();
    let site_port = super::free_port();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("Pingclairfile");
    std::fs::write(
        &config_path,
        format!("{{\n    admin 127.0.0.1:{admin_port}\n    default_bind 127.0.0.1\n}}\n"),
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
    assert_eq!(
        document["global"]["default_bind"],
        serde_json::json!(["127.0.0.1"])
    );

    document["servers"] = serde_json::json!([{
        "listen": [format!(":{site_port}")],
        "routes": [{
            "path": "/*",
            "handler": {"type": "respond", "status": 200, "body": "json-site"}
        }]
    }]);
    let loaded = client
        .post(format!("http://127.0.0.1:{admin_port}/load"))
        .header("Content-Type", "application/json")
        .body(document.to_string())
        .send()
        .await
        .unwrap();
    let status = loaded.status();
    assert!(
        status.is_success(),
        "load failed: {}",
        loaded.text().await.unwrap()
    );

    let served = client
        .get(format!("http://127.0.0.1:{site_port}/"))
        .send()
        .await
        .unwrap();
    let served = (served.status().as_u16(), served.text().await.unwrap());
    // 🎯 A raw connect, so "refused" cannot be confused with an HTTP answer.
    // Only a socket on every interface would accept on the IPv6 loopback.
    let elsewhere = tokio::net::TcpStream::connect(std::net::SocketAddr::from((
        std::net::Ipv6Addr::LOCALHOST,
        site_port,
    )))
    .await
    .map(|_| ())
    .map_err(|error| error.kind());
    assert_eq!(
        (served, elsewhere),
        (
            (200, "json-site".to_string()),
            Err(std::io::ErrorKind::ConnectionRefused)
        )
    );
}
