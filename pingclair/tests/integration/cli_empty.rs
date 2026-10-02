// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 An absent default file starts an admin-only process, while explicit paths fail closed.

use std::process::{Command, Stdio};

struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(unix)]
#[tokio::test]
async fn cli_run_without_config_starts_admin_only() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("notify.sock");
    let notify = std::os::unix::net::UnixDatagram::bind(&socket).unwrap();
    notify.set_nonblocking(true).unwrap();
    // 🧭 This contract uses the default admin port; refuse to probe another process.
    let held = std::net::TcpListener::bind("127.0.0.1:2019")
        .expect("the default admin port must be free for this test");
    drop(held);
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_pingclair"))
            .arg("run")
            .current_dir(dir.path())
            .env("PINGCLAIR_TLS_STORE", dir.path().join("store"))
            .env("NOTIFY_SOCKET", &socket)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut ready = false;
    for _ in 0..200 {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "empty startup exited"
        );
        let mut message = [0; 512];
        if let Ok(length) = notify.recv(&mut message)
            && String::from_utf8_lossy(&message[..length]).contains("READY=1")
        {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        ready,
        "the child never confirmed that its listeners were prepared"
    );
    let client = super::no_proxy_client();
    let document: serde_json::Value = client
        .get("http://127.0.0.1:2019/config/")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(document["servers"], serde_json::json!([]));
    assert_eq!(document["admin"]["enabled"], true);
    assert_eq!(document["admin"]["listen"], "127.0.0.1:2019");
    let port = super::free_port();
    let token = uuid::Uuid::new_v4().to_string();
    let source = |body: &str| {
        format!("{{\n admin 127.0.0.1:2019\n}}\nhttp://127.0.0.1:{port} {{\n respond {body}\n}}\n")
    };
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let taken = held.local_addr().unwrap().port();
    let refused = client
        .post("http://127.0.0.1:2019/load")
        .header("Content-Type", "text/caddyfile")
        .body(format!(
            "{}http://127.0.0.1:{taken} {{\n respond taken\n}}\n",
            source(&token)
        ))
        .send()
        .await
        .unwrap();
    assert!(!refused.status().is_success());
    assert!(
        super::port_is_free(port),
        "failed bootstrap left a listener bound"
    );
    assert_eq!(
        client
            .get("http://127.0.0.1:2019/config/")
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap(),
        document
    );
    let loaded = client
        .post("http://127.0.0.1:2019/load")
        .header("Content-Type", "text/caddyfile")
        .body(source(&token))
        .send()
        .await
        .unwrap();
    let status = loaded.status();
    assert!(
        status.is_success(),
        "first HTTP load failed: {}",
        loaded.text().await.unwrap()
    );
    let url = format!("http://127.0.0.1:{port}/");
    assert_eq!(
        client.get(&url).send().await.unwrap().text().await.unwrap(),
        token
    );
    let h2 = reqwest::Client::builder()
        .no_proxy()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let response = h2.get(&url).send().await.unwrap();
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    assert_eq!(response.text().await.unwrap(), token);
    let updated = uuid::Uuid::new_v4().to_string();
    assert!(
        client
            .post("http://127.0.0.1:2019/load")
            .header("Content-Type", "text/caddyfile")
            .body(source(&updated))
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    assert_eq!(
        client.get(&url).send().await.unwrap().text().await.unwrap(),
        updated
    );
    assert_eq!(
        h2.get(&url).send().await.unwrap().text().await.unwrap(),
        updated
    );
    for signal in ["-HUP", "-USR1"] {
        assert!(
            Command::new("kill")
                .args([signal, &child.0.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "empty startup terminated on {signal}"
        );
        assert!(
            client
                .get("http://127.0.0.1:2019/config/")
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
        );
    }
    drop(child);
    for args in [
        vec!["validate"],
        vec!["run", "missing.Pingclairfile"],
        vec!["run", "-c", "missing.Pingclairfile"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_pingclair"))
            .args(args)
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "an absent required file was accepted"
        );
    }
}

#[tokio::test]
async fn cli_run_resume_without_default_files_uses_autosave() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    std::fs::create_dir(&store).unwrap();
    let port = super::free_port();
    let token = uuid::Uuid::new_v4().to_string();
    let source = format!("{{\n admin off\n}}\nhttp://127.0.0.1:{port} {{\n respond {token}\n}}\n");
    let document = pingclair_config::compile(&source).unwrap();
    // 💾 Autosave is the admin API's JSON document, even when its source was DSL.
    std::fs::write(
        store.join("autosave.json"),
        serde_json::to_vec(&document).unwrap(),
    )
    .unwrap();
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_pingclair"))
            .args(["run", "--resume"])
            .current_dir(dir.path())
            .env("PINGCLAIR_TLS_STORE", &store)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let client = super::no_proxy_client();
    let mut ready = false;
    for _ in 0..200 {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "resume exited before readiness"
        );
        if let Ok(response) = client.get(format!("http://127.0.0.1:{port}/")).send().await
            && response.text().await.unwrap() == token
        {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(ready, "resume never served its own readiness token");
}

#[cfg(unix)]
#[tokio::test]
async fn cli_stdin_startup_survives_reload_signals() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("notify.sock");
    let notify = std::os::unix::net::UnixDatagram::bind(&socket).unwrap();
    notify.set_nonblocking(true).unwrap();
    let port = super::free_port();
    let token = uuid::Uuid::new_v4().to_string();
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_pingclair"))
            .args(["run", "-c", "-"])
            .env("PINGCLAIR_TLS_STORE", dir.path().join("store"))
            .env("NOTIFY_SOCKET", &socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    child
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(
            format!("{{\n admin off\n}}\nhttp://127.0.0.1:{port} {{\n respond {token}\n}}\n")
                .as_bytes(),
        )
        .unwrap();
    let mut ready = false;
    for _ in 0..200 {
        assert!(child.0.try_wait().unwrap().is_none());
        let mut message = [0; 512];
        if let Ok(length) = notify.recv(&mut message)
            && String::from_utf8_lossy(&message[..length]).contains("READY=1")
        {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(ready);
    let client = super::no_proxy_client();
    for signal in ["-HUP", "-USR1"] {
        assert!(
            Command::new("kill")
                .args([signal, &child.0.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "stdin startup terminated on {signal}"
        );
        assert_eq!(
            client
                .get(format!("http://127.0.0.1:{port}/"))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
            token
        );
    }
}
