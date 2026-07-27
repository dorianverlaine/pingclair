use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

struct TestServer {
    process: Child,
    watchdog: Option<Child>,
    server_addresses: Vec<Vec<SocketAddr>>,
    admin_address: Option<SocketAddr>,
    readiness_path: String,
    readiness_token: String,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    stopped: bool,
    _temp_dir: tempfile::TempDir,
}

impl TestServer {
    fn new(config_body: &str) -> Self {
        let temp_dir = tempfile::tempdir().expect("failed to create the test directory");
        let config_path = temp_dir.path().join("config.json");

        let readiness_id = uuid::Uuid::new_v4();
        let readiness_path = format!("/__pingclair_test_ready_{readiness_id}");
        let readiness_token = format!("pingclair-ready-{readiness_id}");
        let mut config: serde_json::Value =
            serde_json::from_str(config_body).expect("invalid integration-test JSON");
        let mut reservations = Vec::new();
        let server_addresses = prepare_server_listeners(
            &mut config,
            &readiness_path,
            &readiness_token,
            &mut reservations,
        );
        let admin_address = prepare_admin_listener(&mut config, &mut reservations);

        // 🧪 Keep every test artifact together so cleanup is atomic and inspectable.
        let mut file = std::fs::File::create(&config_path).unwrap();
        file.write_all(serde_json::to_string_pretty(&config).unwrap().as_bytes())
            .unwrap();

        Self::start(
            temp_dir,
            config_path,
            server_addresses,
            admin_address,
            readiness_path,
            readiness_token,
            reservations,
        )
    }

    /// 📄 Starts the real binary from the extensionless production configuration path.
    fn new_pingclairfile(config_template: &str) -> Self {
        let temp_dir = tempfile::tempdir().expect("failed to create the test directory");
        let config_path = temp_dir.path().join("Pingclairfile");
        let readiness_id = uuid::Uuid::new_v4();
        let readiness_path = format!("/__pingclair_test_ready_{readiness_id}");
        let readiness_token = format!("pingclair-ready-{readiness_id}");
        let mut reservations = Vec::new();
        let address = reserve_loopback_listener(&mut reservations);
        let config = config_template
            .replace("__PINGCLAIR_TEST_LISTEN__", &address.to_string())
            .replace("__PINGCLAIR_TEST_PORT__", &address.port().to_string())
            .replace("__PINGCLAIR_TEST_READINESS_PATH__", &readiness_path)
            .replace("__PINGCLAIR_TEST_READINESS_TOKEN__", &readiness_token);
        assert!(
            !config.contains("__PINGCLAIR_TEST_"),
            "Pingclairfile test fixture contains an unresolved placeholder"
        );

        let mut file = std::fs::File::create(&config_path).unwrap();
        file.write_all(config.as_bytes()).unwrap();

        Self::start(
            temp_dir,
            config_path,
            vec![vec![address]],
            None,
            readiness_path,
            readiness_token,
            reservations,
        )
    }

    /// 🚀 Spawns one isolated Pingclair process after its listener ports are reserved.
    #[allow(clippy::too_many_arguments)]
    fn start(
        temp_dir: tempfile::TempDir,
        config_path: PathBuf,
        server_addresses: Vec<Vec<SocketAddr>>,
        admin_address: Option<SocketAddr>,
        readiness_path: String,
        readiness_token: String,
        reservations: Vec<TcpListener>,
    ) -> Self {
        let tls_store_path = temp_dir.path().join("tls");
        let stdout_path = temp_dir.path().join("stdout.log");
        let stderr_path = temp_dir.path().join("stderr.log");
        std::fs::create_dir(&tls_store_path).expect("failed to create the test TLS store");

        // 🧾 Use files instead of pipes so verbose logs can never block the child.
        let stdout = std::fs::File::create(&stdout_path).unwrap();
        let stderr = std::fs::File::create(&stderr_path).unwrap();
        let bin_path = env!("CARGO_BIN_EXE_pingclair");
        let mut command = Command::new(bin_path);
        command
            .arg("run")
            .arg(&config_path)
            .env("PINGCLAIR_TLS_STORE", &tls_store_path)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));

        // 🧹 Isolate the server so panic and timeout cleanup can reap its descendants.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }

        // 🔓 Release reservations only when the child is ready to bind the ports.
        drop(reservations);
        let mut process = command.spawn().expect("failed to start the test server");
        let watchdog = match spawn_parent_watchdog(process.id()) {
            Ok(watchdog) => watchdog,
            Err(error) => {
                terminate_process_group(&mut process, "test server");
                panic!("failed to start the test parent watchdog: {error}");
            }
        };

        Self {
            process,
            watchdog,
            server_addresses,
            admin_address,
            readiness_path,
            readiness_token,
            stdout_path,
            stderr_path,
            stopped: false,
            _temp_dir: temp_dir,
        }
    }

    fn url(&self, server_index: usize, path: &str) -> String {
        format!("http://{}{}", self.server_addresses[server_index][0], path)
    }

    /// 🔐 Builds an HTTPS URL that preserves the configured SNI host.
    fn tls_url(&self, server_index: usize, host: &str, path: &str) -> String {
        format!(
            "https://{}:{}{}",
            host,
            self.server_addresses[server_index][0].port(),
            path
        )
    }

    fn address(&self, server_index: usize) -> SocketAddr {
        self.server_addresses[server_index][0]
    }

    fn admin_url(&self, path: &str) -> String {
        format!(
            "http://{}{}",
            self.admin_address
                .expect("admin listener is not configured"),
            path
        )
    }

    fn exit_status(&mut self) -> Option<ExitStatus> {
        match self.process.try_wait() {
            Ok(status) => status,
            Err(error) => panic!("failed to inspect the test server: {error}"),
        }
    }

    fn print_diagnostics(&self) {
        for (label, path) in [("STDERR", &self.stderr_path), ("STDOUT", &self.stdout_path)] {
            match std::fs::read_to_string(path) {
                Ok(output) if !output.is_empty() => eprintln!("📋 {label}:\n{output}"),
                Ok(_) => {}
                Err(error) => eprintln!("❌ Failed to read {label}: {error}"),
            }
        }
    }

    fn stop(&mut self) {
        if self.stopped {
            return;
        }

        terminate_process_group(&mut self.process, "test server");
        if let Some(watchdog) = &mut self.watchdog {
            terminate_process_group(watchdog, "test parent watchdog");
        }
        self.stopped = true;
    }

    async fn wait_until_ready(&mut self) -> bool {
        let client = no_proxy_client();
        let url = self.url(0, &self.readiness_path);
        let admin_url = self
            .admin_address
            .map(|address| format!("http://{address}/health"));
        let mut server_ready = false;
        let mut admin_ready = admin_url.is_none();
        for _ in 0..50 {
            if let Some(status) = self.exit_status() {
                eprintln!("❌ Server exited unexpectedly with status: {status}");
                self.stop();
                self.print_diagnostics();
                return false;
            }

            if !server_ready
                && let Ok(response) = client.get(&url).send().await
                && response.status().is_success()
                && let Ok(body) = response.text().await
            {
                server_ready = body == self.readiness_token;
            }
            if !admin_ready && let Some(url) = &admin_url {
                admin_ready = client.get(url).send().await.is_ok();
            }
            if server_ready && admin_ready {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        eprintln!(
            "⏳ Timed out waiting for test readiness (server={server_ready}, admin={admin_ready})."
        );
        self.stop();
        self.print_diagnostics();
        false
    }

    /// 🔐 Waits for the exact readiness token through a real TLS handshake.
    async fn wait_until_tls_ready(&mut self, host: &str) -> bool {
        let client = reqwest::Client::builder()
            .no_proxy()
            .danger_accept_invalid_certs(true)
            .http1_only()
            .resolve(host, self.address(0))
            .build()
            .unwrap();
        let url = self.tls_url(0, host, &self.readiness_path);
        for _ in 0..50 {
            if let Some(status) = self.exit_status() {
                eprintln!("❌ Server exited unexpectedly with status: {status}");
                self.stop();
                self.print_diagnostics();
                return false;
            }

            if let Ok(response) = client.get(&url).send().await
                && response.status().is_success()
                && let Ok(body) = response.text().await
                && body == self.readiness_token
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        eprintln!("⏳ Timed out waiting for TLS test readiness.");
        self.stop();
        self.print_diagnostics();
        false
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn terminate_process_group(process: &mut Child, label: &str) {
    #[cfg(unix)]
    let leader_exited = matches!(process.try_wait(), Ok(Some(_)));
    #[cfg(unix)]
    // SAFETY: 🧯 Every child passed here owns the process group matching its PID.
    unsafe {
        let result = libc::kill(-(process.id() as i32), libc::SIGKILL);
        if result != 0 {
            let error = std::io::Error::last_os_error();
            let process_is_gone = error.raw_os_error() == Some(libc::ESRCH)
                || (leader_exited && error.raw_os_error() == Some(libc::EPERM));
            if !process_is_gone {
                eprintln!("❌ Failed to kill the {label} process group: {error}");
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = label;
        let _ = process.kill();
    }

    let _ = process.wait();
}

fn spawn_parent_watchdog(process_group_id: u32) -> std::io::Result<Option<Child>> {
    spawn_watchdog(std::process::id(), process_group_id)
}

fn spawn_watchdog(parent_process_id: u32, process_group_id: u32) -> std::io::Result<Option<Child>> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        // 🐕 Keep the watchdog outside the harness group so it survives an interrupted test.
        let script = r#"
parent_pid=$1
group_id=$2
while /bin/kill -0 -- "-$group_id" 2>/dev/null; do
    if ! /bin/kill -0 "$parent_pid" 2>/dev/null; then
        /bin/kill -KILL -- "-$group_id" 2>/dev/null
        exit 0
    fi
    sleep 0.1
done
"#;
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(script)
            .arg("pingclair-test-watchdog")
            .arg(parent_process_id.to_string())
            .arg(process_group_id.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        command.spawn().map(Some)
    }
    #[cfg(not(unix))]
    {
        let _ = parent_process_id;
        let _ = process_group_id;
        Ok(None)
    }
}

fn reserve_loopback_listener(reservations: &mut Vec<TcpListener>) -> SocketAddr {
    let listener =
        TcpListener::bind(("127.0.0.1", 0)).expect("failed to reserve a loopback test port");
    let address = listener
        .local_addr()
        .expect("failed to read the reserved test address");
    reservations.push(listener);
    address
}

fn prepare_server_listeners(
    config: &mut serde_json::Value,
    readiness_path: &str,
    readiness_token: &str,
    reservations: &mut Vec<TcpListener>,
) -> Vec<Vec<SocketAddr>> {
    let servers = config
        .get_mut("servers")
        .and_then(serde_json::Value::as_array_mut)
        .expect("integration-test config must contain servers");

    servers
        .iter_mut()
        .map(|server| {
            let listen = server
                .get_mut("listen")
                .and_then(serde_json::Value::as_array_mut)
                .expect("integration-test server must contain a listen array");
            let addresses: Vec<_> = (0..listen.len())
                .map(|_| reserve_loopback_listener(reservations))
                .collect();
            *listen = addresses
                .iter()
                .map(|address| serde_json::Value::String(address.to_string()))
                .collect();

            // 🪪 A per-process token proves that readiness came from this child.
            let routes = server
                .get_mut("routes")
                .and_then(serde_json::Value::as_array_mut)
                .expect("integration-test server must contain routes");
            routes.insert(
                0,
                serde_json::json!({
                    "path": readiness_path,
                    "handler": {
                        "type": "respond",
                        "status": 200,
                        "body": readiness_token
                    }
                }),
            );
            addresses
        })
        .collect()
}

fn prepare_admin_listener(
    config: &mut serde_json::Value,
    reservations: &mut Vec<TcpListener>,
) -> Option<SocketAddr> {
    let admin = config.get_mut("admin")?.as_object_mut()?;
    if !admin
        .get("enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return None;
    }

    let address = reserve_loopback_listener(reservations);
    admin.insert(
        "listen".to_string(),
        serde_json::Value::String(address.to_string()),
    );
    Some(address)
}

/// 🧭 Tests must talk directly to Pingclair, even when macOS has a loopback proxy.
fn no_proxy_client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

/// 🌊 Reads incrementally until the expected protocol marker arrives.
async fn read_until_marker(
    stream: &mut tokio::net::TcpStream,
    marker: &[u8],
    timeout: Duration,
) -> Vec<u8> {
    use tokio::io::AsyncReadExt;

    tokio::time::timeout(timeout, async {
        let mut received = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = stream.read(&mut chunk).await.expect("stream read failed");
            assert!(read > 0, "stream closed before the expected marker");
            received.extend_from_slice(&chunk[..read]);
            if received
                .windows(marker.len())
                .any(|window| window == marker)
            {
                return received;
            }
        }
    })
    .await
    .expect("timed out before the expected marker arrived")
}

/// 📤 Writes one HTTP/1.1 chunk without buffering the event stream.
async fn write_http_chunk(
    stream: &mut tokio::net::tcp::OwnedWriteHalf,
    body: &[u8],
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    stream
        .write_all(format!("{:X}\r\n", body.len()).as_bytes())
        .await?;
    stream.write_all(body).await?;
    stream.write_all(b"\r\n").await?;
    stream.flush().await
}

/// 🧭 Builds a minimal real-proxy fixture for protocol behavior tests.
fn protocol_proxy_config(upstream_address: SocketAddr) -> String {
    protocol_proxy_config_url(format!("http://{upstream_address}"))
}

/// 🌐 Builds a minimal real-proxy fixture with an explicit upstream scheme.
fn protocol_proxy_config_url(upstream_address: String) -> String {
    serde_json::json!({
        "global": { "http3": false },
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "routes": [{
                "path": "/*",
                "handler": {
                    "type": "reverse_proxy",
                    "upstreams": [upstream_address],
                    "load_balance": { "strategy": "round_robin" },
                    "headers_up": {},
                    "headers_down": {}
                }
            }]
        }]
    })
    .to_string()
}

#[tokio::test]
async fn test_drop_reaps_server_and_releases_listener() {
    let config = r#"{
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "routes": [{
                "path": "/",
                "handler": { "type": "respond", "status": 200, "body": "ok" }
            }]
        }]
    }"#;
    let address = {
        let mut server = TestServer::new(config);
        assert!(server.wait_until_ready().await, "server failed to start");
        server.address(0)
    };

    // 🧹 Rebinding proves that Drop waited until the listener was released.
    let rebound = TcpListener::bind(address).expect("test server left its listener behind");
    assert_eq!(rebound.local_addr().unwrap(), address);
}

#[tokio::test]
async fn test_failed_start_reaps_server_and_releases_listener() {
    let config = r#"{
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "routes": [{
                "path": "/",
                "handler": { "type": "intentionally_invalid" }
            }]
        }]
    }"#;
    let mut server = TestServer::new(config);
    let address = server.address(0);

    assert!(
        !server.wait_until_ready().await,
        "invalid configuration unexpectedly started"
    );
    let rebound = TcpListener::bind(address).expect("failed startup left its listener behind");
    assert_eq!(rebound.local_addr().unwrap(), address);
}

#[cfg(unix)]
#[tokio::test]
async fn test_watchdog_kills_group_after_parent_disappears() {
    use std::os::unix::process::CommandExt;

    let mut watched = Command::new("sleep")
        .arg("30")
        .process_group(0)
        .spawn()
        .expect("failed to start the watched process");
    let mut surrogate_parent = Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("failed to start the surrogate parent");
    let mut watchdog = spawn_watchdog(surrogate_parent.id(), watched.id())
        .expect("failed to start the watchdog")
        .expect("watchdog is required on Unix");

    surrogate_parent
        .kill()
        .expect("failed to stop the surrogate parent");
    surrogate_parent
        .wait()
        .expect("failed to reap the surrogate parent");

    for _ in 0..50 {
        if watched
            .try_wait()
            .expect("failed to inspect the watched process")
            .is_some()
        {
            watchdog.wait().expect("failed to reap the watchdog");
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    terminate_process_group(&mut watched, "watchdog test process");
    terminate_process_group(&mut watchdog, "watchdog test helper");
    panic!("watchdog left the watched process running");
}

#[tokio::test]
async fn test_static_file_server() {
    // 📄 Create the static file fixture.
    let tmp_dir = tempfile::tempdir().unwrap();
    let file_path = tmp_dir.path().join("index.html");
    std::fs::write(&file_path, "<h1>Hello World</h1>").unwrap();
    let root_path = tmp_dir.path().to_str().unwrap().replace("\\", "/");

    // ⚙️ Build the JSON configuration.
    let config = format!(
        r#"{{
        "servers": [
            {{
                "listen": ["127.0.0.1:0"],
                "routes": [
                    {{
                        "path": "/",
                        "handler": {{
                            "type": "file_server",
                            "root": "{root_path}"
                        }}
                    }}
                ]
            }}
        ]
    }}"#
    );

    // 🚀 Start the real server binary.
    let mut server = TestServer::new(&config);

    // ⏳ Wait for the unique readiness response.
    assert!(server.wait_until_ready().await, "Server failed to start");

    // ✅ Verify the static response.
    let url = server.url(0, "/index.html");
    let resp = no_proxy_client().get(url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    assert_eq!(text, "<h1>Hello World</h1>");
}

#[tokio::test]
async fn test_admin_api_hot_reload() {
    // 📄 Create distinct fixtures for both configuration versions.
    let tmp_dir = tempfile::tempdir().unwrap();
    let v1_path = tmp_dir.path().join("v1.txt");
    let v2_path = tmp_dir.path().join("v2.txt");
    std::fs::write(&v1_path, "Version 1").unwrap();
    std::fs::write(&v2_path, "Version 2").unwrap();
    let root_path = tmp_dir.path().to_str().unwrap().replace("\\", "/");

    // 🚀 Start with the initial JSON configuration.
    let init_config = format!(
        r#"{{
        "admin": {{
            "enabled": true,
            "listen": "127.0.0.1:0"
        }},
        "servers": [
            {{
                "listen": ["127.0.0.1:0"],
                "routes": [
                    {{
                        "path": "/",
                        "handler": {{
                            "type": "file_server",
                            "root": "{root_path}",
                            "index": ["v1.txt"]
                        }}
                    }}
                ]
            }}
        ]
    }}"#
    );

    let mut server = TestServer::new(&init_config);
    assert!(server.wait_until_ready().await, "Server V1 failed to start");

    // ✅ Verify that the first index file is active.
    let server_url = server.url(0, "/");
    let resp = no_proxy_client().get(&server_url).send().await.unwrap();
    assert_eq!(resp.text().await.unwrap(), "Version 1");

    // 🔄 Apply the replacement configuration through the Admin API.
    let listen_address = server.address(0).to_string();
    let new_config_obj = serde_json::json!({
        "listen": [listen_address],
        "routes": [
            {
                "path": "/",
                "handler": {
                    "type": "file_server",
                    "root": root_path,
                    "index": ["v2.txt"],
                    "browse": false
                }
            }
        ]
    });

    let client = no_proxy_client();
    let reload_resp = client
        .post(server.admin_url("/config/0"))
        .json(&new_config_obj)
        .send()
        .await
        .unwrap();

    assert_eq!(reload_resp.status(), 200);

    // ✅ Verify that the replacement index file is active.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp_v2 = client.get(&server_url).send().await.unwrap();
    assert_eq!(resp_v2.text().await.unwrap(), "Version 2");
}

#[tokio::test]
async fn test_basic_auth_end_to_end() {
    // 🔐 Exercise a bcrypt credential through the complete real-binary pipeline.
    let password_hash = "$2y$04$EBGg0.PJo2Qi2WYiMUqXsuB9orpRrMXiABirLM33AHHNb5GzEcipS";
    let config = serde_json::json!({
        "servers": [
            {
                "listen": ["127.0.0.1:0"],
                "routes": [
                    {
                        "path": "/",
                        "handler": {
                            "type": "pipeline",
                            "handlers": [
                                {
                                    "type": "basic_auth",
                                    "realm": "Test Realm",
                                    "credentials": [
                                        {
                                            "username": "alice",
                                            "password": password_hash,
                                            "hashed": true
                                        }
                                    ]
                                },
                                { "type": "respond", "status": 200, "body": "welcome" }
                            ]
                        }
                    }
                ]
            }
        ]
    })
    .to_string();

    let mut server = TestServer::new(&config);
    let client = no_proxy_client();
    assert!(server.wait_until_ready().await, "server failed to start");
    let url = server.url(0, "/");

    let authed = || async {
        client
            .get(&url)
            .basic_auth("alice", Some("secret1"))
            .send()
            .await
    };

    // 🚫 Missing credentials must return a Basic Auth challenge.
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 401);
    let challenge = resp
        .headers()
        .get("WWW-Authenticate")
        .expect("missing challenge header")
        .to_str()
        .unwrap();
    assert!(
        challenge.contains("Basic"),
        "unexpected challenge: {challenge}"
    );
    assert!(
        challenge.contains("Test Realm"),
        "realm missing: {challenge}"
    );

    // 🚫 An incorrect password must be rejected.
    let resp = client
        .get(&url)
        .basic_auth("alice", Some("wrong"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // 🚫 An unknown user must be rejected.
    let resp = client
        .get(&url)
        .basic_auth("mallory", Some("secret1"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // ✅ Valid credentials must reach the response handler.
    let resp = authed().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "welcome");
}

#[tokio::test]
async fn test_custom_error_pages() {
    // 🎨 Verify custom pages for both static and upstream failures.
    let tmp_dir = tempfile::tempdir().unwrap();
    let page_404 = tmp_dir.path().join("404.html");
    let page_502 = tmp_dir.path().join("502.html");
    std::fs::write(&page_404, "<h1>custom not found</h1>").unwrap();
    std::fs::write(&page_502, "<h1>custom bad gateway</h1>").unwrap();
    // 📁 Keep the document root empty so every static request misses.
    let root = tmp_dir.path().join("www");
    std::fs::create_dir(&root).unwrap();

    let config = format!(
        r#"{{
        "servers": [
            {{
                "listen": ["127.0.0.1:0"],
                "error_pages": {{
                    "404": "{}",
                    "500": "{}",
                    "502": "{}"
                }},
                "routes": [
                    {{
                        "path": "/static/*",
                        "handler": {{
                            "type": "file_server",
                            "root": "{}"
                        }}
                    }},
                    {{
                        "path": "/api/*",
                        "handler": {{
                            "type": "reverse_proxy",
                            "upstreams": ["http://127.0.0.1:1"],
                            "load_balance": {{ "strategy": "round_robin" }},
                            "headers_up": {{}},
                            "headers_down": {{}}
                        }}
                    }}
                ]
            }}
        ]
    }}"#,
        page_404.display(),
        page_502.display(),
        page_502.display(),
        root.display()
    );

    let mut server = TestServer::new(&config);
    let client = no_proxy_client();
    assert!(server.wait_until_ready().await, "server failed to start");

    // ✅ A static miss must use the custom 404 page.
    let resp = client
        .get(server.url(0, "/static/missing.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    assert_eq!(resp.headers().get("Content-Type").unwrap(), "text/html");
    assert_eq!(resp.text().await.unwrap(), "<h1>custom not found</h1>");

    // ✅ A dead upstream must use the configured gateway-error page.
    // ℹ️ Pingora may classify connection refusal as either 500 or 502.
    let resp = client
        .get(server.url(0, "/api/thing"))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    assert!(status == 500 || status == 502, "unexpected status {status}");
    assert_eq!(resp.text().await.unwrap(), "<h1>custom bad gateway</h1>");
}

#[tokio::test]
async fn test_cors_and_access_control_end_to_end() {
    let config = r#"{
        "servers": [
            {
                "listen": ["127.0.0.1:0"],
                "routes": [
                    {
                        "path": "/",
                        "handler": {
                            "type": "pipeline",
                            "handlers": [
                                {
                                    "type": "cors",
                                    "allowed_origins": ["https://app.example"],
                                    "allowed_methods": ["GET", "POST"],
                                    "allowed_headers": ["Content-Type"],
                                    "exposed_headers": ["X-Request-Id"],
                                    "allow_credentials": true,
                                    "max_age": 600
                                },
                                {
                                    "type": "access_control",
                                    "allowed_ips": ["0.0.0.0/0"],
                                    "denied_user_agents": ["(?i)blockedbot"]
                                },
                                { "type": "respond", "status": 200, "body": "welcome" }
                            ]
                        }
                    }
                ]
            }
        ]
    }"#;
    let mut server = TestServer::new(config);
    let client = no_proxy_client();
    assert!(server.wait_until_ready().await, "server failed to start");
    let url = server.url(0, "/");

    let response = client
        .get(&url)
        .header("Origin", "https://app.example")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        "https://app.example"
    );
    assert_eq!(
        response.headers()["access-control-allow-credentials"],
        "true"
    );
    assert_eq!(response.text().await.unwrap(), "welcome");

    let response = client
        .request(reqwest::Method::OPTIONS, &url)
        .header("Origin", "https://app.example")
        .header("Access-Control-Request-Method", "POST")
        .header("Access-Control-Request-Headers", "Content-Type")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);
    assert_eq!(response.headers()["access-control-max-age"], "600");

    let response = client
        .get(&url)
        .header("User-Agent", "BlockedBot/1.0")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
}

#[tokio::test]
async fn test_regex_rewrite_reaches_the_rewritten_static_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    std::fs::write(temp_dir.path().join("hello.txt"), "rewritten").unwrap();
    let root = temp_dir.path().to_str().unwrap().replace("\\", "/");
    let config = format!(
        r#"{{
        "servers": [{{
            "listen": ["127.0.0.1:0"],
            "routes": [{{
                "path": "/*",
                "handler": {{
                    "type": "pipeline",
                    "handlers": [
                        {{
                            "type": "rewrite",
                            "regex": "^/api/(.*)$",
                            "regex_replace": "/$1"
                        }},
                        {{ "type": "file_server", "root": "{root}" }}
                    ]
                }}
            }}]
        }}]
    }}"#
    );
    let mut server = TestServer::new(&config);
    assert!(server.wait_until_ready().await, "Server failed to start");

    let response = no_proxy_client()
        .get(server.url(0, "/api/hello.txt?cache=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "rewritten");
}

#[tokio::test]
async fn test_compression() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let file_path = tmp_dir.path().join("big.txt");
    // 📦 Create a fixture large enough to benefit from compression.
    let content = "Pingclair Compression Test ".repeat(100);
    std::fs::write(&file_path, &content).unwrap();
    let root_path = tmp_dir.path().to_str().unwrap().replace("\\", "/");

    let config = format!(
        r#"{{
        "servers": [
            {{
                "listen": ["127.0.0.1:0"],
                "routes": [
                    {{
                        "path": "/",
                        "handler": {{
                            "type": "file_server",
                            "root": "{root_path}",
                            "compress": true
                        }}
                    }}
                ]
            }}
        ]
    }}"#
    );

    let mut server = TestServer::new(&config);
    assert!(server.wait_until_ready().await, "Server failed to start");

    let client = no_proxy_client();
    let url = server.url(0, "/big.txt");

    // 🗜️ Request and verify gzip compression.
    let resp: reqwest::Response = client
        .get(&url)
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("Content-Encoding").unwrap(), "gzip");

    let compressed_bytes = resp.bytes().await.expect("Failed to get bytes");

    // 🔍 Decompress the response explicitly for byte-level verification.
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut decoder = GzDecoder::new(&compressed_bytes[..]);
    let mut decompressed = String::new();
    decoder
        .read_to_string(&mut decompressed)
        .expect("Failed to decompress");

    assert_eq!(decompressed, content);

    // 🗜️ Request Brotli compression when the build supports it.
    let resp_br: reqwest::Response = client
        .get(&url)
        .header("Accept-Encoding", "br")
        .send()
        .await
        .expect("Failed to send br request");

    // ℹ️ A manually supplied header still lets the test inspect Brotli negotiation.
    // 📊 Pingclair prioritizes Brotli, then Zstandard, then gzip.
    if resp_br
        .headers()
        .get("Content-Encoding")
        .map(|v| v == "br")
        .unwrap_or(false)
    {
        println!("✅ Brotli verified.");
    }
}

#[tokio::test]
async fn test_reverse_proxy_custom_gzip_types() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // 🧪 Serve a MIME type excluded from the default gzip list.
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let body = "custom gzip type ".repeat(200);
    let upstream_body = body.clone();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut request = [0u8; 2048];
        let _ = stream.read(&mut request).await.unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/wasm\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            upstream_body.len(),
            upstream_body
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });

    let config = serde_json::json!({
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "gzip_types": ["application/wasm"],
            "routes": [{
                "path": "/",
                "handler": {
                    "type": "reverse_proxy",
                    "upstreams": [format!("http://{upstream_address}")],
                    "load_balance": { "strategy": "round_robin" },
                    "headers_up": {},
                    "headers_down": {}
                }
            }]
        }]
    })
    .to_string();

    let mut server = TestServer::new(&config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let response = no_proxy_client()
        .get(server.url(0, "/module.wasm"))
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers().get("Content-Encoding").unwrap(), "gzip");

    // 🔍 The compressed proxy response must round-trip to the upstream body.
    use flate2::read::GzDecoder;
    use std::io::Read;
    let compressed = response.bytes().await.unwrap();
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut decompressed = String::new();
    decoder.read_to_string(&mut decompressed).unwrap();
    assert_eq!(decompressed, body);
    upstream_task.await.unwrap();
}

#[tokio::test]
async fn test_trusted_proxies_control_verified_client_identity() {
    let server_config = |trusted_proxies: Vec<&str>| {
        serde_json::json!({
            "global": {
                "http3": false,
                "trusted_proxies": trusted_proxies
            },
            "servers": [{
                "listen": ["127.0.0.1:0"],
                "routes": [{
                    "path": "/",
                    "handler": {
                        "type": "pipeline",
                        "handlers": [
                            {
                                "type": "access_control",
                                "allowed_ips": ["203.0.113.7/32"]
                            },
                            { "type": "respond", "status": 200, "body": "verified" }
                        ]
                    }
                }]
            }]
        })
        .to_string()
    };
    let client = no_proxy_client();

    {
        // ✅ A configured loopback proxy may assert the downstream client IP.
        let config = server_config(vec!["127.0.0.1/32"]);
        let mut server = TestServer::new(&config);
        assert!(server.wait_until_ready().await, "server failed to start");
        let url = server.url(0, "/");

        let allowed = client
            .get(&url)
            .header("X-Forwarded-For", "203.0.113.7")
            .send()
            .await
            .unwrap();
        assert_eq!(allowed.status(), 200);

        // 🚫 Missing or malformed proxy identity fails closed to the loopback peer.
        assert_eq!(client.get(&url).send().await.unwrap().status(), 403);
        assert_eq!(
            client
                .get(&url)
                .header("X-Forwarded-For", "203.0.113.7, invalid")
                .send()
                .await
                .unwrap()
                .status(),
            403
        );
    }

    {
        // 🚫 Without trusted_proxies, the same spoofed header cannot bypass policy.
        let config = server_config(Vec::new());
        let mut server = TestServer::new(&config);
        assert!(server.wait_until_ready().await, "server failed to start");
        let denied = client
            .get(server.url(0, "/"))
            .header("X-Forwarded-For", "203.0.113.7")
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status(), 403);
    }
}

#[tokio::test]
async fn test_untrusted_forwarding_headers_are_sanitized_upstream() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut request = vec![0u8; 8192];
        let read = stream.read(&mut request).await.unwrap();
        request.truncate(read);
        request_tx
            .send(String::from_utf8(request).unwrap())
            .unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });

    let config = serde_json::json!({
        "global": { "http3": false },
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "routes": [{
                "path": "/",
                "handler": {
                    "type": "reverse_proxy",
                    "upstreams": [format!("http://{upstream_address}")],
                    "load_balance": { "strategy": "round_robin" },
                    "headers_up": {
                        "X-Verified-Placeholder": "{remote_ip}"
                    },
                    "headers_down": {}
                }
            }]
        }]
    })
    .to_string();

    let mut server = TestServer::new(&config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let response = no_proxy_client()
        .get(server.url(0, "/"))
        .header("X-Forwarded-For", "203.0.113.7")
        .header("X-Real-IP", "203.0.113.8")
        .header("X-Forwarded-Proto", "https")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "ok");

    // 🛡️ The upstream sees socket-derived identity, not attacker headers.
    let upstream_request = request_rx.await.unwrap().to_ascii_lowercase();
    assert!(upstream_request.contains("\r\nx-forwarded-for: 127.0.0.1\r\n"));
    assert!(upstream_request.contains("\r\nx-real-ip: 127.0.0.1\r\n"));
    assert!(upstream_request.contains("\r\nx-forwarded-proto: http\r\n"));
    assert!(
        upstream_request.contains("\r\nx-forwarded-host: 127.0.0.1:"),
        "unexpected upstream request:\n{upstream_request}"
    );
    assert!(upstream_request.contains("\r\nx-verified-placeholder: 127.0.0.1\r\n"));
    upstream_task.await.unwrap();
}

#[tokio::test]
async fn test_handle_path_and_outer_headers_reach_the_proxy_exchange() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut request = vec![0u8; 8192];
        let read = stream.read(&mut request).await.unwrap();
        request.truncate(read);
        request_tx
            .send(String::from_utf8(request).unwrap())
            .unwrap();
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nServer: upstream\r\nVary: Accept-Encoding\r\nConnection: close\r\n\r\nok",
            )
            .await
            .unwrap();
    });

    let config = serde_json::json!({
        "global": { "http3": false },
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "routes": [{
                "path": "/api/*",
                "handler": {
                    "type": "pipeline",
                    "handlers": [
                        {
                            "type": "headers",
                            "set": { "X-Outer": "outer" },
                            "add": { "Vary": "Origin" },
                            "remove": ["Server"]
                        },
                        {
                            "type": "handle_path",
                            "prefix": "/api",
                            "handlers": [{
                                "type": "reverse_proxy",
                                "upstreams": [format!("http://{upstream_address}")],
                                "load_balance": { "strategy": "round_robin" },
                                "headers_up": {},
                                "headers_down": {
                                    "X-Outer": "proxy-must-not-overwrite",
                                    "X-Proxy": "proxy"
                                }
                            }]
                        }
                    ]
                }
            }]
        }]
    })
    .to_string();

    let mut server = TestServer::new(&config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let response = no_proxy_client()
        .get(server.url(0, "/api/users?q=1"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-outer"], "outer");
    assert_eq!(response.headers()["x-proxy"], "proxy");
    assert!(response.headers().get("server").is_none());
    assert!(response.headers().contains_key("x-request-id"));
    assert!(
        response
            .headers()
            .get_all("vary")
            .iter()
            .any(|value| value == "Origin")
    );
    assert_eq!(response.text().await.unwrap(), "ok");

    // 🧭 The stripped path and shared request ID must reach the actual upstream request.
    let upstream_request = request_rx.await.unwrap().to_ascii_lowercase();
    assert!(upstream_request.starts_with("get /users?q=1 http/1.1\r\n"));
    assert!(upstream_request.contains("\r\nx-request-id: "));
    upstream_task.await.unwrap();
}

#[tokio::test]
async fn test_production_cache_headers_compose_with_reverse_proxy() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        for _ in 0..3 {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut request = vec![0u8; 8192];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nServer: upstream\r\nConnection: close\r\n\r\nok",
                )
                .await
                .unwrap();
        }
    });

    let config = format!(
        r#"
        {{
            admin off
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            header {{
                Strict-Transport-Security "max-age=31536000; includeSubDomains"
                X-Frame-Options "DENY"
                -Server
            }}

            @api path /api/*
            header @api Cache-Control "no-store"

            @hashed path /assets/*
            header @hashed Cache-Control "public, max-age=31536000, immutable"

            @rest {{
                not path /assets/*
                not path /api/*
            }}
            header @rest Cache-Control "no-cache"

            reverse_proxy http://{upstream_address}
        }}
        "#
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = no_proxy_client();
    for (path, expected_cache) in [
        ("/api/session", "no-store"),
        (
            "/assets/app.abc123.js",
            "public, max-age=31536000, immutable",
        ),
        ("/index.html", "no-cache"),
    ] {
        let response = client.get(server.url(0, path)).send().await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some(expected_cache),
            "unexpected headers for {path}: {:?}",
            response.headers()
        );
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert_eq!(
            response.headers()["strict-transport-security"],
            "max-age=31536000; includeSubDomains"
        );
        assert!(response.headers().get("server").is_none());
        assert_eq!(response.text().await.unwrap(), "ok");
    }

    upstream_task.await.unwrap();
}

#[tokio::test]
async fn test_pingclairfile_internal_tls_serves_trusted_h1_and_h2() {
    let config = r#"
        {
            admin off
        }

        https://portfolio.test:__PINGCLAIR_TEST_PORT__ {
            tls internal

            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "internal-ok"
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(
        server.wait_until_tls_ready("portfolio.test").await,
        "server failed to start with internal TLS"
    );

    let root_path = server._temp_dir.path().join("tls/internal/root.crt");
    let authority_path = server._temp_dir.path().join("tls/internal/authority.json");
    let leaf_path = server
        ._temp_dir
        .path()
        .join("tls/internal/certificates/portfolio_test.json");
    let root = reqwest::Certificate::from_pem(&std::fs::read(&root_path).unwrap()).unwrap();
    let base_builder = || {
        reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(root.clone())
            .resolve("portfolio.test", server.address(0))
    };

    let h1_client = base_builder().http1_only().build().unwrap();
    let h1_response = h1_client
        .get(server.tls_url(0, "portfolio.test", "/h1"))
        .send()
        .await
        .unwrap();
    assert_eq!(h1_response.version(), reqwest::Version::HTTP_11);
    assert_eq!(h1_response.text().await.unwrap(), "internal-ok");

    let h2_client = base_builder().build().unwrap();
    let h2_response = h2_client
        .get(server.tls_url(0, "portfolio.test", "/h2"))
        .send()
        .await
        .unwrap();
    assert_eq!(h2_response.version(), reqwest::Version::HTTP_2);
    assert_eq!(h2_response.text().await.unwrap(), "internal-ok");

    assert!(authority_path.is_file());
    assert!(leaf_path.is_file());
    assert_eq!(
        std::fs::read_to_string(root_path)
            .unwrap()
            .matches("BEGIN CERTIFICATE")
            .count(),
        1
    );
}

#[tokio::test]
async fn test_sse_proxy_flushes_each_event_incrementally() {
    use tokio::io::AsyncWriteExt;

    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let (first_written_tx, first_written_rx) = tokio::sync::oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let _ = read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(2)).await;
        let (_, mut writer) = stream.into_split();
        writer
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        write_http_chunk(&mut writer, b"data: first\n\n")
            .await
            .unwrap();
        first_written_tx.send(()).unwrap();
        tokio::time::sleep(Duration::from_millis(700)).await;
        write_http_chunk(&mut writer, b"data: second\n\n")
            .await
            .unwrap();
        writer.write_all(b"0\r\n\r\n").await.unwrap();
    });

    let config = serde_json::json!({
        "global": { "http3": false },
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "routes": [{
                "path": "/events",
                "handler": {
                    "type": "reverse_proxy",
                    "upstreams": [format!("http://{upstream_address}")],
                    "load_balance": { "strategy": "round_robin" },
                    "headers_up": {},
                    "headers_down": {},
                    "flush_interval": -1
                }
            }]
        }]
    })
    .to_string();

    let mut server = TestServer::new(&config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let mut client = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    client.set_nodelay(true).unwrap();
    client
        .write_all(
            format!(
                "GET /events HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                server.address(0)
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    first_written_rx.await.unwrap();
    let first =
        read_until_marker(&mut client, b"data: first\n\n", Duration::from_millis(500)).await;
    assert!(
        !first
            .windows(b"data: second\n\n".len())
            .any(|window| window == b"data: second\n\n"),
        "the second event arrived before its upstream delay"
    );
    let _ = read_until_marker(&mut client, b"data: second\n\n", Duration::from_secs(2)).await;
    upstream_task.await.unwrap();
}

#[tokio::test]
async fn test_sse_client_disconnect_cancels_the_upstream_exchange() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let (first_written_tx, first_written_rx) = tokio::sync::oneshot::channel();
    let (cancelled_tx, cancelled_rx) = tokio::sync::oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let _ = read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(2)).await;
        let (mut reader, mut writer) = stream.into_split();
        writer
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
            )
            .await
            .unwrap();
        write_http_chunk(&mut writer, b"data: first\n\n")
            .await
            .unwrap();
        first_written_tx.send(()).unwrap();

        let payload = vec![b'x'; 16 * 1024];
        let mut probe = [0u8; 1];
        let mut interval = tokio::time::interval(Duration::from_millis(10));
        loop {
            tokio::select! {
                read = reader.read(&mut probe) => {
                    if !matches!(read, Ok(n) if n > 0) {
                        break;
                    }
                }
                _ = interval.tick() => {
                    if write_http_chunk(&mut writer, &payload).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = cancelled_tx.send(());
    });

    let config = serde_json::json!({
        "global": { "http3": false },
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "routes": [{
                "path": "/events",
                "handler": {
                    "type": "reverse_proxy",
                    "upstreams": [format!("http://{upstream_address}")],
                    "load_balance": { "strategy": "round_robin" },
                    "headers_up": {},
                    "headers_down": {},
                    "flush_interval": -1
                }
            }]
        }]
    })
    .to_string();

    let mut server = TestServer::new(&config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let mut client = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    client.set_nodelay(true).unwrap();
    client
        .write_all(
            format!(
                "GET /events HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                server.address(0)
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    first_written_rx.await.unwrap();
    let _ = read_until_marker(&mut client, b"data: first\n\n", Duration::from_secs(2)).await;
    drop(client);

    let cancelled = tokio::time::timeout(Duration::from_secs(3), cancelled_rx).await;
    if cancelled.is_err() {
        upstream_task.abort();
        server.print_diagnostics();
    }
    assert!(
        cancelled.is_ok(),
        "the upstream exchange survived the downstream disconnect"
    );
    upstream_task.await.unwrap();
}

#[tokio::test]
async fn test_expect_continue_round_trips_before_the_request_body() {
    use tokio::io::AsyncWriteExt;

    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let headers = read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(2)).await;
        assert!(
            String::from_utf8_lossy(&headers)
                .to_ascii_lowercase()
                .contains("\r\nexpect: 100-continue\r\n")
        );
        stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .unwrap();
        let body = read_until_marker(&mut stream, b"hello world", Duration::from_secs(2)).await;
        request_tx.send(body).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });

    let mut server = TestServer::new(&protocol_proxy_config(upstream_address));
    assert!(server.wait_until_ready().await, "server failed to start");
    let mut client = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    client
        .write_all(
            format!(
                "POST /upload HTTP/1.1\r\nHost: {}\r\nContent-Length: 11\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
                server.address(0)
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let interim = read_until_marker(&mut client, b"\r\n\r\n", Duration::from_secs(2)).await;
    assert!(
        String::from_utf8_lossy(&interim).starts_with("HTTP/1.1 100"),
        "unexpected interim response: {}",
        String::from_utf8_lossy(&interim)
    );
    client.write_all(b"hello world").await.unwrap();
    let final_response =
        read_until_marker(&mut client, b"\r\n\r\nok", Duration::from_secs(2)).await;
    assert!(
        String::from_utf8_lossy(&final_response).contains("HTTP/1.1 200"),
        "unexpected final response: {}",
        String::from_utf8_lossy(&final_response)
    );
    assert!(
        request_rx
            .await
            .unwrap()
            .windows(b"hello world".len())
            .any(|window| window == b"hello world")
    );
    upstream_task.await.unwrap();
}

#[tokio::test]
async fn test_early_hints_reach_the_client_before_the_final_response() {
    use tokio::io::AsyncWriteExt;

    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let (hints_written_tx, hints_written_rx) = tokio::sync::oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let _ = read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(2)).await;
        stream
            .write_all(
                b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style\r\n\r\n",
            )
            .await
            .unwrap();
        hints_written_tx.send(()).unwrap();
        tokio::time::sleep(Duration::from_millis(700)).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });

    let mut server = TestServer::new(&protocol_proxy_config(upstream_address));
    assert!(server.wait_until_ready().await, "server failed to start");
    let mut client = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    client
        .write_all(
            format!(
                "GET /hints HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                server.address(0)
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    hints_written_rx.await.unwrap();
    let hints = read_until_marker(&mut client, b"\r\n\r\n", Duration::from_millis(500)).await;
    let hints_text = String::from_utf8_lossy(&hints);
    assert!(
        hints_text.starts_with("HTTP/1.1 103"),
        "unexpected informational response: {hints_text}"
    );
    assert!(
        hints_text
            .to_ascii_lowercase()
            .contains("link: </style.css>")
    );
    assert!(!hints_text.contains("HTTP/1.1 200"));

    let final_response =
        read_until_marker(&mut client, b"\r\n\r\nok", Duration::from_secs(2)).await;
    assert!(String::from_utf8_lossy(&final_response).contains("HTTP/1.1 200"));
    upstream_task.await.unwrap();
}

#[tokio::test]
async fn test_declared_request_trailers_fail_clearly_without_an_upstream_exchange() {
    use tokio::io::AsyncWriteExt;

    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let mut server = TestServer::new(&protocol_proxy_config(upstream_address));
    assert!(server.wait_until_ready().await, "server failed to start");
    let mut client = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    client
        .write_all(
            format!(
                "POST /upload HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\nX-Checksum: abc\r\n\r\n",
                server.address(0)
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let response =
        read_until_marker(&mut client, b"501 Not Implemented", Duration::from_secs(2)).await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 501"));
    assert!(
        tokio::time::timeout(Duration::from_millis(300), upstream.accept())
            .await
            .is_err(),
        "request trailers unexpectedly reached an upstream connection"
    );
}

#[tokio::test]
async fn test_upstream_response_trailers_fail_before_response_commit() {
    use tokio::io::AsyncWriteExt;

    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let _ = read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(2)).await;
        let _ = stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\nConnection: close\r\n\r\n2\r\nok\r\n0\r\nX-Checksum: abc\r\n\r\n",
            )
            .await;
    });

    let mut server = TestServer::new(&protocol_proxy_config(upstream_address));
    assert!(server.wait_until_ready().await, "server failed to start");
    let response = no_proxy_client()
        .get(server.url(0, "/trailers"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    assert_eq!(response.text().await.unwrap(), "502 Bad Gateway");
    upstream_task.await.unwrap();
}

#[tokio::test]
async fn test_h2c_prior_knowledge_reaches_the_real_proxy_path() {
    use tokio::io::AsyncWriteExt;

    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let request = read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(2)).await;
        assert!(String::from_utf8_lossy(&request).starts_with("GET /h2c HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nh2c-ok")
            .await
            .unwrap();
    });

    let mut server = TestServer::new(&protocol_proxy_config(upstream_address));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = reqwest::Client::builder()
        .no_proxy()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let response = client.get(server.url(0, "/h2c")).send().await.unwrap();

    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    assert_eq!(response.text().await.unwrap(), "h2c-ok");
    upstream_task.await.unwrap();
}

#[tokio::test]
async fn test_grpc_h2c_upstream_preserves_response_trailers() {
    use bytes::Bytes;

    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let (response_read_tx, response_read_rx) = tokio::sync::oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.unwrap();
        let mut connection = h2::server::handshake(stream).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(request.uri().path(), "/grpc.health.v1.Health/Check");
        assert_eq!(
            request.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "application/grpc"
        );

        let response = http::Response::builder()
            .status(200)
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .body(())
            .unwrap();
        let mut body = respond.send_response(response, false).unwrap();
        body.send_data(Bytes::from_static(b"\0\0\0\0\0"), false)
            .unwrap();
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
        trailers.insert("grpc-message", http::HeaderValue::from_static("healthy"));
        body.send_trailers(trailers).unwrap();

        // 🌊 Keeps driving the H2 connection until the queued trailers are delivered.
        tokio::select! {
            _ = async {
                while connection.accept().await.is_some() {}
            } => {}
            _ = response_read_rx => {}
        }
    });

    let config = protocol_proxy_config_url(format!("h2c://{upstream_address}"));
    let mut server = TestServer::new(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let downstream = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    let (mut client, connection) = h2::client::handshake(downstream).await.unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!(
            "http://{}/grpc.health.v1.Health/Check",
            server.address(0)
        ))
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
    let (response, _) = client.send_request(request, true).unwrap();
    let response = response.await.unwrap();

    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(
        response.headers().get(http::header::CONTENT_TYPE).unwrap(),
        "application/grpc"
    );
    let mut body = response.into_body();
    assert_eq!(
        body.data().await.unwrap().unwrap(),
        Bytes::from_static(b"\0\0\0\0\0")
    );
    assert!(body.data().await.is_none());
    let trailers = body.trailers().await.unwrap().unwrap();
    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
    assert_eq!(trailers.get("grpc-message").unwrap(), "healthy");

    response_read_tx.send(()).unwrap();
    connection_task.abort();
    let _ = connection_task.await;
    upstream_task.await.unwrap();
}

#[tokio::test]
async fn test_websocket_upgrade_tunnels_bytes_in_both_directions() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let request = read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(2)).await;
        let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
        assert!(request.contains("\r\nconnection: upgrade\r\n"));
        assert!(request.contains("\r\nupgrade: websocket\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .unwrap();

        let mut client_payload = [0u8; 11];
        stream.read_exact(&mut client_payload).await.unwrap();
        assert_eq!(&client_payload, b"client-ping");
        stream.write_all(b"upstream-pong").await.unwrap();
    });

    let mut server = TestServer::new(&protocol_proxy_config(upstream_address));
    assert!(server.wait_until_ready().await, "server failed to start");
    let mut client = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    client
        .write_all(
            format!(
                "GET /socket HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
                server.address(0)
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let response = read_until_marker(&mut client, b"\r\n\r\n", Duration::from_secs(2)).await;
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 101"),
        "unexpected upgrade response: {}",
        String::from_utf8_lossy(&response)
    );
    client.write_all(b"client-ping").await.unwrap();
    let downstream = read_until_marker(&mut client, b"upstream-pong", Duration::from_secs(2)).await;
    assert!(
        downstream
            .windows(b"upstream-pong".len())
            .any(|window| window == b"upstream-pong")
    );
    upstream_task.await.unwrap();
}
