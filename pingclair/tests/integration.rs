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
        let tls_store_path = temp_dir.path().join("tls");
        let stdout_path = temp_dir.path().join("stdout.log");
        let stderr_path = temp_dir.path().join("stderr.log");
        std::fs::create_dir(&tls_store_path).expect("failed to create the test TLS store");

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
                            "root": "{}"
                        }}
                    }}
                ]
            }}
        ]
    }}"#,
        root_path
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
                            "root": "{}",
                            "index": ["v1.txt"]
                        }}
                    }}
                ]
            }}
        ]
    }}"#,
        root_path
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
        "unexpected challenge: {}",
        challenge
    );
    assert!(
        challenge.contains("Test Realm"),
        "realm missing: {}",
        challenge
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
    assert!(
        status == 500 || status == 502,
        "unexpected status {}",
        status
    );
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
                        {{ "type": "file_server", "root": "{}" }}
                    ]
                }}
            }}]
        }}]
    }}"#,
        root
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
                            "root": "{}",
                            "compress": true
                        }}
                    }}
                ]
            }}
        ]
    }}"#,
        root_path
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
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
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
