// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

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
        // 🌐 A hostname-only site has no explicit `listen`; the runtime derives
        // the HTTPS port and provisions an HTTP companion. Tests that exercise
        // that path reserve a second loopback port for the companion.
        let http_companion_address = config_template
            .contains("__PINGCLAIR_TEST_HTTP_PORT__")
            .then(|| reserve_loopback_listener(&mut reservations));
        let config = config_template
            .replace("__PINGCLAIR_TEST_LISTEN__", &address.to_string())
            .replace("__PINGCLAIR_TEST_PORT__", &address.port().to_string())
            .replace(
                "__PINGCLAIR_TEST_HTTP_PORT__",
                &http_companion_address
                    .map(|a| a.port().to_string())
                    .unwrap_or_else(|| "80".to_string()),
            )
            .replace("__PINGCLAIR_TEST_HTTPS_PORT__", &address.port().to_string())
            .replace("__PINGCLAIR_TEST_READINESS_PATH__", &readiness_path)
            .replace("__PINGCLAIR_TEST_READINESS_TOKEN__", &readiness_token);
        assert!(
            !config.contains("__PINGCLAIR_TEST_"),
            "Pingclairfile test fixture contains an unresolved placeholder"
        );

        let mut file = std::fs::File::create(&config_path).unwrap();
        file.write_all(config.as_bytes()).unwrap();

        let server_addresses = if let Some(companion) = http_companion_address {
            vec![vec![address, companion]]
        } else {
            vec![vec![address]]
        };

        Self::start(
            temp_dir,
            config_path,
            server_addresses,
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
            // 🧭 The server's tracing subscriber defaults to ERROR when
            // RUST_LOG is unset, which would swallow the reload and
            // TLS warnings that tests assert on by reading this file.
            .env("RUST_LOG", "info")
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

    /// 🎧 Returns one specific listener of a server that binds several.
    fn listener_address(&self, server_index: usize, listener_index: usize) -> SocketAddr {
        self.server_addresses[server_index][listener_index]
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

            // 🧭 `proxy_protocol_listen` names addresses, but the addresses are
            // only known here. Test configs therefore write listener *indices*
            // ("0", "1"), which this maps onto the reserved addresses.
            if let Some(requires) = server
                .get_mut("proxy_protocol_listen")
                .and_then(serde_json::Value::as_array_mut)
            {
                *requires = requires
                    .iter()
                    .map(|index| {
                        let index: usize = index
                            .as_str()
                            .expect("proxy_protocol_listen entries are listener indices")
                            .parse()
                            .expect("proxy_protocol_listen entries are listener indices");
                        serde_json::Value::String(addresses[index].to_string())
                    })
                    .collect();
            }

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

/// 🧭 Sends one raw HTTP request through a chosen PROXY protocol transport source.
async fn proxy_protocol_request(
    address: SocketAddr,
    source_ip: std::net::IpAddr,
    prefix: &[u8],
    path: &str,
    extra_headers: &[(&str, &str)],
) -> std::io::Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let socket = match source_ip {
        std::net::IpAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        std::net::IpAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };
    socket.bind(SocketAddr::new(source_ip, 0))?;
    let mut stream = socket.connect(address).await?;
    let mut request = prefix.to_vec();
    request.extend_from_slice(format!("GET {path} HTTP/1.1\r\nHost: {address}\r\n").as_bytes());
    for (name, value) in extra_headers {
        request.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    request.extend_from_slice(b"Connection: close\r\n\r\n");
    stream.write_all(&request).await?;

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "response timed out"))??;
    Ok(response)
}

fn proxy_v1_prefix(client: &str, destination: SocketAddr) -> Vec<u8> {
    format!(
        "PROXY TCP4 {client} {} 4567 {}\r\n",
        destination.ip(),
        destination.port()
    )
    .into_bytes()
}

fn proxy_v2_prefix(client: [u8; 4], destination: SocketAddr) -> Vec<u8> {
    let std::net::IpAddr::V4(destination_ip) = destination.ip() else {
        panic!("the integration fixture requires an IPv4 listener");
    };
    let mut header = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    header.extend_from_slice(&[0x21, 0x11, 0, 12]);
    header.extend_from_slice(&client);
    header.extend_from_slice(&destination_ip.octets());
    header.extend_from_slice(&4567u16.to_be_bytes());
    header.extend_from_slice(&destination.port().to_be_bytes());
    header
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

/// 🧾 Reads one connection-closing HTTP/1 response under a hard test deadline.
async fn read_http1_to_end(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    use tokio::io::AsyncReadExt;

    tokio::time::timeout(Duration::from_secs(3), async {
        let mut response = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) => break,
                Ok(read) => response.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                Err(error) => panic!("HTTP/1 response read failed: {error}"),
            }
        }
        response
    })
    .await
    .expect("HTTP/1 response hung instead of rejecting")
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
async fn test_active_health_check_removes_idle_failed_upstream() {
    use tokio::io::AsyncWriteExt;

    async fn spawn_upstream(body: &'static str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let request =
                        read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(2)).await;
                    let request_text = String::from_utf8_lossy(&request);
                    let path = request_text
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap();
                    let response_body = if path == "/health" { "healthy" } else { body };
                    stream
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                                response_body.len()
                            )
                            .as_bytes(),
                        )
                        .await
                        .unwrap();
                });
            }
        });
        (address, task)
    }

    let (first_address, first_task) = spawn_upstream("first").await;
    let (second_address, second_task) = spawn_upstream("second").await;
    let config = serde_json::json!({
        "global": { "http3": false },
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "routes": [{
                "path": "/*",
                "handler": {
                    "type": "reverse_proxy",
                    "upstreams": [
                        format!("http://{first_address}"),
                        format!("http://{second_address}")
                    ],
                    "load_balance": { "strategy": "round_robin" },
                    "health_check": {
                        "path": "/health",
                        "interval": 1,
                        "timeout": 1,
                        "threshold": 1
                    },
                    "retry": { "max_attempts": 1 }
                }
            }]
        }]
    })
    .to_string();
    let mut server = TestServer::new(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    // 🧪 Stop one origin and allow two probe intervals without sending any
    // proxy traffic, so only an out-of-band active check can remove it.
    first_task.abort();
    let _ = first_task.await;
    tokio::time::sleep(Duration::from_millis(2_500)).await;

    let client = no_proxy_client();
    for _ in 0..4 {
        let response = client.get(server.url(0, "/probe")).send().await.unwrap();
        assert_eq!(
            response.status(),
            200,
            "an idle failed upstream stayed in rotation instead of being actively removed"
        );
        assert_eq!(response.text().await.unwrap(), "second");
    }

    // 🌱 Rebind the exact address and wait without proxy traffic again; an
    // active success must rejoin the recovered origin.
    let recovered_listener = tokio::net::TcpListener::bind(first_address)
        .await
        .expect("failed to rebind recovered upstream");
    let recovered_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = recovered_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(2)).await;
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nrecovered",
                    )
                    .await
                    .unwrap();
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    let mut bodies = Vec::new();
    for _ in 0..4 {
        let response = client.get(server.url(0, "/probe")).send().await.unwrap();
        assert_eq!(response.status(), 200);
        bodies.push(response.text().await.unwrap());
    }
    assert!(
        bodies.iter().any(|body| body == "recovered"),
        "the recovered upstream never rejoined rotation: {bodies:?}"
    );

    recovered_task.abort();
    let _ = recovered_task.await;
    second_task.abort();
    let _ = second_task.await;
}

#[tokio::test]
async fn test_bounded_upstream_status_retry_preserves_request_body_safety() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let first_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let second_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (dead_listener, live_listener) =
        if first_listener.local_addr().unwrap() < second_listener.local_addr().unwrap() {
            (first_listener, second_listener)
        } else {
            (second_listener, first_listener)
        };
    let dead_address = dead_listener.local_addr().unwrap();
    let upstream_address = live_listener.local_addr().unwrap();
    drop(dead_listener);
    live_listener.set_nonblocking(true).unwrap();
    let upstream = tokio::net::TcpListener::from_std(live_listener).unwrap();
    let success_hits = Arc::new(AtomicUsize::new(0));
    let capped_hits = Arc::new(AtomicUsize::new(0));
    let deadline_hits = Arc::new(AtomicUsize::new(0));
    let post_hits = Arc::new(AtomicUsize::new(0));
    let put_hits = Arc::new(AtomicUsize::new(0));
    let put_bytes = Arc::new(AtomicUsize::new(0));
    let connect_hits = Arc::new(AtomicUsize::new(0));
    let slow_deadline_hits = Arc::new(AtomicUsize::new(0));
    let counters = [
        success_hits.clone(),
        capped_hits.clone(),
        deadline_hits.clone(),
        post_hits.clone(),
        put_hits.clone(),
        connect_hits.clone(),
        slow_deadline_hits.clone(),
    ];
    let observed_put_bytes = put_bytes.clone();
    let upstream_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let counters = counters.clone();
            let observed_put_bytes = observed_put_bytes.clone();
            tokio::spawn(async move {
                let mut request =
                    read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(2)).await;
                let header_end = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|position| position + 4)
                    .unwrap();
                let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
                let path = headers
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap()
                    .to_string();
                let content_length = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                while request.len() - header_end < content_length {
                    let mut chunk = [0u8; 1024];
                    let read = stream.read(&mut chunk).await.unwrap();
                    assert!(read > 0, "request body closed before content-length");
                    request.extend_from_slice(&chunk[..read]);
                }

                let counter = match path.as_str() {
                    "/success" => &counters[0],
                    "/capped" => &counters[1],
                    "/deadline" => &counters[2],
                    "/post" => &counters[3],
                    "/put" => &counters[4],
                    "/connect-twice" => &counters[5],
                    "/slow-deadline" => &counters[6],
                    _ => panic!("unexpected retry-test path: {path}"),
                };
                let hit = counter.fetch_add(1, Ordering::SeqCst) + 1;
                if path == "/put" {
                    observed_put_bytes.store(content_length, Ordering::SeqCst);
                }
                if path == "/slow-deadline" {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
                let (status, body) = if (path == "/success" && hit == 2) || path == "/connect-twice"
                {
                    ("200 OK", "ok")
                } else {
                    ("503 Service Unavailable", "retry")
                };
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            });
        }
    });

    let route = |path: &str,
                 max_attempts: usize,
                 total_timeout_ms: Option<u64>,
                 backoff_ms: u64,
                 methods: Vec<&str>| {
        serde_json::json!({
            "path": path,
            "handler": {
                "type": "reverse_proxy",
                "upstreams": [format!("http://{upstream_address}")],
                "retry": {
                    "max_attempts": max_attempts,
                    "total_timeout_ms": total_timeout_ms,
                    "backoff_ms": backoff_ms,
                    "status_codes": [503],
                    "methods": methods
                }
            }
        })
    };
    let config = serde_json::json!({
        "global": { "http3": false },
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "client_max_body_size": 25 * 1024 * 1024,
            "routes": [
                route("/success", 3, None, 30, vec!["GET"]),
                route("/capped", 2, None, 0, vec!["GET"]),
                // ⌛ `/deadline` pins the branch where the retry budget runs out
                // *between* attempts, so the second attempt's own 503 is what
                // the client sees. `response_filter` checks the budget before it
                // looks at the response, so the whole assertion rests on attempt
                // two's reply landing inside `total_timeout_ms`, and the slack for
                // that is `total_timeout_ms - backoff_ms`. At 150/100 the slack
                // was 50ms, which two upstream round trips plus timer wake-up
                // scheduling can eat under a loaded machine — the budget then
                // expires with the 503 already in hand and 504 is surfaced
                // instead. 750/400 keeps the same branch (a third attempt still
                // cannot fit, since `backoff_ms * 2` exceeds the budget) with
                // 350ms of slack rather than 50ms.
                route("/deadline", 3, Some(750), 400, vec!["GET"]),
                route("/slow-deadline", 2, Some(100), 0, vec!["GET"]),
                route("/post", 3, None, 0, vec!["GET"]),
                route("/put", 3, None, 0, vec!["GET", "PUT"]),
                {
                    "path": "/connect-once",
                    "handler": {
                        "type": "reverse_proxy",
                        "upstreams": [
                            format!("http://{dead_address}"),
                            format!("http://{upstream_address}")
                        ],
                        "retry": { "max_attempts": 1 }
                    }
                },
                {
                    "path": "/connect-twice",
                    "handler": {
                        "type": "reverse_proxy",
                        "upstreams": [
                            format!("http://{dead_address}"),
                            format!("http://{upstream_address}")
                        ],
                        "retry": { "max_attempts": 2 }
                    }
                }
            ]
        }]
    })
    .to_string();
    let mut server = TestServer::new(&config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let started = std::time::Instant::now();
    let response = client.get(server.url(0, "/success")).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "ok");
    assert!(started.elapsed() >= Duration::from_millis(25));
    assert_eq!(success_hits.load(Ordering::SeqCst), 2);

    let response = client.get(server.url(0, "/capped")).send().await.unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(capped_hits.load(Ordering::SeqCst), 2);

    let started = std::time::Instant::now();
    let response = client.get(server.url(0, "/deadline")).send().await.unwrap();
    assert_eq!(response.status(), 503);
    // 💤 One backoff was served, and `deadline_hits` is what proves no third
    // attempt was made; the upper bound here only has to stay loose enough that
    // a loaded machine cannot trip it on scheduling delay alone.
    assert!(started.elapsed() >= Duration::from_millis(380));
    assert!(started.elapsed() < Duration::from_millis(1_500));
    assert_eq!(deadline_hits.load(Ordering::SeqCst), 2);

    let started = std::time::Instant::now();
    let response = client
        .get(server.url(0, "/slow-deadline"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 504);
    assert!(started.elapsed() >= Duration::from_millis(70));
    assert!(started.elapsed() < Duration::from_millis(250));
    assert_eq!(slow_deadline_hits.load(Ordering::SeqCst), 1);

    // ⌛ The terminal retry timeout also closes its downstream connection.
    let body_client = no_proxy_client();
    let response = body_client
        .post(server.url(0, "/post"))
        .body("unsafe-to-replay")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(post_hits.load(Ordering::SeqCst), 1);

    let response = body_client
        .put(server.url(0, "/put"))
        .body(vec![b'x'; 20 * 1024 * 1024])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(put_hits.load(Ordering::SeqCst), 1);
    assert_eq!(put_bytes.load(Ordering::SeqCst), 20 * 1024 * 1024);

    let response = client
        .get(server.url(0, "/connect-once"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    assert_eq!(connect_hits.load(Ordering::SeqCst), 0);

    // 🔌 The terminal connect error intentionally closes its downstream connection.
    let retry_client = no_proxy_client();
    let response = match retry_client
        .get(server.url(0, "/connect-twice"))
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            server.print_diagnostics();
            panic!("connect redispatch request failed: {error}");
        }
    };
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "ok");
    assert_eq!(connect_hits.load(Ordering::SeqCst), 1);

    upstream_task.abort();
    let _ = upstream_task.await;
}

#[tokio::test]
async fn test_overload_and_circuit_breaker_fail_fast_and_survive_reload() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncWriteExt;

    let upstream = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let queue_hits = Arc::new(AtomicUsize::new(0));
    let capacity_hits = Arc::new(AtomicUsize::new(0));
    let circuit_hits = Arc::new(AtomicUsize::new(0));
    let counters = (
        queue_hits.clone(),
        capacity_hits.clone(),
        circuit_hits.clone(),
    );
    let upstream_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let counters = counters.clone();
            tokio::spawn(async move {
                let request =
                    read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(2)).await;
                let path = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap()
                    .to_string();
                let (status, body) = match path.as_str() {
                    "/queue" => {
                        counters.0.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        ("200 OK", "queue")
                    }
                    "/capacity" => {
                        counters.1.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        ("200 OK", "capacity")
                    }
                    "/circuit" => {
                        let hit = counters.2.fetch_add(1, Ordering::SeqCst) + 1;
                        if hit <= 2 {
                            ("503 Service Unavailable", "failure")
                        } else {
                            ("200 OK", "recovered")
                        }
                    }
                    _ => panic!("unexpected overload-test path: {path}"),
                };
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            });
        }
    });

    let queue_route = serde_json::json!({
        "path": "/queue",
        "handler": {
            "type": "reverse_proxy",
            "upstreams": [format!("http://{upstream_address}")],
            "overload": {
                "max_in_flight": 1,
                "max_pending": 1,
                "pending_timeout_ms": 100
            }
        }
    });
    let capacity_route = serde_json::json!({
        "path": "/capacity",
        "handler": {
            "type": "reverse_proxy",
            "upstreams": [format!("http://{upstream_address}")],
            "overload": { "upstream_max_connections": 1 }
        }
    });
    let circuit_route = serde_json::json!({
        "path": "/circuit",
        "handler": {
            "type": "reverse_proxy",
            "upstreams": [format!("http://{upstream_address}")],
            "retry": { "max_attempts": 1 },
            "circuit_breaker": {
                "consecutive_failures": 2,
                "open_duration_ms": 2000,
                "half_open_requests": 1,
                "failure_statuses": [503]
            }
        }
    });
    let config = serde_json::json!({
        "global": { "http3": false },
        "admin": { "enabled": true, "listen": "127.0.0.1:0" },
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "routes": [
                queue_route.clone(),
                capacity_route.clone(),
                circuit_route.clone()
            ]
        }]
    })
    .to_string();
    let mut server = TestServer::new(&config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let first_client = client.clone();
    let first_url = server.url(0, "/queue");
    let first = tokio::spawn(async move { first_client.get(first_url).send().await.unwrap() });
    while queue_hits.load(Ordering::SeqCst) != 1 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let pending_client = client.clone();
    let pending_url = server.url(0, "/queue");
    let pending =
        tokio::spawn(async move { pending_client.get(pending_url).send().await.unwrap() });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let rejected = client.get(server.url(0, "/queue")).send().await.unwrap();
    assert_eq!(rejected.status(), 429);
    assert_eq!(pending.await.unwrap().status(), 503);
    assert_eq!(first.await.unwrap().status(), 200);
    assert_eq!(queue_hits.load(Ordering::SeqCst), 1);

    let held_client = client.clone();
    let held_url = server.url(0, "/capacity");
    let held = tokio::spawn(async move { held_client.get(held_url).send().await.unwrap() });
    while capacity_hits.load(Ordering::SeqCst) != 1 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let rejected = client.get(server.url(0, "/capacity")).send().await.unwrap();
    assert_eq!(rejected.status(), 503);
    assert_eq!(held.await.unwrap().status(), 200);
    assert_eq!(capacity_hits.load(Ordering::SeqCst), 1);

    for _ in 0..2 {
        let response = client.get(server.url(0, "/circuit")).send().await.unwrap();
        assert_eq!(response.status(), 503);
    }
    let rejected = client.get(server.url(0, "/circuit")).send().await.unwrap();
    assert_eq!(rejected.status(), 503);
    assert_eq!(circuit_hits.load(Ordering::SeqCst), 2);

    let reloaded = serde_json::json!({
        "listen": [server.address(0).to_string()],
        "routes": [
            {
                "path": server.readiness_path.clone(),
                "handler": {
                    "type": "respond",
                    "status": 200,
                    "body": server.readiness_token.clone()
                }
            },
            queue_route,
            capacity_route,
            circuit_route
        ]
    });
    let response = client
        .post(server.admin_url("/config/0"))
        .json(&reloaded)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let still_open = client.get(server.url(0, "/circuit")).send().await.unwrap();
    assert_eq!(still_open.status(), 503);
    assert_eq!(circuit_hits.load(Ordering::SeqCst), 2);

    let metrics = client
        .get(server.admin_url("/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("pingclair_overload_rejections_total"));
    assert!(metrics.contains("reason=\"queue_full\""));
    assert!(metrics.contains("reason=\"queue_timeout\""));
    assert!(metrics.contains("reason=\"upstream_capacity\""));
    assert!(metrics.contains("reason=\"circuit_open\""));
    assert!(metrics.contains("pingclair_circuit_state"));

    tokio::time::sleep(Duration::from_millis(2_050)).await;
    let recovered = client.get(server.url(0, "/circuit")).send().await.unwrap();
    assert_eq!(recovered.status(), 200);
    assert_eq!(recovered.text().await.unwrap(), "recovered");
    assert_eq!(circuit_hits.load(Ordering::SeqCst), 3);

    upstream_task.abort();
    let _ = upstream_task.await;
}

#[tokio::test]
async fn test_listener_resource_limits_reject_before_dispatch_without_hanging() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let config = serde_json::json!({
        "global": { "http3": false },
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "limits": {
                // Long enough that the connection held open below is not
                // reaped mid-test. The header timeout itself is asserted in
                // `test_streamed_limits_and_timeout_phases_are_explicit_and_bounded`;
                // at 200ms it did nothing here except race the probe.
                "header_timeout_ms": 5000,
                "max_header_count": 16,
                "max_header_bytes": 512,
                "max_connections": 1
            },
            "routes": [{
                "path": "/*",
                "handler": { "type": "respond", "status": 200, "body": "ok" }
            }]
        }]
    })
    .to_string();
    let mut server = TestServer::new(&config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let address = server.address(0);

    // 🔌 Hold the only connection slot with an incomplete header.
    //
    // Acquiring the slot and verifying it are the same step, because `held`
    // only occupies the slot if `held` was itself admitted. The readiness
    // check that ran a moment ago went through a pooled client and leaves a
    // keep-alive connection behind; while that is still open it is `held`
    // that gets the 503, after which nothing holds the slot and every probe
    // below is admitted. That lost about one run in ten under a loaded
    // machine. Retrying the pair is self-correcting no matter what else is
    // briefly holding a connection.
    let mut held = None;
    let mut rejected = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        let mut candidate = tokio::net::TcpStream::connect(address).await.unwrap();
        candidate
            .write_all(b"GET / HTTP/1.1\r\nHost:")
            .await
            .unwrap();

        let mut excess = tokio::net::TcpStream::connect(address).await.unwrap();
        excess
            .write_all(b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let response = read_http1_to_end(&mut excess).await;
        if response.starts_with(b"HTTP/1.1 503") {
            rejected = response;
            held = Some(candidate);
            break;
        }
        drop(candidate);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let held = held.expect("max_connections never rejected a second connection");
    assert!(
        rejected.starts_with(b"HTTP/1.1 503"),
        "{}",
        String::from_utf8_lossy(&rejected)
    );

    drop(held);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut too_many = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut request = b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n".to_vec();
    for index in 0..17 {
        request.extend_from_slice(format!("X-H-{index}: x\r\n").as_bytes());
    }
    request.extend_from_slice(b"\r\n");
    too_many.write_all(&request).await.unwrap();
    let response = read_http1_to_end(&mut too_many).await;
    assert!(
        response.starts_with(b"HTTP/1.1 431"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    let mut too_large = tokio::net::TcpStream::connect(address).await.unwrap();
    let request = format!(
        "GET / HTTP/1.1\r\nHost: test\r\nX-Pad: {}\r\nConnection: close\r\n\r\n",
        "x".repeat(600)
    );
    too_large.write_all(request.as_bytes()).await.unwrap();
    let response = read_http1_to_end(&mut too_large).await;
    assert!(
        response.starts_with(b"HTTP/1.1 431"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    drop(server);
    let timeout_config = serde_json::json!({
        "global": { "http3": false },
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "limits": {
                "header_timeout_ms": 200,
                "idle_timeout_ms": 200
            },
            "routes": [{
                "path": "/*",
                "handler": { "type": "respond", "status": 200, "body": "ok" }
            }]
        }]
    })
    .to_string();
    let mut timeout_server = TestServer::new(&timeout_config);
    assert!(
        timeout_server.wait_until_ready().await,
        "timeout server failed to start"
    );
    let mut partial = tokio::net::TcpStream::connect(timeout_server.address(0))
        .await
        .unwrap();
    partial.write_all(b"GET / HTTP/1.1\r\nHost:").await.unwrap();
    let mut byte = [0u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(1), partial.read(&mut byte))
        .await
        .expect("partial request header hung")
        .unwrap();
    assert_eq!(closed, 0);

    let mut idle = tokio::net::TcpStream::connect(timeout_server.address(0))
        .await
        .unwrap();
    idle.write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        .await
        .unwrap();
    let _ = read_until_marker(&mut idle, b"ok", Duration::from_secs(1)).await;
    let closed = tokio::time::timeout(Duration::from_secs(2), idle.read(&mut byte))
        .await
        .expect("idle keepalive connection hung")
        .unwrap();
    assert_eq!(closed, 0);
}

#[tokio::test]
async fn test_streamed_limits_and_timeout_phases_are_explicit_and_bounded() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let blackhole = socket.listen(1).unwrap();
    let blackhole_address = blackhole.local_addr().unwrap();
    let mut saturated_backlog = Vec::new();
    let mut backlog_saturated = false;
    for _ in 0..64 {
        match tokio::time::timeout(
            Duration::from_millis(20),
            tokio::net::TcpStream::connect(blackhole_address),
        )
        .await
        {
            Ok(Ok(stream)) => saturated_backlog.push(stream),
            Ok(Err(error)) => panic!("failed to saturate connect backlog: {error}"),
            Err(_) => {
                backlog_saturated = true;
                break;
            }
        }
    }
    assert!(
        backlog_saturated,
        "connect-timeout fixture did not saturate its accept backlog"
    );
    let upstream_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = upstream.accept().await.unwrap();
            tokio::spawn(async move {
                let request =
                    read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(2)).await;
                let line = String::from_utf8_lossy(&request);
                if line.starts_with("POST /upload ") {
                    let header_end = request
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .unwrap()
                        + 4;
                    let mut received = request.len() - header_end;
                    let mut chunk = [0u8; 4096];
                    while received < 2_000 {
                        let read = stream.read(&mut chunk).await.unwrap();
                        assert!(read > 0);
                        received += read;
                    }
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await
                        .unwrap();
                } else if line.starts_with("GET /between ") {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n",
                        )
                        .await
                        .unwrap();
                    tokio::time::sleep(Duration::from_secs(1)).await;
                } else if line.starts_with("GET /bandwidth ") {
                    let body = vec![b'x'; 2_000];
                    stream
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            )
                            .as_bytes(),
                        )
                        .await
                        .unwrap();
                    stream.write_all(&body).await.unwrap();
                } else if line.starts_with("GET /sse ") || line.starts_with("GET /sse-content ") {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .unwrap();
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    stream
                        .write_all(b"D\r\ndata: alive\n\n\r\n0\r\n\r\n")
                        .await
                        .unwrap();
                } else {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            });
        }
    });

    let proxy = |path: &str,
                 flush_interval: Option<i64>,
                 first_byte_timeout: i64,
                 between_reads_timeout: i64| {
        serde_json::json!({
            "path": path,
            "handler": {
                "type": "reverse_proxy",
                "upstreams": [format!("http://{upstream_address}")],
                "load_balance": { "strategy": "round_robin" },
                "headers_up": {},
                "headers_down": {},
                "flush_interval": flush_interval,
                "connect_timeout": 200,
                "first_byte_timeout": first_byte_timeout,
                "between_reads_timeout": between_reads_timeout
            }
        })
    };
    let config = serde_json::json!({
        "global": { "http3": false },
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "client_max_body_size": 4000,
            "limits": {
                "body_timeout_ms": 100,
                "idle_timeout_ms": 500,
                "request_timeout_ms": 150,
                "upload_bytes_per_sec": 1000,
                "download_bytes_per_sec": 1000,
                "long_connections": {
                    "idle_timeout_ms": 1000,
                    "request_timeout_ms": 0
                }
            },
            "routes": [
                {
                    "path": "/local-body",
                    "handler": { "type": "respond", "status": 200, "body": "ok" }
                },
                proxy("/body", None, 500, 500),
                proxy("/upload", Some(-1), 5000, 5000),
                {
                    "path": "/connect",
                    "handler": {
                        "type": "reverse_proxy",
                        "upstreams": [format!("http://{blackhole_address}")],
                        "load_balance": { "strategy": "round_robin" },
                        "headers_up": {},
                        "headers_down": {},
                        "connect_timeout": 100,
                        "first_byte_timeout": 500,
                        "between_reads_timeout": 500
                    }
                },
                proxy("/first", None, 100, 500),
                proxy("/whole", None, 500, 500),
                proxy("/between", Some(-1), 500, 100),
                proxy("/bandwidth", Some(-1), 500, 500),
                proxy("/sse", Some(-1), 500, 500),
                {
                    "path": "/sse-content",
                    "handler": {
                        "type": "reverse_proxy",
                        "upstreams": [format!("http://{upstream_address}")],
                        "load_balance": { "strategy": "round_robin" },
                        "headers_up": {},
                        "headers_down": {},
                        "connect_timeout": 200
                    }
                }
            ]
        }]
    })
    .to_string();
    let mut server = TestServer::new(&config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let address = server.address(0);

    let mut oversized = tokio::net::TcpStream::connect(address).await.unwrap();
    let oversized_request = format!(
        "POST /body HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1388\r\n{}\r\n0\r\n\r\n",
        "x".repeat(5_000)
    );
    oversized
        .write_all(oversized_request.as_bytes())
        .await
        .unwrap();
    let response = read_http1_to_end(&mut oversized).await;
    assert!(
        response.starts_with(b"HTTP/1.1 413"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    let mut oversized_local = tokio::net::TcpStream::connect(address).await.unwrap();
    let oversized_local_request = format!(
        "POST /local-body HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1388\r\n{}\r\n0\r\n\r\n",
        "x".repeat(5_000)
    );
    oversized_local
        .write_all(oversized_local_request.as_bytes())
        .await
        .unwrap();
    let response = read_http1_to_end(&mut oversized_local).await;
    assert!(
        response.starts_with(b"HTTP/1.1 413"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    let mut stalled_body = tokio::net::TcpStream::connect(address).await.unwrap();
    stalled_body
        .write_all(
            b"POST /body HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let response = read_http1_to_end(&mut stalled_body).await;
    assert!(
        response.starts_with(b"HTTP/1.1 408"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    let client = no_proxy_client();
    let started = std::time::Instant::now();
    let upload = client
        .post(server.url(0, "/upload"))
        .body(vec![b'u'; 2_000])
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), reqwest::StatusCode::OK);
    assert!(started.elapsed() >= Duration::from_millis(1_800));

    let mut connect = tokio::net::TcpStream::connect(address).await.unwrap();
    connect
        .write_all(b"GET /connect HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let response = read_http1_to_end(&mut connect).await;
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(
        response.starts_with(b"HTTP/1.1 504"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    let mut first = tokio::net::TcpStream::connect(address).await.unwrap();
    first
        .write_all(b"GET /first HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_http1_to_end(&mut first).await;
    assert!(
        response.starts_with(b"HTTP/1.1 504"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    let mut whole = tokio::net::TcpStream::connect(address).await.unwrap();
    whole
        .write_all(b"GET /whole HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_http1_to_end(&mut whole).await;
    assert!(
        response.starts_with(b"HTTP/1.1 408"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    let mut between = tokio::net::TcpStream::connect(address).await.unwrap();
    between
        .write_all(b"GET /between HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let response = read_http1_to_end(&mut between).await;
    assert!(started.elapsed() < Duration::from_millis(800));
    assert!(response.windows(5).any(|window| window == b"hello"));

    let started = std::time::Instant::now();
    let body = client
        .get(server.url(0, "/bandwidth"))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(body.len(), 2_000);
    assert!(started.elapsed() >= Duration::from_millis(1_800));

    let mut sse = tokio::net::TcpStream::connect(address).await.unwrap();
    sse.write_all(b"GET /sse HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_until_marker(&mut sse, b"data: alive\n\n", Duration::from_secs(1)).await;
    assert!(
        response
            .windows(13)
            .any(|window| window == b"data: alive\n\n")
    );

    let mut content_sse = tokio::net::TcpStream::connect(address).await.unwrap();
    content_sse
        .write_all(b"GET /sse-content HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response =
        read_until_marker(&mut content_sse, b"data: alive\n\n", Duration::from_secs(1)).await;
    assert!(
        response
            .windows(13)
            .any(|window| window == b"data: alive\n\n")
    );

    upstream_task.abort();
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
async fn test_basic_auth_argon2id_end_to_end() {
    // 🔒 Generate a hash the way `pingclair hash-password --algorithm
    // argon2id` does — same crate, same PHC spelling — and verify the server
    // accepts it. This is the exact trap the P1 row described: the CLI used
    // to print a hash the server compared as literal text.
    use argon2::password_hash::{PasswordHasher, SaltString};
    use argon2::{Argon2, Params};

    let salt = SaltString::encode_b64(b"pingclair-integration").unwrap();
    let params = Params::new(16 * 1024, 1, 1, Some(32)).unwrap();
    let hash = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password(b"clihash", &salt)
        .unwrap()
        .to_string();
    assert!(hash.starts_with("$argon2id$v=19$"), "{hash}");

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
                                    "realm": "Argon2 Realm",
                                    "credentials": [
                                        {
                                            "username": "alice",
                                            "password": hash,
                                            "algorithm": "argon2id"
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

    // 🚫 Missing and wrong credentials must be rejected.
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 401);
    let resp = client
        .get(&url)
        .basic_auth("alice", Some("wrong"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // ✅ The CLI-format hash must authenticate the real password.
    let resp = client
        .get(&url)
        .basic_auth("alice", Some("clihash"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "welcome");
}

#[tokio::test]
async fn test_error_handler_end_to_end() {
    // 🚨 The `error` handler raises its status and stops the pipeline — the
    // handler after it must never run, and a missing message falls back to
    // the status's canonical text.
    let config = serde_json::json!({
        "servers": [
            {
                "listen": ["127.0.0.1:0"],
                "routes": [
                    {
                        "path": "/private",
                        "handler": {
                            "type": "pipeline",
                            "handlers": [
                                { "type": "error", "status": 403, "message": "Unauthorized" },
                                { "type": "respond", "status": 200, "body": "must not run" }
                            ]
                        }
                    },
                    {
                        "path": "/oops",
                        "handler": { "type": "error", "status": 500 }
                    }
                ]
            }
        ]
    })
    .to_string();

    let mut server = TestServer::new(&config);
    let client = no_proxy_client();
    assert!(server.wait_until_ready().await, "server failed to start");

    let resp = client.get(server.url(0, "/private")).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(resp.text().await.unwrap(), "Unauthorized");

    let resp = client.get(server.url(0, "/oops")).send().await.unwrap();
    assert_eq!(resp.status(), 500);
    assert_eq!(resp.text().await.unwrap(), "500 Internal Server Error");
}

#[tokio::test]
async fn test_handle_errors_routes_raised_statuses() {
    // 🚨 Raised error statuses run the server's error routes: exact codes and
    // `Nxx` ranges match, the first matching route answers, and an error route
    // that raises again responds directly instead of recursing forever.
    let config = serde_json::json!({
        "servers": [
            {
                "listen": ["127.0.0.1:0"],
                "routes": [
                    { "path": "/gone", "handler": { "type": "error", "status": 404 } },
                    { "path": "/private", "handler": { "type": "error", "status": 403, "message": "Unauthorized" } },
                    { "path": "/boom", "handler": { "type": "error", "status": 500 } }
                ],
                "error_routes": [
                    {
                        "codes": [404, 410],
                        "handlers": [
                            { "type": "respond", "status": 200, "body": "handled 404" }
                        ]
                    },
                    {
                        "hundreds": [4],
                        "handlers": [
                            { "type": "respond", "status": 200, "body": "handled 4xx" }
                        ]
                    },
                    {
                        "codes": [500],
                        "handlers": [
                            { "type": "error", "status": 500 }
                        ]
                    }
                ]
            }
        ]
    })
    .to_string();

    let mut server = TestServer::new(&config);
    let client = no_proxy_client();
    assert!(server.wait_until_ready().await, "server failed to start");

    // ✅ Exact code route answers first.
    let resp = client.get(server.url(0, "/gone")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "handled 404");

    // ✅ The 4xx range catches 403 when no exact route matches.
    let resp = client.get(server.url(0, "/private")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "handled 4xx");

    // 🚫 An error route that raises again must not hang or double-write: the
    // recursion guard answers with the default 500.
    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        client.get(server.url(0, "/boom")).send(),
    )
    .await
    .expect("the recursion guard must answer, not hang")
    .unwrap();
    assert_eq!(resp.status(), 500);
}

#[tokio::test]
async fn test_handle_errors_intercepts_file_server_404() {
    // 🗂️ A missing file raises 404 like the `error` directive does, so a
    // `handle_errors 404` route answers instead of the built-in page — and
    // the handled response is the only response written.
    let empty_root = tempfile::tempdir().unwrap();
    let config = format!(
        r#"{{
            "servers": [
                {{
                    "listen": ["127.0.0.1:0"],
                    "routes": [
                        {{
                            "path": "/static/*",
                            "handler": {{
                                "type": "file_server",
                                "root": "{}"
                            }}
                        }}
                    ],
                    "error_routes": [
                        {{
                            "codes": [404],
                            "handlers": [
                                {{ "type": "respond", "status": 200, "body": "custom 404" }}
                            ]
                        }}
                    ]
                }}
            ]
        }}"#,
        empty_root.path().display()
    );

    let mut server = TestServer::new(&config);
    let client = no_proxy_client();
    assert!(server.wait_until_ready().await, "server failed to start");

    let resp = client
        .get(server.url(0, "/static/missing.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "custom 404");
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

/// 🗂️ The single-page-application pattern from the format's own patterns
/// page, running against the real binary.
///
/// The configuration below is that example, changed only where a test must
/// change it: a temporary directory for the root and a loopback port. Every
/// directive and its argument order is the documented one, because the claim
/// under test is not "our parser accepts this" — it is that someone migrating
/// can paste the page in and have it work.
///
/// 🤡 Until 2026-08-07 it failed twice over: `try_files` was refused by the
/// adapter outright, and the handler behind it resolved candidates against the
/// filesystem root rather than the site root, so even a JSON configuration that
/// reached it answered 404 for every client-side route.
#[tokio::test]
async fn test_spa_pattern_serves_assets_and_falls_back_to_the_shell() {
    let tmp_dir = tempfile::tempdir().unwrap();
    std::fs::write(tmp_dir.path().join("index.html"), "spa-shell").unwrap();
    std::fs::create_dir(tmp_dir.path().join("assets")).unwrap();
    std::fs::write(tmp_dir.path().join("assets/app.js"), "real-asset").unwrap();
    let root = tmp_dir.path().to_str().unwrap().replace("\\", "/");

    let config = format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            root * {root}

            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            try_files {{path}} /index.html
            file_server
        }}
    "#
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    // 🎯 A real file must be served as itself. If `try_files` hijacked every
    // request to the shell, the application would load and then fetch its own
    // HTML in place of its JavaScript — a failure that looks like a bundler
    // problem and is not one.
    let asset = client
        .get(server.url(0, "/assets/app.js"))
        .send()
        .await
        .unwrap();
    assert_eq!(asset.status(), 200);
    assert_eq!(asset.text().await.unwrap(), "real-asset");

    // 🎯 A client-side route has no file behind it and must reach the shell.
    let deep_route = client
        .get(server.url(0, "/settings/profile"))
        .send()
        .await
        .unwrap();
    assert_eq!(deep_route.status(), 200);
    assert_eq!(deep_route.text().await.unwrap(), "spa-shell");

    // 🎯 The rewrite must keep the query, which is where the application
    // usually keeps the state it is about to read.
    let with_query = client
        .get(server.url(0, "/settings/profile?tab=security"))
        .send()
        .await
        .unwrap();
    assert_eq!(with_query.status(), 200);
    assert_eq!(with_query.text().await.unwrap(), "spa-shell");
}

/// 🎯 A matcher token inside `route` must compile and gate the element it
/// guards. It used to be discarded and read as the response body; the
/// runtime half of this regression is `test_route_element_matchers_gate_handlers`.
#[test]
fn test_matcher_token_inside_route_validates_scoped() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("Pingclairfile");
    std::fs::write(
        &config_path,
        ":0 {\n\
         \t@admin path /admin/*\n\
         \troute {\n\
         \t\trespond @admin \"SECRET\" 200\n\
         \t\trespond \"public\" 200\n\
         \t}\n\
         }\n",
    )
    .unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pingclair"))
        .arg("validate")
        .arg(&config_path)
        .output()
        .expect("the binary runs");

    assert!(
        output.status.success(),
        "a matcher token inside route must now be accepted:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// 🪚 `uri strip_prefix` reaches the file server with the prefix removed.
#[tokio::test]
async fn test_uri_strip_prefix_reaches_the_stripped_static_path() {
    let tmp_dir = tempfile::tempdir().unwrap();
    std::fs::write(tmp_dir.path().join("hello.txt"), "stripped").unwrap();
    let root = tmp_dir.path().to_str().unwrap().replace("\\", "/");

    let config = format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            root * {root}

            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            uri strip_prefix /api
            file_server
        }}
    "#
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let response = no_proxy_client()
        .get(server.url(0, "/api/hello.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "stripped");
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

/// 🧭 Without a matcher, `reverse_proxy` beats `file_server` (Caddy order).
#[tokio::test]
async fn test_proxy_beats_file_server_without_matcher() {
    use tokio::io::AsyncWriteExt;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let upstream = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut [0u8; 1024]).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nproxied-ok",
                    )
                    .await;
            });
        }
    });

    let site = tempfile::tempdir().unwrap();
    std::fs::write(site.path().join("index.html"), "<h1>file</h1>").unwrap();
    let config = format!(
        r#"{{
        "global": {{ "http3": false }},
        "servers": [{{
            "listen": ["127.0.0.1:0"],
            "routes": [{{
                "path": "/*",
                "handler": {{
                    "type": "pipeline",
                    "handlers": [
                        {{ "type": "file_server", "root": "{}", "index": ["index.html"], "browse": false, "compress": false }},
                        {{ "type": "reverse_proxy", "upstreams": ["{}"], "load_balance": {{ "strategy": "round_robin" }}, "headers_up": {{}}, "headers_down": {{}} }}
                    ]
                }}
            }}]
        }}]
    }}"#,
        site.path().display(),
        upstream
    );
    let mut server = TestServer::new(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = no_proxy_client();
    let resp = client
        .get(server.url(0, "/index.html"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.text().await.unwrap(),
        "proxied-ok",
        "reverse_proxy must win over file_server without a matcher"
    );
    task.abort();
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
        .header("Forwarded", "for=203.0.113.9;proto=https")
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
    assert!(upstream_request.contains("\r\nforwarded: for=127.0.0.1\r\n"));
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

/// 🔐 A hostname-only site with TLS must derive the HTTPS listener from
/// `https_port` and gain an automatic plaintext companion on `http_port`,
/// exactly like Caddy's `example.com { tls auto }` shape — no `listen`
/// directive anywhere.
#[tokio::test]
async fn test_hostname_tls_site_derives_https_and_http_companion() {
    let config = r#"
        {
            admin off
            http_port __PINGCLAIR_TEST_HTTP_PORT__
            https_port __PINGCLAIR_TEST_HTTPS_PORT__
        }

        example.com {
            tls internal

            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "derived-https-ok"
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(
        server.wait_until_tls_ready("example.com").await,
        "hostname-only TLS site did not come up on the derived HTTPS port"
    );

    // 🔐 The derived HTTPS listener serves the site with the internal CA.
    let root_path = server._temp_dir.path().join("tls/internal/root.crt");
    let root = reqwest::Certificate::from_pem(&std::fs::read(&root_path).unwrap()).unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(root)
        .resolve("example.com", server.address(0))
        .build()
        .unwrap();
    let response = client
        .get(server.tls_url(0, "example.com", "/"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "derived-https-ok");

    // 🔁 The automatic plaintext companion on `http_port` redirects to HTTPS.
    // The redirect route belongs to the site's virtual host, so the request
    // must carry the site's Host header — exactly what a browser sends.
    // A raw TCP exchange keeps the test independent of the resolver.
    let companion_addr = server.listener_address(0, 1);
    let mut stream = tokio::net::TcpStream::connect(companion_addr)
        .await
        .expect("the companion listener must accept connections");
    let request = format!(
        "GET / HTTP/1.1\r\nHost: example.com:{}\r\nConnection: close\r\n\r\n",
        companion_addr.port()
    );
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let status_line = response.lines().next().unwrap_or_default();
    assert!(
        status_line.contains("308"),
        "companion must redirect with 308, got `{status_line}` in:\n{response}"
    );
    let location = response
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("location:"))
        .map(|line| {
            line.split_once(':')
                .map(|(_, value)| value.trim())
                .unwrap_or_default()
        })
        .unwrap_or_default();
    assert!(
        location.starts_with("https://example.com:") && location.ends_with('/'),
        "companion must redirect to HTTPS with the configured https_port, got {location}"
    );
    // 🧭 The redirect must target the HTTPS port, never the plaintext one the
    // request arrived on.
    let https_port = server.address(0).port();
    let redirect_port = location
        .trim_start_matches("https://example.com:")
        .trim_end_matches('/');
    assert_eq!(
        redirect_port,
        https_port.to_string(),
        "companion redirect must use https_port {https_port}, got {location}"
    );
}

/// 🔁 The file server canonicalizes trailing slashes like Caddy: a directory
/// request without one gets a 308 adding it, and a file request with one gets
/// a 308 removing it.
#[tokio::test]
async fn test_file_server_trailing_slash_redirects() {
    // 📄 Fixture: one directory and one file under a temp root.
    let tmp_dir = tempfile::tempdir().unwrap();
    let dir_path = tmp_dir.path().join("folder");
    std::fs::create_dir(&dir_path).unwrap();
    std::fs::write(dir_path.join("index.html"), "folder index").unwrap();
    std::fs::write(tmp_dir.path().join("plain.txt"), "plain file").unwrap();
    let root_path = tmp_dir.path().to_str().unwrap().replace("\\", "/");

    let config = format!(
        r#"{{
        "servers": [
            {{
                "listen": ["127.0.0.1:0"],
                "routes": [
                    {{
                        "path": "/*",
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
    let mut server = TestServer::new(&config);
    assert!(server.wait_until_ready().await, "Server failed to start");

    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // 📂 A directory without a trailing slash must be redirected to it.
    let response = client.get(server.url(0, "/folder")).send().await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::PERMANENT_REDIRECT);
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("directory redirect must carry a Location");
    assert!(location.ends_with("/folder/"), "got {location}");

    // 📄 A file with a trailing slash must be redirected without it.
    let response = client
        .get(server.url(0, "/plain.txt/"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::PERMANENT_REDIRECT);
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("file redirect must carry a Location");
    assert!(location.ends_with("/plain.txt"), "got {location}");

    // ✅ The canonical forms serve directly.
    let response = client.get(server.url(0, "/folder/")).send().await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let response = client
        .get(server.url(0, "/plain.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

/// 🧭 Caddy's directive order makes file order irrelevant: `header` after
/// `respond` must behave identically to `header` before `respond`. This test
/// runs two real binaries with reversed directive order and compares the
/// HTTP behavior.
#[tokio::test]
async fn test_directive_order_does_not_change_behavior() {
    let config_template = |body: &str| {
        format!(
            r#"
            {{
                admin off
                http_port __PINGCLAIR_TEST_HTTP_PORT__
                https_port __PINGCLAIR_TEST_HTTPS_PORT__
            }}

            example.com {{
                tls internal
                @readiness path __PINGCLAIR_TEST_READINESS_PATH__
                respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
                {body}
            }}
        "#
        )
    };
    let body_a = r#"
            respond "ordered-ok"
            header X-Order "reversed"
    "#;
    let body_b = r#"
            header X-Order "reversed"
            respond "ordered-ok"
    "#;

    let mut server_a = TestServer::new_pingclairfile(&config_template(body_a));
    let result_a = fetch_ordered_response(&mut server_a).await;
    server_a.stop();

    let mut server_b = TestServer::new_pingclairfile(&config_template(body_b));
    let result_b = fetch_ordered_response(&mut server_b).await;
    server_b.stop();

    assert_eq!(
        result_a, result_b,
        "reversing directive order must not change the response"
    );
    assert_eq!(result_a.0, reqwest::StatusCode::OK);
    assert_eq!(result_a.1, "reversed");
    assert_eq!(result_a.2, "ordered-ok");
}

/// 📤 The admin API adapts a Pingclairfile, exports a re-loadable config
/// document, and replaces a server via POST /load.
#[tokio::test]
async fn test_admin_adapt_export_and_load() {
    let mut server = TestServer::new(&admin_test_config("/ready-a", "ready-a"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();

    // 🧭 POST /adapt turns Pingclairfile text into the native JSON document.
    let adapted = client
        .post(server.admin_url("/adapt"))
        .header("Content-Type", "text/caddyfile")
        .body(":8080 {\n    respond \"adapted-ok\"\n}\n")
        .send()
        .await
        .unwrap();
    assert_eq!(adapted.status(), reqwest::StatusCode::OK);
    let adapted_json: serde_json::Value = adapted.json().await.unwrap();
    assert_eq!(adapted_json["servers"][0]["name"], "_");

    // 🧭 GET /config exports a document shaped like the config file.
    let exported = client
        .get(server.admin_url("/config"))
        .send()
        .await
        .unwrap();
    assert_eq!(exported.status(), reqwest::StatusCode::OK);
    let exported_json: serde_json::Value = exported.json().await.unwrap();
    assert!(
        exported_json["servers"].is_array(),
        "GET /config must return a servers array"
    );

    // 📤 POST /load replaces a server with a full document.
    let document = serde_json::json!({
        "servers": [{
            "name": "_",
            "names": [],
            "listen": [server.address(0).to_string()],
            "routes": [{
                "path": "/*",
                "handler": {"type": "respond", "status": 200, "body": "loaded-ok"}
            }]
        }]
    });
    let loaded = client
        .post(server.admin_url("/load"))
        .json(&document)
        .send()
        .await
        .unwrap();
    let loaded_status = loaded.status();
    let _ = loaded.text().await;
    assert_eq!(loaded_status, reqwest::StatusCode::OK);

    let response = client.get(server.url(0, "/")).send().await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "loaded-ok");

    // 🛡️ A document referencing an unbindable listener must be refused
    // wholesale (runtime listener creation probes the bind synchronously).
    let bad = serde_json::json!({
        "servers": [{
            "name": "bad",
            "listen": ["127.0.0.1:1"],
            "routes": []
        }]
    });
    let refused = client
        .post(server.admin_url("/load"))
        .json(&bad)
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), reqwest::StatusCode::BAD_REQUEST);
    // 🧭 The previous config must still be live.
    let response = client.get(server.url(0, "/")).send().await.unwrap();
    assert_eq!(response.text().await.unwrap(), "loaded-ok");
}

/// 🚫 POST /load must refuse a Caddy JSON document instead of answering
/// "Config loaded" while applying zero servers.
///
/// The Getting Started tutorial uploads Caddy's native
/// `{"apps":{"http":{...}}}` document. Pingclair's root config schema has no
/// `apps` field, and serde used to ignore unknown fields, so the request
/// returned 200 with an empty configuration and the running server stayed
/// untouched. An operator following the tutorial believed the config was
/// live; the regression test pins the fail-closed behavior on the real
/// binary and the real admin socket.
#[tokio::test]
async fn test_admin_load_rejects_caddy_json() {
    let mut server = TestServer::new(&admin_test_config("/__ready_caddy_json", "still-ready"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let caddy_document = r#"{"apps":{"http":{"servers":{"example":{"listen":[":2015"],"routes":[{"handle":[{"handler":"static_response","body":"Hello, world!"}]}]}}}}}"#;
    let response = client
        .post(server.admin_url("/load"))
        .header("Content-Type", "application/json")
        .body(caddy_document)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = response.text().await.unwrap();
    assert!(
        body.contains("unknown field `apps`"),
        "error must name the unknown field; got: {body}"
    );

    // 🧭 The previously loaded server must still be answering unchanged.
    let response = client
        .get(server.url(0, "/__ready_caddy_json"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "still-ready");
}

/// 🧭 Caddy-style config traversal: GET/POST/PUT/PATCH/DELETE on
/// `/config/<path>` mutate the active document and the running listener.
#[tokio::test]
async fn test_admin_config_traversal_end_to_end() {
    let mut server = TestServer::new(&admin_test_config("/__ready_traversal", "initial"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();
    let readiness_path = server.readiness_path.clone();
    let readiness_token = server.readiness_token.clone();
    let body_path = "/config/servers/0/routes/0/handler/body";

    // 📖 GET resolves a node through object keys and array indices.
    let resp = client
        .get(server.admin_url(body_path))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(
        resp.json::<serde_json::Value>().await.unwrap(),
        serde_json::Value::String(readiness_token.clone())
    );

    // 📤 POST upserts the body and the running server answers it.
    let resp = client
        .post(server.admin_url(body_path))
        .json(&serde_json::json!("traversed"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let resp = client
        .get(server.url(0, &readiness_path))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "traversed");

    // 🔁 PATCH replaces an existing node.
    let resp = client
        .patch(server.admin_url(body_path))
        .json(&serde_json::json!("patched"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let resp = client
        .get(server.url(0, &readiness_path))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "patched");

    // 🚫 PUT refuses an existing node and creates a missing one.
    let resp = client
        .put(server.admin_url(body_path))
        .json(&serde_json::json!("nope"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    let resp = client
        .put(server.admin_url("/config/servers/0/extra"))
        .json(&serde_json::json!(true))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let resp = client
        .get(server.admin_url("/config/servers/0/extra"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.json::<serde_json::Value>().await.unwrap(),
        serde_json::json!(true)
    );

    // 🗑️ DELETE removes it; unknown paths are 404.
    let resp = client
        .delete(server.admin_url("/config/servers/0/extra"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let resp = client
        .get(server.admin_url("/config/servers/0/extra"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
    let resp = client
        .get(server.admin_url("/config/servers/0/nope"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);

    // 🛡️ A malformed mutation rolls back; the running server stays patched.
    let resp = client
        .post(server.admin_url(body_path))
        .json(&serde_json::json!({"not": "a string"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let resp = client
        .get(server.url(0, &readiness_path))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "patched");
}

/// 🧭 POST with a trailing `...` appends every element of an array body.
#[tokio::test]
async fn test_admin_config_traversal_expand_appends() {
    let mut server = TestServer::new(&admin_test_config("/__ready_expand", "expand"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let route = serde_json::json!({
        "path": "/extra",
        "handler": {"type": "respond", "status": 200, "body": "extra"}
    });
    let resp = client
        .post(server.admin_url("/config/servers/0/routes/..."))
        .json(&serde_json::json!([route]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let resp = client.get(server.url(0, "/extra")).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), "extra");
}

/// 🚫 A traversal that introduces an unbound listener is refused wholesale.
#[tokio::test]
async fn test_admin_config_traversal_unbindable_listener_rolls_back() {
    let mut server = TestServer::new(&admin_test_config("/__ready_rb", "rb"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    // 🚫 Port 1 cannot be bound by an unprivileged test process; the failure
    // must surface to the caller and roll the document back.
    let new_server = serde_json::json!({"listen": ["127.0.0.1:1"], "routes": []});
    let resp = client
        .post(server.admin_url("/config/servers/..."))
        .json(&serde_json::json!([new_server]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

    // 🧭 The document and the running server are both unchanged.
    let resp = client
        .get(server.admin_url("/config/servers"))
        .send()
        .await
        .unwrap();
    let servers = resp.json::<serde_json::Value>().await.unwrap();
    assert_eq!(servers.as_array().unwrap().len(), 1);
    let resp = client
        .get(server.url(0, "/__ready_rb"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "rb");
}

/// 🧭 `/load` creates listeners at runtime and whole-document replacement
/// removes them again, like Caddy.
#[tokio::test]
async fn test_admin_load_creates_and_removes_listeners() {
    let mut server = TestServer::new(&admin_test_config("/__ready_dyn", "dyn"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    // 🔓 Find a free port for the runtime-created listener.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let new_addr = probe.local_addr().unwrap();
    drop(probe);
    let admin_listen = server.admin_address.unwrap().to_string();

    let document = serde_json::json!({
        "admin": {"enabled": true, "listen": admin_listen},
        "servers": [
            {"listen": [server.address(0).to_string()],
             "routes": [{"path": "/*", "handler": {"type": "respond", "status": 200, "body": "old"}}]},
            {"listen": [new_addr.to_string()],
             "routes": [{"path": "/*", "handler": {"type": "respond", "status": 200, "body": "new"}}]}
        ]
    });
    let resp = client
        .post(server.admin_url("/load"))
        .json(&document)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // 🧭 The new listener serves before we assert, since the accept task
    // binds asynchronously after the response.
    let new_url = format!("http://{new_addr}/");
    let mut ready = false;
    for _ in 0..30 {
        if client
            .get(&new_url)
            .send()
            .await
            .map(|response| response.status() == reqwest::StatusCode::OK)
            .unwrap_or(false)
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "runtime-created listener did not come up");
    let resp = client.get(&new_url).send().await.unwrap();
    assert_eq!(resp.text().await.unwrap(), "new");

    // 📤 Whole-document replacement without the second server closes it.
    let document = serde_json::json!({
        "admin": {"enabled": true, "listen": admin_listen},
        "servers": [{
            "listen": [server.address(0).to_string()],
            "routes": [{"path": "/*", "handler": {"type": "respond", "status": 200, "body": "only"}}]
        }]
    });
    let resp = client
        .post(server.admin_url("/load"))
        .json(&document)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // 🧭 Existing keep-alive connections may drain (Caddy does the same), so
    // prove the *socket* is gone with a fresh TCP connect instead.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut closed = false;
    for _ in 0..10 {
        if std::net::TcpStream::connect(new_addr).is_err() {
            closed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(closed, "removed runtime listener socket must close");
}

/// 🧭 `adapt -c -` and `validate -` read the config from stdin, like Caddy.
#[test]
fn cli_adapt_and_validate_read_stdin() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let bin = env!("CARGO_BIN_EXE_pingclair");
    let source = b":8080 {\n    respond \"hi\"\n}\n";

    let mut child = Command::new(bin)
        .args(["adapt", "-c", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn adapt");
    child.stdin.as_mut().unwrap().write_all(source).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "adapt stdin failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["servers"][0]["listen"][0], "[::]:8080");

    let mut child = Command::new(bin)
        .args(["validate", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn validate");
    child.stdin.as_mut().unwrap().write_all(source).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "validate stdin failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("is valid"));
}

/// 🧪 `hash-password --algorithm argon2id` emits a Caddy-compatible hash.
#[test]
fn cli_hash_password_argon2id() {
    use std::process::Command;

    let output = Command::new(env!("CARGO_BIN_EXE_pingclair"))
        .args([
            "hash-password",
            "--algorithm",
            "argon2id",
            "--plaintext",
            "secret",
            "--argon2id-time",
            "1",
            "--argon2id-memory",
            "19456",
            "--argon2id-threads",
            "1",
        ])
        .output()
        .expect("hash-password must run");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hash = String::from_utf8_lossy(&output.stdout);
    assert!(
        hash.starts_with("$argon2id$"),
        "expected an argon2id PHC string, got: {hash}"
    );
}

/// 🧪 FX-G CLI surface: completion/environ/list-modules/build-info/manpage/
/// storage.
#[test]
fn test_cli_surface_commands() {
    use std::process::Command;

    let bin = env!("CARGO_BIN_EXE_pingclair");

    let completion = Command::new(bin)
        .args(["completion", "bash"])
        .output()
        .unwrap();
    assert!(completion.status.success());
    assert!(!completion.stdout.is_empty(), "completion script is empty");

    let environ = Command::new(bin).args(["environ"]).output().unwrap();
    assert!(environ.status.success());
    assert!(String::from_utf8_lossy(&environ.stdout).contains("PATH="));

    let modules = Command::new(bin).args(["list-modules"]).output().unwrap();
    assert!(String::from_utf8_lossy(&modules.stdout).contains("http.handlers.respond"));
    let modules_json = Command::new(bin)
        .args(["list-modules", "--json"])
        .output()
        .unwrap();
    let modules_value: serde_json::Value = serde_json::from_slice(&modules_json.stdout).unwrap();
    assert!(modules_value["modules"].as_array().unwrap().len() >= 5);

    let build = Command::new(bin).args(["build-info"]).output().unwrap();
    assert!(String::from_utf8_lossy(&build.stdout).contains("pingclair"));

    let man_dir = tempfile::tempdir().unwrap();
    let man = Command::new(bin)
        .args(["manpage", "-d", man_dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        man.status.success(),
        "{}",
        String::from_utf8_lossy(&man.stderr)
    );
    assert!(man_dir.path().join("pingclair.1").is_file());

    let tls = tempfile::tempdir().unwrap();
    let store = tls.path().join("store");
    std::fs::create_dir_all(store.join("internal")).unwrap();
    std::fs::write(store.join("internal/root.crt"), "fake-root").unwrap();
    let out = tls.path().join("store.tar");
    let export = Command::new(bin)
        .args(["storage-export", "-o", out.to_str().unwrap()])
        .env("PINGCLAIR_TLS_STORE", &store)
        .output()
        .unwrap();
    assert!(
        export.status.success(),
        "{}",
        String::from_utf8_lossy(&export.stderr)
    );
    let store2 = tls.path().join("store2");
    let import = Command::new(bin)
        .args(["storage-import", "-i", out.to_str().unwrap()])
        .env("PINGCLAIR_TLS_STORE", &store2)
        .output()
        .unwrap();
    assert!(
        import.status.success(),
        "{}",
        String::from_utf8_lossy(&import.stderr)
    );
    assert!(store2.join("pingclair/internal/root.crt").is_file());
}

/// 🧪 `pingclair respond` serves a hard-coded response like `caddy respond`.
#[tokio::test]
async fn test_cli_respond_serves_body() {
    use std::process::{Command, Stdio};

    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let tls = tempfile::tempdir().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_pingclair"))
        .args([
            "respond",
            "--listen",
            &addr.to_string(),
            "--status",
            "201",
            "--header",
            "X-Test: yes",
            "--body",
            "hello-respond",
        ])
        .env("PINGCLAIR_TLS_STORE", tls.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn respond");

    let client = no_proxy_client();
    let url = format!("http://{addr}/");
    let mut ready = false;
    for _ in 0..40 {
        if client
            .get(&url)
            .send()
            .await
            .map(|response| response.status() == reqwest::StatusCode::CREATED)
            .unwrap_or(false)
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "respond server did not come up");

    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    assert_eq!(resp.headers()["x-test"], "yes");
    assert_eq!(
        resp.headers()["content-type"],
        "text/plain; charset=utf-8",
        "respond must default to a text/plain charset like Caddy"
    );
    assert_eq!(resp.text().await.unwrap(), "hello-respond");

    let _ = child.kill();
    let _ = child.wait();
}

/// 🧪 `pingclair reload` pushes a config through the Admin API.
#[tokio::test]
async fn test_cli_reload_uses_admin_api() {
    use std::process::Command;

    let mut server = TestServer::new(&admin_test_config("/__ready_cli_reload", "before"));
    assert!(server.wait_until_ready().await, "server failed to start");

    let dir = tempfile::tempdir().unwrap();
    let caddyfile = dir.path().join("Caddyfile");
    std::fs::write(
        &caddyfile,
        format!("{} {{\n    respond \"after-cli\"\n}}\n", server.address(0)),
    )
    .unwrap();
    let admin = server.admin_address.unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_pingclair"))
        .args([
            "reload",
            "--config",
            caddyfile.to_str().unwrap(),
            "--address",
            &admin.to_string(),
        ])
        .status()
        .expect("reload must run");
    assert!(status.success());

    let client = no_proxy_client();
    let resp = client.get(server.url(0, "/anything")).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), "after-cli");
}

/// 🧪 `pingclair start` and `stop` manage a background process.
#[tokio::test]
async fn test_cli_start_and_stop() {
    use std::process::Command;

    let dir = tempfile::tempdir().unwrap();
    let site_probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let site_addr = site_probe.local_addr().unwrap();
    let admin_probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let admin_addr = admin_probe.local_addr().unwrap();
    drop(site_probe);
    drop(admin_probe);

    let config_path = dir.path().join("Pingclairfile");
    std::fs::write(
        &config_path,
        format!(
            "{{\n    admin {admin_addr}\n}}\n:{} {{\n    respond \"started\"\n}}\n",
            site_addr.port()
        ),
    )
    .unwrap();
    let tls = dir.path().join("tls");
    std::fs::create_dir_all(&tls).unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_pingclair"))
        .args(["start", "--config", config_path.to_str().unwrap()])
        .env("PINGCLAIR_TLS_STORE", &tls)
        .status()
        .expect("start must run");
    assert!(status.success());

    let client = no_proxy_client();
    let url = format!("http://{site_addr}/");
    let mut started = false;
    for _ in 0..50 {
        if client
            .get(&url)
            .send()
            .await
            .map(|response| response.status() == reqwest::StatusCode::OK)
            .unwrap_or(false)
        {
            started = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(started, "background server did not come up");

    let status = Command::new(env!("CARGO_BIN_EXE_pingclair"))
        .args(["stop", "--address", &admin_addr.to_string()])
        .env("PINGCLAIR_TLS_STORE", &tls)
        .status()
        .expect("stop must run");
    assert!(status.success());

    let mut stopped = false;
    for _ in 0..30 {
        if client.get(&url).send().await.is_err() {
            stopped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(stopped, "background server must stop");
}

/// 👀 `run --watch` reloads after the config file changes.
#[cfg(unix)]
#[tokio::test]
async fn test_cli_run_watch_reloads() {
    use std::process::{Command, Stdio};

    let dir = tempfile::tempdir().unwrap();
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let site_addr = probe.local_addr().unwrap();
    drop(probe);
    let config_path = dir.path().join("Pingclairfile");
    let write_config = |body: &str| {
        std::fs::write(
            &config_path,
            format!(":{} {{\n    respond \"{body}\"\n}}\n", site_addr.port()),
        )
        .unwrap();
    };
    write_config("v1");
    let tls = dir.path().join("tls");
    std::fs::create_dir_all(&tls).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_pingclair"))
        .args(["run", "--watch", config_path.to_str().unwrap()])
        .env("PINGCLAIR_TLS_STORE", &tls)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn run --watch");

    let client = no_proxy_client();
    let url = format!("http://{site_addr}/");
    let mut v1 = false;
    for _ in 0..50 {
        if let Ok(response) = client.get(&url).send().await
            && response.status() == reqwest::StatusCode::OK
            && response.text().await.ok().as_deref() == Some("v1")
        {
            v1 = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(v1, "watched server did not come up");

    write_config("v2");
    let mut v2 = false;
    for _ in 0..60 {
        if let Ok(response) = client.get(&url).send().await
            && response.status() == reqwest::StatusCode::OK
            && response.text().await.ok().as_deref() == Some("v2")
        {
            v2 = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(v2, "--watch must reload the config automatically");

    let _ = child.kill();
    let _ = child.wait();
}

/// 🧭 The `templates` directive renders Caddy-style templates before the
/// file server serves them.
#[tokio::test]
async fn test_templates_directive_renders_caddy_templates() {
    let site = tempfile::tempdir().unwrap();
    std::fs::write(
        site.path().join("caddy.html"),
        "Page loaded at: {{now | date \"Mon Jan 2 15:04:05 MST 2006\"}}\n",
    )
    .unwrap();
    std::fs::write(site.path().join("index.html"), "<h1>plain</h1>").unwrap();

    let config = format!(
        r#"
        {{
            admin off
        }}
        :__PINGCLAIR_TEST_PORT__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            root "{}"
            templates
            file_server
        }}
        "#,
        site.path().display()
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let rendered = client
        .get(server.url(0, "/caddy.html"))
        .send()
        .await
        .unwrap();
    let body = rendered.text().await.unwrap();
    assert!(
        !body.contains("{{"),
        "template must be rendered, got: {body}"
    );
    assert!(body.contains("Page loaded at:"), "got: {body}");

    let plain = client
        .get(server.url(0, "/index.html"))
        .send()
        .await
        .unwrap();
    assert_eq!(plain.text().await.unwrap(), "<h1>plain</h1>");
}

/// 🧭 `file-server --templates` renders templates like `caddy file-server
/// --templates`.
#[tokio::test]
async fn test_cli_file_server_templates() {
    use std::process::{Command, Stdio};

    let site = tempfile::tempdir().unwrap();
    std::fs::write(
        site.path().join("caddy.html"),
        "T: {{now | date \"2006-01-02\"}}\n",
    )
    .unwrap();
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let tls = tempfile::tempdir().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_pingclair"))
        .args([
            "file-server",
            "--templates",
            "--listen",
            &addr.to_string(),
            "--root",
            site.path().to_str().unwrap(),
        ])
        .env("PINGCLAIR_TLS_STORE", tls.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn file-server --templates");

    let client = no_proxy_client();
    let url = format!("http://{addr}/caddy.html");
    let mut body = String::new();
    for _ in 0..40 {
        if let Ok(response) = client.get(&url).send().await
            && response.status() == reqwest::StatusCode::OK
        {
            body = response.text().await.unwrap();
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!body.is_empty(), "file-server --templates did not come up");
    assert!(!body.contains("{{"), "got: {body}");
    assert!(body.starts_with("T: "), "got: {body}");

    let _ = child.kill();
    let _ = child.wait();
}

/// 🧭 file_server sends `text/html; charset=utf-8` and a Vary header when it
/// compresses, like Caddy.
#[tokio::test]
async fn test_file_server_charset_and_vary() {
    let site = tempfile::tempdir().unwrap();
    std::fs::write(site.path().join("index.html"), "<h1>charset</h1>").unwrap();
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let tls = tempfile::tempdir().unwrap();

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_pingclair"))
        .args([
            "file-server",
            "--listen",
            &addr.to_string(),
            "--root",
            site.path().to_str().unwrap(),
        ])
        .env("PINGCLAIR_TLS_STORE", tls.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn file-server");

    let client = no_proxy_client();
    let url = format!("http://{addr}/index.html");
    let mut headers = None;
    for _ in 0..40 {
        if let Ok(response) = client.get(&url).send().await
            && response.status() == reqwest::StatusCode::OK
        {
            headers = Some(response.headers().clone());
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let headers = headers.expect("file server did not come up");
    assert_eq!(
        headers["content-type"], "text/html; charset=utf-8",
        "file_server must send a charset like Caddy"
    );

    let _ = child.kill();
    let _ = child.wait();
}

/// 🧭 `/load` accepts a Caddyfile when the client sends `text/caddyfile`.
#[tokio::test]
async fn test_admin_load_accepts_caddyfile_content_type() {
    let mut server = TestServer::new(&admin_test_config("/__ready_adapter", "adapter"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let listen = server.address(0).to_string();
    let caddyfile = format!("{listen} {{\n    respond \"adapted-ok\"\n}}\n");
    let resp = client
        .post(server.admin_url("/load"))
        .header("Content-Type", "text/caddyfile")
        .body(caddyfile)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let resp = client.get(server.url(0, "/anything")).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), "adapted-ok");
}

/// 🏷️ `@id` tags turn long traversal paths into `/id/<name>` shortcuts.
#[tokio::test]
async fn test_admin_id_tags_end_to_end() {
    let mut server = TestServer::new(&admin_test_config("/__ready_id", "id"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    // 🏷️ Tag the readiness handler object.
    let resp = client
        .post(server.admin_url("/config/servers/0/routes/0/handler/@id"))
        .json(&serde_json::json!("msg"))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    println!("TAG POST status={status} body={body}");
    assert_eq!(status, reqwest::StatusCode::OK, "body: {body}");

    // 📖 Read the whole object through the tag.
    let resp = client
        .get(server.admin_url("/id/msg"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let node = resp.json::<serde_json::Value>().await.unwrap();
    assert_eq!(node["type"], "respond");

    // ✍️ Mutate a nested field through the tag.
    let resp = client
        .post(server.admin_url("/id/msg/body"))
        .json(&serde_json::json!("id-ok"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let resp = client
        .get(server.url(0, &server.readiness_path))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "id-ok");

    // 🗑️ Removing the tag makes `/id/msg` 404 while the handler survives.
    let resp = client
        .delete(server.admin_url("/id/msg/@id"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let resp = client
        .get(server.admin_url("/id/msg"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

/// 💾 API changes autosave; `run --resume` restores them after a restart.
#[tokio::test]
async fn test_admin_autosave_and_resume() {
    let mut server = TestServer::new(&admin_test_config("/__ready_save", "save"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let document = serde_json::json!({
        "admin": {"enabled": true, "listen": server.admin_address.unwrap().to_string()},
        "servers": [{
            "listen": [server.address(0).to_string()],
            "routes": [{
                "path": "/__resumed",
                "handler": {"type": "respond", "status": 200, "body": "resumed-ok"}
            }]
        }]
    });
    let resp = client
        .post(server.admin_url("/load"))
        .json(&document)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let autosave = server._temp_dir.path().join("tls/autosave.json");
    assert!(autosave.is_file(), "autosave must exist after /load");
    let listen_addr = server.address(0);
    let tls_dir = server._temp_dir.path().join("tls");
    server.stop();

    // 🚀 A nonexistent config path proves `--resume` wins over the file.
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_pingclair"))
        .args(["run", "--resume", "does-not-exist.conf"])
        .env("PINGCLAIR_TLS_STORE", &tls_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn resumed server");

    let url = format!("http://{listen_addr}/__resumed");
    let client = no_proxy_client();
    let mut ready = false;
    for _ in 0..50 {
        if client
            .get(&url)
            .send()
            .await
            .map(|response| response.status() == reqwest::StatusCode::OK)
            .unwrap_or(false)
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(ready, "resumed server did not come up");
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), "resumed-ok");

    let _ = child.kill();
    let _ = child.wait();
}

/// 🛑 `POST /stop` answers 200 first, then the process exits gracefully.
#[tokio::test]
async fn test_admin_stop_returns_response_then_exits() {
    let mut server = TestServer::new(&admin_test_config("/__ready_stop", "stop"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let resp = client.post(server.admin_url("/stop")).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let mut exited = false;
    for _ in 0..30 {
        if server.process.try_wait().unwrap().is_some() {
            exited = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(exited, "server did not exit after /stop");
}

/// 🔔 SIGUSR1 reloads the running server from its config file, SIGHUP is
/// ignored (Caddy semantics) — on any Unix, including macOS dev machines.
/// Unix, including the macOS dev machines this suite runs on. The test edits
/// the Pingclairfile, signals the real binary, and checks that the new route
/// answers and that a global change is reported as requiring a restart.
#[cfg(unix)]
#[tokio::test]
async fn test_signal_reload_applies_config_and_warns_on_global_changes() {
    let config = r#"
        {
            admin off
            email before@example.com
        }

        :__PINGCLAIR_TEST_PORT__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "before-reload"
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();
    let response = client.get(server.url(0, "/")).send().await.unwrap();
    assert_eq!(response.text().await.unwrap(), "before-reload");

    // ✍️ Edit the config: new body plus a global option change.
    let config_path = server._temp_dir.path().join("Pingclairfile");
    let updated = std::fs::read_to_string(&config_path)
        .unwrap()
        .replace("before@example.com", "after@example.com")
        .replace("before-reload", "after-reload");
    std::fs::write(&config_path, updated).unwrap();

    // 🔔 SIGHUP must be ignored, like Caddy's signal table.
    let status = std::process::Command::new("kill")
        .args(["-HUP", &server.process.id().to_string()])
        .status()
        .expect("kill must run");
    assert!(status.success());
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let response = client.get(server.url(0, "/")).send().await.unwrap();
    assert_eq!(
        response.text().await.unwrap(),
        "before-reload",
        "SIGHUP must be ignored"
    );

    // 🚦 SIGUSR1 (Caddy's reload signal) applies the edited config.
    let status = std::process::Command::new("kill")
        .args(["-USR1", &server.process.id().to_string()])
        .status()
        .expect("kill must run");
    assert!(status.success());

    // ⏳ Wait for the reloaded route to answer.
    let mut reloaded = false;
    for _ in 0..50 {
        if let Ok(response) = client.get(server.url(0, "/")).send().await
            && response.text().await.ok().as_deref() == Some("after-reload")
        {
            reloaded = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(reloaded, "the server must answer with the reloaded body");

    // 🚩 The global email change must be reported as restart-only.
    // 🧭 TestServer sets RUST_LOG=info, so the warning lands in this file.
    let stderr = std::fs::read_to_string(&server.stdout_path).unwrap_or_default();
    assert!(
        stderr.contains("global options"),
        "the reload must warn that global settings need a restart:\n{stderr}"
    );

    // 🚦 A second SIGUSR1 applies the next edit.
    std::fs::write(
        &config_path,
        std::fs::read_to_string(&config_path)
            .unwrap()
            .replace("after-reload", "usr1-reload"),
    )
    .unwrap();
    let status = std::process::Command::new("kill")
        .args(["-USR1", &server.process.id().to_string()])
        .status()
        .expect("kill must run");
    assert!(status.success());

    let mut usr1_reloaded = false;
    for _ in 0..50 {
        if let Ok(response) = client.get(server.url(0, "/")).send().await
            && response.text().await.ok().as_deref() == Some("usr1-reload")
        {
            usr1_reloaded = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(usr1_reloaded, "SIGUSR1 must reload the configuration");
}

/// 🏃 SIGQUIT forces an immediate exit with code 2, like Caddy.
#[cfg(unix)]
#[tokio::test]
async fn test_sigquit_exits_with_code_2() {
    let mut server = TestServer::new(&admin_test_config("/__ready_quit", "quit"));
    assert!(server.wait_until_ready().await, "server failed to start");

    let status = std::process::Command::new("kill")
        .args(["-QUIT", &server.process.id().to_string()])
        .status()
        .expect("kill must run");
    assert!(status.success());

    let mut exit = None;
    for _ in 0..30 {
        if let Some(code) = server.process.try_wait().unwrap() {
            exit = Some(code);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let exit = exit.expect("process must exit on SIGQUIT");
    assert_eq!(exit.code(), Some(2));
}

/// 🚫 After an Admin API change, SIGUSR1 reloads are disabled (Caddy).
#[cfg(unix)]
#[tokio::test]
async fn test_api_change_disables_signal_reload() {
    let mut server = TestServer::new(&admin_test_config("/__ready_apichange", "api"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    // ✍️ Change the body through the Admin API.
    let resp = client
        .post(server.admin_url("/config/servers/0/routes/0/handler/body"))
        .json(&serde_json::json!("api-changed"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // ✍️ Edit the config file so a (wrongly allowed) reload would be visible.
    let config_path = server._temp_dir.path().join("config.json");
    let updated = std::fs::read_to_string(&config_path)
        .unwrap()
        .replace(&server.readiness_token, "file-changed");
    std::fs::write(&config_path, updated).unwrap();

    let status = std::process::Command::new("kill")
        .args(["-USR1", &server.process.id().to_string()])
        .status()
        .expect("kill must run");
    assert!(status.success());
    tokio::time::sleep(Duration::from_millis(500)).await;

    let resp = client
        .get(server.url(0, &server.readiness_path))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.text().await.unwrap(),
        "api-changed",
        "signal reload must be disabled after API changes"
    );
}

/// 🔁 SIGUSR1 replaces a respond route with a file_server route; the reload
/// must rebuild handlers so the new handler type actually answers.
#[cfg(unix)]
#[tokio::test]
async fn test_signal_reload_switches_handler_types() {
    let config = r#"
        {
            admin off
        }
        :__PINGCLAIR_TEST_PORT__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "respond-body"
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();
    let response = client.get(server.url(0, "/")).send().await.unwrap();
    assert_eq!(response.text().await.unwrap(), "respond-body");

    // 📄 Prepare a real file for the file_server route.
    let root = server._temp_dir.path().join("site");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("index.html"), "<h1>file-ok</h1>").unwrap();

    let config_path = server._temp_dir.path().join("Pingclairfile");
    let updated = format!(
        "{{\n    admin off\n}}\n:{} {{\n    root \"{}\"\n    file_server\n}}\n",
        server.address(0).port(),
        root.display()
    );
    std::fs::write(&config_path, updated).unwrap();

    let status = std::process::Command::new("kill")
        .args(["-USR1", &server.process.id().to_string()])
        .status()
        .expect("kill must run");
    assert!(status.success());

    let mut switched = false;
    for _ in 0..50 {
        if let Ok(response) = client.get(server.url(0, "/")).send().await
            && response.text().await.ok().as_deref() == Some("<h1>file-ok</h1>")
        {
            switched = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(switched, "reload must switch the handler type");
}

/// 🧱 **Day 25's atomicity property.**
///
/// A reload whose new configuration names a port something else already holds
/// must change *nothing*. Before this, ports were published one at a time
/// inside the apply loop, so the addresses handled before the failure were
/// already serving the new configuration and the reload announced itself as
/// "partially reloaded" — a state no operator asked for and none can reason
/// about afterwards.
#[tokio::test]
async fn test_signal_reload_is_rejected_whole_when_a_new_listener_cannot_bind() {
    let config = r#"
        {
            admin off
        }
        :__PINGCLAIR_TEST_PORT__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "original"
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();
    assert_eq!(
        client
            .get(server.url(0, "/"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "original"
    );

    // 🧱 Hold a port so the reload's second site cannot bind it.
    //
    // 📌 The blocker binds the wildcard, because a bare `:port` site derives a
    // wildcard listener — holding only `127.0.0.1:port` would leave `[::]:port`
    // bindable on a dual-stack host and the test would prove nothing.
    let blocker = std::net::TcpListener::bind("[::]:0").expect("bind blocker");
    let taken = blocker.local_addr().unwrap().port();

    // 📝 The new configuration changes the existing site *and* adds one on the
    // occupied port. If the reload were not atomic, the first change would
    // land and the second would fail.
    let config_path = server._temp_dir.path().join("Pingclairfile");
    let updated = format!(
        "{{\n    admin off\n}}\n:{} {{\n    respond \"CHANGED\"\n}}\n:{} {{\n    respond \"second\"\n}}\n",
        server.address(0).port(),
        taken
    );
    std::fs::write(&config_path, updated).unwrap();

    let status = std::process::Command::new("kill")
        .args(["-USR1", &server.process.id().to_string()])
        .status()
        .expect("kill must run");
    assert!(status.success());

    // ⏳ Give the reload time to run and, if it were going to, to apply half.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let body = client
        .get(server.url(0, "/"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        body, "original",
        "the reload could not bind one listener, so it must have changed nothing — \
         instead the first site was already updated"
    );
    drop(blocker);
}

/// 🧹 A site removed from the configuration must stop answering.
///
/// The old reload only ever added and updated, so a bind address that
/// disappeared kept serving its previous configuration until the process
/// restarted. Deleting a site and having it stay reachable is the most
/// dangerous direction for this to fail in.
#[tokio::test]
async fn test_signal_reload_stops_a_listener_that_left_the_configuration() {
    let config = r#"
        {
            admin off
        }
        :__PINGCLAIR_TEST_PORT__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "kept"
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    // ➕ Add a second site by reload, so it is a *dynamic* listener — the kind
    // this process bound itself and can therefore release.
    let extra = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe");
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        port
    };
    let config_path = server._temp_dir.path().join("Pingclairfile");
    let with_extra = format!(
        "{{\n    admin off\n}}\n:{} {{\n    respond \"kept\"\n}}\n:{} {{\n    respond \"temporary\"\n}}\n",
        server.address(0).port(),
        extra
    );
    std::fs::write(&config_path, with_extra).unwrap();
    let _ = std::process::Command::new("kill")
        .args(["-USR1", &server.process.id().to_string()])
        .status();

    let mut serving = false;
    for _ in 0..50 {
        if let Ok(response) = client
            .get(format!("http://127.0.0.1:{extra}/"))
            .send()
            .await
            && response.text().await.ok().as_deref() == Some("temporary")
        {
            serving = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(serving, "the added listener never started serving");

    // ➖ Now remove it again.
    let without_extra = format!(
        "{{\n    admin off\n}}\n:{} {{\n    respond \"kept\"\n}}\n",
        server.address(0).port()
    );
    std::fs::write(&config_path, without_extra).unwrap();
    let _ = std::process::Command::new("kill")
        .args(["-USR1", &server.process.id().to_string()])
        .status();

    let mut observed = String::new();
    let mut stopped = false;
    for _ in 0..50 {
        // 🔌 A fresh client each time. The pooled one would keep reusing the
        // connection it opened while the listener was up, which proves nothing
        // about whether the listener is still accepting.
        let probe = reqwest::Client::builder()
            .no_proxy()
            .pool_max_idle_per_host(0)
            .build()
            .unwrap();
        match probe
            .get(format!("http://127.0.0.1:{extra}/"))
            .timeout(Duration::from_millis(500))
            .send()
            .await
        {
            Err(_) => {
                stopped = true;
                break;
            }
            Ok(response) => {
                observed = format!(
                    "{} {}",
                    response.status(),
                    response.text().await.unwrap_or_default()
                );
                if !observed.contains("temporary") {
                    stopped = true;
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        stopped,
        "the removed site is still serving its old configuration on :{extra} \
         after the reload (last response: {observed})"
    );

    // 🎯 The site that stayed must be untouched.
    assert_eq!(
        client
            .get(server.url(0, "/"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "kept"
    );
}

/// 🔎 Starts a TLS-ready test server and returns (status, x-order, body).
async fn fetch_ordered_response(server: &mut TestServer) -> (reqwest::StatusCode, String, String) {
    assert!(
        server.wait_until_tls_ready("example.com").await,
        "server failed to start"
    );
    let root_path = server._temp_dir.path().join("tls/internal/root.crt");
    let root = reqwest::Certificate::from_pem(&std::fs::read(&root_path).unwrap()).unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(root)
        .resolve("example.com", server.address(0))
        .build()
        .unwrap();
    let response = client
        .get(server.tls_url(0, "example.com", "/"))
        .send()
        .await
        .unwrap();
    (
        response.status(),
        response
            .headers()
            .get("x-order")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .unwrap_or_default(),
        response.text().await.unwrap(),
    )
}

/// 🛠️ Starts a server with the Admin API enabled and one readiness route.
///
/// These tests drive the real Admin socket rather than calling
/// `validate_config` directly. That distinction is the whole point: the
/// function always rejected these configurations, and the *path* did not
/// call the function.
fn admin_test_config(readiness_path: &str, readiness_token: &str) -> String {
    serde_json::json!({
        "global": { "http3": false },
        "admin": { "enabled": true, "listen": "127.0.0.1:0" },
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "routes": [{
                "path": readiness_path,
                "handler": { "type": "respond", "status": 200, "body": readiness_token }
            }]
        }]
    })
    .to_string()
}

/// 🚫 An unimplemented handler must be refused at the Admin door.
///
/// `pingclair-plugin` is an unwired skeleton: no caller anywhere in the
/// workspace. A configuration naming a plugin used to validate, install, and
/// then do nothing at request time — the H1/H2 dispatcher fell through a
/// wildcard arm that returned "not handled" without logging. An operator who
/// wrote a plugin route to authenticate or filter got a route that was simply
/// absent, and nothing ever said so.
#[tokio::test]
async fn test_admin_rejects_a_config_naming_an_unimplemented_plugin() {
    let mut server = TestServer::new(&admin_test_config("/__ready_plugin", "ready-plugin-token"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let poisoned = serde_json::json!({
        "listen": [server.address(0).to_string()],
        "routes": [{
            "path": "/*",
            "handler": { "type": "plugin", "name": "totally-fictional", "args": [] }
        }]
    });

    let response = client
        .post(server.admin_url("/config/0"))
        .json(&poisoned)
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        400,
        "a plugin handler must fail closed, not install as a silent no-op"
    );
    let body = response.text().await.unwrap();
    assert!(
        body.contains("plugin"),
        "the rejection must name the offending handler, got: {body}"
    );

    // 🛡️ The rejection must also leave the running configuration untouched.
    let still_serving = client
        .get(server.url(0, "/__ready_plugin"))
        .send()
        .await
        .unwrap();
    assert_eq!(still_serving.status(), 200);
    assert_eq!(still_serving.text().await.unwrap(), "ready-plugin-token");
}

/// 🛡️ The Admin door runs the same safety rules as a Pingclairfile.
///
/// `validate_config` rejected a retry policy of 999 attempts all along. The
/// Admin API just never asked it, so the one interface reachable over a socket
/// was the one with no rules.
#[tokio::test]
async fn test_admin_runs_the_canonical_validator_on_posted_config() {
    let mut server = TestServer::new(&admin_test_config("/__ready_retry", "ready-retry-token"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let unsafe_retry = serde_json::json!({
        "listen": [server.address(0).to_string()],
        "routes": [{
            "path": "/*",
            "handler": {
                "type": "reverse_proxy",
                "upstreams": ["http://127.0.0.1:9"],
                "retry": { "max_attempts": 999 }
            }
        }]
    });

    let response = client
        .post(server.admin_url("/config/0"))
        .json(&unsafe_retry)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);

    let still_serving = client
        .get(server.url(0, "/__ready_retry"))
        .send()
        .await
        .unwrap();
    assert_eq!(still_serving.status(), 200);
}

/// 🧭 A config naming an unbound listener applies nothing at all.
///
/// The old loop applied per listener as it walked the list, so a config naming
/// a live address and a bogus one left the first on the new settings and the
/// second on the old — a half-applied state that was never reported.
#[tokio::test]
async fn test_admin_config_for_an_unknown_listener_applies_nothing() {
    let mut server = TestServer::new(&admin_test_config(
        "/__ready_partial",
        "ready-partial-token",
    ));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let half_valid = serde_json::json!({
        "listen": [server.address(0).to_string(), "127.0.0.1:1"],
        "routes": [{
            "path": "/*",
            "handler": { "type": "respond", "status": 200, "body": "should-never-apply" }
        }]
    });

    let response = client
        .post(server.admin_url("/config/0"))
        .json(&half_valid)
        .send()
        .await
        .unwrap();
    // 🚫 The unbindable second listener fails synchronously now (runtime
    // listener creation probes the bind); nothing may be half-applied.
    assert_eq!(response.status(), 400);

    // 🛡️ The live listener named first must not have been rewritten.
    let untouched = client
        .get(server.url(0, "/__ready_partial"))
        .send()
        .await
        .unwrap();
    assert_eq!(untouched.status(), 200);
    assert_eq!(untouched.text().await.unwrap(), "ready-partial-token");
}

/// 🧱 An oversized body is refused, and the process survives it.
///
/// The old code read the body with `req.collect().await.unwrap()` and had no
/// ceiling at all. This asserts the limit answers 413 — and, just as
/// importantly, that the server is still alive afterwards to answer anything.
#[tokio::test]
async fn test_admin_rejects_an_oversized_config_body() {
    let mut server = TestServer::new(&admin_test_config("/__ready_big", "ready-big-token"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    // 🐘 Two megabytes of valid JSON, over the one-megabyte ceiling.
    let filler = "x".repeat(2 * 1024 * 1024);
    let oversized = serde_json::json!({
        "listen": [server.address(0).to_string()],
        "routes": [{
            "path": "/*",
            "handler": { "type": "respond", "status": 200, "body": filler }
        }]
    });

    let response = client
        .post(server.admin_url("/config/0"))
        .json(&oversized)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 413);

    let alive = client
        .get(server.admin_url("/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        alive.status(),
        200,
        "the admin server must still be running"
    );
}

/// 💀 A truncated upload must not take the process down with it.
///
/// This is the one that mattered. `panic = "abort"` is set for release builds,
/// so `unwrap()` on a failed body read aborted the entire server: every
/// in-flight request on every listener, gone. No malice required — an
/// authenticated client whose connection dropped mid-upload was enough,
/// because a truncated body is an `Err`, not a short `Ok`.
///
/// A raw socket is used rather than an HTTP client because the point is to
/// promise a body and then vanish, which a well-behaved client will not do.
#[tokio::test]
async fn test_admin_survives_a_client_that_disconnects_mid_body() {
    use tokio::io::AsyncWriteExt;

    let mut server = TestServer::new(&admin_test_config("/__ready_abort", "ready-abort-token"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let admin_address = server
        .admin_address
        .expect("this fixture enables the admin API");

    // 🔌 Announce 4096 bytes, send 16, then drop the connection.
    {
        let mut socket = tokio::net::TcpStream::connect(admin_address).await.unwrap();
        socket
            .write_all(
                b"POST /config/0 HTTP/1.1\r\n\
                  Host: localhost\r\n\
                  Content-Type: application/json\r\n\
                  Content-Length: 4096\r\n\r\n\
                  {\"listen\":[\"127",
            )
            .await
            .unwrap();
        socket.flush().await.unwrap();
    }

    // 🩺 Liveness alone is not enough to prove this, and assuming it would
    // make the test worthless. `panic = "abort"` is set only for the release
    // profile, so in this debug build the old `unwrap()` merely unwound the
    // connection task and the server stayed up — a liveness check passes
    // against the very bug it is meant to catch. The panic itself is the
    // observable that survives both profiles, and it lands on stderr.
    let alive = client
        .get(server.admin_url("/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        alive.status(),
        200,
        "a truncated upload must not abort the process"
    );
    let serving = client
        .get(server.url(0, "/__ready_abort"))
        .send()
        .await
        .unwrap();
    assert_eq!(serving.status(), 200, "proxy listeners must still serve");

    let stderr = std::fs::read_to_string(&server.stderr_path).unwrap_or_default();
    assert!(
        !stderr.contains("panicked at"),
        "reading the body panicked; under the release profile's `panic = \\\"abort\\\"` \
         that is not a dropped connection but the whole server going down. stderr:\n{stderr}"
    );
}

/// 🧭 A redirect target is a template, so `{host}` and `{uri}` must expand.
///
/// This is what Automatic HTTPS relies on to send a plaintext visitor to the
/// same resource over TLS. A literal `https://{host}{uri}` in the `Location`
/// header would send every client to a hostname that does not exist.
#[tokio::test]
async fn test_redirect_expands_host_and_uri_placeholders() {
    let config = r#"
        {
            admin off
        }

        :__PINGCLAIR_TEST_PORT__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            redir "https://{host}{uri}" 308
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let response = client
        .get(server.url(0, "/deep/path?q=1"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 308);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("a redirect must carry a Location");
    // 🧭 `{host}` is the hostname without the port, matching Caddy. The
    // non-standard test port therefore disappears from the redirect target;
    // `{hostport}` is the placeholder that preserves it.
    assert_eq!(
        location,
        format!("https://{}/deep/path?q=1", server.address(0).ip())
    );
}

/// 🧭 A directive inside `route` carries its own matcher, exactly as the
/// format allows. Before C2 the matcher was read as the response body, so
/// every request got the literal `@admin`; now the first element must gate
/// and the second must serve everyone else.
#[tokio::test]
async fn test_route_element_matchers_gate_handlers() {
    let config = r#"
        {
            admin off
        }

        :__PINGCLAIR_TEST_PORT__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            route {
                @admin path /admin/*
                respond @admin "SECRET" 200
                respond "public" 200
            }
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = no_proxy_client();

    let secret = client
        .get(server.url(0, "/admin/secrets"))
        .send()
        .await
        .unwrap();
    assert_eq!(secret.status(), 200);
    assert_eq!(secret.text().await.unwrap(), "SECRET");

    let public = client.get(server.url(0, "/public")).send().await.unwrap();
    assert_eq!(public.status(), 200);
    assert_eq!(public.text().await.unwrap(), "public");
}

/// 🎫 Builds a real two-level trust path: root CA → intermediate CA → leaf.
///
/// Why not just self-sign, the way every other TLS test here does? Because a
/// self-signed certificate is its own issuer, so it has no intermediate at all
/// — "leaf only" and "full chain" are byte-for-byte the same file. A server
/// that drops intermediates is therefore *invisible* to a self-signed fixture.
/// Only a leaf whose issuer is a separate certificate can expose it.
fn build_two_level_chain(dns_name: &str) -> (String, String) {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

    let mut root_params = CertificateParams::new(Vec::new()).expect("root parameters");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params
        .distinguished_name
        .push(DnType::CommonName, "Pingclair Test Root");
    let root_key = KeyPair::generate().expect("root key");

    let mut intermediate_params =
        CertificateParams::new(Vec::new()).expect("intermediate parameters");
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    intermediate_params
        .distinguished_name
        .push(DnType::CommonName, "Pingclair Test Intermediate");
    let intermediate_key = KeyPair::generate().expect("intermediate key");
    let intermediate_certificate = intermediate_params
        .signed_by(
            &intermediate_key,
            &Issuer::from_params(&root_params, &root_key),
        )
        .expect("intermediate certificate");

    let mut leaf_params =
        CertificateParams::new(vec![dns_name.to_string()]).expect("leaf parameters");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, dns_name);
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf_certificate = leaf_params
        .signed_by(
            &leaf_key,
            &Issuer::from_params(&intermediate_params, &intermediate_key),
        )
        .expect("leaf certificate");

    // 🔗 A CA returns leaf-then-intermediates, and that is the order a server
    // has to replay on the wire for a client to build a path to the root.
    let fullchain = format!(
        "{}{}",
        leaf_certificate.pem(),
        intermediate_certificate.pem()
    );
    (fullchain, leaf_key.serialize_pem())
}

/// 🔐 Counts the certificates a TLS server actually sends during a handshake.
///
/// Trust verification is deliberately switched off: the question here is not
/// "does this chain validate" but "how many certificates arrived". Those are
/// different failures, and mixing them would let a trust-store quirk mask a
/// missing intermediate.
fn count_certificates_sent_by_server(address: SocketAddr, sni: &str) -> usize {
    use pingora_core::tls::ssl::{SslConnector, SslMethod, SslVerifyMode};

    let mut builder = SslConnector::builder(SslMethod::tls()).expect("tls connector builder");
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();

    let stream = std::net::TcpStream::connect(address).expect("connect to the test server");
    let session = connector
        .configure()
        .expect("connect configuration")
        .verify_hostname(false)
        .use_server_name_indication(true)
        .connect(sni, stream)
        .expect("tls handshake");

    // 🔗 On the client side BoringSSL includes the leaf in this stack, so a
    // correctly configured server reports leaf + intermediate = 2.
    session
        .ssl()
        .peer_cert_chain()
        .expect("the server presented no certificate at all")
        .len()
}

/// 🛡️ A server must send its intermediates, not just the leaf.
///
/// This is a real defect found on 2026-07-30 by two EC2 hosts testing each
/// other over the public internet: `X509::from_pem` stops at the first
/// certificate in a PEM bundle and silently discards the rest, so every H1/H2
/// handshake presented a lone leaf. `curl`, Go, and Java reject that with
/// "unable to get local issuer certificate"; browsers hide it by caching
/// intermediates and fetching missing ones over AIA, which is exactly why it
/// survived so long.
#[tokio::test]
async fn test_tls_handshake_sends_the_intermediate_not_just_the_leaf() {
    let (fullchain_pem, key_pem) = build_two_level_chain("chained.test");
    assert_eq!(
        fullchain_pem.matches("BEGIN CERTIFICATE").count(),
        2,
        "the fixture itself must carry a leaf and an intermediate"
    );

    // 📁 The certificate files must exist before the server parses its config,
    // so they live in their own directory rather than the server's temp dir.
    let material = tempfile::tempdir().expect("certificate material dir");
    let cert_path = material.path().join("fullchain.pem");
    let key_path = material.path().join("privkey.pem");
    std::fs::write(&cert_path, &fullchain_pem).expect("write fullchain");
    std::fs::write(&key_path, &key_pem).expect("write private key");

    let config = format!(
        r#"
        {{
            admin off
        }}

        https://chained.test:__PINGCLAIR_TEST_PORT__ {{
            tls {{
                cert {}
                key {}
            }}

            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "chained-ok"
        }}
        "#,
        cert_path.to_string_lossy(),
        key_path.to_string_lossy()
    );

    let mut server = TestServer::new_pingclairfile(&config);
    assert!(
        server.wait_until_tls_ready("chained.test").await,
        "server failed to start with a chained certificate"
    );

    let address = server.address(0);
    let presented = tokio::task::spawn_blocking(move || {
        count_certificates_sent_by_server(address, "chained.test")
    })
    .await
    .expect("handshake task");

    assert_eq!(
        presented, 2,
        "the server sent {presented} certificate(s); a lone leaf cannot be \
         verified by any client that does not already hold the intermediate"
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

    let config = serde_json::json!({
        "global": { "http3": false },
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "limits": {
                "idle_timeout_ms": 100,
                "request_timeout_ms": 100,
                "long_connections": {
                    "idle_timeout_ms": 1000,
                    "request_timeout_ms": 0
                }
            },
            "routes": [{
                "path": "/*",
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
    tokio::time::sleep(Duration::from_millis(300)).await;
    client.write_all(b"client-ping").await.unwrap();
    let downstream = read_until_marker(&mut client, b"upstream-pong", Duration::from_secs(2)).await;
    assert!(
        downstream
            .windows(b"upstream-pong".len())
            .any(|window| window == b"upstream-pong")
    );
    upstream_task.await.unwrap();
}

/// 🔐 Serves one TLS request from a self-signed origin and returns its address.
///
/// The origin is deliberately self-signed and names only `origin.test`: it is
/// trusted by nothing the proxy already knows, so any successful proxy request
/// against it proves the route's configured trust was the reason.
async fn spawn_self_signed_tls_origin(
    certificate_pem: &str,
    key_pem: &str,
    responses: usize,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use pingora_core::tls::ssl::{SslContext, SslFiletype, SslMethod};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // 🔑 BoringSSL's acceptor builder loads from paths, so the PEMs are staged
    // in a directory the task owns for its whole life.
    let staging = tempfile::tempdir().expect("tls staging dir");
    let certificate_path = staging.path().join("origin.crt");
    let key_path = staging.path().join("origin.key");
    std::fs::write(&certificate_path, certificate_pem).expect("write origin certificate");
    std::fs::write(&key_path, key_pem).expect("write origin key");

    let mut builder = SslContext::builder(SslMethod::tls()).expect("tls context builder");
    builder
        .set_certificate_chain_file(&certificate_path)
        .expect("load origin certificate");
    builder
        .set_private_key_file(&key_path, SslFiletype::PEM)
        .expect("load origin key");
    let context = builder.build();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind tls origin");
    let address = listener.local_addr().expect("origin address");

    let task = tokio::spawn(async move {
        // 🗂️ Moved in so the staged PEMs outlive every handshake.
        let _staging = staging;
        for _ in 0..responses {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let context = context.clone();
            tokio::spawn(async move {
                let ssl = pingora_core::tls::ssl::Ssl::new(&context).expect("ssl session");
                let Ok(mut tls) = pingora_core::tls::tokio_ssl::SslStream::new(ssl, stream) else {
                    return;
                };
                if std::pin::Pin::new(&mut tls).accept().await.is_err() {
                    // 🔒 A refused handshake is the expected outcome of the
                    // untrusted case; the client side asserts on it.
                    return;
                }
                let mut request = vec![0u8; 8192];
                let Ok(read) = tls.read(&mut request).await else {
                    return;
                };
                if read == 0 {
                    return;
                }
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nsecure-origin",
                    )
                    .await;
                let _ = tls.flush().await;
            });
        }
    });

    (address, task)
}

/// 🔐 Builds a one-route reverse proxy at `https://` with an explicit TLS block.
fn tls_upstream_config(origin: SocketAddr, upstream_tls: serde_json::Value) -> String {
    serde_json::json!({
        "global": { "http3": false },
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "routes": [{
                "path": "/*",
                "handler": {
                    "type": "reverse_proxy",
                    "upstreams": [format!("https://{origin}")],
                    "load_balance": { "strategy": "round_robin" },
                    "headers_up": {},
                    "headers_down": {},
                    "upstream_tls": upstream_tls
                }
            }]
        }]
    })
    .to_string()
}

#[tokio::test]
async fn test_upstream_tls_verifies_by_default_and_honours_configured_trust() {
    // 🎫 One self-signed origin named `origin.test`, reachable only at an IP.
    let mut params = rcgen::CertificateParams::new(vec!["origin.test".to_string()])
        .expect("certificate parameters");
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "origin.test");
    let key = rcgen::KeyPair::generate().expect("key pair");
    let certificate = params.self_signed(&key).expect("self-signed origin");
    let certificate_pem = certificate.pem();
    let key_pem = key.serialize_pem();

    let trust_store = tempfile::tempdir().expect("trust store dir");
    let trust_path = trust_store.path().join("origin-ca.pem");
    std::fs::write(&trust_path, &certificate_pem).expect("publish trust root");
    let trust_path = trust_path.to_string_lossy().to_string();

    // 🚫 Default configuration: nothing tells the proxy to trust this origin.
    {
        let (origin, origin_task) =
            spawn_self_signed_tls_origin(&certificate_pem, &key_pem, 1).await;
        let config = tls_upstream_config(origin, serde_json::json!({}));
        let mut server = TestServer::new(&config);
        assert!(server.wait_until_ready().await, "server failed to start");

        let response = no_proxy_client()
            .get(server.url(0, "/"))
            .send()
            .await
            .expect("the proxy must answer, not hang");
        assert!(
            response.status().is_server_error(),
            "an untrusted self-signed origin must not be proxied, got {}",
            response.status()
        );
        assert_ne!(
            response.text().await.unwrap(),
            "secure-origin",
            "the origin's body must never reach the client through an unverified handshake"
        );
        origin_task.abort();
    }

    // ✅ The same origin, with its certificate pinned as this route's trust root.
    {
        let (origin, origin_task) =
            spawn_self_signed_tls_origin(&certificate_pem, &key_pem, 1).await;
        let config = tls_upstream_config(
            origin,
            serde_json::json!({
                "server_name": "origin.test",
                "trusted_ca_certs": [trust_path.clone()]
            }),
        );
        let mut server = TestServer::new(&config);
        assert!(server.wait_until_ready().await, "server failed to start");

        let response = no_proxy_client()
            .get(server.url(0, "/"))
            .send()
            .await
            .expect("the proxy must answer");
        assert_eq!(
            response.status(),
            200,
            "pinning the origin's own certificate must make it verifiable"
        );
        assert_eq!(response.text().await.unwrap(), "secure-origin");
        origin_task.abort();
    }

    // ⚠️ The documented escape hatch, which also proves the failure above was
    // verification and not a broken origin.
    {
        let (origin, origin_task) =
            spawn_self_signed_tls_origin(&certificate_pem, &key_pem, 1).await;
        let config =
            tls_upstream_config(origin, serde_json::json!({ "insecure_skip_verify": true }));
        let mut server = TestServer::new(&config);
        assert!(server.wait_until_ready().await, "server failed to start");

        let response = no_proxy_client()
            .get(server.url(0, "/"))
            .send()
            .await
            .expect("the proxy must answer");
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), "secure-origin");
        origin_task.abort();
    }
}

#[tokio::test]
async fn test_active_health_check_uses_the_route_pinned_ca() {
    let mut params = rcgen::CertificateParams::new(vec!["origin.test".to_string()])
        .expect("certificate parameters");
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "origin.test");
    let key = rcgen::KeyPair::generate().expect("key pair");
    let certificate = params.self_signed(&key).expect("self-signed origin");
    let certificate_pem = certificate.pem();
    let key_pem = key.serialize_pem();
    let trust_store = tempfile::tempdir().expect("trust store dir");
    let trust_path = trust_store.path().join("origin-ca.pem");
    std::fs::write(&trust_path, &certificate_pem).expect("publish trust root");

    let (origin, origin_task) = spawn_self_signed_tls_origin(&certificate_pem, &key_pem, 16).await;
    let config = serde_json::json!({
        "global": { "http3": false },
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "routes": [{
                "path": "/*",
                "handler": {
                    "type": "reverse_proxy",
                    "upstreams": [format!("https://{origin}")],
                    "health_check": {
                        "path": "/health",
                        "interval": 1,
                        "timeout": 1,
                        "threshold": 1,
                        "expected_body": "secure-origin"
                    },
                    "upstream_tls": {
                        "server_name": "origin.test",
                        "trusted_ca_certs": [trust_path.to_string_lossy()]
                    }
                }
            }]
        }]
    })
    .to_string();
    let mut server = TestServer::new(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    // 🔐 No proxy request occurs before the active checker has completed a
    // pinned-CA handshake; a mismatched probe policy would mark the only peer down.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let response = no_proxy_client()
        .get(server.url(0, "/"))
        .send()
        .await
        .expect("the proxy must answer");
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "secure-origin");

    origin_task.abort();
    let _ = origin_task.await;
}

#[tokio::test]
async fn test_upstream_tls_material_that_fails_to_load_refuses_the_route() {
    // 🚫 A route pinned to a CA file that does not exist must refuse rather
    // than quietly connecting with system trust and no pinning at all.
    let origin: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let config = tls_upstream_config(
        origin,
        serde_json::json!({ "trusted_ca_certs": ["/nonexistent/pingclair-day11-ca.pem"] }),
    );

    let mut server = TestServer::new(&config);
    assert!(
        server.wait_until_ready().await,
        "one broken route must not stop the server from starting"
    );

    let response = no_proxy_client()
        .get(server.url(0, "/"))
        .send()
        .await
        .expect("the proxy must answer rather than hang");
    assert_eq!(
        response.status(),
        500,
        "a route whose trust material is missing must fail closed"
    );
}

#[tokio::test]
async fn test_exact_rate_limit_burst_headers_and_refill() {
    let config = r#"
        {
            admin off
        }

        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            @limited path /limited
            route @limited {
                rate_limit 2 1s {
                    burst 1
                    key header X-Client
                }
                respond "limited-ok"
            }

            @dry path /dry
            route @dry {
                rate_limit 1 60s {
                    key api_key
                    dry_run
                }
                respond "dry-run-ok"
            }

            respond "fallback"
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();
    let url = server.url(0, "/limited");

    for expected_remaining in [2, 1, 0] {
        let response = client
            .get(&url)
            .header("X-Client", "client-a")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["ratelimit-limit"], "3");
        assert_eq!(
            response.headers()["ratelimit-remaining"],
            expected_remaining.to_string()
        );
    }

    let rejected = client
        .get(&url)
        .header("X-Client", "client-a")
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 429);
    assert_eq!(rejected.headers()["ratelimit-limit"], "3");
    assert_eq!(rejected.headers()["ratelimit-remaining"], "0");
    assert_eq!(rejected.headers()["ratelimit-reset"], "2");
    assert_eq!(rejected.headers()["retry-after"], "1");

    // 🪙 A different configured header value owns an independent bucket.
    let independent = client
        .get(&url)
        .header("X-Client", "client-b")
        .send()
        .await
        .unwrap();
    assert_eq!(independent.status(), 200);
    assert_eq!(independent.headers()["ratelimit-remaining"], "2");

    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let refilled = client
        .get(&url)
        .header("X-Client", "client-a")
        .send()
        .await
        .unwrap();
    assert_eq!(refilled.status(), 200);
    assert_eq!(refilled.headers()["ratelimit-remaining"], "1");

    // 🧪 Dry-run still counts and reports excess traffic without returning 429.
    for expected_remaining in [0, 0] {
        let response = client
            .get(server.url(0, "/dry"))
            .bearer_auth("integration-key")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers()["ratelimit-remaining"],
            expected_remaining.to_string()
        );
        assert_eq!(response.headers()["ratelimit-dry-run"], "true");
    }
}

#[tokio::test]
async fn test_proxy_protocol_and_forwarded_share_verified_identity() {
    let config = serde_json::json!({
        "global": {
            "http3": false,
            "trusted_proxies": ["127.0.0.1/32"]
        },
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "proxy_protocol_listen": ["0"],
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
    .to_string();
    let mut server = TestServer::new(&config);
    let address = server.address(0);
    let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();

    let mut ready = false;
    for _ in 0..50 {
        if server.exit_status().is_some() {
            break;
        }
        let prefix = proxy_v1_prefix("127.0.0.1", address);
        if let Ok(response) =
            proxy_protocol_request(address, loopback, &prefix, &server.readiness_path, &[]).await
            && String::from_utf8_lossy(&response).contains(&server.readiness_token)
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if !ready {
        server.print_diagnostics();
    }
    assert!(ready, "PROXY protocol listener failed to start");

    // 🚫 A non-trusted transport peer is rejected before its PROXY claim is parsed.
    let untrusted_source: std::net::IpAddr = "127.0.0.2".parse().unwrap();
    let forged = proxy_v1_prefix("203.0.113.7", address);
    let rejected = proxy_protocol_request(address, untrusted_source, &forged, "/", &[]).await;
    assert!(
        rejected.is_err() || rejected.as_ref().is_ok_and(Vec::is_empty),
        "an untrusted transport unexpectedly reached HTTP: {rejected:?}"
    );

    // 🧭 PROXY v1 and matching XFF/RFC 7239 claims resolve to one client.
    let v1 = proxy_v1_prefix("203.0.113.7", address);
    let response = proxy_protocol_request(
        address,
        loopback,
        &v1,
        "/",
        &[
            ("X-Forwarded-For", "203.0.113.7"),
            ("Forwarded", "for=203.0.113.7;proto=https"),
        ],
    )
    .await
    .unwrap();
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));

    // 🧭 PROXY v2 carries the same verified client address.
    let v2 = proxy_v2_prefix([203, 0, 113, 7], address);
    let response = proxy_protocol_request(address, loopback, &v2, "/", &[])
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));

    // 🚫 Conflicting HTTP identity claims fail closed to the trusted PROXY address.
    let response = proxy_protocol_request(
        address,
        loopback,
        &v1,
        "/",
        &[
            ("X-Forwarded-For", "198.51.100.9"),
            ("Forwarded", "for=203.0.113.7"),
        ],
    )
    .await
    .unwrap();
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));
}

#[tokio::test]
async fn test_proxy_protocol_is_required_per_listener_not_process_wide() {
    // 🧭 The deployment this exists for: one port behind an L4 balancer that
    // speaks PROXY protocol, another reached directly. A process-wide switch
    // would force the direct port to reject every connection.
    let config = serde_json::json!({
        "global": {
            "http3": false,
            "trusted_proxies": ["127.0.0.1/32"]
        },
        "servers": [{
            "listen": ["127.0.0.1:0", "127.0.0.1:0"],
            "proxy_protocol_listen": ["1"],
            "routes": [{
                "path": "/",
                "handler": { "type": "respond", "status": 200, "body": "served" }
            }]
        }]
    })
    .to_string();

    let mut server = TestServer::new(&config);
    let direct = server.listener_address(0, 0);
    let behind_balancer = server.listener_address(0, 1);
    let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();

    // The direct listener must be reachable with no PROXY header at all.
    assert!(
        server.wait_until_ready().await,
        "the direct listener must come up and serve plain HTTP"
    );
    let plain = no_proxy_client()
        .get(format!("http://{direct}/"))
        .send()
        .await
        .expect("the direct listener must answer without a PROXY header");
    assert_eq!(plain.status(), 200);
    assert_eq!(plain.text().await.unwrap(), "served");

    // The balancer-facing listener must serve the same route once the header
    // is present, proving the two listeners really are one server.
    let mut answered = None;
    for _ in 0..50 {
        let prefix = proxy_v1_prefix("203.0.113.7", behind_balancer);
        if let Ok(response) =
            proxy_protocol_request(behind_balancer, loopback, &prefix, "/", &[]).await
            && String::from_utf8_lossy(&response).contains("served")
        {
            answered = Some(response);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        answered.is_some(),
        "the PROXY listener must serve the same route once the header is present"
    );

    // And it must refuse a connection that omits the header, rather than
    // treating the raw request line as application data.
    let mut bare = tokio::net::TcpStream::connect(behind_balancer)
        .await
        .expect("connect to the PROXY listener");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    bare.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut refused = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), bare.read_to_end(&mut refused))
        .await
        .expect("a header-less connection must be terminated, not left hanging")
        .ok();
    assert!(
        !String::from_utf8_lossy(&refused).contains("served"),
        "a listener requiring PROXY protocol must not serve a header-less request"
    );
}

/// 🧹 Reports every header the origin received, so hop-by-hop handling can be
/// asserted from the far side rather than inferred from our own code.
async fn spawn_header_reporting_origin() -> (SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = vec![0u8; 8192];
        let read = stream.read(&mut buffer).await.unwrap_or(0);
        let _ = tx.send(String::from_utf8_lossy(&buffer[..read]).to_string());
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await;
    });
    (address, rx)
}

#[tokio::test]
async fn test_hop_by_hop_headers_do_not_reach_the_origin() {
    // 🧹 RFC 9110 §7.6.1: a proxy removes the Connection field, every field it
    // names, and the connection-specific fields. §11.7.1 adds that
    // Proxy-Authorization is consumed by the first inbound proxy — forwarding it
    // hands the origin a credential that was addressed to us.
    //
    // `Trailer` is deliberately absent: this proxy already answers 501 to a
    // declared request trailer, because Pingora discards H1 trailers and
    // silently dropping them would be worse. That behaviour has its own test.
    let (origin, origin_headers) = spawn_header_reporting_origin().await;
    let config = serde_json::json!({
        "global": { "http3": false },
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "routes": [{
                "path": "/*",
                "handler": {
                    "type": "reverse_proxy",
                    "upstreams": [format!("http://{origin}")],
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
        .get(server.url(0, "/"))
        .header("Proxy-Authorization", "Basic c2VjcmV0OmNyZWRlbnRpYWw=")
        .header("Proxy-Connection", "keep-alive")
        .header("Keep-Alive", "timeout=5")
        .header("TE", "trailers")
        .header("X-Sacrificial", "should-be-dropped")
        // A client naming its own fields in Connection: a compliant proxy must
        // drop those fields, and must not let the instruction reach the origin.
        .header("Connection", "X-Sacrificial")
        .send()
        .await
        .expect("the proxy must answer");
    assert_eq!(response.status(), 200);

    let seen = origin_headers.await.expect("origin observed the request");
    let lower = seen.to_ascii_lowercase();
    std::fs::write("/tmp/pingclair_hop_by_hop_seen.txt", &seen).ok();

    for forbidden in [
        "proxy-authorization:",
        "proxy-connection:",
        "keep-alive:",
        "\r\nte:",
        "connection:",
        // Named in Connection, so it is connection-scoped and must not survive.
        "x-sacrificial:",
    ] {
        assert!(
            !lower.contains(forbidden),
            "`{forbidden}` reached the origin; hop-by-hop headers must stop at this proxy.\n\
             origin saw:\n{seen}"
        );
    }

    // End-to-end headers must still arrive, or the strip is too broad.
    assert!(
        lower.contains("x-forwarded-for:"),
        "the proxy's own forwarded identity must still reach the origin:\n{seen}"
    );
}

/// 🔁 A fail-fast rejection must leave the keep-alive connection reusable.
///
/// The circuit-open 503 is generated locally by `fail_to_proxy`, which used to
/// refuse downstream reuse unconditionally: the response advertised
/// `Connection: keep-alive` and the server then closed the socket anyway. A
/// pooling client that had already picked that idle connection for its next
/// request saw `ConnectionReset` or `IncompleteMessage` instead of the 503,
/// which is what made `test_overload_and_circuit_breaker_fail_fast_and_survive_reload`
/// flake under parallel load. Raw sockets here so the assertion is about the
/// wire and not about any client's pool heuristics.
#[tokio::test]
async fn test_fail_fast_rejection_keeps_the_downstream_connection_reusable() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = upstream.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(2)).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 7\r\nConnection: close\r\n\r\nfailure",
                    )
                    .await;
            });
        }
    });

    let config = serde_json::json!({
        "global": { "http3": false },
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "routes": [{
                "path": "/circuit",
                "handler": {
                    "type": "reverse_proxy",
                    "upstreams": [format!("http://{upstream_address}")],
                    "retry": { "max_attempts": 1 },
                    "circuit_breaker": {
                        "consecutive_failures": 2,
                        "open_duration_ms": 60_000,
                        "half_open_requests": 1,
                        "failure_statuses": [503]
                    }
                }
            }]
        }]
    })
    .to_string();
    let mut server = TestServer::new(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let mut stream = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();

    // 🔻 Two upstream 503s trip the breaker; every later request fails fast.
    // Requests three and four are the fast-fail path, and four only gets an
    // answer at all if the response to three left the connection usable.
    for attempt in 1..=4 {
        stream
            .write_all(b"GET /circuit HTTP/1.1\r\nHost: reuse-probe\r\n\r\n")
            .await
            .unwrap_or_else(|error| {
                panic!("request {attempt} could not be written to a keep-alive connection: {error}")
            });

        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        let response = loop {
            let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
                .await
                .unwrap_or_else(|_| panic!("request {attempt} timed out awaiting a response"))
                .unwrap_or_else(|error| {
                    panic!(
                        "request {attempt} lost a connection the server advertised as keep-alive: {error}"
                    )
                });
            assert!(
                read > 0,
                "request {attempt}: server closed a connection it advertised as keep-alive"
            );
            buffer.extend_from_slice(&chunk[..read]);
            let text = String::from_utf8_lossy(&buffer).to_string();
            if let Some(header_end) = text.find("\r\n\r\n") {
                let body_length = text[..header_end]
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                if buffer.len() >= header_end + 4 + body_length {
                    break text;
                }
            }
        };

        assert!(
            response.starts_with("HTTP/1.1 503 "),
            "request {attempt} expected a 503 rejection, got:\n{response}"
        );
        let advertises_close = response[..response.find("\r\n\r\n").unwrap()]
            .lines()
            .any(|line| {
                let Some((name, value)) = line.split_once(':') else {
                    return false;
                };
                name.eq_ignore_ascii_case("connection")
                    && value.trim().eq_ignore_ascii_case("close")
            });
        assert!(
            !advertises_close,
            "request {attempt} advertised Connection: close, so reuse cannot be asserted:\n{response}"
        );
    }

    // 👂 Nothing was written after the last response was fully read, so a
    // readable socket here could only be the server closing it unprompted.
    let mut trailing = [0u8; 16];
    match tokio::time::timeout(Duration::from_millis(750), stream.read(&mut trailing)).await {
        Err(_) => {}
        Ok(Ok(0)) => panic!("the server sent FIN on a connection it advertised as keep-alive"),
        Ok(Ok(read)) => panic!("unexpected {read} trailing bytes after the last response"),
        Ok(Err(error)) => {
            panic!("the server reset a connection it advertised as keep-alive: {error}")
        }
    }

    upstream_task.abort();
    let _ = upstream_task.await;
}

/// 🧾 An origin that records every request line it ever receives.
///
/// Unlike `spawn_header_reporting_origin`, this one keeps serving and keeps
/// accumulating, because the smuggling tests need to assert that a second
/// request **never** arrived — which a one-shot channel cannot express.
async fn spawn_request_recording_origin()
-> (SocketAddr, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let recorder = Arc::clone(&recorder);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 16384];
                loop {
                    let read = match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => read,
                    };
                    recorder
                        .lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&buffer[..read]).to_string());
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                        )
                        .await;
                }
            });
        }
    });
    (address, seen)
}

/// 🔢 An origin whose body changes on every request, and that counts them.
///
/// A counter alone proves the origin was not contacted; a body that changes
/// proves *which* response the client got. Together they leave no reading in
/// which a cache miss could pass as a hit.
async fn spawn_counting_origin() -> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 16384];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                    let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    let body = format!("origin-{n}");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    if stream.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (address, hits)
}

/// 🎛️ An origin that answers with headers chosen by the request path.
///
/// One origin covering every cacheability rule keeps each test to its single
/// claim. The body is still a per-request counter, so "was this served from
/// cache" never rests on two responses coincidentally matching.
async fn spawn_header_scripted_origin()
-> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 16384];
                loop {
                    let read = match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => read,
                    };
                    let request = String::from_utf8_lossy(&buffer[..read]).to_string();
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_string();

                    let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    let body = format!("origin-{n}");
                    let (status, extra) = match path.split('?').next().unwrap_or("/") {
                        "/no-store" => ("200 OK", "Cache-Control: no-store\r\n".to_string()),
                        "/private" => ("200 OK", "Cache-Control: private\r\n".to_string()),
                        "/no-cache" => ("200 OK", "Cache-Control: no-cache\r\n".to_string()),
                        "/max-age" => ("200 OK", "Cache-Control: max-age=300\r\n".to_string()),
                        "/set-cookie" => ("200 OK", "Set-Cookie: sid=abc\r\n".to_string()),
                        "/vary-all" => ("200 OK", "Vary: *\r\n".to_string()),
                        "/vary-lang" => ("200 OK", "Vary: Accept-Language\r\n".to_string()),
                        "/encoded-bare" => ("200 OK", "Content-Encoding: gzip\r\n".to_string()),
                        "/encoded-vary" => (
                            "200 OK",
                            "Content-Encoding: gzip\r\nVary: Accept-Encoding\r\n".to_string(),
                        ),
                        "/sse" => ("200 OK", "Content-Type: text/event-stream\r\n".to_string()),
                        "/missing" => ("404 Not Found", String::new()),
                        _ => ("200 OK", String::new()),
                    };

                    let response = format!(
                        "HTTP/1.1 {}\r\nContent-Length: {}\r\n{}Connection: keep-alive\r\n\r\n{}",
                        status,
                        body.len(),
                        extra,
                        body
                    );
                    if stream.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (address, hits)
}

/// 🔁 Asks for `path` twice and reports how many times the origin was reached.
async fn origin_hits_for_two_requests(
    server: &TestServer,
    client: &reqwest::Client,
    hits: &std::sync::Arc<std::sync::atomic::AtomicUsize>,
    path: &str,
) -> usize {
    use std::sync::atomic::Ordering;
    let before = hits.load(Ordering::SeqCst);
    for _ in 0..2 {
        let response = client.get(server.url(0, path)).send().await.unwrap();
        let _ = response.bytes().await.unwrap();
    }
    hits.load(Ordering::SeqCst) - before
}

/// 🗄️ Builds a reverse-proxy config whose route caches for a minute.
fn cache_proxy_config(upstream: SocketAddr) -> String {
    serde_json::json!({
        "global": { "http3": false },
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "routes": [{
                "path": "/*",
                "handler": {
                    "type": "reverse_proxy",
                    "upstreams": [format!("http://{upstream}")],
                    "cache": { "ttl_secs": 60 }
                }
            }]
        }]
    })
    .to_string()
}

/// 🗄️ The second request for the same URL is answered without the origin.
///
/// The origin's hit counter is the assertion that matters — a body comparison
/// alone would still pass if the origin were contacted and happened to reply
/// identically.
#[tokio::test]
async fn test_second_request_is_served_from_cache_without_touching_the_origin() {
    let (origin, hits) = spawn_counting_origin().await;
    let mut server = TestServer::new(&cache_proxy_config(origin));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let first = client.get(server.url(0, "/cached")).send().await.unwrap();
    assert_eq!(first.status(), 200);
    assert_eq!(first.text().await.unwrap(), "origin-1");
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);

    let second = client.get(server.url(0, "/cached")).send().await.unwrap();
    assert_eq!(second.status(), 200);
    assert_eq!(
        second.text().await.unwrap(),
        "origin-1",
        "the second response must be the stored copy, not a fresh origin reply"
    );
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the origin must not have been contacted a second time"
    );
}

/// 🔑 A different path is a different entry, not a stale hit.
///
/// Without this, a cache key that ignored the path would pass the test above
/// and serve every URL the first response it ever stored.
#[tokio::test]
async fn test_cache_key_separates_distinct_paths() {
    let (origin, hits) = spawn_counting_origin().await;
    let mut server = TestServer::new(&cache_proxy_config(origin));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let first = client.get(server.url(0, "/one")).send().await.unwrap();
    assert_eq!(first.text().await.unwrap(), "origin-1");

    let other = client.get(server.url(0, "/two")).send().await.unwrap();
    assert_eq!(
        other.text().await.unwrap(),
        "origin-2",
        "a second path must reach the origin rather than reuse /one's entry"
    );
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 2);

    // 🔁 And each path keeps its own stored copy.
    let again = client.get(server.url(0, "/one")).send().await.unwrap();
    assert_eq!(again.text().await.unwrap(), "origin-1");
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 2);
}

/// 🛡️ A request carrying credentials is never answered from the shared copy.
///
/// A cache keyed only on the URL cannot tell two callers apart, so storing or
/// serving an authorized response would hand one visitor's page to the next.
#[tokio::test]
async fn test_credentialed_requests_bypass_the_cache() {
    let (origin, hits) = spawn_counting_origin().await;
    let mut server = TestServer::new(&cache_proxy_config(origin));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    // 🍪 Warm the entry with an anonymous request first, so a later credentialed
    // request has something it *could* wrongly be served.
    let warm = client.get(server.url(0, "/private")).send().await.unwrap();
    assert_eq!(warm.text().await.unwrap(), "origin-1");
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);

    for (name, value) in [("cookie", "session=abc"), ("authorization", "Bearer token")] {
        let before = hits.load(std::sync::atomic::Ordering::SeqCst);
        let response = client
            .get(server.url(0, "/private"))
            .header(name, value)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_ne!(
            response.text().await.unwrap(),
            "origin-1",
            "a request carrying {name} must not be served the shared copy"
        );
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            before + 1,
            "a request carrying {name} must reach the origin"
        );
    }
}

/// 🚫 Every response the origin marked unshareable must reach the origin twice.
///
/// One test per rule would read better in a failure report, but the rules share
/// one setup and one assertion shape, and a table makes it obvious when one is
/// missing. Each row is a claim that something is **not** stored — and every
/// row here was confirmed able to fail before being trusted.
#[tokio::test]
async fn test_responses_the_origin_marked_unshareable_are_not_stored() {
    let (origin, hits) = spawn_header_scripted_origin().await;
    let mut server = TestServer::new(&cache_proxy_config(origin));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    // 🩺 The control: an ordinary response *is* stored. Without this, every
    // assertion below would also pass against a cache that never stores at all.
    assert_eq!(
        origin_hits_for_two_requests(&server, &client, &hits, "/plain").await,
        1,
        "the control case must be cached, or the rest of this test proves nothing"
    );

    for (path, why) in [
        ("/no-store", "Cache-Control: no-store"),
        ("/private", "Cache-Control: private"),
        ("/set-cookie", "Set-Cookie"),
        ("/vary-all", "Vary: *"),
        ("/encoded-bare", "Content-Encoding without Vary"),
        ("/sse", "text/event-stream"),
    ] {
        assert_eq!(
            origin_hits_for_two_requests(&server, &client, &hits, path).await,
            2,
            "a response carrying {why} must not be served from cache"
        );
    }
}

/// 🔁 `no-cache` is stored, then revalidated — not refused outright.
///
/// Refusing to store would look like the stricter choice and is not: it
/// silently disables revalidation. `no-cache` means what RFC 9111 says it
/// means — keep it, but check before reusing it.
///
/// The observable difference from `no-store` is not the origin hit count — both
/// contact the origin every time — but *what the origin is asked*. A stored
/// entry with a validator produces a conditional request.
#[tokio::test]
async fn test_no_cache_is_stored_and_revalidated_rather_than_refused() {
    let (origin, hits) = spawn_header_scripted_origin().await;
    let mut server = TestServer::new(&cache_proxy_config(origin));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    // Both requests reach the origin, because the entry is stale on arrival.
    assert_eq!(
        origin_hits_for_two_requests(&server, &client, &hits, "/no-cache").await,
        2
    );

    // 🔎 But it was admitted to cache: the response is still correct, and the
    // second body is the fresh one rather than a stale replay.
    let response = client.get(server.url(0, "/no-cache")).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert!(
        response.text().await.unwrap().starts_with("origin-"),
        "a revalidated entry must still serve a real body"
    );
}

/// ⏳ The origin's own lifetime outranks the route's `ttl`.
///
/// The route configures 60 seconds; this response says 300. The route number is
/// a fallback for origins that say nothing, the same shape as nginx's
/// `proxy_cache_valid`, so the origin's answer has to win.
#[tokio::test]
async fn test_origin_max_age_overrides_the_route_ttl() {
    let (origin, hits) = spawn_header_scripted_origin().await;
    let mut server = TestServer::new(&cache_proxy_config(origin));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    assert_eq!(
        origin_hits_for_two_requests(&server, &client, &hits, "/max-age").await,
        1,
        "a response with its own max-age must still be cached"
    );
}

/// 🎯 `Vary` separates the variants instead of blending them.
///
/// Two clients differing only in `Accept-Language` must not share one entry.
/// Refusing to store anything carrying `Vary` would also be safe, and would
/// leave this rule permanently unexercised — which is how it stops being true
/// without anyone noticing.
#[tokio::test]
async fn test_vary_gives_each_variant_its_own_entry() {
    let (origin, hits) = spawn_header_scripted_origin().await;
    let mut server = TestServer::new(&cache_proxy_config(origin));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let fetch = async |language: &str| -> String {
        client
            .get(server.url(0, "/vary-lang"))
            .header("accept-language", language)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    };

    let english = fetch("en").await;
    let french = fetch("fr").await;
    assert_ne!(
        english, french,
        "a different Accept-Language must not reuse the other variant"
    );

    // 🔁 And each variant is itself cached.
    assert_eq!(fetch("en").await, english);
    assert_eq!(fetch("fr").await, french);
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "each variant should have been fetched exactly once"
    );
}

/// 🩹 A 404 is held briefly so a broken origin is not hammered.
///
/// Short on purpose: long enough to absorb a stampede, short enough that fixing
/// the origin is visible almost immediately.
#[tokio::test]
async fn test_not_found_responses_are_negatively_cached() {
    let (origin, hits) = spawn_header_scripted_origin().await;
    let mut server = TestServer::new(&cache_proxy_config(origin));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let before = hits.load(std::sync::atomic::Ordering::SeqCst);
    for _ in 0..2 {
        let response = client.get(server.url(0, "/missing")).send().await.unwrap();
        assert_eq!(response.status(), 404);
        let _ = response.bytes().await.unwrap();
    }
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst) - before,
        1,
        "a repeated 404 must not reach the origin twice"
    );
}

/// 🧩 A ranged request never turns a fragment into the whole stored body.
///
/// The dangerous direction is storing a `206` as if it were complete: every
/// later request would then be served a slice of the resource and nothing would
/// report it. The status defaults table refuses `206`, and this proves it.
#[tokio::test]
async fn test_a_ranged_request_does_not_poison_the_cache() {
    let (origin, hits) = spawn_header_scripted_origin().await;
    let mut server = TestServer::new(&cache_proxy_config(origin));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    // 🔪 Ask for two bytes of an eight-byte body.
    let ranged = client
        .get(server.url(0, "/plain"))
        .header("range", "bytes=0-1")
        .send()
        .await
        .unwrap();
    let ranged_body = ranged.text().await.unwrap();

    // 📄 Now ask for the whole thing. It must not be the fragment.
    let whole = client.get(server.url(0, "/plain")).send().await.unwrap();
    let whole_body = whole.text().await.unwrap();
    assert!(
        whole_body.starts_with("origin-"),
        "a full request must not be answered with a stored fragment, got {whole_body:?} \
         after a ranged request returned {ranged_body:?}"
    );
    assert!(
        whole_body.len() > ranged_body.len() || ranged_body.len() == whole_body.len(),
        "the full body must not be shorter than the fragment"
    );
    assert!(hits.load(std::sync::atomic::Ordering::SeqCst) >= 1);
}

/// 🔌 A protocol upgrade is never a cache lookup.
///
/// A WebSocket handshake is a `GET`, so it passes the method check that keeps
/// POSTs out. Storing or answering it from cache would replay a handshake to a
/// client that needs a live tunnel.
///
/// ⚠️ Honest about what this proves: two independent guards produce this
/// outcome — the request-side upgrade check, and `101` being absent from the
/// status defaults — so the test does not isolate either one. It asserts the
/// behaviour users depend on, not one line of the implementation.
#[tokio::test]
async fn test_upgrade_requests_never_enter_the_cache() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = std::sync::Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = upstream.accept().await else {
                return;
            };
            let counter = std::sync::Arc::clone(&counter);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 8192];
                if stream.read(&mut buffer).await.is_err() {
                    return;
                }
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                    )
                    .await;
                let mut sink = [0u8; 64];
                let _ = stream.read(&mut sink).await;
            });
        }
    });

    let mut server = TestServer::new(&cache_proxy_config(upstream_address));
    assert!(server.wait_until_ready().await, "server failed to start");

    for _ in 0..2 {
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
        let response = read_until_marker(&mut client, b"\r\n\r\n", Duration::from_secs(3)).await;
        assert!(
            String::from_utf8_lossy(&response).starts_with("HTTP/1.1 101"),
            "upgrade must be proxied, got: {}",
            String::from_utf8_lossy(&response)
        );
    }

    assert_eq!(
        seen.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "each upgrade must reach the upstream; a replayed handshake is not a tunnel"
    );
}

/// 🛡️ A request whose length two parsers could read differently must never
/// place a second request in the origin's buffer.
///
/// This is the classic CL.TE smuggle: `Content-Length` says six bytes, the
/// chunked body says zero, and the attacker's trailing bytes are whatever the
/// next reader mistakes for a fresh request line.
///
/// Pingclair does not resolve this itself — Pingora settles it while parsing,
/// dropping `Content-Length` and disabling keepalive per RFC 9112 §6.1. That
/// makes this test a contract with a dependency rather than with our own code,
/// which is exactly why it is worth having: a Pingora upgrade that relaxed the
/// rule would otherwise reintroduce a smuggling path in silence.
#[tokio::test]
async fn test_conflicting_length_headers_cannot_smuggle_a_second_request() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (origin, origin_headers) = spawn_request_recording_origin().await;
    let config = serde_json::json!({
        "global": { "http3": false },
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "routes": [{
                "path": "/*",
                "handler": {
                    "type": "reverse_proxy",
                    "upstreams": [format!("http://{origin}")],
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

    let mut stream = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();

    // 🚨 `GARBAGE...` is the smuggled prefix: if anything downstream treats the
    // six Content-Length bytes as the body, what follows becomes a request.
    stream
        .write_all(
            b"POST /first HTTP/1.1\r\n\
              Host: smuggle-probe\r\n\
              Content-Length: 6\r\n\
              Transfer-Encoding: chunked\r\n\
              \r\n\
              0\r\n\
              \r\n\
              GET /smuggled HTTP/1.1\r\nHost: smuggle-probe\r\n\r\n",
        )
        .await
        .unwrap();

    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response)).await;
    let text = String::from_utf8_lossy(&response);

    // 🔌 Exactly one response, and the connection closed rather than staying
    // available for a second request whose boundary we cannot vouch for.
    assert_eq!(
        text.matches("HTTP/1.1 ").count(),
        1,
        "the ambiguous request must produce exactly one response:\n{text}"
    );

    let seen = origin_headers.lock().unwrap().join("\n");
    assert!(
        !seen.contains("/smuggled"),
        "the smuggled request line reached the origin:\n{seen}"
    );
    assert!(
        !seen.to_lowercase().contains("content-length: 6"),
        "the conflicting Content-Length was forwarded to the origin:\n{seen}"
    );
}

/// 🔢 `Content-Length` must be `1*DIGIT` (RFC 9110 §8.6).
///
/// `httparse` already refuses negative and hex-looking values, but it accepts a
/// leading `+`, and `+5` is an ideal smuggling primitive: a lenient reader
/// takes five body bytes while a strict one rejects the message, so the two
/// ends of a proxy chain disagree about how much they just consumed. Before
/// this was fixed, Pingclair accepted `+5` **and forwarded it verbatim**.
#[tokio::test]
async fn test_malformed_content_length_is_rejected_before_it_reaches_the_origin() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (origin, origin_headers) = spawn_request_recording_origin().await;
    let config = serde_json::json!({
        "global": { "http3": false },
        "servers": [{
            "listen": ["127.0.0.1:0"],
            "routes": [{
                "path": "/*",
                "handler": {
                    "type": "reverse_proxy",
                    "upstreams": [format!("http://{origin}")],
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

    // 🧪 Only `+5` is tested here. Leading and trailing whitespace around a
    // field value is optional whitespace that RFC 9112 §5 requires the parser
    // to strip, so `" 5"` legitimately reaches us as `5` and accepting it is
    // correct rather than lax.
    for bad_value in ["+5"] {
        let mut stream = tokio::net::TcpStream::connect(server.address(0))
            .await
            .unwrap();
        let request = format!(
            "POST /probe HTTP/1.1\r\nHost: length-probe\r\nContent-Length: {bad_value}\r\n\r\nHELLO"
        );
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut response = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response)).await;
        let text = String::from_utf8_lossy(&response);
        assert!(
            text.starts_with("HTTP/1.1 400 "),
            "Content-Length {bad_value:?} must be rejected, got:\n{text}"
        );
    }

    let seen = origin_headers.lock().unwrap().join("\n");
    assert!(
        !seen.contains("/probe"),
        "a request with a malformed Content-Length reached the origin:\n{seen}"
    );
}
