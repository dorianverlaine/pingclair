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
                route("/deadline", 3, Some(150), 100, vec!["GET"]),
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
    assert!(started.elapsed() >= Duration::from_millis(90));
    assert!(started.elapsed() < Duration::from_millis(250));
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
