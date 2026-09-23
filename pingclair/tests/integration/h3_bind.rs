// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔌 HTTP/3 is bound at startup, or the process does not start.
//!
//! The QUIC socket used to be bound inside a background task after startup
//! had already reported success and every HTTPS listener had started sending
//! `Alt-Svc: h3=":PORT"; ma=86400`. A taken UDP port became one log line, and
//! clients cached a day-long promise of a service nobody was running.

use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// 🔌 A loopback port whose TCP and UDP halves are both free, with the UDP
/// half held by the returned socket.
fn port_with_udp_held() -> (SocketAddr, UdpSocket) {
    for _ in 0..64 {
        let udp = UdpSocket::bind("127.0.0.1:0").expect("bind a UDP probe");
        let address = udp.local_addr().unwrap();
        // 🧭 The TCP half must be free too, or the failure below would be the
        // TCP bind and prove nothing about QUIC.
        if TcpListener::bind(address).is_ok() {
            return (address, udp);
        }
    }
    panic!("no loopback port had both halves free");
}

/// 🚫 A taken UDP port stops startup instead of being advertised.
#[test]
fn test_startup_fails_when_the_http3_port_is_taken() {
    let (address, _held) = port_with_udp_held();
    let companion = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_port = companion.local_addr().unwrap().port();
    drop(companion);

    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("Pingclairfile");
    std::fs::write(
        &config_path,
        format!(
            r#"
            {{
                admin off
                http_port {http_port}
            }}

            https://localhost:{port} {{
                bind 127.0.0.1
                tls internal
                respond "should-not-serve"
            }}
            "#,
            port = address.port(),
        ),
    )
    .unwrap();
    let tls_store = dir.path().join("tls");
    std::fs::create_dir(&tls_store).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_pingclair"))
        .arg("run")
        .arg(&config_path)
        .env("RUST_LOG", "info")
        .env("PINGCLAIR_TLS_STORE", &tls_store)
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
            panic!("pingclair kept running although its HTTP/3 port was taken");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut stderr = String::new();
    std::io::Read::read_to_string(child.stderr.as_mut().unwrap(), &mut stderr).unwrap();

    assert!(!status.success(), "startup reported success: {stderr}");
    assert!(
        stderr.contains("failed to bind HTTP/3 (UDP)"),
        "startup failed for some other reason: {stderr}"
    );
}
