// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🏷️ A refused TCP handshake names the reason in its TLS alert.
//!
//! RFC 9846 §6.2 answers a name nobody serves with `unrecognized_name`, and
//! §9.2 answers a ClientHello with no name, where one is required, with
//! `missing_extension`. Both used to arrive as `internal_error`, because the
//! listener reached the end of certificate selection empty-handed and left
//! BoringSSL to report that however it liked.

use std::net::SocketAddr;

use super::TestServer;

/// 🔢 `missing_extension`, from RFC 9846 §6.
const MISSING_EXTENSION: i32 = 109;
/// 🔢 `unrecognized_name`, from RFC 9846 §6.
const UNRECOGNIZED_NAME: i32 = 112;

/// 🧾 Handshakes with `sni` (or with no SNI at all) and returns the alert the
/// server ended it with, or `None` when the handshake completed.
///
/// BoringSSL records a received alert as the error reason
/// `SSL_AD_REASON_OFFSET + alert` (`ssl/tls_record.cc`), so the alert number
/// is read back out of the error queue rather than out of a message string.
fn received_alert(address: SocketAddr, sni: Option<&str>) -> Option<i32> {
    use pingora_core::tls::ssl::{HandshakeError, SslConnector, SslMethod, SslVerifyMode};

    const SSL_AD_REASON_OFFSET: i32 = 1000;
    let mut builder = SslConnector::builder(SslMethod::tls()).expect("tls connector builder");
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();
    let stream = std::net::TcpStream::connect(address).expect("connect to the test server");
    let mut configuration = connector.configure().expect("connect configuration");
    configuration.set_verify_hostname(false);
    configuration.set_use_server_name_indication(sni.is_some());
    // 🔌 The name passed here only matters when SNI is on; with it off the
    // connector sends no `server_name` extension at all.
    let failed = match configuration.connect(sni.unwrap_or("unused.invalid"), stream) {
        Ok(_) => return None,
        Err(HandshakeError::Failure(failed)) => failed,
        Err(other) => panic!("the handshake failed before reaching the server: {other}"),
    };
    let error = failed.error();
    let alerts: Vec<i32> = error
        .ssl_error()
        .into_iter()
        .flat_map(|stack| stack.errors())
        .map(|entry| entry.reason_code() - SSL_AD_REASON_OFFSET)
        .filter(|alert| (0..256).contains(alert))
        .collect();
    match alerts.as_slice() {
        [alert] => Some(*alert),
        other => panic!("expected exactly one received alert, got {other:?} from {error:?}"),
    }
}

/// 🚫 An unknown name and a missing name each get the alert that says so,
/// and the configured name still completes, over the same listener.
#[tokio::test]
async fn test_unservable_names_are_refused_with_the_matching_alert() {
    let config = r#"
        {
            admin off
            http_port __PINGCLAIR_TEST_HTTP_PORT__
        }

        https://known.sandbox.test:__PINGCLAIR_TEST_PORT__ {
            tls internal

            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "known"
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(
        server.wait_until_tls_ready("known.sandbox.test").await,
        "server failed to start"
    );
    let address = server.address(0);

    let alerts = tokio::task::spawn_blocking(move || {
        [
            received_alert(address, Some("known.sandbox.test")),
            received_alert(address, Some("stranger.sandbox.test")),
            received_alert(address, None),
        ]
    })
    .await
    .unwrap();
    assert_eq!(
        alerts,
        [None, Some(UNRECOGNIZED_NAME), Some(MISSING_EXTENSION)],
        "known name, unknown name, no name"
    );
    server.stop();
}
