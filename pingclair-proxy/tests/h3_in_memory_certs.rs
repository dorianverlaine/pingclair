//! Proves that `tokio_quiche` can serve certificates out of Pingclair's
//! in-memory `CertTable` — no private key is ever written to disk.
//!
//! This is the gate for the H3 migration. `tokio_quiche::ConnectionParams`
//! demands a `TlsCertificatePaths`, which looks like it forces certificates
//! onto the filesystem. It does not: the paths are only handed to the
//! `ConnectionHook`, and the code that reads them is the branch taken when the
//! hook declines. These tests assert that empirically, against a real
//! handshake, with sentinel paths that do not exist.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pingclair_proxy::client_auth::{ClientAuthTable, PublishedListenerPolicy};
use pingclair_proxy::quic::{CertTable, CertTableSslHook, IN_MEMORY_CERT_SENTINEL};
// 🔗 Through `tokio-quiche`, so the test client and the server under test are
// provably the same quiche. See the note in `quic.rs`.
use tokio_quiche::quiche;
use tokio_quiche::settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths};
use tokio_quiche::{ApplicationOverQuic, ConnectionParams};

const TEST_ALPN: &[u8] = b"h3";

// 🏷️ Which alert a refused name is refused with. A sibling file so this one
// keeps to the question of where certificates come from.
#[path = "h3_in_memory_certs/sni_alerts.rs"]
mod sni_alerts;

/// Generate a self-signed cert+key for `names`.
fn self_signed_pem(names: &[&str]) -> (String, String) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap();
    (cert.pem(), signing_key.serialize_pem())
}

/// A do-nothing `ApplicationOverQuic`.
///
/// The handshake is what's under test, so this deliberately implements the
/// minimum: it proves the trait is implementable by us, and it lets the worker
/// loop drive a connection to `established` without an H3 layer in the way.
struct HandshakeOnlyApp;

impl HandshakeOnlyApp {
    fn new() -> Self {
        Self
    }
}

impl ApplicationOverQuic for HandshakeOnlyApp {
    fn on_conn_established(
        &mut self,
        _qconn: &mut tokio_quiche::quic::QuicheConnection,
        _handshake_info: &tokio_quiche::quic::HandshakeInfo,
    ) -> tokio_quiche::QuicResult<()> {
        Ok(())
    }

    fn should_act(&self) -> bool {
        true
    }

    // Never resolves: the worker loop selects this against inbound packets and
    // timers, so returning `pending` simply means we add no events of our own.
    async fn wait_for_data(
        &mut self,
        _qconn: &mut tokio_quiche::quic::QuicheConnection,
    ) -> tokio_quiche::QuicResult<()> {
        std::future::pending().await
    }

    fn process_reads(
        &mut self,
        _qconn: &mut tokio_quiche::quic::QuicheConnection,
    ) -> tokio_quiche::QuicResult<()> {
        Ok(())
    }

    fn process_writes(
        &mut self,
        _qconn: &mut tokio_quiche::quic::QuicheConnection,
    ) -> tokio_quiche::QuicResult<()> {
        Ok(())
    }
}

/// Start a listener whose certificates come only from `table`.
///
/// Returns the bound address. Note the `TlsCertificatePaths` given here point
/// at [`IN_MEMORY_CERT_SENTINEL`], which is not a path that can be opened.
async fn spawn_listener(table: Arc<CertTable>, default_sni: Option<&str>) -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    let mut quic_settings = QuicSettings::default();
    quic_settings.alpn = vec![TEST_ALPN.to_vec()];
    // 🛡️ Two 2^16-entry DATAGRAM queues per connection buy us nothing without
    // MASQUE or WebTransport, so they stay off.
    quic_settings.enable_dgram = false;

    // 🧾 Read the default through the same DSL used by an operator.
    let option = default_sni
        .map(|name| format!("default_sni {name}"))
        .unwrap_or_default();
    let config = pingclair_config::compile(&format!(
        "{{\n admin off\n {option}\n}}\nhttps://fixture.test:8443 {{\n tls internal\n}}"
    ))
    .unwrap();
    let configured_default = config.servers[0]
        .tls
        .as_ref()
        .unwrap()
        .default_sni
        .as_deref();
    let policy = PublishedListenerPolicy::new(Arc::new(ClientAuthTable::default()))
        .with_default_sni(configured_default);
    let hooks = Hooks {
        connection_hook: Some(Arc::new(CertTableSslHook::new(table, Arc::new(policy)))),
    };

    let mut listeners = tokio_quiche::listen(
        [socket],
        ConnectionParams::new_server(
            quic_settings,
            TlsCertificatePaths {
                cert: IN_MEMORY_CERT_SENTINEL,
                private_key: IN_MEMORY_CERT_SENTINEL,
                kind: CertificateKind::X509,
            },
            hooks,
        ),
        tokio_quiche::metrics::DefaultMetrics,
    )
    .expect("listener should start with in-memory certificates");

    tokio::spawn(async move {
        use futures::StreamExt;
        let stream = &mut listeners[0];
        while let Some(Ok(conn)) = stream.next().await {
            conn.start(HandshakeOnlyApp::new());
        }
    });

    addr
}

/// Handshake against `server` with the given SNI, returning the leaf
/// certificate DER the server presented.
async fn handshake_and_capture_cert(
    server: SocketAddr,
    sni: Option<&str>,
) -> Result<Vec<u8>, String> {
    let mut config = quiche::Config::with_boring_ssl_ctx_builder(
        quiche::PROTOCOL_VERSION,
        boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap(),
    )
    .unwrap();
    // Self-signed fixtures: we are asserting *which* cert was served, not that
    // it chains to a root.
    config.verify_peer(false);
    config.set_application_protos(&[TEST_ALPN]).unwrap();
    config.set_max_idle_timeout(5_000);
    config.set_max_recv_udp_payload_size(1350);
    config.set_max_send_udp_payload_size(1350);
    config.set_initial_max_data(1_000_000);
    config.set_initial_max_stream_data_bidi_local(100_000);
    config.set_initial_max_streams_bidi(10);

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local = socket.local_addr().unwrap();

    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    getrandom(&mut scid);
    let scid = quiche::ConnectionId::from_ref(&scid);

    let mut conn = quiche::connect(sni, &scid, local, server, &mut config)
        .map_err(|e| format!("connect: {e}"))?;

    let mut out = [0u8; 1350];
    let mut buf = [0u8; 65535];

    // Initial flight.
    while let Ok((write, _)) = conn.send(&mut out) {
        socket.send_to(&out[..write], server).await.unwrap();
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !conn.is_established() {
        if conn.is_closed() {
            return Err(format!(
                "connection closed before established: {:?}",
                conn.peer_error()
            ));
        }

        let timeout = conn
            .timeout()
            .unwrap_or(Duration::from_millis(50))
            .min(Duration::from_millis(200));

        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                return Err("handshake timed out".to_string());
            }
            recv = socket.recv_from(&mut buf) => {
                let (len, from) = recv.unwrap();
                let info = quiche::RecvInfo { from, to: local };
                if let Err(e) = conn.recv(&mut buf[..len], info) {
                    return Err(format!("recv: {e}"));
                }
            }
            _ = tokio::time::sleep(timeout) => {
                conn.on_timeout();
            }
        }

        while let Ok((write, _)) = conn.send(&mut out) {
            socket.send_to(&out[..write], server).await.unwrap();
        }
    }

    let cert = conn
        .peer_cert()
        .ok_or_else(|| "established without a peer certificate".to_string())?
        .to_vec();
    Ok(cert)
}

fn getrandom(buf: &mut [u8]) {
    use std::hash::{BuildHasher, Hasher, RandomState};
    let mut i = 0;
    while i < buf.len() {
        let v = RandomState::new().build_hasher().finish().to_ne_bytes();
        let n = v.len().min(buf.len() - i);
        buf[i..i + n].copy_from_slice(&v[..n]);
        i += n;
    }
}

/// Extract the DER of the leaf certificate we put in the table, so it can be
/// compared byte-for-byte against what the server actually served.
fn leaf_der(cert_pem: &str) -> Vec<u8> {
    let chain = boring::x509::X509::stack_from_pem(cert_pem.as_bytes()).unwrap();
    chain[0].to_der().unwrap()
}

#[tokio::test]
async fn in_memory_cert_table_serves_the_sni_matched_certificate() {
    let table = Arc::new(CertTable::new());
    let (cert_a, key_a) = self_signed_pem(&["a.pingclair.test"]);
    let (cert_b, key_b) = self_signed_pem(&["b.pingclair.test"]);
    table
        .upsert_pem("A.PINGCLAIR.TEST.", &cert_a, &key_a)
        .unwrap();
    table
        .upsert_pem("b.pingclair.test", &cert_b, &key_b)
        .unwrap();

    let server = spawn_listener(Arc::clone(&table), None).await;

    let served_a = handshake_and_capture_cert(server, Some("a.pingclair.test"))
        .await
        .expect("handshake for a.pingclair.test should succeed");
    let served_b = handshake_and_capture_cert(server, Some("b.pingclair.test"))
        .await
        .expect("handshake for b.pingclair.test should succeed");

    // The decisive assertions: distinct certificates, each matching the SNI,
    // all sourced from memory.
    assert_eq!(
        served_a,
        leaf_der(&cert_a),
        "SNI a.pingclair.test must be served its own certificate"
    );
    assert_eq!(
        served_b,
        leaf_der(&cert_b),
        "SNI b.pingclair.test must be served its own certificate"
    );
    assert_ne!(
        served_a, served_b,
        "the two SNIs must not collapse to one certificate"
    );
}

#[tokio::test]
async fn sentinel_certificate_path_is_never_opened() {
    // If tokio-quiche ever started reading `tls_cert`, this path would have to
    // exist. Assert it does not, so the test above cannot pass by accident.
    assert!(
        !std::path::Path::new(IN_MEMORY_CERT_SENTINEL).exists(),
        "the sentinel must not be a real path"
    );

    let table = Arc::new(CertTable::new());
    let (cert, key) = self_signed_pem(&["only.pingclair.test"]);
    table
        .upsert_pem("only.pingclair.test", &cert, &key)
        .unwrap();

    let server = spawn_listener(Arc::clone(&table), None).await;
    let served = handshake_and_capture_cert(server, Some("only.pingclair.test"))
        .await
        .expect("handshake should succeed with certificates that exist only in memory");

    assert_eq!(served, leaf_der(&cert));
}

#[tokio::test]
async fn cert_table_publication_applies_to_the_next_handshake() {
    // The reload guarantee: renewing a certificate must not require rebuilding
    // the SSL context or restarting the listener.
    let table = Arc::new(CertTable::new());
    let (cert_v1, key_v1) = self_signed_pem(&["rotate.pingclair.test"]);
    table
        .upsert_pem("rotate.pingclair.test", &cert_v1, &key_v1)
        .unwrap();

    let server = spawn_listener(Arc::clone(&table), None).await;

    let before = handshake_and_capture_cert(server, Some("rotate.pingclair.test"))
        .await
        .expect("first handshake should succeed");
    assert_eq!(before, leaf_der(&cert_v1));

    // Renew in place, on the live table.
    let (cert_v2, key_v2) = self_signed_pem(&["rotate.pingclair.test"]);
    assert_ne!(
        leaf_der(&cert_v1),
        leaf_der(&cert_v2),
        "fixture must actually differ"
    );
    table
        .upsert_pem("rotate.pingclair.test", &cert_v2, &key_v2)
        .unwrap();

    let after = handshake_and_capture_cert(server, Some("rotate.pingclair.test"))
        .await
        .expect("handshake after renewal should succeed");
    assert_eq!(
        after,
        leaf_der(&cert_v2),
        "a renewed certificate must be served without restarting the listener"
    );
}

/// 🔐 Unidentified clients must not receive whichever certificate arrived first.
#[tokio::test]
async fn no_sni_without_default_is_refused() {
    let table = Arc::new(CertTable::new());
    let (cert, key) = self_signed_pem(&["only.pingclair.test"]);
    table
        .upsert_pem("only.pingclair.test", &cert, &key)
        .unwrap();
    let server = spawn_listener(table, None).await;
    assert!(handshake_and_capture_cert(server, None).await.is_err());
}

/// 🔐 An unknown explicit name must not borrow an unrelated site's certificate.
#[tokio::test]
async fn unknown_sni_is_refused() {
    let table = Arc::new(CertTable::new());
    let (cert, key) = self_signed_pem(&["only.pingclair.test"]);
    table
        .upsert_pem("only.pingclair.test", &cert, &key)
        .unwrap();
    let server = spawn_listener(table, None).await;
    assert!(
        handshake_and_capture_cert(server, Some("unknown.pingclair.test"))
            .await
            .is_err()
    );
}

/// 🏷️ A shared renewable table does not make listener defaults global.
#[tokio::test]
async fn default_sni_is_local_to_each_listener_and_tracks_rotation() {
    let table = Arc::new(CertTable::new());
    let (cert_a, key_a) = self_signed_pem(&["a.pingclair.test"]);
    let (cert_b, key_b) = self_signed_pem(&["b.pingclair.test"]);
    table
        .upsert_pem("a.pingclair.test", &cert_a, &key_a)
        .unwrap();
    table
        .upsert_pem("b.pingclair.test", &cert_b, &key_b)
        .unwrap();
    let listener_a = spawn_listener(Arc::clone(&table), Some("a.pingclair.test")).await;
    let listener_b = spawn_listener(Arc::clone(&table), Some("B.PINGCLAIR.TEST.")).await;

    for (listener, expected) in [(listener_a, &cert_a), (listener_b, &cert_b)] {
        assert_eq!(
            handshake_and_capture_cert(listener, None).await.unwrap(),
            leaf_der(expected)
        );
    }
    assert_eq!(
        handshake_and_capture_cert(listener_b, Some("A.PINGCLAIR.TEST."))
            .await
            .unwrap(),
        leaf_der(&cert_a),
        "an explicit name takes precedence over the listener default"
    );
    assert!(
        handshake_and_capture_cert(listener_b, Some("unknown.pingclair.test"))
            .await
            .is_err()
    );

    let (rotated, rotated_key) = self_signed_pem(&["b.pingclair.test"]);
    let update = table
        .prepare_manual_update(
            ["b.pingclair.test"],
            [("b.pingclair.test", rotated.as_str(), rotated_key.as_str())],
        )
        .unwrap();
    table.publish_manual_update(update);
    assert_eq!(
        handshake_and_capture_cert(listener_b, None).await.unwrap(),
        leaf_der(&rotated)
    );
    assert_eq!(
        handshake_and_capture_cert(listener_a, None).await.unwrap(),
        leaf_der(&cert_a)
    );

    let removed = table
        .prepare_manual_update(["B.PINGCLAIR.TEST."], [])
        .unwrap();
    table.publish_manual_update(removed);
    assert!(handshake_and_capture_cert(listener_b, None).await.is_err());
}

/// 🚫 Missing and excluded defaults cannot fall through to another site's key.
#[tokio::test]
async fn default_sni_must_resolve_to_an_enabled_certificate() {
    let table = Arc::new(CertTable::new());
    let (cert, key) = self_signed_pem(&["*.pingclair.test"]);
    table.upsert_pem("*.pingclair.test", &cert, &key).unwrap();
    let wildcard = spawn_listener(Arc::clone(&table), Some("a.pingclair.test")).await;
    assert_eq!(
        handshake_and_capture_cert(wildcard, None).await.unwrap(),
        leaf_der(&cert)
    );

    let missing = spawn_listener(Arc::clone(&table), Some("missing.other.test")).await;
    assert!(handshake_and_capture_cert(missing, None).await.is_err());
    table.set_excluded_names(["A.PINGCLAIR.TEST."]);
    assert!(handshake_and_capture_cert(wildcard, None).await.is_err());
}
