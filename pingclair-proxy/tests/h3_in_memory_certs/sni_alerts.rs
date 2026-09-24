//! 🏷️ A refused QUIC handshake names the reason in its TLS alert.
//!
//! quiche carries a TLS alert as the QUIC transport error `0x100 + alert`
//! (RFC 9001 §4.8), so the code the client reads back is the alert byte the
//! server chose. Before this, every unservable name came back as `0x128`,
//! `handshake_failure`, whether the client had asked for a stranger's name or
//! for no name at all.

use super::*;

/// 🔢 `unrecognized_name` (112) on the QUIC wire.
const UNRECOGNIZED_NAME: u64 = 0x100 + 112;
/// 🔢 `missing_extension` (109) on the QUIC wire.
const MISSING_EXTENSION: u64 = 0x100 + 109;

/// 🧾 A listener serving one name, with an optional `default_sni`.
async fn one_site_listener(default_sni: Option<&str>) -> SocketAddr {
    let table = Arc::new(CertTable::new());
    let (cert, key) = self_signed_pem(&["only.pingclair.test"]);
    table
        .upsert_pem("only.pingclair.test", &cert, &key)
        .unwrap();
    spawn_listener(table, default_sni).await
}

/// 🎯 Asserts the handshake was closed with exactly this transport error.
///
/// The helper reports a refusal as the `Debug` of quiche's peer error, so the
/// assertion reads the code out of that text rather than growing the helper's
/// return type for one caller.
fn assert_closed_with(outcome: Result<Vec<u8>, String>, code: u64, what: &str) {
    let error = outcome.expect_err(what);
    assert!(
        error.contains(&format!("error_code: {code},")),
        "{what}: expected transport error {code:#x}, got {error}"
    );
}

/// 🚫 A name this listener has no certificate for is `unrecognized_name`.
#[tokio::test]
async fn an_unknown_sni_is_refused_with_unrecognized_name() {
    let server = one_site_listener(None).await;
    assert_closed_with(
        handshake_and_capture_cert(server, Some("unknown.pingclair.test")).await,
        UNRECOGNIZED_NAME,
        "an unknown SNI must be refused as an unrecognized name",
    );
}

/// 🚫 No name and no `default_sni` is `missing_extension`: the listener needs
/// a name to choose a certificate by, and the client gave none.
#[tokio::test]
async fn a_missing_sni_without_a_default_is_refused_with_missing_extension() {
    let server = one_site_listener(None).await;
    assert_closed_with(
        handshake_and_capture_cert(server, None).await,
        MISSING_EXTENSION,
        "a nameless ClientHello must be refused as missing its extension",
    );
}

/// 🏷️ The name callback must not refuse what `default_sni` exists to serve.
#[tokio::test]
async fn a_missing_sni_with_a_default_is_still_served() {
    let server = one_site_listener(Some("only.pingclair.test")).await;
    handshake_and_capture_cert(server, None)
        .await
        .expect("a nameless ClientHello is served the listener's default certificate");
}
