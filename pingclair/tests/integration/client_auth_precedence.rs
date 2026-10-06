// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🎯 A site's own name outranks a wildcard's `client_auth` (issue #259).
//!
//! A wildcard site that demanded client certificates used to impose that
//! demand on a different, explicitly named site sharing its port. The
//! handshake's policy table held only the sites that configured `client_auth`,
//! so the explicit site had no row of its own and fell through to the
//! wildcard's: every visitor was asked for a certificate the site never wanted.
//! The HTTP/3 half of this lives in `scripts/test-h3-client-auth-local.sh`,
//! because this suite has no QUIC client.

use super::*;

/// 🧾 A demanding wildcard, an explicit open name it would otherwise cover,
/// and a readiness site outside the wildcard so startup is observable even
/// when the open name is (wrongly) refusing handshakes. The sites use
/// `tls internal`, as the report did: a manual certificate on a wildcard site
/// is a separate question this test should not depend on.
fn wildcard_mutual_tls_fixture() -> (TestServer, TestAuthority, tempfile::TempDir) {
    let authority = TestAuthority::new("Pingclair Wildcard Client CA");
    let material = tempfile::tempdir().expect("certificate material dir");
    let ca_path = material.path().join("client-ca.pem");
    std::fs::write(&ca_path, &authority.ca_pem).expect("write client CA");

    let config = format!(
        r#"
        {{
            admin off
            http_port __PINGCLAIR_TEST_HTTP_PORT__
        }}

        https://*.sandbox.test:__PINGCLAIR_TEST_PORT__ {{
            tls {{
                internal
                client_auth {{
                    mode require_and_verify
                    trusted_ca_cert_file {ca}
                }}
            }}
            respond "wild-ok"
        }}

        https://public.sandbox.test:__PINGCLAIR_TEST_PORT__ {{
            tls {{
                internal
            }}
            respond "public-ok"
        }}

        https://ready.test:__PINGCLAIR_TEST_PORT__ {{
            tls {{
                internal
            }}
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
        }}
        "#,
        ca = ca_path.to_string_lossy(),
    );
    (TestServer::new_pingclairfile(&config), authority, material)
}

/// 🎯 The explicit site serves without a certificate, the wildcard still
/// demands one, and naming the open site in the handshake still cannot reach
/// a wildcard-covered host.
#[tokio::test]
async fn test_exact_site_without_client_auth_outranks_demanding_wildcard() {
    let (mut server, authority, _material) = wildcard_mutual_tls_fixture();
    assert!(
        server.wait_until_tls_ready("ready.test").await,
        "server failed to start with a wildcard client_auth site"
    );
    let address = server.address(0);
    let (trusted_cert, trusted_key) = authority.issue(&["client.test"]);

    let outcomes = tokio::task::spawn_blocking(move || {
        [
            // 🔓 The site that configured nothing is asked for nothing.
            mutual_tls_attempt(address, "public.sandbox.test", "public.sandbox.test", None),
            // 🪪 The wildcard keeps its demand for the names only it covers.
            mutual_tls_attempt(address, "other.sandbox.test", "other.sandbox.test", None),
            mutual_tls_attempt(
                address,
                "other.sandbox.test",
                "other.sandbox.test",
                Some((&trusted_cert, &trusted_key)),
            ),
            // 🛡️ Relaxing the open name must not open a way into the wildcard:
            // SNI and `Host` still have to agree on this listener.
            mutual_tls_attempt(address, "public.sandbox.test", "other.sandbox.test", None),
        ]
    })
    .await
    .expect("handshake task");

    assert_eq!(
        outcomes,
        [
            MutualTlsOutcome::Status(200),
            MutualTlsOutcome::HandshakeRejected,
            MutualTlsOutcome::Status(200),
            MutualTlsOutcome::Status(421),
        ],
        "[open name, wildcard without cert, wildcard with cert, open SNI to wildcard Host]"
    );
}
