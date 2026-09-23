// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;

/// 🔐 A Pingclairfile auth subrequest trusts only the configured private CA.
#[tokio::test]
async fn forward_auth_transport_uses_its_configured_ca() {
    let make_certificate = || {
        let mut params = rcgen::CertificateParams::new(vec!["auth.test".to_string()])
            .expect("certificate parameters");
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "auth.test");
        let key = rcgen::KeyPair::generate().expect("key pair");
        let certificate = params.self_signed(&key).expect("self-signed auth service");
        (certificate.pem(), key.serialize_pem())
    };
    let (certificate, key) = make_certificate();
    let (wrong_certificate, _) = make_certificate();
    let trust_store = tempfile::tempdir().expect("trust store dir");
    let trusted_path = trust_store.path().join("auth-ca.pem");
    let wrong_path = trust_store.path().join("wrong-ca.pem");
    std::fs::write(&trusted_path, &certificate).expect("publish trust root");
    std::fs::write(&wrong_path, wrong_certificate).expect("publish unrelated root");

    let config = |origin: SocketAddr, ca_path: &std::path::Path| {
        format!(
            r#"
            {{
                admin off
            }}

            http://__PINGCLAIR_TEST_LISTEN__ {{
                @readiness path __PINGCLAIR_TEST_READINESS_PATH__
                respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

                @private path /private
                forward_auth @private https://{origin} {{
                    uri /auth
                    transport http {{
                        tls_server_name auth.test
                        tls_trusted_ca_certs {ca}
                    }}
                }}
                respond "allowed" 200
            }}
            "#,
            ca = ca_path.display()
        )
    };

    for (ca_path, expected_success) in [(&trusted_path, true), (&wrong_path, false)] {
        let (origin, origin_task) = spawn_self_signed_tls_origin(&certificate, &key, 2).await;
        let mut server = TestServer::new_pingclairfile(&config(origin, ca_path));
        assert!(server.wait_until_ready().await, "server failed to start");
        let response = no_proxy_client()
            .get(server.url(0, "/private"))
            .send()
            .await
            .expect("the auth request must receive a response");
        if expected_success {
            assert_eq!(response.status(), 200);
            assert_eq!(response.text().await.unwrap(), "allowed");
        } else {
            assert!(response.status().is_server_error());
            assert_ne!(response.text().await.unwrap(), "allowed");
        }
        origin_task.abort();
    }
}
