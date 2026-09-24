//! 🔤 The QUIC handshake reads the SNI the way the certificate table is keyed.
//!
//! DNS names are case-insensitive, so `OPTED-OUT.h3.test` and
//! `opted-out.h3.test` are one site. The HTTP/3 certificate callback used to
//! look the client's bytes up verbatim, so a capital letter was enough to miss
//! a site's `http3 off` exclusion and be handed the default certificate.

use super::*;

/// 🚫 A site that turned HTTP/3 off stays off however the client spells it.
#[tokio::test]
async fn h3_exclusion_holds_for_a_mixed_case_sni() {
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    // 🔌 The server takes this bound socket, so no parallel test can claim the
    // port between probing and serving (#184).
    let socket = bind_udp(listen).unwrap();
    let address = socket.local_addr().unwrap();

    let proxy = PingclairProxy::with_published_listener_policy(Arc::new(
        PublishedListenerPolicy::new(Arc::new(ClientAuthTable::default())),
    ));
    proxy.update_config(vec![ServerConfig {
        listen: vec![address.to_string()],
        routes: vec![RouteConfig {
            path: "/*".to_string(),
            handler: HandlerConfig::Respond {
                status: 200,
                body: Some("kept".to_string()),
                headers: std::collections::BTreeMap::new(),
            },
            methods: None,
            matcher: None,
        }],
        ..Default::default()
    }]);

    // 🃏 The kept site is inserted first, so it is the default entry a missed
    // exclusion would fall through to.
    let certs = Arc::new(CertTable::new());
    let (cert, key) = self_signed_pem(&["kept.h3.test", "opted-out.h3.test"]);
    certs.upsert_pem("kept.h3.test", &cert, &key).unwrap();
    certs.upsert_pem("opted-out.h3.test", &cert, &key).unwrap();
    certs.set_excluded_names(["opted-out.h3.test"]);

    let server =
        QuicServer::new(address, Arc::new(proxy), certs, 8, Vec::new()).with_socket(socket);
    tokio::spawn(async move {
        if let Err(e) = server.run().await {
            eprintln!("H3 server stopped: {e}");
        }
    });

    let kept = h3_attempt(
        H3Attempt {
            sni: "kept.h3.test",
            authority: "kept.h3.test",
            ..H3Attempt::to(address, "/")
        },
        None,
    )
    .await
    .expect("the site that kept HTTP/3 must still answer");
    assert_eq!((kept.status, kept.body.as_slice()), (200, &b"kept"[..]));

    assert_handshake_refused(
        h3_attempt(
            H3Attempt {
                sni: "OPTED-OUT.h3.test",
                authority: "opted-out.h3.test",
                ..H3Attempt::to(address, "/")
            },
            None,
        )
        .await,
        "an uppercase SNI slipped past `http3 off` to the default certificate",
    );
}
