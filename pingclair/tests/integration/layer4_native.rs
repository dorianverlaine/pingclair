// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔌 Native matcher composition selects a tunnel before forwarding original bytes.

use super::*;

#[tokio::test]
async fn native_conditions_preserve_route_order_bytes_and_half_close() {
    timeout(Duration::from_secs(30), async {
        let selected = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let fallback = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let wrong = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let config = format!(
            r#"
Admin(listen: "__PINGCLAIR_TEST_ADMIN_LISTEN__")
Shutdown(grace: .seconds(5))
@Matcher
let local = .from(["127.0.0.0/8"])
TCPListener(on: ":__PINGCLAIR_TEST_HTTP_PORT__") {{
    Route(when: .all([.tls(), .from(["192.0.2.0/24"])])) {{ Proxy(to: "{}") }}
    Route(when: .all([.tls(sni: ["example.test"], alpn: ["h2"]), local])) {{ Proxy(to: "{}") }}
    Fallback {{ Proxy(to: "{}") }}
}}
.limits(maxConnections: 8, preread: .kibibytes(16), relay: .kibibytes(1))
.timeouts(preread: .seconds(2), connect: .seconds(2), idle: .seconds(5))
.halfClose(enabled: true)
HTTPListener(on: "__PINGCLAIR_TEST_LISTEN__") {{
    Site(host: "*") {{
        Fallback {{ Respond(body: "__PINGCLAIR_TEST_READINESS_TOKEN__") }}
    }}
}}
"#,
            wrong.local_addr().unwrap(),
            selected.local_addr().unwrap(),
            fallback.local_addr().unwrap()
        );
        let mut server = TestServer::new_native(&config);
        assert!(server.wait_until_ready().await);
        for (origin, mut payload) in [(selected, hello()), (fallback, b"plain\0bytes".to_vec())] {
            payload.extend(std::iter::repeat_n(0x5a, 2 * 1024 * 1024));
            let expected = payload.clone();
            let backend = tokio::spawn(async move {
                let (mut stream, _) = origin.accept().await.unwrap();
                let mut received = Vec::new();
                stream.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, expected);
                stream.write_all(b"after EOF").await.unwrap();
            });
            let mut stream = TcpStream::connect(server.listener_address(0, 1))
                .await
                .unwrap();
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"after EOF");
            backend.await.unwrap();
        }
        assert!(
            timeout(Duration::from_millis(100), wrong.accept())
                .await
                .is_err()
        );
    })
    .await
    .unwrap();
}
