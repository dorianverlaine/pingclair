// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔌 Matcher sets select a tunnel in route order before forwarding original bytes.

use super::*;

#[tokio::test]
async fn matcher_sets_preserve_route_order_bytes_and_half_close() {
    timeout(Duration::from_secs(30), async {
        let selected = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let fallback = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let wrong = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let routes = format!(
            "@wrong {{\n tls\n remote_ip 192.0.2.0/24\n }}\n route @wrong {{\n proxy {}\n }}\n\
             @selected {{\n tls {{\n sni example.test\n alpn h2\n }}\n remote_ip 127.0.0.0/8\n }}\n\
             route @selected {{\n proxy {}\n }}\n route {{\n proxy {}\n }}",
            wrong.local_addr().unwrap(),
            selected.local_addr().unwrap(),
            fallback.local_addr().unwrap()
        );
        let config = fixture(
            "max_connections 8\n preread_buffer_size 16k\n proxy_buffer_size 1k\n \
             preread_timeout 2s\n proxy_connect_timeout 2s\n proxy_timeout 5s",
            &routes,
        );
        let mut server = TestServer::new_pingclairfile(&config);
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
