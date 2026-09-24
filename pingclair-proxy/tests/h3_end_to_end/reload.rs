//! ♻️ An HTTP/3 request that arrives during a reload is served, not refused.
//!
//! The QUIC path used to share the TCP path's publication gate: while a reload
//! swapped routes and client-auth policy one after the other, every request
//! was answered `503 Configuration Reload In Progress`. Both now come from one
//! generation published with a single swap, so there is nothing to wait out.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

/// 🏗️ One generation of sites, each answering `body`.
fn generation(address: SocketAddr, body: &str) -> Vec<ServerConfig> {
    (0..32)
        .map(|site| ServerConfig {
            name: Some(if site == 0 {
                "h3.pingclair.test".to_string()
            } else {
                format!("site{site}.h3.test")
            }),
            listen: vec![address.to_string()],
            routes: vec![RouteConfig {
                path: "/*".to_string(),
                handler: HandlerConfig::Respond {
                    status: 200,
                    body: Some(body.to_string()),
                    headers: std::collections::BTreeMap::new(),
                },
                methods: None,
                matcher: None,
            }],
            ..Default::default()
        })
        .collect()
}

/// ♻️ Requests sent while generations are published back to back all succeed.
#[tokio::test]
async fn h3_requests_during_reloads_are_all_served() {
    let socket = bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
    let address = socket.local_addr().unwrap();
    let listener_policy = Arc::new(PublishedListenerPolicy::new(Arc::new(
        ClientAuthTable::default(),
    )));
    let proxy = PingclairProxy::with_published_listener_policy(Arc::clone(&listener_policy));
    proxy.update_config(generation(address, "gen-0"));

    let certs = Arc::new(CertTable::new());
    let (cert, key) = self_signed_pem(&["h3.pingclair.test"]);
    certs.upsert_pem("h3.pingclair.test", &cert, &key).unwrap();
    let server =
        QuicServer::new(address, Arc::new(proxy.clone()), certs, 8, Vec::new()).with_socket(socket);
    tokio::spawn(async move {
        if let Err(error) = server.run().await {
            eprintln!("H3 server stopped: {error}");
        }
    });

    // 🔁 Publish generations continuously from a plain thread, the way the
    // signal handler's reload does, until the requests below are finished.
    let stop = Arc::new(AtomicBool::new(false));
    let publisher = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut published = 0_u64;
            while !stop.load(Ordering::Relaxed) {
                published += 1;
                let routes = proxy.prepare_routes(generation(address, &format!("gen-{published}")));
                listener_policy.publish(Arc::new(ClientAuthTable::default()), Arc::new(routes));
            }
            published
        })
    };

    let mut failures = Vec::new();
    for _ in 0..40 {
        match h3_attempt(H3Attempt::to(address, "/"), None).await {
            Ok(response) if response.status == 200 => {}
            Ok(response) => failures.push(format!(
                "{}: {}",
                response.status,
                String::from_utf8_lossy(&response.body)
            )),
            Err(error) => failures.push(error),
        }
    }
    stop.store(true, Ordering::Relaxed);
    let published = publisher.join().expect("publisher thread");

    assert!(published > 1, "the test never overlapped a reload");
    assert!(
        failures.is_empty(),
        "{} of 40 HTTP/3 requests failed across {published} reloads: {:?}",
        failures.len(),
        &failures[..failures.len().min(5)]
    );
}
