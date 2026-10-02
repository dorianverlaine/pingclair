// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔑 A cached response belongs to the upstream that produced it.
//!
//! One caching route can reach different upstreams: its dial can be a
//! placeholder such as `{http.vars.backend}`, and site-level `vars` can change
//! what the route sends upstream. Keyed on the route alone, the first response
//! stored answered for every upstream the route could reach — including
//! across a reload that pointed the variables somewhere else.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::response_pipeline::spawn_scripted_origin;
use super::{TestServer, no_proxy_client};

/// 📄 A complete response with a fixed body and no caching headers.
fn page(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// 🧭 One route whose dial is `{http.vars.backend}`: guarded requests are sent
/// to the internal upstream, everyone else to the public one.
#[tokio::test]
async fn test_a_placeholder_dial_keeps_each_upstreams_entries_apart() {
    let (internal, internal_hits) = spawn_scripted_origin(page("confidential")).await;
    let (public, public_hits) = spawn_scripted_origin(page("public")).await;
    let mut server = TestServer::new_pingclairfile(&format!(
        r#"
        {{
            admin __PINGCLAIR_TEST_ADMIN_LISTEN__
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            @internal header X-Internal yes
            vars backend {public}
            vars @internal backend {internal}

            reverse_proxy {{http.vars.backend}} {{
                cache {{
                    ttl 60s
                }}
            }}
        }}
        "#
    ));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let mut bodies = Vec::new();
    for internal_view in [true, false, true, false] {
        let mut request = client.get(server.url(0, "/report"));
        if internal_view {
            request = request.header("X-Internal", "yes");
        }
        bodies.push(request.send().await.unwrap().text().await.unwrap());
    }
    assert_eq!(
        (
            bodies,
            internal_hits.load(Ordering::SeqCst),
            public_hits.load(Ordering::SeqCst)
        ),
        (
            vec!["confidential", "public", "confidential", "public"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>(),
            1,
            1
        ),
        "each upstream serves its own page, and each is still cached"
    );

    // 🧹 Each upstream's copy is a variant of one URL entry, so one purge by
    // URL reaches both.
    let purge = client
        .post(server.admin_url("/cache/purge"))
        .json(&serde_json::json!({
            "host": server.server_addresses[0][0].to_string(),
            "path": "/report",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(purge.text().await.unwrap(), r#"{"purged":true}"#);
    for internal_view in [true, false] {
        let mut request = client.get(server.url(0, "/report"));
        if internal_view {
            request = request.header("X-Internal", "yes");
        }
        let _ = request.send().await.unwrap().text().await.unwrap();
    }
    assert_eq!(
        (
            internal_hits.load(Ordering::SeqCst),
            public_hits.load(Ordering::SeqCst)
        ),
        (2, 2),
        "both upstreams' copies were purged"
    );
}

/// 🪞 An origin whose body is the request's `X-Tenant` header.
async fn spawn_tenant_echo() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 16384];
                let Ok(read) = stream.read(&mut buffer).await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let request = String::from_utf8_lossy(&buffer[..read]).to_string();
                let tenant = request
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.trim()
                            .eq_ignore_ascii_case("x-tenant")
                            .then(|| value.trim().to_string())
                    })
                    .unwrap_or_default();
                let _ = stream.write_all(&page(&tenant)).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (address, hits)
}

/// 🔄 A reload that changes a site variable the route sends upstream does not
/// keep serving the entries stored under the old value.
#[tokio::test]
async fn test_a_reload_that_changes_site_vars_starts_the_route_cold() {
    let (origin, hits) = spawn_tenant_echo().await;
    let config = |tenant: &str, listen: &str, admin: &str| {
        format!(
            r#"
            {{
                admin {admin}
            }}

            http://{listen} {{
                @readiness path __PINGCLAIR_TEST_READINESS_PATH__
                respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

                vars tenant {tenant}

                reverse_proxy http://{origin} {{
                    header_up X-Tenant {{http.vars.tenant}}
                    cache {{
                        ttl 60s
                    }}
                }}
            }}
            "#
        )
    };
    let mut server = TestServer::new_pingclairfile(&config(
        "internal",
        "__PINGCLAIR_TEST_LISTEN__",
        "__PINGCLAIR_TEST_ADMIN_LISTEN__",
    ));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let before = client.get(server.url(0, "/report")).send().await.unwrap();
    assert_eq!(before.text().await.unwrap(), "internal");

    // 🔄 The readiness placeholders stay literal in the reloaded file: nothing
    // probes readiness after this point, and the route under test is the same.
    let reloaded = client
        .post(server.admin_url("/load"))
        .header("Content-Type", "text/caddyfile")
        .body(config(
            "public",
            &server.address(0).to_string(),
            &server.admin_address.unwrap().to_string(),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(reloaded.status(), reqwest::StatusCode::OK);

    let after = client.get(server.url(0, "/report")).send().await.unwrap();
    assert_eq!(
        (after.text().await.unwrap(), hits.load(Ordering::SeqCst)),
        ("public".to_string(), 2),
        "the new variable reaches the origin instead of the old entry answering"
    );
}
