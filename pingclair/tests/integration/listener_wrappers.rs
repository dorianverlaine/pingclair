// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧢 The two global options that describe listener behaviour rather than
//! routes: `servers { listener_wrappers { … } }` and `ocsp_stapling off`.
//!
//! Both were refused outright, so a Caddyfile carried over from upstream could
//! not load at all. They are now read as far as this build can honour them, and
//! what is asserted here is that the reading reaches the socket and the startup
//! line — not merely that the file parsed.

use std::time::Duration;

use super::{TestServer, proxy_protocol_request, proxy_v1_prefix, wait_for_captured_line};

/// 🧢 `servers { listener_wrappers { proxy_protocol } }` requires the header on
/// every listener this Caddyfile declares.
///
/// 🤡 The option was refused, so a migrating Caddyfile had to be edited before
/// it would run — and there is no other way to say "every listener" in the DSL,
/// because `listen … proxy_protocol` names one listener at a time. The proof
/// that the global spelling works is that a connection *without* a header is
/// turned away and one *with* a header is answered; a parse alone would not
/// distinguish this from an option that was accepted and then dropped.
///
/// 🔐 The trusted source is loopback here, which is what makes the test able to
/// send a header the server will believe; the same `trusted_proxies` rule as
/// the per-listener spelling applies, and a configuration that asks for the
/// header without one is refused before startup.
#[tokio::test]
async fn the_listener_wrappers_option_requires_the_header_on_every_listener() {
    let config = r#"
        {
            admin off
            servers {
                trusted_proxies static 127.0.0.1/8
                listener_wrappers {
                    proxy_protocol
                }
            }
        }

        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "through-the-proxy"
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    let address = server.address(0);
    let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let prefix = proxy_v1_prefix("127.0.0.1", address);

    // 🎯 Readiness has to go through the header too: the listener is the one
    // the option just changed, so a plain GET would hang rather than answer.
    let mut ready = false;
    for _ in 0..50 {
        if server.exit_status().is_some() {
            break;
        }
        if let Ok(response) =
            proxy_protocol_request(address, loopback, &prefix, &server.readiness_path, &[]).await
            && String::from_utf8_lossy(&response).contains(&server.readiness_token)
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if !ready {
        server.print_diagnostics();
    }
    assert!(
        ready,
        "the listener never answered through the PROXY header"
    );

    // 🚫 A request with no header is what the option exists to refuse. An empty
    // read or a failed connection are both that refusal — the server drops the
    // transport rather than answering something, which is what a client that
    // reached the port directly must see.
    let plain = proxy_protocol_request(address, loopback, &[], "/", &[]).await;
    assert!(
        !plain.as_ref().is_ok_and(|response| !response.is_empty()),
        "a request without a PROXY header must not be answered: {:?}",
        plain.map(|response| String::from_utf8_lossy(&response).to_string())
    );

    // ✅ And the header is what makes the difference, not the port being shut.
    let answered = proxy_protocol_request(address, loopback, &prefix, "/", &[])
        .await
        .expect("a request carrying the header must be answered");
    assert!(
        String::from_utf8_lossy(&answered).contains("through-the-proxy"),
        "the site must answer a PROXY-framed request: {}",
        String::from_utf8_lossy(&answered)
    );
    server.stop();
}

/// 📴 `ocsp_stapling off` is accepted and says so at startup, because this
/// build staples nothing and the option therefore changes nothing.
///
/// 🤡 The startup line is the whole point of accepting the option: an operator
/// who wrote it is asking for a state, and the honest answer is that the state
/// was already in force — not silence, which would let them believe a stapler
/// had been configured, and not a refusal, which would block a Caddyfile whose
/// meaning is exactly what this build does.
#[tokio::test]
async fn the_ocsp_stapling_option_is_announced_at_startup() {
    let config = r#"
        {
            admin off
            ocsp_stapling off
        }

        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "stapling-is-off"
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(
        server.wait_until_ready().await,
        "a server configured with `ocsp_stapling off` must start and serve"
    );

    let captured = wait_for_captured_line(
        &server.stdout_path,
        "OCSP stapling: off",
        Duration::from_secs(5),
    )
    .await;
    assert!(
        captured.contains("OCSP stapling: off") && captured.contains("no OCSP response"),
        "the startup line must say what this build does instead:\n{captured}"
    );
    server.stop();
}
