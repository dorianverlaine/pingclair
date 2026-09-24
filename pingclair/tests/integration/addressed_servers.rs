// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 What an addressed `servers <address> { … }` block does to one listener.
//!
//! The address used to be dropped when the block's children were lifted to the
//! global level, so an option written for one listener either reached all of
//! them or was refused outright. `trusted_proxies` is the option these tests
//! use because it has an answer a client can see: whether a forwarded address
//! is believed decides which site a `client_ip` matcher picks, so the same
//! request with the same header gets two different bodies on two listeners.
//!
//! 📌 The measurement upstream was taken from is in
//! `compat-audit/verify/impl-gaps-ab/runtime/47/caddy-probe.log`, and the same
//! four requests appear in `runtime/47/ours-probe.log`.

use super::TestServer;

/// 🛡️ The same site on two listeners, only the first of which believes
/// `127.0.0.1`'s `X-Forwarded-For`.
///
/// 📌 `__PINGCLAIR_TEST_HTTP_PORT__` is the harness's second reserved port. It
/// exists for the plaintext companion of an HTTPS site; here it is a second
/// plaintext listener, which is the shape this test needs.
const TWO_LISTENERS: &str = "{
	admin off
	auto_https off
	servers :__PINGCLAIR_TEST_HTTP_PORT__ {
		trusted_proxies static 127.0.0.1/32
	}
}

http://__PINGCLAIR_TEST_LISTEN__ {
	@readiness path __PINGCLAIR_TEST_READINESS_PATH__
	respond @readiness \"__PINGCLAIR_TEST_READINESS_TOKEN__\"

	@forwarded client_ip 203.0.113.9
	respond @forwarded \"believed\"
	respond \"direct\"
}

:__PINGCLAIR_TEST_HTTP_PORT__ {
	@forwarded client_ip 203.0.113.9
	respond @forwarded \"believed\"
	respond \"direct\"
}
";

async fn body(client: &reqwest::Client, url: String, forwarded: bool) -> String {
    let mut request = client.get(url);
    if forwarded {
        request = request.header("X-Forwarded-For", "203.0.113.9");
    }
    request
        .send()
        .await
        .expect("the listener must answer")
        .text()
        .await
        .expect("a body")
}

#[tokio::test]
async fn the_forwarded_address_is_believed_on_one_listener_only() {
    let mut server = TestServer::new_pingclairfile(TWO_LISTENERS);
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = super::no_proxy_client();

    // 📌 A Pingclairfile fixture compiles to one server entry holding every
    // listener it declares: `[0]` is the site's own address and `[1]` is the
    // second reserved port, which is the one the `servers` block names.
    // `url(1, …)` would index a second *server* that does not exist.
    let untrusted = server.url(0, "/");
    let trusted = format!("http://{}/", server.server_addresses[0][1]);

    assert_eq!(
        body(&client, trusted.clone(), true).await,
        "believed",
        "the addressed listener was told to trust 127.0.0.1"
    );
    assert_eq!(
        body(&client, untrusted.clone(), true).await,
        "direct",
        "the listener the block did not name must ignore the forwarded address"
    );
    // 🔁 Without the header both listeners see the socket peer, so the matcher
    // picks the same answer — which is what makes the pair above a statement
    // about the forwarded address rather than about the two listeners being
    // configured differently in general.
    assert_eq!(body(&client, trusted, false).await, "direct");
    assert_eq!(body(&client, untrusted, false).await, "direct");

    server.stop();
}
