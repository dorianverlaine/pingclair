//! 🛡️ A trailing dot in the SNI names the same host for mutual TLS too.
//!
//! `secure.h3.test.` and `secure.h3.test` are one DNS name. Certificate
//! selection and routing already treat them as one, but the client-auth
//! lookup on the QUIC handshake used the SNI as sent, found no policy for the
//! dotted spelling, and asked for no client certificate. The request then
//! reached the protected site anyway, because routing drops the dot and the
//! SNI-against-`:authority` check compared the two dotted spellings.

use super::*;

/// 🚫 Adding a trailing dot must not opt a client out of `require_and_verify`.
#[tokio::test]
async fn h3_client_auth_holds_for_a_trailing_dot_sni() {
    let authority = H3Authority::new("H3 Client CA");
    let (address, _material) = spawn_h3_mtls_listener(
        pingclair_core::config::ClientAuthMode::RequireAndVerify,
        &authority.ca_pem,
    )
    .await;

    let dotted = h3_attempt(
        H3Attempt {
            sni: "secure.h3.test.",
            authority: "secure.h3.test.",
            ..H3Attempt::to(address, "/probe")
        },
        None,
    )
    .await;
    assert_handshake_refused(
        dotted,
        "a client with no certificate reached the mutual-TLS site over HTTP/3 by adding a \
         trailing dot to the SNI",
    );
}
