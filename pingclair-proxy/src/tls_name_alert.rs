//! 🏷️ The TLS alert a handshake ends with when its server name cannot be served.
//!
//! A client that asks for a name this listener has no certificate for should
//! be told exactly that, because the alert is the only diagnosis it gets: RFC
//! 9846 §6.2 names `unrecognized_name` for "no server exists" under the
//! offered name, and §9.2 names `missing_extension` for a ClientHello that
//! offered no name where one is required. Left to itself, BoringSSL reaches
//! the same dead end by a side road and reports it as something else — on TCP
//! an empty credential list becomes `internal_error`, and on QUIC a refused
//! certificate selection becomes `handshake_failure` — so a client and its
//! operator went looking for a broken server instead of a wrong hostname.
//!
//! 🧭 Both transports install the same decision through BoringSSL's
//! servername callback. That callback is the one place the library lets a
//! server choose the alert, and it runs at the right moment for both: after
//! QUIC's certificate selection (so HTTP/3 can ask whether a certificate was
//! installed) and before TCP's asynchronous certificate callback (so HTTP/1
//! and HTTP/2 ask the certificate manager whether the name is configured).
//! The order is `do_read_client_hello_after_ech` in BoringSSL as pinned by
//! `boring-sys` 5.2.0: `select_certificate_cb`, then
//! `ssl_parse_clienthello_tlsext` (which runs this callback), then `cert_cb`.

use std::sync::Arc;

use boring::ssl::{NameType, SniError, SslAlert, SslContextBuilder, SslRef};

/// 🎯 Decides whether a handshake's name can be served, and if not, which
/// alert says why.
///
/// `offered` is the SNI exactly as the client sent it; `default_sni` is the
/// listener's name for clients that send none; `serves` answers whether a
/// certificate exists for a name. The three refusals match three different
/// parties at fault:
///
/// - the client named something nobody configured → `unrecognized_name`;
/// - the client named nothing and the listener has no default →
///   `missing_extension`, since without a name there is nothing to choose by;
/// - the listener's own default has no certificate → `internal_error`,
///   because the client did everything it could and the configuration is
///   what is broken.
pub fn name_alert(
    offered: Option<&str>,
    default_sni: Option<&str>,
    serves: impl FnOnce(&str) -> bool,
) -> Result<(), SslAlert> {
    match (offered.filter(|name| !name.is_empty()), default_sni) {
        (Some(name), _) => serves(name)
            .then_some(())
            .ok_or(SslAlert::UNRECOGNIZED_NAME),
        (None, Some(default)) => serves(default)
            .then_some(())
            .ok_or(SslAlert::INTERNAL_ERROR),
        (None, None) => Err(SslAlert::MISSING_EXTENSION),
    }
}

/// 🔐 Installs [`name_alert`] as the context's servername callback.
///
/// `serves` receives the handshake as well as the name, because the two
/// transports answer from different places: HTTP/3 has already chosen its
/// certificate by the time this runs and only needs to look at the handshake,
/// while TCP has not yet and asks its certificate manager about the name.
///
/// 📌 A served name is now acknowledged in the server's reply (an empty
/// `server_name` extension), as RFC 6066 §3 asks of a server that used the
/// name. Without a callback BoringSSL never acknowledged it; clients do not
/// act on the acknowledgement, so this changes bytes rather than behaviour.
pub fn install_name_alert<F>(
    builder: &mut SslContextBuilder,
    default_sni: Option<Arc<str>>,
    serves: F,
) where
    F: Fn(&SslRef, &str) -> bool + Send + Sync + 'static,
{
    builder.set_servername_callback(move |ssl, alert| {
        let ssl: &SslRef = ssl;
        let offered = ssl.servername(NameType::HOST_NAME);
        match name_alert(offered, default_sni.as_deref(), |name| serves(ssl, name)) {
            Ok(()) => Ok(()),
            Err(refusal) => {
                // 📉 `debug`, because any stranger can make this line appear
                // as often as they can open connections.
                tracing::debug!(
                    alert = ?refusal,
                    sni = offered.unwrap_or(""),
                    "🚫 Refused a TLS handshake whose server name this listener does not serve"
                );
                *alert = refusal;
                Err(SniError::ALERT_FATAL)
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🧾 Every combination of offered name and default lands on the alert
    /// that names whoever is at fault.
    #[test]
    fn each_unservable_case_has_its_own_alert() {
        let serves = |name: &str| name == "known.test";
        let outcomes = [
            name_alert(Some("known.test"), None, serves),
            name_alert(Some("stranger.test"), Some("known.test"), serves),
            name_alert(None, Some("known.test"), serves),
            name_alert(Some(""), Some("known.test"), serves),
            name_alert(None, Some("gone.test"), serves),
            name_alert(None, None, serves),
        ];
        assert_eq!(
            outcomes,
            [
                Ok(()),
                Err(SslAlert::UNRECOGNIZED_NAME),
                Ok(()),
                Ok(()),
                Err(SslAlert::INTERNAL_ERROR),
                Err(SslAlert::MISSING_EXTENSION),
            ]
        );
    }
}
