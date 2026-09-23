// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔐 When a response may carry `Strict-Transport-Security`.
//!
//! The header tells a browser "only ever reach this host over TLS", so it is
//! only meaningful on a response that itself arrived over TLS. RFC 6797 §7.2
//! forbids sending it on plaintext, and §7.1 asks for it on every encrypted
//! response of a host that opted in. The question is therefore about the
//! connection the response travels on, never about whether the site happens to
//! have a `tls` block: a site can have one and still own a plaintext listener,
//! and a `tls internal` site answers over TLS without an ACME policy at all.
//!
//! 📌 Two sources can put the header on a response. An operator writes
//! `header Strict-Transport-Security "max-age=…"` (the only Pingclairfile
//! spelling), or a JSON configuration turns on the built-in `security.hsts`
//! policy. A value already on the response — from the operator's `header` or
//! from the upstream — wins over the built-in one, because it is the more
//! specific instruction. On plaintext every source is stripped.

use http::HeaderValue;
use http::header::STRICT_TRANSPORT_SECURITY;
use pingclair_core::config::{HstsConfig, SecurityConfig};
use pingora_core::Result as PingoraResult;
use pingora_http::ResponseHeader;

/// 🔐 The built-in HSTS value, rendered once when the configuration loads.
///
/// 🏎️ The value cannot change between two requests on the same
/// configuration, so it lives in `ProxyState` as a ready `HeaderValue` rather
/// than being formatted per response.
#[derive(Debug, Clone, Default)]
pub(crate) struct StrictTransport {
    builtin: Option<HeaderValue>,
}

impl StrictTransport {
    /// 🧱 Renders the built-in policy, or nothing when the security policy or
    /// its HSTS half is off.
    pub(crate) fn from_security(security: &SecurityConfig) -> Self {
        let builtin = security
            .hsts
            .as_ref()
            .filter(|_| security.enabled)
            .map(render);
        Self { builtin }
    }

    /// 🔎 The built-in value, for the H3 path that writes its own header list.
    pub(crate) fn builtin(&self) -> Option<&HeaderValue> {
        self.builtin.as_ref()
    }

    /// 🔐 Settles the header on an H1/H2 response.
    ///
    /// `encrypted` must describe the client's leg of the exchange: TLS on this
    /// connection, or a trusted ingress that says it terminated TLS.
    pub(crate) fn apply_pingora(
        policy: Option<&Self>,
        response: &mut ResponseHeader,
        encrypted: bool,
    ) -> PingoraResult<()> {
        if !encrypted {
            // 🚫 RFC 6797 §7.2: never on plaintext, whoever set it.
            response.remove_header(&STRICT_TRANSPORT_SECURITY);
            return Ok(());
        }
        if let Some(value) = policy.and_then(Self::builtin)
            && !response.headers.contains_key(STRICT_TRANSPORT_SECURITY)
        {
            response.insert_header(STRICT_TRANSPORT_SECURITY, value.clone())?;
        }
        Ok(())
    }
}

/// 🧾 Spells one policy as RFC 6797 §6.1 writes it: directives separated by
/// `; `, with no trailing separator.
fn render(hsts: &HstsConfig) -> HeaderValue {
    let mut value = format!("max-age={}", hsts.max_age);
    if hsts.include_subdomains {
        value.push_str("; includeSubDomains");
    }
    if hsts.preload {
        value.push_str("; preload");
    }
    // 🛡️ Digits, ASCII letters and `; ` only, so this cannot fail.
    HeaderValue::from_str(&value).expect("an HSTS value is always a valid header value")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(enabled: bool, hsts: Option<HstsConfig>) -> StrictTransport {
        StrictTransport::from_security(&SecurityConfig {
            enabled,
            hsts,
            ..SecurityConfig::default()
        })
    }

    fn hsts(include_subdomains: bool, preload: bool) -> HstsConfig {
        HstsConfig {
            max_age: 60,
            include_subdomains,
            preload,
        }
    }

    fn sts(response: &ResponseHeader) -> Vec<&[u8]> {
        response
            .headers
            .get_all(STRICT_TRANSPORT_SECURITY)
            .iter()
            .map(HeaderValue::as_bytes)
            .collect()
    }

    /// 🧾 The rendered value has no trailing `;` and names only what is on.
    #[test]
    fn test_builtin_value_follows_the_rfc_grammar() {
        let rendered: Vec<_> = [(false, false), (true, false), (true, true)]
            .into_iter()
            .map(|(sub, pre)| policy(true, Some(hsts(sub, pre))).builtin.unwrap())
            .collect();
        assert_eq!(
            rendered,
            [
                "max-age=60",
                "max-age=60; includeSubDomains",
                "max-age=60; includeSubDomains; preload",
            ]
        );
        assert!(policy(false, Some(hsts(true, true))).builtin.is_none());
        assert!(policy(true, None).builtin.is_none());
    }

    /// 🔐 The built-in value reaches an encrypted response that has none, and
    /// yields to one already there.
    #[test]
    fn test_encrypted_response_gets_the_builtin_unless_one_is_set() {
        let policy = policy(true, Some(hsts(true, false)));
        let mut bare = ResponseHeader::build(200, None).unwrap();
        StrictTransport::apply_pingora(Some(&policy), &mut bare, true).unwrap();
        assert_eq!(sts(&bare), [b"max-age=60; includeSubDomains".as_slice()]);

        let mut operator = ResponseHeader::build(200, None).unwrap();
        operator
            .insert_header(STRICT_TRANSPORT_SECURITY, "max-age=5")
            .unwrap();
        StrictTransport::apply_pingora(Some(&policy), &mut operator, true).unwrap();
        assert_eq!(sts(&operator), [b"max-age=5".as_slice()]);
    }

    /// 🚫 A plaintext response loses the header, however it got there.
    #[test]
    fn test_plaintext_response_never_carries_the_header() {
        let policy = policy(true, Some(hsts(true, false)));
        let mut response = ResponseHeader::build(200, None).unwrap();
        response
            .insert_header(STRICT_TRANSPORT_SECURITY, "max-age=5")
            .unwrap();
        StrictTransport::apply_pingora(Some(&policy), &mut response, false).unwrap();
        assert!(sts(&response).is_empty());
    }
}
