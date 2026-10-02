// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🙈 Masks configured secrets in what the admin API's reads return.
//!
//! The stored document keeps every secret, because `/load`, the traversal
//! writes and the autosave all need the real values. Only the copy a read
//! hands out is masked. The document is untyped JSON, so the secret fields are
//! found by shape: every field the typed configuration holds as a
//! `SecretString` — the admin `api_key` and each DNS provider's `arguments` —
//! has one listed here, and the test below builds a typed configuration with
//! all of them set to prove nothing is missed.
//!
//! 📌 Off the request path: this runs once per admin read and clones the
//! document, which is the clear shape rather than the fast one.

use pingclair_core::config::SecretString;
use serde_json::Value;

/// 🏷️ The keys whose object value is a DNS provider (`{name, arguments}`):
/// the global `dns` and `acme_dns` options, and a site's
/// `dns_challenge.provider`.
const DNS_PROVIDER_KEYS: [&str; 3] = ["dns", "acme_dns", "provider"];

/// 🙈 Returns a copy of `document` with every configured secret masked.
pub(crate) fn redacted(document: &Value) -> Value {
    let mut copy = document.clone();
    mask(&mut copy);
    copy
}

fn mask(node: &mut Value) {
    match node {
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                if key == "api_key" && value.is_string() {
                    *value = Value::from(SecretString::REDACTED);
                    continue;
                }
                if DNS_PROVIDER_KEYS.contains(&key.as_str())
                    && let Some(Value::Array(arguments)) = value.get_mut("arguments")
                {
                    arguments.fill(Value::from(SecretString::REDACTED));
                }
                mask(value);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(mask),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingclair_core::config::{
        AdminConfig, DnsChallengeConfig, DnsProviderConfig, PingclairConfig, ServerConfig,
    };

    /// 🙈 Every `SecretString` the typed configuration can hold is masked.
    ///
    /// Each one is set to the same sentinel; if a new secret field is added
    /// and not taught to [`mask`], the sentinel survives and this fails.
    #[test]
    fn every_secret_field_is_masked() {
        const SENTINEL: &str = "sentinel-secret-value";
        let provider = || DnsProviderConfig {
            name: "cloudflare".into(),
            arguments: vec![SENTINEL.into(), SENTINEL.into()],
        };
        let mut config: PingclairConfig =
            serde_json::from_value(serde_json::json!({ "servers": [] })).unwrap();
        config.admin = Some(AdminConfig {
            api_key: Some(SENTINEL.into()),
            ..serde_json::from_value(serde_json::json!({ "listen": "127.0.0.1:2019" })).unwrap()
        });
        config.global.dns = Some(provider());
        config.global.acme_dns = Some(Some(provider()));
        let mut server: ServerConfig =
            serde_json::from_value(serde_json::json!({ "tls": {} })).unwrap();
        server.tls.as_mut().unwrap().dns_challenge = Some(DnsChallengeConfig {
            provider: Some(provider()),
            ..DnsChallengeConfig::default()
        });
        config.servers.push(server);

        let document = serde_json::to_value(&config).unwrap();
        assert_eq!(
            document.to_string().matches(SENTINEL).count(),
            7,
            "the fixture really carries every secret"
        );
        let masked = redacted(&document).to_string();
        assert!(!masked.contains(SENTINEL), "a secret survived: {masked}");
    }
}
