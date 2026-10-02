// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🙈 Masks configured secrets in what the admin API's reads return.
//!
//! The stored document keeps every secret, because `/load`, the traversal
//! writes and the autosave all need the real values. Only the copy a read
//! hands out is masked. The document is untyped JSON, so secrets are found by
//! shape, in two families:
//!
//! - Every field the typed configuration holds as a `SecretString`: the admin
//!   `api_key` and each DNS provider's `arguments`. A test below builds a
//!   typed configuration with all of them set, and another counts the
//!   `SecretString` fields so a new one cannot be added without being listed.
//! - Credentials an operator writes as ordinary strings: a header such as
//!   `header_up Authorization …` or `X-API-Key`, a FastCGI `env` entry named
//!   like a password, a basic-auth hash. These are recognised by the name
//!   they are stored under ([`is_credential_name`]), wherever it appears.
//!
//! A masked value is replaced by [`SecretString::REDACTED`], and a document
//! carrying that placeholder at a secret position is refused on the way back
//! in ([`carries_placeholder`]), so a masked export cannot be loaded as-is.
//!
//! 📌 Off the request path: this runs once per admin read or write and clones
//! the document, which is the clear shape rather than the fast one.

use pingclair_core::config::SecretString;
use serde_json::Value;

/// 🏷️ The keys whose object value is a DNS provider (`{name, arguments}`):
/// the global `dns` and `acme_dns` options, and a site's
/// `dns_challenge.provider`.
const DNS_PROVIDER_KEYS: [&str; 3] = ["dns", "acme_dns", "provider"];

/// 🔐 Names that carry a credential whatever object they appear in.
const CREDENTIAL_NAMES: [&str; 4] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
];

/// 🔐 Fragments that mark a name as a credential: `X-API-Key`, `api_key`,
/// `X-Auth-Token`, `CLIENT_SECRET`, `DB_PASSWORD`, a basic-auth `password`.
const CREDENTIAL_FRAGMENTS: [&str; 6] = [
    "api-key", "api_key", "apikey", "token", "secret", "password",
];

/// 🔎 Reports whether a field or header name holds a credential.
///
/// A header map key may carry an operation prefix (`+Name`, `-Name`, `?Name`,
/// `>Name`), which is ignored. Over-matching costs one masked value in an admin
/// read; under-matching hands a credential to every reader, so the list leans
/// towards masking.
fn is_credential_name(name: &str) -> bool {
    let name = name
        .trim_start_matches(['+', '-', '?', '>'])
        .to_ascii_lowercase();
    CREDENTIAL_NAMES.contains(&name.as_str())
        || CREDENTIAL_FRAGMENTS
            .iter()
            .any(|fragment| name.contains(fragment))
}

/// 🙈 Returns a copy of `document` with every configured secret masked.
pub(crate) fn redacted(document: &Value) -> Value {
    let mut copy = document.clone();
    each_secret(&mut copy, &mut |secret| {
        *secret = Value::from(SecretString::REDACTED);
    });
    copy
}

/// 🚫 Reports whether `document` holds the mask placeholder where a secret
/// belongs, which means it came from a masked read and lost the real value.
pub(crate) fn carries_placeholder(document: &Value) -> bool {
    let mut found = false;
    each_secret(&mut document.clone(), &mut |secret| {
        found |= secret.as_str() == Some(SecretString::REDACTED);
    });
    found
}

/// 🧭 Calls `visit` on every non-empty string in a secret position.
fn each_secret(node: &mut Value, visit: &mut impl FnMut(&mut Value)) {
    match node {
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                if is_credential_name(key) {
                    each_string(value, visit);
                    continue;
                }
                if DNS_PROVIDER_KEYS.contains(&key.as_str())
                    && let Some(arguments) = value.get_mut("arguments")
                {
                    each_string(arguments, visit);
                }
                each_secret(value, visit);
            }
        }
        Value::Array(items) => {
            for item in items {
                each_secret(item, visit);
            }
        }
        _ => {}
    }
}

/// 🧭 Calls `visit` on a non-empty string, or on each one in an array of them.
fn each_string(value: &mut Value, visit: &mut impl FnMut(&mut Value)) {
    match value {
        Value::String(text) if !text.is_empty() => visit(value),
        Value::Array(items) => {
            for item in items {
                if item.as_str().is_some_and(|text| !text.is_empty()) {
                    visit(item);
                }
            }
        }
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
    /// Each one is set to the same sentinel; a field [`each_secret`] does not
    /// reach would let the sentinel survive. The masked copy must also be
    /// recognised as one on the way back in, and the original must not.
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
        let masked = redacted(&document);
        assert!(
            !masked.to_string().contains(SENTINEL),
            "a secret survived: {masked}"
        );
        assert_eq!(
            (carries_placeholder(&masked), carries_placeholder(&document)),
            (true, false)
        );
    }

    /// 🧾 The `SecretString` fields are exactly the ones the test above sets.
    ///
    /// A new field left at its default would not appear in that fixture, so
    /// the fixture alone cannot notice it. Counting the declarations in the
    /// configuration types does: adding one fails here until it is taught to
    /// [`each_secret`] and added to the fixture, and this number is raised.
    #[test]
    fn the_secret_field_inventory_is_complete() {
        let types = include_str!("../../pingclair-core/src/config/types.rs");
        assert_eq!(
            types.matches("config::SecretString>").count(),
            2,
            "a SecretString field was added or removed; update redaction.rs"
        );
    }

    /// 🔐 Credentials stored as ordinary strings are masked by name, and
    /// ordinary values beside them are not.
    #[test]
    fn credential_names_are_masked_wherever_they_appear() {
        let document = serde_json::json!({
            "headers_up": {
                "Authorization": "Bearer a",
                "+X-Api-Key": "b",
                "X-Plain": "kept",
                "-Cookie": ""
            },
            "env": { "DB_PASSWORD": "c", "APP_ENV": "production" },
            "health_headers": { "X-Auth-Token": ["d", "e"] },
            "accounts": [{ "username": "admin", "password": "$2y$hash" }]
        });
        assert_eq!(
            redacted(&document),
            serde_json::json!({
                "headers_up": {
                    "Authorization": "[redacted]",
                    "+X-Api-Key": "[redacted]",
                    "X-Plain": "kept",
                    "-Cookie": ""
                },
                "env": { "DB_PASSWORD": "[redacted]", "APP_ENV": "production" },
                "health_headers": { "X-Auth-Token": ["[redacted]", "[redacted]"] },
                "accounts": [{ "username": "admin", "password": "[redacted]" }]
            })
        );
    }
}
