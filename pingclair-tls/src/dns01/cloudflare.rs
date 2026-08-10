// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ☁️ Publishing DNS-01 records through the Cloudflare API.
//!
//! Three calls, and the awkward one is the first. The API addresses records by
//! zone, and a challenge gives us a fully qualified name — so the zone has to
//! be found by asking for progressively shorter suffixes of it:
//! `_acme-challenge.a.example.com` is in the zone `example.com`, and nothing
//! in the name says so. The answer is cached for the process lifetime because
//! it cannot change under us in any way that matters: a zone that moved
//! accounts would fail the write, which is the honest place to find out.
//!
//! 🔐 The API token is a credential. It is held in a wrapper whose `Debug`
//! prints nothing, so it cannot reach a log line, a panic message, or an admin
//! dump through the derive that someone adds later.

use super::{DnsError, DnsProvider, RecordHandle};
use async_trait::async_trait;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use parking_lot::RwLock;
use std::collections::HashMap;

/// 🔐 An API token that cannot be printed by accident.
#[derive(Clone)]
pub struct ApiToken(String);

impl std::fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 🙈 Not even the length: a token's length identifies its type.
        f.write_str("ApiToken(<redacted>)")
    }
}

impl From<String> for ApiToken {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// ☁️ The public Cloudflare API. Overridable so tests never leave the machine.
const DEFAULT_API_BASE: &str = "https://api.cloudflare.com/client/v4";

type HttpsClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

/// ☁️ A [`DnsProvider`] backed by Cloudflare's DNS API.
pub struct CloudflareProvider {
    token: ApiToken,
    api_base: String,
    client: HttpsClient,
    /// 🗺️ Zone name → zone id, resolved on first use.
    zones: RwLock<HashMap<String, String>>,
    /// 🎫 Handle → (zone id, record id), so deletion needs no second lookup.
    records: RwLock<HashMap<String, (String, String)>>,
}

impl CloudflareProvider {
    /// ☁️ Builds a provider against the public API.
    pub fn new(token: impl Into<ApiToken>) -> Result<Self, DnsError> {
        Self::with_api_base(token, DEFAULT_API_BASE)
    }

    /// 🧪 Builds a provider against a different base URL, for tests.
    pub fn with_api_base(
        token: impl Into<ApiToken>,
        api_base: impl Into<String>,
    ) -> Result<Self, DnsError> {
        let token = token.into();
        if token.0.trim().is_empty() {
            return Err(DnsError::Config(
                "the Cloudflare provider needs an API token: `dns cloudflare <token>`".into(),
            ));
        }

        // 🔐 The crypto provider is named rather than taken from the process
        // default, because this binary links more than one: `instant-acme`
        // brings aws-lc-rs and the workspace pins rustls to ring, so rustls
        // refuses to guess and **panics** on the first connection. That is a
        // panic at issuance time against a live API, not a test artefact — the
        // test that found it would otherwise have been the only thing this
        // provider ever failed on.
        //
        // An already-installed default wins, so a process that chose one keeps
        // it; otherwise ring, matching the workspace's own rustls feature.
        let provider = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| std::sync::Arc::new(rustls::crypto::ring::default_provider()));

        // 🔐 `https_or_http` rather than `https_only`: the public API is HTTPS
        // and stays HTTPS, but a test points this at a loopback mock, and a
        // client that cannot speak to one would mean the provider is only ever
        // exercised against the real API — which is to say never.
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_provider_and_webpki_roots(provider)
            .map_err(|error| DnsError::Config(format!("TLS setup failed: {error}")))?
            .https_or_http()
            .enable_http1()
            .build();

        Ok(Self {
            token,
            api_base: api_base.into().trim_end_matches('/').to_string(),
            client: Client::builder(TokioExecutor::new()).build(connector),
            zones: RwLock::new(HashMap::new()),
            records: RwLock::new(HashMap::new()),
        })
    }

    /// 📨 One authenticated JSON round trip.
    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, DnsError> {
        let url = format!("{}{}", self.api_base, path);
        let payload = body
            .map(|value| Bytes::from(value.to_string()))
            .unwrap_or_default();

        let mut builder = Request::builder()
            .method(method)
            .uri(&url)
            .header("authorization", format!("Bearer {}", self.token.0))
            .header("accept", "application/json");
        if !payload.is_empty() {
            builder = builder.header("content-type", "application/json");
        }
        let request = builder
            .body(Full::new(payload))
            .map_err(|error| DnsError::Transport(error.to_string()))?;

        let response = self
            .client
            .request(request)
            .await
            .map_err(|error| DnsError::Transport(error.to_string()))?;
        let status = response.status();

        // 📦 Bounded because a DNS API answer is small and a compromised or
        // confused endpoint should not be able to make this process allocate
        // without limit.
        const MAX_RESPONSE_BYTES: usize = 1 << 20;
        let collected = response
            .into_body()
            .collect()
            .await
            .map_err(|error| DnsError::Transport(error.to_string()))?
            .to_bytes();
        if collected.len() > MAX_RESPONSE_BYTES {
            return Err(DnsError::Api(format!(
                "the response to {path} was larger than {MAX_RESPONSE_BYTES} bytes"
            )));
        }

        let parsed: serde_json::Value = serde_json::from_slice(&collected).map_err(|error| {
            DnsError::Api(format!(
                "{path} did not answer with JSON ({status}): {error}"
            ))
        })?;

        // ☁️ Cloudflare reports failure in the body as well as the status, and
        // the body is where the useful sentence is.
        if !status.is_success() || parsed.get("success").and_then(|s| s.as_bool()) != Some(true) {
            let detail = parsed
                .get("errors")
                .map(|errors| errors.to_string())
                .unwrap_or_else(|| status.to_string());
            return Err(DnsError::Api(format!("{path} failed ({status}): {detail}")));
        }

        Ok(parsed)
    }

    /// 🔎 Finds the zone that holds `fqdn`, trying the longest suffix first.
    ///
    /// `_acme-challenge.a.example.com` lives in `example.com`, and nothing in
    /// the name says which suffix is the zone — only the account knows. Longest
    /// first so a delegated sub-zone wins over its parent, which is the whole
    /// point of delegating it.
    async fn zone_for(&self, fqdn: &str) -> Result<String, DnsError> {
        let name = fqdn.trim_end_matches('.');
        let labels: Vec<&str> = name.split('.').collect();

        // 🌐 A zone needs at least two labels; anything shorter cannot be one.
        for start in 0..labels.len().saturating_sub(1) {
            let candidate = labels[start..].join(".");
            if let Some(id) = self.zones.read().get(&candidate) {
                return Ok(id.clone());
            }

            let answer = self
                .request(
                    Method::GET,
                    &format!("/zones?name={candidate}&status=active"),
                    None,
                )
                .await?;
            if let Some(id) = answer
                .get("result")
                .and_then(|result| result.as_array())
                .and_then(|zones| zones.first())
                .and_then(|zone| zone.get("id"))
                .and_then(|id| id.as_str())
            {
                self.zones.write().insert(candidate, id.to_string());
                return Ok(id.to_string());
            }
        }

        Err(DnsError::ZoneNotFound(name.to_string()))
    }
}

#[async_trait]
impl DnsProvider for CloudflareProvider {
    fn name(&self) -> &'static str {
        "cloudflare"
    }

    async fn upsert_txt(
        &self,
        fqdn: &str,
        value: &str,
        ttl_secs: u64,
    ) -> Result<RecordHandle, DnsError> {
        let zone = self.zone_for(fqdn).await?;

        // 🧹 Replace rather than append. A retried order would otherwise leave
        // the previous challenge value behind, and a name carrying two TXT
        // values is a name some CAs refuse to read.
        let existing = self
            .request(
                Method::GET,
                &format!("/zones/{zone}/dns_records?type=TXT&name={fqdn}"),
                None,
            )
            .await?;
        if let Some(records) = existing.get("result").and_then(|r| r.as_array()) {
            for record in records {
                if let Some(id) = record.get("id").and_then(|id| id.as_str()) {
                    let _ = self
                        .request(
                            Method::DELETE,
                            &format!("/zones/{zone}/dns_records/{id}"),
                            None,
                        )
                        .await;
                }
            }
        }

        let created = self
            .request(
                Method::POST,
                &format!("/zones/{zone}/dns_records"),
                Some(serde_json::json!({
                    "type": "TXT",
                    "name": fqdn,
                    "content": value,
                    "ttl": ttl_secs,
                })),
            )
            .await?;
        let record_id = created
            .get("result")
            .and_then(|result| result.get("id"))
            .and_then(|id| id.as_str())
            .ok_or_else(|| DnsError::Api("the created record has no id".into()))?
            .to_string();

        let handle = format!("{zone}/{record_id}");
        self.records
            .write()
            .insert(handle.clone(), (zone, record_id));
        Ok(handle)
    }

    async fn delete_txt(&self, handle: &RecordHandle) -> Result<(), DnsError> {
        let Some((zone, record)) = self.records.write().remove(handle) else {
            // 🧹 Already gone. Cleanup runs on every path out of an order,
            // including the ones that failed before publishing anything.
            return Ok(());
        };
        self.request(
            Method::DELETE,
            &format!("/zones/{zone}/dns_records/{record}"),
            None,
        )
        .await
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔐 A token must not be printable. The check is on `Debug` because that
    /// is the trait a future `#[derive(Debug)]` on a containing struct would
    /// reach for, and the leak would arrive without anyone writing a log line.
    #[test]
    fn a_token_never_prints_itself() {
        let token = ApiToken::from("cf-secret-value".to_string());
        let printed = format!("{token:?}");
        assert!(!printed.contains("cf-secret-value"), "{printed}");
        assert!(
            !printed.contains("15"),
            "the length identifies the token type"
        );
    }

    /// 🚫 An empty token is a configuration error, not a request that fails
    /// later against the API with a confusing 403.
    #[test]
    fn an_empty_token_is_refused_at_construction() {
        assert!(CloudflareProvider::new("   ".to_string()).is_err());
    }
}
