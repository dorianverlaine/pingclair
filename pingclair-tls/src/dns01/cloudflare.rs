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
    /// ⏱️ How long one API round trip may take before it is abandoned.
    request_timeout: std::time::Duration,
}

/// ⏱️ The per-request budget. Generous, because DNS APIs are occasionally slow
/// and a spurious failure here means a certificate that did not renew — but
/// finite, because the alternative is an order that waits forever.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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
            request_timeout: REQUEST_TIMEOUT,
        })
    }

    /// ⏱️ Overrides the per-request deadline. Tests only — a mock that never
    /// answers should not cost the suite the production budget.
    #[cfg(test)]
    fn set_request_timeout(&mut self, timeout: std::time::Duration) {
        self.request_timeout = timeout;
    }

    /// 📨 One authenticated JSON round trip, under a deadline.
    ///
    /// ⏱️ The deadline covers the whole trip — connect, send, and read — because
    /// a partial answer is no more useful than none, and issuance is what waits
    /// on this. Without it an API that accepted the connection and said nothing
    /// held a certificate order open forever.
    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, DnsError> {
        let timeout = self.request_timeout;
        tokio::time::timeout(timeout, self.round_trip(method, path, body))
            .await
            .map_err(|_| {
                DnsError::Transport(format!(
                    "{path} did not answer within {}ms",
                    timeout.as_millis()
                ))
            })?
    }

    async fn round_trip(
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

        // 📦 Read frame by frame against a running total, so the ceiling bounds
        // what this process allocates rather than describing it afterwards.
        //
        // 🤡 This used to be `.collect()` followed by a length check, under a
        // comment claiming it was bounded. It was not: the whole body was in
        // memory before the check could run, and the body's size is a remote
        // API's choice. Same shape as the two static-file bugs this repository
        // has already shipped — the difference being that here the peer is not
        // even ours.
        const MAX_RESPONSE_BYTES: usize = 1 << 20;
        let mut body = response.into_body();
        let mut collected: Vec<u8> = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|error| DnsError::Transport(error.to_string()))?;
            let Some(chunk) = frame.data_ref() else {
                // 🧾 A trailers frame carries no body bytes; nothing to weigh.
                continue;
            };
            if collected.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(DnsError::Api(format!(
                    "the response to {path} was larger than {MAX_RESPONSE_BYTES} bytes"
                )));
            }
            collected.extend_from_slice(chunk);
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
        // 🔒 Cloned out and the guard dropped before the await below. A lock held
        // across an await needs a reason written next to it, and this one has no
        // reason to be held at all.
        let Some((zone, record)) = self.records.read().get(handle).cloned() else {
            // 🧹 Already gone. Cleanup runs on every path out of an order,
            // including the ones that failed before publishing anything.
            return Ok(());
        };
        self.request(
            Method::DELETE,
            &format!("/zones/{zone}/dns_records/{record}"),
            None,
        )
        .await?;
        // 🧹 Forgotten only now that the remote copy is actually gone.
        //
        // 🤡 This removal used to happen first. So a delete that failed left the
        // TXT record published in DNS with nothing left that knew about it: the
        // next cleanup found no local entry, returned `Ok`, and the record stayed
        // forever. A stale `_acme-challenge` record is not only litter — it
        // remains standing evidence of control over that name long after the
        // order it belonged to, and it is the operator who cannot see it.
        self.records.write().remove(handle);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// 🧪 What a mock API does after it has read one request head.
    enum Mode {
        /// 📦 Claims a huge `Content-Length`, sends part of it, then stalls —
        /// the shape a compromised or confused endpoint has.
        OversizedThenStall,
        /// ⏱️ Accepts the connection and never answers at all.
        Silent,
        /// 🚨 Answers every request with a 500, counting them.
        AlwaysFailing(Arc<AtomicUsize>),
    }

    /// 🧪 A loopback HTTP/1 mock. Raw TCP rather than a server crate, because
    /// these tests are about what happens when a peer *misbehaves* — stalling
    /// mid-body and never responding are not things a well-behaved server API
    /// makes easy to express.
    async fn mock_api(mode: Mode) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let count = match &mode {
                    Mode::AlwaysFailing(count) => Some(count.clone()),
                    _ => None,
                };
                let silent = matches!(mode, Mode::Silent);
                let oversized = matches!(mode, Mode::OversizedThenStall);
                tokio::spawn(async move {
                    // 📥 Read just the head; the body does not matter here.
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while stream.read_exact(&mut byte).await.is_ok() {
                        head.push(byte[0]);
                        if head.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    if silent {
                        // ⏱️ Hold the connection open, answering nothing.
                        std::future::pending::<()>().await;
                    }
                    if oversized {
                        let claimed = 64 * 1024 * 1024;
                        let _ = stream
                            .write_all(
                                format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                     Content-Length: {claimed}\r\n\r\n"
                                )
                                .as_bytes(),
                            )
                            .await;
                        // 🌊 Two mebibytes, then nothing. A reader with a ceiling
                        // stops here; a reader that collects the whole body first
                        // waits for the other 62 MiB that never come.
                        let chunk = vec![b'x'; 64 * 1024];
                        for _ in 0..32 {
                            if stream.write_all(&chunk).await.is_err() {
                                return;
                            }
                        }
                        std::future::pending::<()>().await;
                    }
                    if let Some(count) = count {
                        count.fetch_add(1, Ordering::SeqCst);
                        let body = br#"{"success":false,"errors":["nope"]}"#;
                        let _ = stream
                            .write_all(
                                format!(
                                    "HTTP/1.1 500 Internal Server Error\r\n\
                                     Content-Type: application/json\r\n\
                                     Content-Length: {}\r\n\r\n",
                                    body.len()
                                )
                                .as_bytes(),
                            )
                            .await;
                        let _ = stream.write_all(body).await;
                    }
                });
            }
        });
        base
    }

    /// 📦 The response ceiling has to bound the *allocation*, not describe it
    /// after the fact.
    ///
    /// The limit was checked after `.collect()` had already buffered the whole
    /// body, so the comment claiming it was bounded was describing something the
    /// code did not do. This is the shape that shipped twice in the static file
    /// server, and it is worse here: the peer is a remote API, so the size is
    /// entirely somebody else's choice.
    #[tokio::test]
    async fn an_oversized_response_is_refused_without_being_buffered() {
        let base = mock_api(Mode::OversizedThenStall).await;
        let provider = CloudflareProvider::with_api_base("test-token".to_string(), base).unwrap();

        // ⏱️ A hard bound on the test itself, because the failure mode when this
        // regresses is *waiting*, and a test that hangs is the least useful way
        // to say no.
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            provider.request(Method::GET, "/zones", None),
        )
        .await;

        let Ok(result) = outcome else {
            panic!(
                "the client was still reading after 5s, so it is collecting the \
                 whole body before checking the ceiling"
            );
        };
        let error = result.expect_err("an oversized response must not be accepted");
        assert!(
            format!("{error:?}").contains("larger than"),
            "expected a size refusal, got {error:?}"
        );
    }

    /// ⏱️ An API that never answers must not hold issuance open forever.
    #[tokio::test]
    async fn a_silent_api_is_given_up_on() {
        let base = mock_api(Mode::Silent).await;
        let mut provider =
            CloudflareProvider::with_api_base("test-token".to_string(), base).unwrap();
        provider.set_request_timeout(Duration::from_millis(300));

        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            provider.request(Method::GET, "/zones", None),
        )
        .await;

        let Ok(result) = outcome else {
            panic!("the request had no deadline of its own and waited past 5s");
        };
        let error = result.expect_err("a silent API must not look like success");
        assert!(
            format!("{error:?}").contains("within"),
            "expected a timeout, got {error:?}"
        );
    }

    /// 🧹 A record is forgotten only once the remote copy is actually gone.
    ///
    /// The local handle was removed first, so a failed delete orphaned the TXT
    /// record in DNS permanently: the next cleanup found no local entry and
    /// reported success. A stale `_acme-challenge` record is not just litter — it
    /// stays as standing evidence of control long after the order it belonged to.
    #[tokio::test]
    async fn a_failed_delete_does_not_forget_the_record() {
        let deletes = Arc::new(AtomicUsize::new(0));
        let base = mock_api(Mode::AlwaysFailing(deletes.clone())).await;
        let provider = CloudflareProvider::with_api_base("test-token".to_string(), base).unwrap();

        let handle = "zone123/record456".to_string();
        provider.records.write().insert(
            handle.clone(),
            ("zone123".to_string(), "record456".to_string()),
        );

        assert!(
            provider.delete_txt(&handle).await.is_err(),
            "a 500 from the API is not a successful cleanup"
        );
        assert!(
            provider.delete_txt(&handle).await.is_err(),
            "the second attempt must still know about the record"
        );
        assert_eq!(
            deletes.load(Ordering::SeqCst),
            2,
            "the record was forgotten after the first failure, so the remote copy \
             would be orphaned"
        );
    }

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
