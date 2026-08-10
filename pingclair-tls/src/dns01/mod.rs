// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📡 Answering the DNS-01 challenge.
//!
//! DNS-01 is the only ACME challenge that can prove control of a wildcard
//! name, which is the whole reason it is worth the machinery: `*.example.com`
//! cannot be issued any other way. The price is that proving control means
//! writing a record into someone else's DNS, waiting for it to be visible, and
//! then taking it away again — three steps that HTTP-01 collapses into
//! "serve a file".
//!
//! The split here follows those steps:
//!
//! - [`DnsProvider`] is the only part that knows an API. One method publishes a
//!   TXT record and one removes it, and everything provider-specific — auth,
//!   zone discovery, record identifiers — stays behind that line.
//! - [`Dns01Handler`] is the ACME side. It turns a challenge into a record
//!   name and value, waits for propagation, and guarantees the record is
//!   removed afterwards.
//!
//! 🐢 None of this is on a request path. It runs at issuance and at renewal,
//! minutes apart at best, so it is written to be obvious rather than fast —
//! the propagation wait alone is measured in tens of seconds.

pub mod cloudflare;

use crate::acme::{AcmeError, ChallengeHandler, ChallengeResponse, ChallengeType};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// 🎫 What a provider hands back so the record can be found again to delete it.
///
/// Opaque on purpose: Cloudflare needs a zone id and a record id, another
/// provider will need something else, and the handler should never learn the
/// difference.
pub type RecordHandle = String;

/// 📡 Somewhere TXT records can be published.
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// 🏷️ The provider's name as it is written in a configuration.
    fn name(&self) -> &'static str;

    /// ✍️ Publishes `value` as a TXT record at `fqdn`, replacing any record
    /// this provider previously wrote there.
    ///
    /// Replacing rather than appending matters: a retried issuance would
    /// otherwise leave two challenge records, and some CAs treat a name with
    /// several TXT values as ambiguous.
    async fn upsert_txt(
        &self,
        fqdn: &str,
        value: &str,
        ttl_secs: u64,
    ) -> Result<RecordHandle, DnsError>;

    /// 🧹 Removes a record published by [`DnsProvider::upsert_txt`].
    async fn delete_txt(&self, handle: &RecordHandle) -> Result<(), DnsError>;
}

/// 🚫 Everything that can go wrong between here and a DNS zone.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("DNS provider request failed: {0}")]
    Transport(String),
    #[error("DNS provider rejected the request: {0}")]
    Api(String),
    #[error("no zone in the account covers {0}")]
    ZoneNotFound(String),
    #[error("DNS provider configuration is unusable: {0}")]
    Config(String),
}

/// ⏱️ How long to wait, and how patiently, for a record to become visible.
#[derive(Debug, Clone)]
pub struct PropagationPolicy {
    /// ⏳ A flat wait before checking anything. Some providers accept a record
    /// and serve it seconds later, and checking during that window only
    /// produces confusing negatives.
    pub delay: Duration,
    /// ⌛ How long to keep checking before giving up.
    pub timeout: Duration,
    /// 🔎 Authoritative-ish resolvers to ask. Empty means "do not check" —
    /// the flat delay is then the whole guarantee.
    pub resolvers: Vec<String>,
    /// 🕰️ The TTL published on the record.
    pub ttl_secs: u64,
}

impl Default for PropagationPolicy {
    fn default() -> Self {
        Self {
            // 🐢 Upstream's defaults. They look generous because DNS is: a
            // provider that has accepted a write is not a provider that is
            // serving it yet.
            delay: Duration::ZERO,
            timeout: Duration::from_secs(120),
            resolvers: Vec::new(),
            ttl_secs: 60,
        }
    }
}

/// 📡 The ACME side of DNS-01.
pub struct Dns01Handler {
    provider: Arc<dyn DnsProvider>,
    policy: PropagationPolicy,
    /// 🎫 Records this handler published, so cleanup can find them.
    ///
    /// Keyed by the record name rather than the challenge token: the token is
    /// what ACME calls it, but the record name is what has to be deleted, and
    /// a retried order reuses the name with a new token.
    deployed: Mutex<HashMap<String, RecordHandle>>,
}

impl Dns01Handler {
    pub fn new(provider: Arc<dyn DnsProvider>, policy: PropagationPolicy) -> Self {
        Self {
            provider,
            policy,
            deployed: Mutex::new(HashMap::new()),
        }
    }

    /// 🏷️ The record name a challenge for `domain` is written to.
    ///
    /// A wildcard proves control of the parent, so `*.example.com` and
    /// `example.com` share one challenge record — which is also why an order
    /// covering both must not delete the record after the first authorization.
    pub fn challenge_name(domain: &str) -> String {
        let base = domain.strip_prefix("*.").unwrap_or(domain);
        format!("_acme-challenge.{base}")
    }
}

#[async_trait]
impl ChallengeHandler for Dns01Handler {
    async fn deploy(&self, challenge: &ChallengeResponse) -> Result<(), AcmeError> {
        if challenge.challenge_type != ChallengeType::Dns01 {
            return Err(AcmeError::ChallengeFailed(format!(
                "the DNS-01 handler was given a {:?} challenge",
                challenge.challenge_type
            )));
        }

        let name = Self::challenge_name(&challenge.domain);
        let handle = self
            .provider
            .upsert_txt(&name, &challenge.key_authorization, self.policy.ttl_secs)
            .await
            .map_err(|error| AcmeError::ChallengeFailed(error.to_string()))?;
        self.deployed.lock().insert(name.clone(), handle);

        tracing::info!(
            "📡 Published the DNS-01 record for {} via {}",
            name,
            self.provider.name()
        );

        if !self.policy.delay.is_zero() {
            tracing::info!(
                "⏳ Waiting {:?} before checking DNS-01 propagation for {}",
                self.policy.delay,
                name
            );
            tokio::time::sleep(self.policy.delay).await;
        }

        wait_for_propagation(&name, &challenge.key_authorization, &self.policy).await
    }

    /// 🚫 DNS-01 has no token for anyone to fetch over HTTP.
    ///
    /// The trait carries this because the HTTP-01 handler doubles as the
    /// store the `/.well-known/acme-challenge/` route reads. Answering
    /// anything here would mean a DNS-01 deployment could be satisfied by
    /// serving a file, which is a different proof entirely.
    fn get_token(&self, _token: &str) -> Option<String> {
        None
    }

    async fn cleanup(&self, challenge: &ChallengeResponse) -> Result<(), AcmeError> {
        let name = Self::challenge_name(&challenge.domain);
        let Some(handle) = self.deployed.lock().remove(&name) else {
            return Ok(());
        };
        self.provider
            .delete_txt(&handle)
            .await
            .map_err(|error| AcmeError::ChallengeFailed(error.to_string()))?;
        tracing::info!("🧹 Removed the DNS-01 record for {}", name);
        Ok(())
    }
}

/// 🔎 Waits until the configured resolvers can see the record.
///
/// With no resolvers configured this returns immediately, and the flat delay
/// above is the whole guarantee — which is upstream's behaviour too. The check
/// exists because the alternative is handing the CA a name it cannot resolve
/// yet and burning one of the account's validation failures on a race.
async fn wait_for_propagation(
    name: &str,
    expected: &str,
    policy: &PropagationPolicy,
) -> Result<(), AcmeError> {
    if policy.resolvers.is_empty() {
        return Ok(());
    }

    let deadline = tokio::time::Instant::now() + policy.timeout;
    let mut attempt = 0u32;
    loop {
        match resolve_txt(name, &policy.resolvers).await {
            Ok(values) if values.iter().any(|value| value == expected) => {
                tracing::info!("👍 DNS-01 record for {} is visible", name);
                return Ok(());
            }
            Ok(_) => {}
            Err(error) => {
                tracing::debug!(
                    "🔎 DNS-01 lookup for {} did not answer yet: {}",
                    name,
                    error
                );
            }
        }

        if tokio::time::Instant::now() >= deadline {
            return Err(AcmeError::ChallengeFailed(format!(
                "the DNS-01 record for {name} was not visible to {} after {:?}; \
                 raise `propagation_timeout` if this provider is slow",
                policy.resolvers.join(", "),
                policy.timeout
            )));
        }

        // 🐢 A fixed two-second poll rather than a backoff. The whole window is
        // bounded by `propagation_timeout`, and a backoff would spend most of a
        // two-minute budget asleep past the moment the record appeared.
        attempt += 1;
        tracing::debug!("⏳ DNS-01 propagation check {} for {}", attempt, name);
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// 🔎 Asks the named resolvers for the TXT values at `name`.
///
/// Built per check rather than once: propagation checking happens a handful of
/// times per certificate, minutes apart, and a resolver held across renewals
/// would cache the very negative answer this is waiting to stop seeing.
async fn resolve_txt(name: &str, resolvers: &[String]) -> Result<Vec<String>, String> {
    use hickory_resolver::TokioAsyncResolver;
    use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};

    let mut config = ResolverConfig::new();
    for resolver in resolvers {
        // 🔌 A bare address means port 53; an explicit port is honoured so an
        // operator can point the check at a local authoritative server.
        let address: std::net::SocketAddr = match resolver.parse() {
            Ok(address) => address,
            Err(_) => match resolver.parse::<std::net::IpAddr>() {
                Ok(ip) => std::net::SocketAddr::new(ip, 53),
                Err(error) => {
                    return Err(format!("resolver `{resolver}` is not an address: {error}"));
                }
            },
        };
        config.add_name_server(NameServerConfig::new(address, Protocol::Udp));
    }

    let mut options = ResolverOpts::default();
    // 🚫 No cache. The point of the check is to observe a change, and a cached
    // NXDOMAIN would hide it for the whole propagation window.
    options.cache_size = 0;
    let resolver = TokioAsyncResolver::tokio(config, options);

    let lookup = resolver
        .txt_lookup(format!("{name}."))
        .await
        .map_err(|error| error.to_string())?;
    Ok(lookup
        .iter()
        .map(|txt| {
            let joined: Vec<u8> = txt
                .txt_data()
                .iter()
                .flat_map(|chunk| chunk.iter().copied())
                .collect();
            String::from_utf8_lossy(&joined).into_owned()
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🏷️ A wildcard proves control of its parent, so both names have to reach
    /// the same record — writing `_acme-challenge.*.example.com` would be a
    /// name no zone can hold.
    #[test]
    fn a_wildcard_and_its_parent_share_one_record_name() {
        assert_eq!(
            Dns01Handler::challenge_name("*.example.com"),
            "_acme-challenge.example.com"
        );
        assert_eq!(
            Dns01Handler::challenge_name("example.com"),
            "_acme-challenge.example.com"
        );
    }
}
