// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Alt-Svc advertisement for HTTP/3 discovery.
//!
//! When HTTP/3 (QUIC) is enabled on an HTTPS listener, clients have no way
//! to learn about it from a plain HTTPS response unless the server says so.
//! The standard mechanism is the `Alt-Svc` response header
//! (`h3=":PORT"; ma=86400`). This module is registered as a Pingora
//! *downstream* module, so the header is added to every response written
//! through the listener — locally generated responses (static files,
//! `respond`, error pages) and upstream-proxied ones alike. Plain-HTTP
//! listeners never register a value, so they never emit the header.
//!
//! 🚫 One listener can serve several sites, and a site with `tls { http3 off }`
//! must not be advertised: its QUIC handshake is refused on purpose, and a
//! client that cached the claim would retry that doomed handshake on every new
//! connection for a day. The advertisement therefore carries the opted-out
//! names, matched by the same rule the HTTP/3 certificate table uses to refuse
//! them, so "is this name served over QUIC" has one answer on both sides.

use std::collections::HashSet;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use http::HeaderValue;
use pingora_core::modules::http::{HttpModule, HttpModuleBuilder, Module};
use pingora_http::{RequestHeader, ResponseHeader};

/// Format the `Alt-Svc` header value advertising HTTP/3 on `port`.
pub fn alt_svc_value(port: u16) -> String {
    format!("h3=\":{port}\"; ma=86400")
}

/// 📣 What one listener advertises, decided at startup.
///
/// 🏎️ The header value is built once, so a response only bumps a reference
/// count. The excluded set is empty on most deployments, and then the request
/// host is never even looked at.
pub struct Advertisement {
    value: HeaderValue,
    /// 🚫 Canonical names (and `*.suffix` patterns) that stay off HTTP/3.
    excluded: HashSet<String>,
}

impl Advertisement {
    /// 📣 Advertises HTTP/3 on `port` for every name except `excluded`.
    pub fn new<I, S>(port: u16, excluded: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            value: HeaderValue::try_from(alt_svc_value(port))
                .expect("a formatted port is always a valid header value"),
            // 🔤 Normalized exactly as the certificate table normalizes its
            // exclusions, so `Opted-Out.example.` and a request for
            // `opted-out.example` agree.
            excluded: excluded
                .into_iter()
                .map(|name| crate::quic::certificate_name(name.as_ref()).into_owned())
                .collect(),
        }
    }

    /// 🧭 The value to send for a request, or `None` for an opted-out name.
    fn value_for(&self, request: &RequestHeader) -> Option<&HeaderValue> {
        if self.excluded.is_empty() {
            return Some(&self.value);
        }
        let host = crate::http_policy::request_host(crate::http_policy::request_authority(request));
        (!crate::quic::covered_by(&self.excluded, &host)).then_some(&self.value)
    }
}

/// Builds a per-request [`AltSvcModule`]. One builder per Pingora service;
/// the shared `ArcSwap` slot lets the value be flipped at runtime (e.g. on
/// hot reload) without rebuilding the service.
pub struct AltSvcModuleBuilder {
    value: Arc<ArcSwap<Option<Advertisement>>>,
}

impl AltSvcModuleBuilder {
    pub fn new(value: Arc<ArcSwap<Option<Advertisement>>>) -> Self {
        Self { value }
    }
}

impl HttpModuleBuilder for AltSvcModuleBuilder {
    fn init(&self) -> Module {
        Box::new(AltSvcModule {
            value: self.value.clone(),
            decision: Decision::Undecided,
        })
    }
}

/// 🧭 What the request half of the module decided for the response half.
enum Decision {
    /// 📌 No request header was seen, e.g. an error written before parsing
    /// finished; the response half falls back to the listener-wide value
    /// only when no name on the listener is opted out.
    Undecided,
    Advertise(HeaderValue),
    Silent,
}

/// Per-request module that appends `Alt-Svc` to the response header when a
/// value is configured for the listener and the requested name is not
/// opted out of HTTP/3.
pub struct AltSvcModule {
    value: Arc<ArcSwap<Option<Advertisement>>>,
    decision: Decision,
}

#[async_trait]
impl HttpModule for AltSvcModule {
    async fn request_header_filter(&mut self, req: &mut RequestHeader) -> pingora_core::Result<()> {
        // 🏎️ The one snapshot load per request happens here, where the host
        // is visible; cloning a `HeaderValue` is a reference-count bump.
        let advertisement = self.value.load();
        self.decision = match Option::as_ref(&advertisement).and_then(|a| a.value_for(req)) {
            Some(value) => Decision::Advertise(value.clone()),
            None => Decision::Silent,
        };
        Ok(())
    }

    async fn response_header_filter(
        &mut self,
        resp: &mut ResponseHeader,
        _end_of_stream: bool,
    ) -> pingora_core::Result<()> {
        // 📌 Read by reference: an interim `100 Continue` passes through here
        // too, and the final response must still get the same answer.
        match &self.decision {
            Decision::Advertise(value) => {
                resp.insert_header("Alt-Svc", value.clone())?;
            }
            Decision::Silent => {}
            Decision::Undecided => {
                // 🚫 Without a host the answer is only safe when no site on
                // this listener opted out.
                let advertisement = self.value.load();
                if let Some(advertisement) = Option::as_ref(&advertisement)
                    && advertisement.excluded.is_empty()
                {
                    resp.insert_header("Alt-Svc", advertisement.value.clone())?;
                }
            }
        }
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot_with(value: Option<Advertisement>) -> Arc<ArcSwap<Option<Advertisement>>> {
        Arc::new(ArcSwap::from_pointee(value))
    }

    /// 🧪 Runs one request for `host` through a fresh module and returns the
    /// `Alt-Svc` it wrote, if any.
    async fn alt_svc_for(slot: &Arc<ArcSwap<Option<Advertisement>>>, host: &str) -> Option<String> {
        let mut module = AltSvcModuleBuilder::new(slot.clone()).init();
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("Host", host).unwrap();
        module.request_header_filter(&mut req).await.unwrap();
        let mut resp = ResponseHeader::build(200, None).unwrap();
        module
            .response_header_filter(&mut resp, false)
            .await
            .unwrap();
        resp.headers
            .get("alt-svc")
            .map(|value| value.to_str().unwrap().to_owned())
    }

    #[test]
    fn alt_svc_value_format() {
        assert_eq!(alt_svc_value(443), "h3=\":443\"; ma=86400");
        assert_eq!(alt_svc_value(8443), "h3=\":8443\"; ma=86400");
    }

    #[tokio::test]
    async fn adds_alt_svc_header_when_configured() {
        let slot = slot_with(Some(Advertisement::new(443, [] as [&str; 0])));
        assert_eq!(
            alt_svc_for(&slot, "a.example").await.as_deref(),
            Some("h3=\":443\"; ma=86400")
        );
    }

    #[tokio::test]
    async fn no_alt_svc_header_when_not_configured() {
        assert_eq!(alt_svc_for(&slot_with(None), "a.example").await, None);
    }

    /// 🚫 An opted-out name is silent in any DNS spelling; its neighbours,
    /// including a sibling of a wildcard, keep the advertisement.
    #[tokio::test]
    async fn opted_out_names_are_not_advertised() {
        let slot = slot_with(Some(Advertisement::new(
            443,
            ["Off.example", "*.wild.example"],
        )));
        assert_eq!(alt_svc_for(&slot, "off.example").await, None);
        assert_eq!(alt_svc_for(&slot, "OFF.example.:443").await, None);
        assert_eq!(alt_svc_for(&slot, "a.wild.example").await, None);
        assert!(alt_svc_for(&slot, "on.example").await.is_some());
        assert!(alt_svc_for(&slot, "wild.example").await.is_some());
    }

    #[tokio::test]
    async fn reflects_runtime_updates_to_the_shared_slot() {
        // 🔁 The builder and module share the ArcSwap slot, so flipping the
        // value after the module is built must take effect immediately —
        // this is what hot-reload and QUIC shutdown rely on.
        let slot = slot_with(None);
        assert_eq!(alt_svc_for(&slot, "a.example").await, None);
        slot.store(Arc::new(Some(Advertisement::new(443, [] as [&str; 0]))));
        assert!(alt_svc_for(&slot, "a.example").await.is_some());
    }
}
