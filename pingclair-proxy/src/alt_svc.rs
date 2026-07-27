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

use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora_core::modules::http::{HttpModule, HttpModuleBuilder, Module};
use pingora_http::ResponseHeader;

/// Format the `Alt-Svc` header value advertising HTTP/3 on `port`.
pub fn alt_svc_value(port: u16) -> String {
    format!("h3=\":{port}\"; ma=86400")
}

/// Builds a per-request [`AltSvcModule`]. One builder per Pingora service;
/// the shared `ArcSwap` slot lets the value be flipped at runtime (e.g. on
/// hot reload) without rebuilding the service.
pub struct AltSvcModuleBuilder {
    value: Arc<ArcSwap<Option<String>>>,
}

impl AltSvcModuleBuilder {
    pub fn new(value: Arc<ArcSwap<Option<String>>>) -> Self {
        Self { value }
    }
}

impl HttpModuleBuilder for AltSvcModuleBuilder {
    fn init(&self) -> Module {
        Box::new(AltSvcModule {
            value: self.value.clone(),
        })
    }
}

/// Per-request module that appends `Alt-Svc` to the response header when a
/// value is configured for the listener.
pub struct AltSvcModule {
    value: Arc<ArcSwap<Option<String>>>,
}

#[async_trait]
impl HttpModule for AltSvcModule {
    async fn response_header_filter(
        &mut self,
        resp: &mut ResponseHeader,
        _end_of_stream: bool,
    ) -> pingora_core::Result<()> {
        let value = self.value.load();
        if let Some(v) = value.as_ref() {
            resp.insert_header("Alt-Svc", v.as_str())?;
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

    fn module_with(value: Option<String>) -> AltSvcModule {
        AltSvcModule {
            value: Arc::new(ArcSwap::from_pointee(value)),
        }
    }

    #[test]
    fn alt_svc_value_format() {
        assert_eq!(alt_svc_value(443), "h3=\":443\"; ma=86400");
        assert_eq!(alt_svc_value(8443), "h3=\":8443\"; ma=86400");
    }

    #[tokio::test]
    async fn adds_alt_svc_header_when_configured() {
        let mut module = module_with(Some(alt_svc_value(443)));
        let mut resp = ResponseHeader::build(200, None).unwrap();

        module
            .response_header_filter(&mut resp, false)
            .await
            .unwrap();

        let header = resp
            .headers
            .get("alt-svc")
            .expect("Alt-Svc header must be present");
        assert_eq!(header.to_str().unwrap(), "h3=\":443\"; ma=86400");
    }

    #[tokio::test]
    async fn no_alt_svc_header_when_not_configured() {
        let mut module = module_with(None);
        let mut resp = ResponseHeader::build(200, None).unwrap();

        module
            .response_header_filter(&mut resp, false)
            .await
            .unwrap();

        assert!(resp.headers.get("alt-svc").is_none());
    }

    #[tokio::test]
    async fn reflects_runtime_updates_to_the_shared_slot() {
        // The builder and module share the ArcSwap slot, so flipping the
        // value after the module is built must take effect immediately —
        // this is what hot-reload relies on.
        let slot = Arc::new(ArcSwap::from_pointee(None));
        let builder = AltSvcModuleBuilder::new(slot.clone());
        let mut module = builder.init();

        let mut resp = ResponseHeader::build(200, None).unwrap();
        module
            .response_header_filter(&mut resp, false)
            .await
            .unwrap();
        assert!(resp.headers.get("alt-svc").is_none());

        slot.store(Arc::new(Some(alt_svc_value(443))));

        let mut resp = ResponseHeader::build(200, None).unwrap();
        module
            .response_header_filter(&mut resp, false)
            .await
            .unwrap();
        assert!(resp.headers.get("alt-svc").is_some());
    }
}
