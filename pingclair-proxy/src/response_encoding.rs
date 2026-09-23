// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🗜️ Compresses H1/H2 response bodies as the very last step before the wire.
//!
//! The coding belongs to one client's response, not to the stored copy of
//! it. If compression runs before the cache stores the body — which is where
//! Pingora's upstream body filter sits — the store ends up holding gzip bytes
//! under the origin's identity headers, and the next client that never asked
//! for gzip is handed gzip.
//!
//! A Pingora *downstream module* runs after the cache on every path: fresh
//! upstream bodies, cache hits, and misses streamed back out of the cache
//! while they are still being written. It is also the only hook that sees
//! the `Done` task those cache paths use to end a body, so it is the only
//! place that can write the coding's trailer on them; `ProxyHttp`'s own
//! `response_body_filter` never hears about `Done`, and a gzip stream without
//! its trailer does not decode.
//!
//! 📌 The module does not decide anything. `response_filter` makes the
//! decision on the final response header, rewrites that header, and installs
//! the encoder here through [`install`]; the module only drives it.

use bytes::Bytes;
use pingora_core::modules::http::{HttpModule, HttpModuleBuilder, HttpModuleCtx, Module};

use crate::encoding::{ResponseEncoder, stream_chunk};

/// 🏗️ Registers one [`ResponseEncodingModule`] per downstream request.
pub struct ResponseEncodingModuleBuilder;

impl HttpModuleBuilder for ResponseEncodingModuleBuilder {
    fn init(&self) -> Module {
        Box::new(ResponseEncodingModule { encoder: None })
    }
}

/// 🌊 Holds the encoder the current response's header announced, if any.
pub struct ResponseEncodingModule {
    encoder: Option<ResponseEncoder>,
}

/// 🗜️ Hands `encoder` to this request's module, which compresses every body
/// chunk written after this point.
///
/// 🛡️ Call only after the response header has been rewritten to announce the
/// coding: the header and the body must describe the same bytes. Returns
/// `false` when the module is not registered, so the caller can leave the
/// header alone instead of announcing a coding nobody will apply.
pub(crate) fn install(modules: &mut HttpModuleCtx, encoder: ResponseEncoder) -> bool {
    match modules.get_mut::<ResponseEncodingModule>() {
        Some(module) => {
            module.encoder = Some(encoder);
            true
        }
        None => false,
    }
}

#[async_trait::async_trait]
impl HttpModule for ResponseEncodingModule {
    fn response_body_filter(
        &mut self,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> pingora_core::Result<()> {
        stream_chunk(&mut self.encoder, body, end_of_stream);
        Ok(())
    }

    /// 🧹 Writes the coding's trailer for bodies that end with `Done` rather
    /// than with a chunk flagged as the last one.
    fn response_done_filter(&mut self) -> pingora_core::Result<Option<Bytes>> {
        let mut tail = None;
        stream_chunk(&mut self.encoder, &mut tail, true);
        Ok(tail)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
