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
use pingora_http::ResponseHeader;

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

/// 🔍 Yields every comma-separated token of every `name` field line,
/// trimmed, without allocating.
///
/// 📌 A list-valued field may arrive as several lines or as one line with
/// commas; both spellings mean the same list (RFC 9110 §5.3), so every
/// question about such a field has to read all of them.
fn field_tokens<'a>(header: &'a ResponseHeader, name: &'a str) -> impl Iterator<Item = &'a str> {
    header
        .headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
}

/// 🧊 Adds `Accept-Encoding` to the response's `Vary` without disturbing what
/// is already there.
///
/// 🛡️ Replacing the field instead erased `Vary: Origin` from a CORS response
/// and `Vary: Cookie` from a personalised one. A shared cache then keyed the
/// stored copy on the coding alone and handed one user's response — or one
/// origin's CORS grant — to the next client that asked for the same coding.
/// `Vary: *` already says no two requests share a response, so it is left
/// alone, and a field that already names `Accept-Encoding` is not repeated.
pub(crate) fn vary_on_accept_encoding(header: &mut ResponseHeader) -> pingora_core::Result<()> {
    let covered = field_tokens(header, "vary")
        .any(|token| token == "*" || token.eq_ignore_ascii_case("accept-encoding"));
    if covered {
        return Ok(());
    }
    // 🔗 A second field line joins the existing list; no need to rebuild it.
    header.append_header("Vary", "Accept-Encoding")?;
    Ok(())
}

/// 📐 Whether this response carries a complete representation that the
/// proxy may re-encode for the client.
///
/// 🚫 A `206` or any response with `Content-Range` encloses a slice counted
/// in the origin's identity bytes (RFC 9110 §14.1.2). Compressing it keeps a
/// `Content-Range` that no longer describes the body, so a client splicing
/// ranges together writes the wrong bytes at the wrong offsets. `HEAD`,
/// `204` and `304` have no body to compress, and an informational response
/// only predicts the final one.
pub(crate) fn is_full_representation(method: &http::Method, header: &ResponseHeader) -> bool {
    let status = header.status;
    !(status.is_informational()
        || status == http::StatusCode::NO_CONTENT
        || status == http::StatusCode::PARTIAL_CONTENT
        || status == http::StatusCode::NOT_MODIFIED
        || *method == http::Method::HEAD
        || header.headers.contains_key(http::header::CONTENT_RANGE))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn response(vary: &[&str]) -> ResponseHeader {
        let mut header = ResponseHeader::build(200, None).unwrap();
        for value in vary {
            header.append_header("Vary", *value).unwrap();
        }
        header
    }

    fn vary_lines(header: &ResponseHeader) -> Vec<&str> {
        header
            .headers
            .get_all("vary")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect()
    }

    /// 🚫 Partial, bodiless and interim responses are never re-encoded.
    #[test]
    fn only_complete_bodies_are_rewritable() {
        let get = http::Method::GET;
        for (status, method, range, expected) in [
            (200, &get, false, true),
            (404, &get, false, true),
            (200, &get, true, false),
            (206, &get, true, false),
            (204, &get, false, false),
            (304, &get, false, false),
            (103, &get, false, false),
            (200, &http::Method::HEAD, false, false),
        ] {
            let mut header = ResponseHeader::build(status, None).unwrap();
            if range {
                header
                    .insert_header("Content-Range", "bytes 0-9/100")
                    .unwrap();
            }
            assert_eq!(
                is_full_representation(method, &header),
                expected,
                "{status} {method} range={range}"
            );
        }
    }

    /// 🛡️ Every rule the compressor has to respect when it announces that the
    /// response now varies by coding.
    #[test]
    fn vary_keeps_existing_members_and_never_repeats_accept_encoding() {
        let cases: [(&[&str], &[&str]); 6] = [
            (&[], &["Accept-Encoding"]),
            (&["Origin"], &["Origin", "Accept-Encoding"]),
            (&["Cookie, Origin"], &["Cookie, Origin", "Accept-Encoding"]),
            (
                &["Origin", "accept-encoding"],
                &["Origin", "accept-encoding"],
            ),
            (&["Origin, Accept-Encoding"], &["Origin, Accept-Encoding"]),
            (&["*"], &["*"]),
        ];
        for (before, after) in cases {
            let mut header = response(before);
            vary_on_accept_encoding(&mut header).unwrap();
            assert_eq!(vary_lines(&header), after, "starting from {before:?}");
        }
    }
}
