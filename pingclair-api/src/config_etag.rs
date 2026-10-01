// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🏷️ Config validators identify both the subtree and its serialized contents.

use bytes::Bytes;
use http_body_util::Full;
use hyper::Response;
use serde_json::Value;

pub(super) fn etag(path: &str, node: &Value) -> String {
    let json = serde_json::to_vec(node).expect("JSON values serialize");
    let hash = boring::sha::sha256(&json);
    let mut tag = format!("\"{path} ");
    use std::fmt::Write;
    for byte in hash {
        write!(tag, "{byte:02x}").expect("strings accept formatting");
    }
    tag.push('"');
    tag
}

pub(super) fn config_response(path: &str, node: &Value) -> Response<Full<Bytes>> {
    Response::builder()
        .header(hyper::header::ETAG, etag(path, node))
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(
            serde_json::to_string_pretty(node).expect("JSON values serialize"),
        )))
        .expect("config response is valid")
}
