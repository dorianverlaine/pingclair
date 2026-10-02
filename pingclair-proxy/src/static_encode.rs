// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🎯 Static representation selection sees the transport's final header policy.

use crate::http_policy::{ResponseHeaderPolicy, StrictTransport};
use crate::server::{PingclairProxy, ProxyState};

/// 🎯 Applies policy to identity metadata before the file server chooses a coding.
pub(crate) fn apply_policy(
    policy: &ResponseHeaderPolicy,
    state: &ProxyState,
    request_id: &http::HeaderValue,
    encrypted: bool,
    status: u16,
    headers: &mut http::HeaderMap,
) -> bool {
    let Ok(response) = http::Response::builder().status(status).body(()) else {
        return false;
    };
    let (mut parts, ()) = response.into_parts();
    parts.headers = std::mem::take(headers);
    let mut response = pingora_http::ResponseHeader::from(parts);
    let applied = policy
        .apply_pingora(&mut response, request_id, None)
        .and_then(|()| PingclairProxy::apply_security_response_headers(&mut response, state))
        .and_then(|()| {
            StrictTransport::apply_pingora(Some(&state.strict_transport), &mut response, encrypted)
        });
    let parts: http::response::Parts = response.into();
    *headers = parts.headers;
    applied.is_ok()
}
