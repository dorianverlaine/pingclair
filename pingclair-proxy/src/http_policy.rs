// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use http::{HeaderMap, Method};
use pingora_core::Result as PingoraResult;
use pingora_http::ResponseHeader;
use regex::Regex;

/// 🌐 Extracts a hostname from HTTP authority syntax without breaking IPv6 literals.
pub(crate) fn authority_host(authority: &str) -> &str {
    if let Some(bracketed) = authority.strip_prefix('[') {
        return bracketed
            .split_once(']')
            .map_or(authority, |(host, _)| host);
    }
    if authority.bytes().filter(|byte| *byte == b':').count() > 1 {
        return authority;
    }
    authority
        .rsplit_once(':')
        .filter(|(_, port)| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
        .map_or(authority, |(host, _)| host)
}

/// 🧭 Stores transport-neutral downstream header mutations in execution order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ResponseHeaderPolicy {
    set: HashMap<String, String>,
    add: Vec<(String, String)>,
    remove: Vec<String>,
    suppress_server: bool,
}

impl ResponseHeaderPolicy {
    /// 📝 Replaces a downstream header with one normalized value.
    pub(crate) fn set(&mut self, name: impl AsRef<str>, value: impl Into<String>) {
        self.set
            .insert(name.as_ref().to_ascii_lowercase(), value.into());
    }

    /// ➕ Appends one downstream header value after replacement mutations.
    pub(crate) fn add(&mut self, name: impl AsRef<str>, value: impl Into<String>) {
        self.add
            .push((name.as_ref().to_ascii_lowercase(), value.into()));
    }

    /// 🧹 Removes a downstream header after every set and append mutation.
    pub(crate) fn remove(&mut self, name: impl AsRef<str>) {
        let name = name.as_ref().to_ascii_lowercase();
        if name == "server" {
            self.suppress_server = true;
        }
        if !self.remove.iter().any(|existing| existing == &name) {
            self.remove.push(name);
        }
    }

    /// 🧩 Adds proxy-owned replacements without overriding outer middleware.
    pub(crate) fn merge_proxy_set(&mut self, headers: &HashMap<String, String>) {
        for (name, value) in headers {
            self.set
                .entry(name.to_ascii_lowercase())
                .or_insert_with(|| value.clone());
        }
    }

    /// 🔗 Merges a middleware decision into the active response policy.
    pub(crate) fn merge(&mut self, other: ResponseHeaderPolicy) {
        self.set.extend(other.set);
        self.add.extend(other.add);
        for name in other.remove {
            self.remove(name);
        }
        self.suppress_server |= other.suppress_server;
    }

    /// 🍎 Applies the shared policy to a Pingora response.
    pub(crate) fn apply_pingora(
        &self,
        response: &mut ResponseHeader,
        request_id: &str,
    ) -> PingoraResult<()> {
        for (name, value) in &self.set {
            response.insert_header(name.clone(), value.as_str())?;
        }
        for (name, value) in &self.add {
            response.append_header(name.clone(), value.as_str())?;
        }
        for name in &self.remove {
            let _ = response.remove_header(name);
        }
        if self.suppress_server {
            let _ = response.remove_header("server");
        } else {
            response.insert_header("server", "Pingclair")?;
        }
        response.insert_header("x-request-id", request_id)?;
        Ok(())
    }

    /// 🌐 Exposes normalized set mutations to protocol adapters.
    pub(crate) fn set_headers(&self) -> impl Iterator<Item = (&str, &str)> {
        self.set
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    /// 🌐 Exposes normalized append mutations to protocol adapters.
    pub(crate) fn add_headers(&self) -> impl Iterator<Item = (&str, &str)> {
        self.add
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    /// 🌐 Exposes normalized removals to protocol adapters.
    pub(crate) fn removed_headers(&self) -> impl Iterator<Item = &str> {
        self.remove.iter().map(String::as_str)
    }

    /// 🌐 Reports whether middleware suppresses the default server header.
    pub(crate) fn suppresses_server(&self) -> bool {
        self.suppress_server
    }
}

/// 🌍 Describes the transport-neutral result of one CORS middleware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CorsDecision {
    PassThrough,
    Continue(ResponseHeaderPolicy),
    Respond {
        status: u16,
        body: &'static str,
        headers: ResponseHeaderPolicy,
    },
}

/// 🌍 Evaluates CORS without depending on Pingora sessions or QUIC streams.
#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_cors(
    method: &Method,
    headers: &HeaderMap,
    allowed_origins: &[String],
    allowed_methods: &[String],
    allowed_headers: &[String],
    exposed_headers: &[String],
    allow_credentials: bool,
    max_age: u64,
) -> CorsDecision {
    let Some(origin) = headers
        .get("origin")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
    else {
        return CorsDecision::PassThrough;
    };

    let wildcard_origin = allowed_origins.iter().any(|value| value == "*");
    let origin_allowed = allowed_origins.is_empty()
        || wildcard_origin
        || allowed_origins.iter().any(|value| value == origin);
    if !origin_allowed {
        return CorsDecision::PassThrough;
    }

    let allow_origin = if wildcard_origin && !allow_credentials {
        "*"
    } else {
        origin
    };

    if method == Method::OPTIONS && headers.contains_key("access-control-request-method") {
        let requested_method = headers
            .get("access-control-request-method")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        if !allowed_methods.is_empty()
            && !allowed_methods
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(requested_method))
        {
            return CorsDecision::Respond {
                status: 403,
                body: "CORS method not allowed",
                headers: ResponseHeaderPolicy::default(),
            };
        }

        let requested_headers = headers
            .get("access-control-request-headers")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        let headers_allowed = allowed_headers.iter().any(|header| header == "*")
            || requested_headers
                .split(',')
                .map(str::trim)
                .filter(|header| !header.is_empty())
                .all(|requested| {
                    allowed_headers
                        .iter()
                        .any(|allowed| allowed.eq_ignore_ascii_case(requested))
                });
        if !headers_allowed {
            return CorsDecision::Respond {
                status: 403,
                body: "CORS header not allowed",
                headers: ResponseHeaderPolicy::default(),
            };
        }

        let mut policy = ResponseHeaderPolicy::default();
        policy.set("access-control-allow-origin", allow_origin);
        policy.set("access-control-allow-methods", allowed_methods.join(", "));
        policy.set("access-control-allow-headers", allowed_headers.join(", "));
        policy.set("access-control-max-age", max_age.to_string());
        if allow_credentials {
            policy.set("access-control-allow-credentials", "true");
        }
        if !exposed_headers.is_empty() {
            policy.set("access-control-expose-headers", exposed_headers.join(", "));
        }
        policy.add("vary", "Origin");
        return CorsDecision::Respond {
            status: 204,
            body: "",
            headers: policy,
        };
    }

    let mut policy = ResponseHeaderPolicy::default();
    policy.set("access-control-allow-origin", allow_origin);
    policy.add("vary", "Origin");
    if allow_credentials {
        policy.set("access-control-allow-credentials", "true");
    }
    if !exposed_headers.is_empty() {
        policy.set("access-control-expose-headers", exposed_headers.join(", "));
    }
    CorsDecision::Continue(policy)
}

/// 🕰️ Captures one process-wide timestamp instead of reading the clock per request.
static REQUEST_ID_EPOCH_US: OnceLock<u64> = OnceLock::new();

/// 🔢 Provides a lock-free process-local sequence for request identifiers.
static REQUEST_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// 🪪 Generates a compact request identifier shared by every HTTP transport.
pub(crate) fn generate_request_id() -> String {
    let epoch = *REQUEST_ID_EPOCH_US.get_or_init(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64
    });
    let sequence = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{epoch:x}-{sequence:x}")
}

/// 🛡️ Accepts only bounded visible ASCII request identifiers.
pub(crate) fn sanitize_request_id(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return None;
    }
    if trimmed.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        Some(trimmed.to_string())
    } else {
        None
    }
}

/// 🪪 Adopts a safe client identifier or creates a process-local fallback.
pub(crate) fn resolve_request_id(raw: Option<&str>) -> String {
    raw.and_then(sanitize_request_id)
        .unwrap_or_else(generate_request_id)
}

/// 🧭 Rewrites one URI while preserving the original query when appropriate.
pub(crate) fn rewrite_uri(
    current: &str,
    strip_prefix: Option<&str>,
    strip_suffix: Option<&str>,
    replace: Option<&str>,
    regex: Option<&Regex>,
    regex_replace: Option<&str>,
) -> String {
    let (path, query) = current.split_once('?').unwrap_or((current, ""));
    let mut rewritten = path.to_string();

    if let Some(prefix) = strip_prefix
        && let Some(rest) = rewritten.strip_prefix(prefix)
    {
        rewritten = if rest.is_empty() {
            "/".to_string()
        } else if rest.starts_with('/') {
            rest.to_string()
        } else {
            format!("/{rest}")
        };
    }
    if let Some(suffix) = strip_suffix
        && let Some(rest) = rewritten.strip_suffix(suffix)
    {
        rewritten = if rest.is_empty() {
            "/".to_string()
        } else {
            rest.to_string()
        };
    }
    if let Some(replacement) = replace {
        rewritten = replacement.to_string();
    }
    if let Some(regex) = regex {
        rewritten = regex
            .replace_all(&rewritten, regex_replace.unwrap_or(""))
            .into_owned();
    }
    if !rewritten.starts_with('/') {
        rewritten.insert(0, '/');
    }
    if rewritten.contains('?') || query.is_empty() {
        rewritten
    } else {
        format!("{rewritten}?{query}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cors_preflight_rejects_disallowed_methods() {
        let mut headers = HeaderMap::new();
        headers.insert("origin", "https://app.example".parse().unwrap());
        headers.insert("access-control-request-method", "DELETE".parse().unwrap());

        let decision = evaluate_cors(
            &Method::OPTIONS,
            &headers,
            &["https://app.example".to_string()],
            &["GET".to_string()],
            &["content-type".to_string()],
            &[],
            false,
            600,
        );
        assert!(matches!(
            decision,
            CorsDecision::Respond {
                status: 403,
                body: "CORS method not allowed",
                ..
            }
        ));
    }

    #[test]
    fn cors_simple_request_builds_shared_response_policy() {
        let mut headers = HeaderMap::new();
        headers.insert("origin", "https://app.example".parse().unwrap());

        let decision = evaluate_cors(
            &Method::GET,
            &headers,
            &["https://app.example".to_string()],
            &["GET".to_string()],
            &[],
            &["x-request-id".to_string()],
            true,
            600,
        );
        let CorsDecision::Continue(policy) = decision else {
            panic!("expected a continuing CORS policy");
        };
        assert_eq!(
            policy
                .set_headers()
                .collect::<HashMap<&str, &str>>()
                .get("access-control-allow-origin"),
            Some(&"https://app.example")
        );
    }

    #[test]
    fn rewrite_preserves_query_and_capture_groups() {
        let regex = Regex::new(r"^/old/(.*)$").unwrap();
        assert_eq!(
            rewrite_uri(
                "/old/path?q=1",
                None,
                None,
                None,
                Some(&regex),
                Some("/new/$1"),
            ),
            "/new/path?q=1"
        );
    }

    #[test]
    fn repeated_append_mutations_preserve_every_value() {
        let mut policy = ResponseHeaderPolicy::default();
        policy.add("vary", "Origin");
        policy.add("vary", "Accept-Encoding");
        assert_eq!(
            policy.add_headers().collect::<Vec<_>>(),
            vec![("vary", "Origin"), ("vary", "Accept-Encoding")]
        );
    }

    #[test]
    fn authority_host_supports_ports_and_bracketed_ipv6() {
        assert_eq!(authority_host("example.com:8443"), "example.com");
        assert_eq!(authority_host("example.com"), "example.com");
        assert_eq!(authority_host("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(authority_host("2001:db8::1"), "2001:db8::1");
    }
}
