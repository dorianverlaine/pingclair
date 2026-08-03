// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
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

/// 🔀 The `Via` protocol-version token for one hop, per RFC 9110 §7.6.3.
///
/// The token describes the protocol the message was **received** over, not the
/// one it will leave by — which is why a proxy that takes HTTP/2 from a client
/// and speaks HTTP/1.1 upstream ends up writing `2.0` on the request and `1.1`
/// on the response. `protocol-name` is omitted because it defaults to HTTP.
pub(crate) fn via_version(version: http::Version) -> &'static str {
    match version {
        http::Version::HTTP_09 => "0.9",
        http::Version::HTTP_10 => "1.0",
        http::Version::HTTP_2 => "2.0",
        http::Version::HTTP_3 => "3.0",
        // HTTP_11 and anything a future http crate adds: 1.1 is the safe
        // reading, since Via is advisory and a wrong token is worse than a
        // conservative one.
        _ => "1.1",
    }
}

/// 🔀 This hop's `Via` field value, e.g. `1.1 Pingclair`.
///
/// The token only depends on the protocol version, so the five possible
/// values are `'static` — building a `String` per proxied request was pure
/// per-request allocation on the hot path.
pub(crate) fn via_value(version: http::Version) -> &'static str {
    match via_version(version) {
        "0.9" => "0.9 Pingclair",
        "1.0" => "1.0 Pingclair",
        "1.1" => "1.1 Pingclair",
        "2.0" => "2.0 Pingclair",
        "3.0" => "3.0 Pingclair",
        // `via_version` returns "1.1" for anything else; keep them in lockstep.
        _ => "1.1 Pingclair",
    }
}

/// 🧭 Stores transport-neutral downstream header mutations in execution order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ResponseHeaderPolicy {
    set: HashMap<String, String>,
    /// Precompiled header-name bytes for `set`: `Bytes` is the cheapest
    /// `IntoCaseHeaderName` input (clone is a shared-bytes reference bump),
    /// and building it once here keeps the per-request name path free of
    /// `String` clones and re-parses.
    set_names: HashMap<String, Bytes>,
    /// Precompiled `HeaderValue`s for `set`: cloning one is a shared-bytes
    /// reference bump, while re-parsing the stored string on every request
    /// copies the bytes. `None` means the configured value was not a valid
    /// header value, in which case the request-time error path is preserved.
    set_values: HashMap<String, Option<http::HeaderValue>>,
    add: Vec<(String, String)>,
    /// Precompiled header-name bytes for `add`, mirroring `set_names`.
    add_names: Vec<Bytes>,
    /// Precompiled `HeaderValue`s for `add`, mirroring `set_values`.
    add_values: Vec<(String, Option<http::HeaderValue>)>,
    remove: Vec<String>,
    suppress_server: bool,
    suppress_via: bool,
}

impl ResponseHeaderPolicy {
    /// 📝 Replaces a downstream header with one normalized value.
    pub(crate) fn set(&mut self, name: impl AsRef<str>, value: impl Into<String>) {
        let name = name.as_ref().to_ascii_lowercase();
        let value = value.into();
        self.set_names
            .insert(name.clone(), Bytes::copy_from_slice(name.as_bytes()));
        self.set_values
            .insert(name.clone(), http::HeaderValue::from_str(&value).ok());
        self.set.insert(name, value);
    }

    /// ➕ Appends one downstream header value after replacement mutations.
    pub(crate) fn add(&mut self, name: impl AsRef<str>, value: impl Into<String>) {
        let name = name.as_ref().to_ascii_lowercase();
        let value = value.into();
        self.add_names.push(Bytes::copy_from_slice(name.as_bytes()));
        self.add_values
            .push((name.clone(), http::HeaderValue::from_str(&value).ok()));
        self.add.push((name, value));
    }

    /// 🧹 Removes a downstream header after every set and append mutation.
    pub(crate) fn remove(&mut self, name: impl AsRef<str>) {
        let name = name.as_ref().to_ascii_lowercase();
        if name == "server" {
            self.suppress_server = true;
        }
        if name == "via" {
            self.suppress_via = true;
        }
        if !self.remove.iter().any(|existing| existing == &name) {
            self.remove.push(name);
        }
    }

    /// 🧩 Adds proxy-owned replacements without overriding outer middleware.
    pub(crate) fn merge_proxy_set(&mut self, headers: &HashMap<String, String>) {
        for (name, value) in headers {
            let name = name.to_ascii_lowercase();
            if !self.set.contains_key(&name) {
                self.set_names
                    .insert(name.clone(), Bytes::copy_from_slice(name.as_bytes()));
                self.set_values
                    .insert(name.clone(), http::HeaderValue::from_str(value).ok());
                self.set.insert(name, value.clone());
            }
        }
    }

    /// 🔗 Merges a middleware decision into the active response policy.
    pub(crate) fn merge(&mut self, other: ResponseHeaderPolicy) {
        self.set.extend(other.set);
        self.set_names.extend(other.set_names);
        self.set_values.extend(other.set_values);
        self.add.extend(other.add);
        self.add_names.extend(other.add_names);
        self.add_values.extend(other.add_values);
        for name in other.remove {
            self.remove(name);
        }
        self.suppress_server |= other.suppress_server;
        self.suppress_via |= other.suppress_via;
    }

    /// 🍎 Applies the shared policy to a Pingora response.
    pub(crate) fn apply_pingora(
        &self,
        response: &mut ResponseHeader,
        request_id: &http::HeaderValue,
        via_hop: Option<http::Version>,
    ) -> PingoraResult<()> {
        for (name, value) in &self.set {
            let name_bytes = &self.set_names[name];
            match self.set_values.get(name).and_then(|v| v.clone()) {
                Some(header_value) => {
                    response.insert_header(name_bytes.clone(), header_value)?;
                }
                None => {
                    response.insert_header(name_bytes.clone(), value.as_str())?;
                }
            }
        }
        for ((name, value), name_bytes) in self.add.iter().zip(&self.add_names) {
            let header_value = self
                .add_values
                .iter()
                .find(|(n, _)| n == name)
                .and_then(|(_, v)| v.clone());
            match header_value {
                Some(header_value) => {
                    response.append_header(name_bytes.clone(), header_value)?;
                }
                None => {
                    response.append_header(name_bytes.clone(), value.as_str())?;
                }
            }
        }
        for name in &self.remove {
            let _ = response.remove_header(name);
        }
        if self.suppress_server {
            let _ = response.remove_header("server");
        } else {
            response.insert_header("server", "Pingclair")?;
        }

        // `Via` is *appended*, never inserted: the field records the whole
        // chain of intermediaries, so replacing it would erase whoever sits
        // in front of us. `via_hop` is `None` for a response this server
        // produced itself — there was no hop, and claiming one would be a lie.
        if let Some(version) = via_hop.filter(|_| !self.suppress_via) {
            response.append_header("via", via_value(version))?;
        }

        response.insert_header("x-request-id", request_id.clone())?;
        Ok(())
    }

    /// 🔀 Whether `-Via` asked for the proxy chain to stay hidden.
    pub(crate) fn suppresses_via(&self) -> bool {
        self.suppress_via
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

// MARK: - Request framing

/// 🚫 Why a request's message framing cannot be trusted.
///
/// Each variant is a way for this proxy and the origin behind it to disagree
/// about where one request ends and the next begins. That disagreement is the
/// whole of HTTP request smuggling, so the answer is always to refuse the
/// request rather than to guess well.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FramingRejection {
    /// The message carries both `Content-Length` and `Transfer-Encoding`.
    AmbiguousLength,
    /// `Transfer-Encoding` appeared on a protocol that forbids it entirely.
    TransferEncodingForbidden,
    /// `Content-Length` was not `1*DIGIT` (RFC 9110 §8.6).
    MalformedContentLength,
    /// An HTTP/1.1 request arrived without a `Host` field.
    MissingHost,
    /// More than one `Host` field, so the virtual host is a matter of opinion.
    AmbiguousHost,
    /// `Host` carried something that is not a bare authority.
    MalformedHost,
}

impl FramingRejection {
    /// A reason safe to hand back to the client: it names the offending field
    /// without echoing the attacker's own bytes.
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::AmbiguousLength => "Ambiguous Message Framing",
            Self::TransferEncodingForbidden => "Transfer-Encoding Not Allowed",
            Self::MalformedContentLength => "Malformed Content-Length",
            Self::MissingHost => "Missing Host Header",
            Self::AmbiguousHost => "Ambiguous Host Header",
            Self::MalformedHost => "Malformed Host Header",
        }
    }
}

/// 🛡️ Rejects requests whose length is open to more than one reading.
///
/// The rules differ by protocol version, so the caller passes the version it
/// actually parsed rather than the one the client claimed:
///
/// - **HTTP/1.1** — carrying both `Content-Length` and `Transfer-Encoding` is
///   forbidden to senders and "ought to be handled as an error" by recipients
///   (RFC 9112 §6.1). ⚠️ In practice this branch does not fire today: Pingora
///   settles the ambiguity while parsing, removing `Content-Length` and
///   disabling keepalive (`pingora-core-0.8.1`
///   `protocols/http/v1/server.rs:272`), so by the time any filter runs the
///   evidence is already gone. The check stays as defence in depth for the day
///   that behaviour changes under us, and
///   `test_conflicting_length_headers_cannot_smuggle_a_second_request` is what
///   actually holds Pingora to it.
/// - **HTTP/2 and HTTP/3** — `Transfer-Encoding` is not merely discouraged, it
///   is forbidden outright (RFC 9113 §8.2.2, RFC 9114 §4.1), because those
///   protocols carry their own framing.
///
/// `Content-Length` is validated on every version. `httparse` already rejects
/// negative and hex-looking values, but it accepts a leading `+`, and a value
/// like `+5` is the ideal smuggling primitive: lenient parsers read five bytes
/// and strict ones reject, so the two ends of a chain disagree about how much
/// body they just consumed.
/// 🛡️ Rejects requests whose length is open to more than one reading.
pub(crate) fn check_request_framing(
    version: http::Version,
    headers: &HeaderMap,
) -> Result<(), FramingRejection> {
    let has_transfer_encoding = headers.contains_key(http::header::TRANSFER_ENCODING);
    let has_content_length = headers.contains_key(http::header::CONTENT_LENGTH);

    if has_transfer_encoding {
        if version == http::Version::HTTP_2 || version == http::Version::HTTP_3 {
            return Err(FramingRejection::TransferEncodingForbidden);
        }
        if has_content_length {
            return Err(FramingRejection::AmbiguousLength);
        }
    }

    // 🔢 RFC 9110 §8.6: `Content-Length = 1*DIGIT`. No sign, no whitespace, no
    // empty value — and every duplicate must independently satisfy that, since
    // a lenient reader might take the first and a strict one the last.
    for value in headers.get_all(http::header::CONTENT_LENGTH) {
        let raw = value.as_bytes();
        if content_length_value_invalid(raw) {
            return Err(FramingRejection::MalformedContentLength);
        }
    }

    Ok(())
}

/// 🔢 True when a `Content-Length` field value violates RFC 9110 §8.6's
/// `1*DIGIT` grammar (empty, signed, whitespace-padded, or non-digit bytes).
fn content_length_value_invalid(raw: &[u8]) -> bool {
    raw.is_empty() || !raw.iter().all(u8::is_ascii_digit)
}

/// 🛡️ Rejects an HTTP/3 request whose raw header list carries untrustworthy
/// framing, without materializing an [`http::HeaderMap`] just to validate it.
///
/// `quiche` already enforces H3's wire framing, so the only fields this proxy
/// still has to police are `Transfer-Encoding` (forbidden outright) and
/// `Content-Length` (`1*DIGIT`, every duplicate). This is the same rule set as
/// [`check_request_framing`], expressed over the header list `parse_h3_request`
/// already owns, so the H3 event loop does not parse each header twice.
pub(crate) fn check_h3_request_framing(
    headers: &[(String, String)],
) -> Result<(), FramingRejection> {
    let has_transfer_encoding = headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"));
    if has_transfer_encoding {
        return Err(FramingRejection::TransferEncodingForbidden);
    }
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length")
            && content_length_value_invalid(value.as_bytes())
        {
            return Err(FramingRejection::MalformedContentLength);
        }
    }
    Ok(())
}

/// 🏠 Rejects a request whose `Host` cannot be resolved to exactly one authority.
///
/// RFC 9112 §3.2 is unusually blunt here: a server **must** answer 400 to an
/// HTTP/1.1 request that lacks `Host`, carries more than one, or carries one
/// with an invalid value. The reason is the same shape as path confusion — this
/// proxy picks a virtual host from the first field it finds, and an origin that
/// picks the last one is serving a different site than the one whose policy was
/// just applied.
///
/// Only HTTP/1.1 and later are checked. HTTP/1.0 predates `Host` and may
/// legitimately omit it, and HTTP/2 and HTTP/3 carry `:authority` instead,
/// which their own parsers already validate.
pub(crate) fn check_request_host(
    version: http::Version,
    headers: &HeaderMap,
) -> Result<(), FramingRejection> {
    if version == http::Version::HTTP_09 || version == http::Version::HTTP_10 {
        return Ok(());
    }
    if version != http::Version::HTTP_11 {
        return Ok(());
    }

    let mut hosts = headers.get_all(http::header::HOST).into_iter();
    let Some(host) = hosts.next() else {
        return Err(FramingRejection::MissingHost);
    };
    if hosts.next().is_some() {
        return Err(FramingRejection::AmbiguousHost);
    }

    // 🔍 An authority has no spaces, no control characters, and no embedded
    // separators. Anything else lets two parsers disagree about the name.
    let raw = host.as_bytes();
    if raw.is_empty()
        || raw
            .iter()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control() || *byte == b',')
    {
        return Err(FramingRejection::MalformedHost);
    }

    Ok(())
}

/// 🧭 Resolves `.` and `..` in a request path, the way nginx and Caddy do.
///
/// A path arriving at a proxy is supposed to be normalized already
/// (RFC 9110 §4.2.3), so these segments are not a client convenience — left
/// alone they let a request match one route while the origin resolves it to a
/// different resource. `GET /api/../admin/x` would match an `/api/*` route
/// here, so a policy bound to `/admin/*` never runs, and the origin — which
/// almost certainly normalizes — serves `/admin/x` anyway.
///
/// Resolving rather than refusing is the deliberate choice: both reference
/// implementations answer 403 for that request because the policy on the
/// resolved path is what runs, and matching them matters more than the
/// marginally stricter 400 that refusing would give. The security property is
/// identical either way — routing decides on the same path the origin will.
///
/// `%2e` and `%2E` are decoded to `.` first, because an origin that decodes
/// before it normalizes sees `..` either way. Nothing else is decoded: turning
/// `%2f` into a separator would change which resource is named, which is a
/// documented footgun rather than a hardening measure.
///
/// `..` can never climb above the root; empty segments collapse, so `//a`
/// becomes `/a`. Returns `None` when the path is already normal, so the common
/// request pays for a scan and no allocation.
pub(crate) fn normalize_request_path(path: &str) -> Option<String> {
    let decoded = decode_encoded_dots(path);
    let source = decoded.as_deref().unwrap_or(path);

    // 🍃 A cheap scan first, so an ordinary request allocates nothing. No
    // slicing by index: this reads attacker-controlled bytes, and `path[1..]`
    // panics on an empty string or a multi-byte first character — which, with
    // `panic = "abort"`, would be a remote kill rather than a bad request.
    let needs_work = decoded.is_some()
        || source.contains("//")
        || source
            .split('/')
            .any(|segment| segment == "." || segment == "..");
    if !needs_work {
        return None;
    }

    let (raw_path, query) = match source.split_once('?') {
        Some((raw_path, query)) => (raw_path, Some(query)),
        None => (source, None),
    };

    let mut resolved: Vec<&str> = Vec::new();
    for segment in raw_path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                // 🧱 The root is the floor; `/../x` is `/x`, never an escape.
                resolved.pop();
            }
            other => resolved.push(other),
        }
    }

    let mut out = String::with_capacity(raw_path.len());
    for segment in &resolved {
        out.push('/');
        out.push_str(segment);
    }
    if out.is_empty() {
        out.push('/');
    }
    // 🏁 A trailing slash is meaningful to origins, so it survives.
    if raw_path.len() > 1 && raw_path.ends_with('/') && !out.ends_with('/') {
        out.push('/');
    }
    if let Some(query) = query {
        out.push('?');
        out.push_str(query);
    }

    (out != path).then_some(out)
}

/// Decode only `%2e` and `%2E` into `.`, leaving every other escape alone.
fn decode_encoded_dots(path: &str) -> Option<String> {
    if !path.contains("%2e") && !path.contains("%2E") {
        return None;
    }
    Some(path.replace("%2e", ".").replace("%2E", "."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_of(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                http::HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    // MARK: - Property tests
    //
    // 💥 `panic = "abort"` is set for release builds, so a panic anywhere on the
    // request path is not an error message — it is the whole process dying at a
    // remote client's choosing. These validators read attacker-controlled bytes
    // before anything else does, which makes "never panics, for any input" the
    // property worth proving rather than assuming.

    proptest::proptest! {
        #[test]
        fn framing_never_panics(value in ".*", te in ".*") {
            let mut headers = HeaderMap::new();
            if let Ok(value) = http::HeaderValue::from_str(&value) {
                headers.append(http::header::CONTENT_LENGTH, value);
            }
            if let Ok(te) = http::HeaderValue::from_str(&te) {
                headers.append(http::header::TRANSFER_ENCODING, te);
            }
            for version in [
                http::Version::HTTP_10,
                http::Version::HTTP_11,
                http::Version::HTTP_2,
                http::Version::HTTP_3,
            ] {
                let _ = check_request_framing(version, &headers);
                let _ = check_request_host(version, &headers);
            }
        }

        #[test]
        fn normalizing_never_panics(path in ".*") {
            let _ = normalize_request_path(&path);
        }

        #[test]
        fn a_normalized_path_has_no_traversal_left(
            prefix in "[a-z/]{0,12}",
            dots in proptest::sample::select(vec!["..", ".", "%2e%2e", "%2E.", ".%2e"]),
            suffix in "[a-z/]{0,12}",
        ) {
            // 🛡️ The security property, stated directly: whatever went in, what
            // routing sees afterwards contains no segment that could resolve
            // somewhere else at the origin.
            let path = format!("/{prefix}/{dots}/{suffix}");
            let normalized = normalize_request_path(&path).unwrap_or(path.clone());
            let settled = normalize_request_path(&normalized);
            proptest::prop_assert!(
                settled.is_none(),
                "{path:?} normalized to {normalized:?}, which still needs work"
            );
            proptest::prop_assert!(
                !normalized.split('/').any(|s| s == "." || s == ".."),
                "{path:?} normalized to {normalized:?}, which still contains traversal"
            );
        }

        #[test]
        fn normalizing_never_escapes_the_root(depth in 1usize..8) {
            // 🧱 However many times a client climbs, it cannot get above `/`.
            let path = format!("/{}", "../".repeat(depth));
            let normalized = normalize_request_path(&path).unwrap_or(path);
            proptest::prop_assert!(
                normalized.starts_with('/') && !normalized.contains(".."),
                "climbing produced {normalized:?}"
            );
        }

        #[test]
        fn a_content_length_of_only_digits_is_always_accepted(digits in "[0-9]{1,18}") {
            // 🔢 The inverse of the rejection rule, so a future tightening cannot
            // quietly start refusing ordinary requests.
            let headers = headers_of(&[("content-length", &digits)]);
            proptest::prop_assert_eq!(
                check_request_framing(http::Version::HTTP_11, &headers),
                Ok(())
            );
        }
    }

    #[test]
    fn host_must_be_present_exactly_once_and_well_formed() {
        let ok = headers_of(&[("host", "example.test:8443")]);
        assert_eq!(check_request_host(http::Version::HTTP_11, &ok), Ok(()));

        assert_eq!(
            check_request_host(http::Version::HTTP_11, &headers_of(&[])),
            Err(FramingRejection::MissingHost)
        );
        assert_eq!(
            check_request_host(
                http::Version::HTTP_11,
                &headers_of(&[("host", "a.test"), ("host", "evil.test")])
            ),
            Err(FramingRejection::AmbiguousHost)
        );
        for bad in ["a b", "a\tb", "a,b", ""] {
            assert_eq!(
                check_request_host(http::Version::HTTP_11, &headers_of(&[("host", bad)])),
                Err(FramingRejection::MalformedHost),
                "Host {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn host_is_not_required_before_http_1_1() {
        // 🕰️ HTTP/1.0 predates the field, so its absence is not an error.
        assert_eq!(
            check_request_host(http::Version::HTTP_10, &headers_of(&[])),
            Ok(())
        );
        // 🔀 H2 and H3 carry `:authority`; their own parsers own this rule.
        assert_eq!(
            check_request_host(http::Version::HTTP_2, &headers_of(&[])),
            Ok(())
        );
    }

    #[test]
    fn traversal_is_resolved_the_way_nginx_and_caddy_resolve_it() {
        for (input, expected) in [
            ("/api/../admin/x", "/admin/x"),
            ("/api/%2e%2e/admin/x", "/admin/x"),
            ("/api/%2E%2E/admin/x", "/admin/x"),
            ("/admin/./x", "/admin/x"),
            ("//admin/x", "/admin/x"),
            ("/a/b/../../c", "/c"),
            ("/a/b/..", "/a"),
        ] {
            assert_eq!(
                normalize_request_path(input).as_deref(),
                Some(expected),
                "{input:?} must normalize to {expected:?}"
            );
        }
    }

    #[test]
    fn normalizing_cannot_climb_above_the_root() {
        // 🧱 `..` at the root is absorbed, never an escape.
        assert_eq!(
            normalize_request_path("/../secret").as_deref(),
            Some("/secret")
        );
        assert_eq!(normalize_request_path("/../../..").as_deref(), Some("/"));
    }

    #[test]
    fn normalizing_preserves_query_and_trailing_slash() {
        assert_eq!(
            normalize_request_path("/api/../admin/?x=1").as_deref(),
            Some("/admin/?x=1")
        );
        assert_eq!(normalize_request_path("/a/./b/").as_deref(), Some("/a/b/"));
    }

    #[test]
    fn ordinary_paths_are_left_exactly_alone() {
        // 🍃 `None` means no allocation and no rewriting for the common request.
        for path in [
            "/api/users",
            "/static/ok.txt",
            "/a..b/c",
            "/...",
            "/file.tar.gz",
            "/",
            "/api/%252e%252e/x",
            "/api/a%2fb",
        ] {
            assert_eq!(
                normalize_request_path(path),
                None,
                "{path:?} is already normal and must not be rewritten"
            );
        }
    }

    #[test]
    fn framing_accepts_a_single_well_formed_length() {
        assert_eq!(
            check_request_framing(
                http::Version::HTTP_11,
                &headers_of(&[("content-length", "5")])
            ),
            Ok(())
        );
        assert_eq!(
            check_request_framing(
                http::Version::HTTP_11,
                &headers_of(&[("transfer-encoding", "chunked")])
            ),
            Ok(())
        );
        assert_eq!(
            check_request_framing(http::Version::HTTP_11, &headers_of(&[])),
            Ok(())
        );
    }

    #[test]
    fn framing_rejects_content_length_with_transfer_encoding() {
        // 🚨 Both header orders, because a parser that only looks at the first
        // length field it meets would disagree depending on the order.
        assert_eq!(
            check_request_framing(
                http::Version::HTTP_11,
                &headers_of(&[("content-length", "6"), ("transfer-encoding", "chunked")])
            ),
            Err(FramingRejection::AmbiguousLength)
        );
        assert_eq!(
            check_request_framing(
                http::Version::HTTP_11,
                &headers_of(&[("transfer-encoding", "chunked"), ("content-length", "6")])
            ),
            Err(FramingRejection::AmbiguousLength)
        );
    }

    #[test]
    fn framing_rejects_transfer_encoding_on_h2_and_h3() {
        for version in [http::Version::HTTP_2, http::Version::HTTP_3] {
            assert_eq!(
                check_request_framing(version, &headers_of(&[("transfer-encoding", "chunked")])),
                Err(FramingRejection::TransferEncodingForbidden),
                "Transfer-Encoding must be refused on {version:?}"
            );
        }
    }

    #[test]
    fn h3_framing_matches_the_shared_rule_set() {
        // 📋 The raw-list variant must reach the same verdict as the
        // HeaderMap variant for every framing decision the H3 event loop can
        // produce.
        for headers in [
            vec![],
            vec![("content-length", "5")],
            vec![("Content-Length", "5")],
            vec![("content-length", "5"), ("content-length", "5")],
            vec![("transfer-encoding", "chunked")],
            vec![("Transfer-Encoding", "chunked"), ("content-length", "6")],
            vec![("content-length", "")],
            vec![("content-length", "5 ")],
            vec![("content-length", "-5")],
            vec![("content-length", "5"), ("content-length", "x")],
            vec![("content-length", "5"), ("Content-Length", "6")],
        ] {
            let list: Vec<(String, String)> = headers
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect();
            let mut map = http::HeaderMap::new();
            for (name, value) in &list {
                if let (Ok(name), Ok(value)) = (
                    http::header::HeaderName::from_bytes(name.as_bytes()),
                    http::HeaderValue::from_str(value),
                ) {
                    map.append(name, value);
                }
            }
            assert_eq!(
                check_h3_request_framing(&list),
                check_request_framing(http::Version::HTTP_3, &map),
                "H3 list framing diverged from the shared rule for {headers:?}"
            );
        }
    }

    #[test]
    fn h3_framing_fails_closed_on_values_the_header_map_cannot_carry() {
        // 🚨 A value that cannot become an `http::HeaderValue` was silently
        // dropped by the old H3 path, which then accepted the request. The
        // raw-list variant rejects it instead, matching the H1/H2 rule that
        // a declared `Content-Length` must be `1*DIGIT`.
        assert_eq!(
            check_h3_request_framing(&[("content-length".to_string(), "5\x01".to_string())]),
            Err(FramingRejection::MalformedContentLength)
        );
    }

    #[test]
    fn framing_rejects_content_length_that_is_not_all_digits() {
        for bad in ["+5", " 5", "5 ", "", "5,5", "0x5", "-1", "५"] {
            assert_eq!(
                check_request_framing(
                    http::Version::HTTP_11,
                    &headers_of(&[("content-length", bad)])
                ),
                Err(FramingRejection::MalformedContentLength),
                "Content-Length {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn framing_checks_every_duplicate_content_length() {
        // 🧮 The first value is valid, so a check that stopped at `get()`
        // instead of `get_all()` would let this through.
        assert_eq!(
            check_request_framing(
                http::Version::HTTP_11,
                &headers_of(&[("content-length", "5"), ("content-length", "+5")])
            ),
            Err(FramingRejection::MalformedContentLength)
        );
    }

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

    // ---- Via (RFC 9110 §7.6.3) ----

    fn applied(policy: &ResponseHeaderPolicy, hop: Option<http::Version>) -> ResponseHeader {
        let mut response = ResponseHeader::build(200, None).unwrap();
        policy
            .apply_pingora(&mut response, &http::HeaderValue::from_static("req-1"), hop)
            .unwrap();
        response
    }

    fn via_values(response: &ResponseHeader) -> Vec<String> {
        response
            .headers
            .get_all("via")
            .iter()
            .map(|value| value.to_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn the_via_token_names_the_protocol_the_hop_arrived_on() {
        // Not the one it leaves by — a proxy taking HTTP/2 from a client and
        // HTTP/1.1 from an origin writes a different token in each direction.
        assert_eq!(via_version(http::Version::HTTP_10), "1.0");
        assert_eq!(via_version(http::Version::HTTP_11), "1.1");
        assert_eq!(via_version(http::Version::HTTP_2), "2.0");
        assert_eq!(via_version(http::Version::HTTP_3), "3.0");
        assert_eq!(via_value(http::Version::HTTP_2), "2.0 Pingclair");
    }

    #[test]
    fn a_proxied_response_carries_via_and_a_local_one_does_not() {
        let policy = ResponseHeaderPolicy::default();

        assert_eq!(
            via_values(&applied(&policy, Some(http::Version::HTTP_11))),
            vec!["1.1 Pingclair"]
        );
        // Nothing was proxied, so there is no hop to record and claiming one
        // would be a lie about the message's path.
        assert!(via_values(&applied(&policy, None)).is_empty());
    }

    #[test]
    fn via_is_appended_so_the_chain_in_front_of_us_survives() {
        // The whole point of the field is recording every intermediary. An
        // `insert` here would erase Cloudflare, or any proxy ahead of it, from
        // a header whose only job is to say who handled the message.
        let mut response = ResponseHeader::build(200, None).unwrap();
        response.insert_header("via", "1.1 upstream-cache").unwrap();
        ResponseHeaderPolicy::default()
            .apply_pingora(
                &mut response,
                &http::HeaderValue::from_static("req-1"),
                Some(http::Version::HTTP_11),
            )
            .unwrap();

        assert_eq!(
            via_values(&response),
            vec!["1.1 upstream-cache", "1.1 Pingclair"]
        );
    }

    #[test]
    fn removing_via_hides_the_chain_entirely() {
        // `-Via` is for operators who do not want their topology advertised,
        // so it has to drop the upstream's value too, not just ours.
        let mut policy = ResponseHeaderPolicy::default();
        policy.remove("Via");
        assert!(policy.suppresses_via());

        let mut response = ResponseHeader::build(200, None).unwrap();
        response.insert_header("via", "1.1 upstream-cache").unwrap();
        policy
            .apply_pingora(
                &mut response,
                &http::HeaderValue::from_static("req-1"),
                Some(http::Version::HTTP_11),
            )
            .unwrap();

        assert!(via_values(&response).is_empty());
    }

    #[test]
    fn suppression_survives_a_middleware_merge() {
        let mut outer = ResponseHeaderPolicy::default();
        let mut inner = ResponseHeaderPolicy::default();
        inner.remove("via");
        outer.merge(inner);
        assert!(outer.suppresses_via());
    }
}
