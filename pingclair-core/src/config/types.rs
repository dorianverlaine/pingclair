// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Configuration type definitions
//!
//! These types represent the runtime configuration for Pingclair.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Root configuration for Pingclair
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PingclairConfig {
    /// Debug mode
    #[serde(default)]
    pub debug: bool,

    /// Server configurations
    #[serde(default)]
    pub servers: Vec<ServerConfig>,

    /// Admin API configuration
    #[serde(default)]
    pub admin: Option<AdminConfig>,

    /// Global configuration
    #[serde(default)]
    pub global: GlobalConfig,

    /// Global logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Global configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// Global ACME email
    pub email: Option<String>,

    /// 🌐 Port the server uses for plaintext HTTP, matching Caddy's
    /// `http_port` option. The automatic port-80 companion and the default
    /// listener for non-TLS hostname sites honor this.
    #[serde(default = "default_http_port")]
    pub http_port: u16,

    /// 🔐 Port the server uses for HTTPS, matching Caddy's `https_port`
    /// option. The automatic-443 derivation and `server_requires_tls`
    /// conventions use this instead of a hard-coded 443.
    #[serde(default = "default_https_port")]
    pub https_port: u16,

    /// Global auto-HTTPS setting
    #[serde(default)]
    pub auto_https: AutoHttpsMode,

    /// Blocked IP addresses (CIDR supported)
    #[serde(default)]
    pub blocked_ips: Vec<String>,

    /// 🛡️ Proxy IP or CIDR ranges allowed to supply client identity headers.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,

    /// Max number of idle upstream connections Pingora keeps open per
    /// worker thread for reuse. Explicitly configurable rather than left
    /// as an implicit framework default, so a deployment under load has a
    /// deliberate, known ceiling on upstream connection fan-out instead of
    /// an invisible one. `None` uses Pingora's own default (128).
    #[serde(default)]
    pub upstream_keepalive_pool_size: Option<usize>,

    /// Enable HTTP/3 (QUIC) listeners on HTTPS ports. Defaults to true;
    /// set to false to serve HTTPS over TCP (HTTP/1.1 + HTTP/2) only.
    #[serde(default = "default_bool_true")]
    pub http3: bool,

    /// Worker threads **per listen service**. Pingora's default is 1, which
    /// single-threads the entire server; `None` scales to the machine's
    /// available parallelism (nginx `worker_processes auto` semantics).
    #[serde(default)]
    pub worker_threads: Option<usize>,

    /// How often hostname upstreams are re-resolved, in seconds. `0` turns
    /// re-resolution off and pins every upstream to the address it had at
    /// startup. Only names are affected: IP literals never reach a resolver.
    #[serde(default = "default_dns_refresh_secs")]
    pub dns_refresh_secs: u64,
}

/// 🌐 Default plaintext HTTP port, matching Caddy's default.
fn default_http_port() -> u16 {
    80
}

/// 🔐 Default HTTPS port, matching Caddy's default.
fn default_https_port() -> u16 {
    443
}

/// Default upstream re-resolution interval (seconds).
pub fn default_dns_refresh_secs() -> u64 {
    30
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            email: None,
            http_port: default_http_port(),
            https_port: default_https_port(),
            auto_https: AutoHttpsMode::default(),
            blocked_ips: Vec::new(),
            trusted_proxies: Vec::new(),
            upstream_keepalive_pool_size: None,
            http3: true,
            worker_threads: None,
            dns_refresh_secs: default_dns_refresh_secs(),
        }
    }
}

/// Auto-HTTPS modes
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AutoHttpsMode {
    #[default]
    On,
    Off,
    DisableRedirects,
}

/// 🗜️ Default MIME patterns eligible for reverse-proxy gzip compression.
pub const DEFAULT_GZIP_TYPES: &[&str] = &[
    "text/*",
    "application/json",
    "application/*+json",
    "application/x-ndjson",
    "application/json-seq",
    "application/xml",
    "application/*+xml",
    "application/javascript",
    "application/x-javascript",
    "image/svg+xml",
];

/// 🗜️ Builds the default reverse-proxy gzip MIME pattern list.
pub fn default_gzip_types() -> Vec<String> {
    DEFAULT_GZIP_TYPES
        .iter()
        .map(|value| (*value).to_string())
        .collect()
}

/// 🗜️ A content coding Pingclair can actually *produce* for a proxied response.
///
/// Deliberately narrower than what the config grammar accepts: the parser also
/// understands `br`, but the reverse-proxy path has no streaming Brotli
/// encoder, so the compiler rejects it rather than silently downgrading to
/// gzip. Anything present in this enum is guaranteed to have a working encoder
/// behind it — that invariant is what lets the negotiator treat the configured
/// list as offerable without further checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    Gzip,
    Zstd,
}

impl Encoding {
    /// The `Content-Encoding` / `Accept-Encoding` token for this coding.
    pub fn token(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Zstd => "zstd",
        }
    }

    /// Parses an `Accept-Encoding` token into a coding we can produce.
    ///
    /// Returns `None` for well-formed codings we simply do not implement
    /// (`br`, `deflate`, …) as well as for junk — the caller treats both the
    /// same way, by offering something else.
    pub fn from_token(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => Some(Self::Gzip),
            "zstd" => Some(Self::Zstd),
            _ => None,
        }
    }
}

/// 🗜️ Codings offered when a server declares no `encode` directive at all.
///
/// Gzip-only, which is what every Pingclair release through `0.1.7` did
/// unconditionally. Keeping it as the default means making `encode` real is
/// not a silent behavior change for configs that never mentioned it.
pub fn default_encodings() -> Vec<Encoding> {
    vec![Encoding::Gzip]
}

/// Server (virtual host) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server name / hostname
    pub name: Option<String>,

    /// 🏠 Every hostname this site serves. The primary name is also kept in
    /// [`Self::name`] for backward compatibility; the runtime registers each
    /// entry as a virtual host pointing at the same configuration.
    #[serde(default)]
    pub names: Vec<String>,

    /// 📍 Optional interface to bind the site's listener to (`bind` directive).
    /// When the site has no explicit `listen`, the runtime uses this as the
    /// host for the automatically derived 443/80 address.
    #[serde(default)]
    pub bind: Option<String>,

    /// Listen addresses
    #[serde(default)]
    pub listen: Vec<String>,

    /// 🧭 The subset of [`Self::listen`] that requires a PROXY protocol header.
    ///
    /// Kept as a parallel list rather than folded into `listen` so the shape of
    /// `listen` stays a plain array of strings: it round-trips through the
    /// Admin API unchanged, and a configuration written before this field
    /// existed still loads as "no listener requires the header".
    ///
    /// Every entry must also appear in `listen`. An address here that is not
    /// listened on is rejected rather than ignored — silently dropping it would
    /// leave a listener the operator believes is protected accepting anything.
    #[serde(default)]
    pub proxy_protocol_listen: Vec<String>,

    /// TLS configuration
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// Routes for this server
    #[serde(default)]
    pub routes: Vec<RouteConfig>,

    /// Log configuration for this server
    #[serde(default)]
    pub log: Option<LogConfig>,

    /// Maximum request body size in bytes (default: 1MB)
    #[serde(default = "default_body_limit")]
    pub client_max_body_size: u64,

    /// 🧱 Configurable downstream resource and time bounds.
    #[serde(default)]
    pub limits: ResourceLimitsConfig,

    /// Security headers configuration
    #[serde(default)]
    pub security: SecurityConfig,

    /// 🗜️ MIME patterns eligible for reverse-proxy gzip compression.
    #[serde(default = "default_gzip_types")]
    pub gzip_types: Vec<String>,

    /// 🗜️ Content codings offered for proxied responses, in *server*
    /// preference order — the order the `encode` directive listed them.
    ///
    /// An empty list disables response compression for this server entirely
    /// (`encode off`); the field is absent from older JSON configs, which
    /// fall back to [`default_encodings`].
    #[serde(default = "default_encodings")]
    pub encodings: Vec<Encoding>,

    /// Custom error pages: HTTP status code → file path served for that
    /// error (404/500/502/504, ...). Falls back to the built-in plain-text
    /// response when unset or unreadable.
    #[serde(default)]
    pub error_pages: HashMap<u16, String>,
}

/// Hand-written rather than derived so `ServerConfig::default()` agrees with
/// what deserializing `{}` produces. `#[derive(Default)]` ignores the
/// `#[serde(default = ...)]` attributes, which would silently hand out
/// `client_max_body_size: 0` (unlimited) and an empty `encodings` list
/// (compression off) — both the opposite of the documented default.
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            name: None,
            names: Vec::new(),
            bind: None,
            listen: Vec::new(),
            proxy_protocol_listen: Vec::new(),
            tls: None,
            routes: Vec::new(),
            log: None,
            client_max_body_size: default_body_limit(),
            limits: ResourceLimitsConfig::default(),
            security: SecurityConfig::default(),
            gzip_types: default_gzip_types(),
            encodings: default_encodings(),
            error_pages: HashMap::new(),
        }
    }
}

fn default_body_limit() -> u64 {
    1024 * 1024 // 1MB
}

/// 🧱 Bounds one virtual host's downstream resource consumption.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ResourceLimitsConfig {
    /// ⏱️ Maximum time spent reading an HTTP/1 request header.
    pub header_timeout_ms: Option<u64>,
    /// ⏱️ Maximum pause allowed while receiving request-body chunks.
    pub body_timeout_ms: Option<u64>,
    /// 💤 Maximum inactive downstream interval for ordinary requests.
    pub idle_timeout_ms: Option<u64>,
    /// ⌛ Maximum wall-clock duration after request headers are accepted.
    pub request_timeout_ms: Option<u64>,
    /// 🧾 Maximum number of decoded request fields, excluding pseudo-headers.
    pub max_header_count: Option<usize>,
    /// 📏 Maximum decoded request-header bytes, including names and values.
    pub max_header_bytes: Option<usize>,
    /// 🔌 Maximum simultaneous downstream transport connections per listener.
    pub max_connections: Option<usize>,
    /// 📥 Maximum downstream request-body throughput in bytes per second.
    pub upload_bytes_per_sec: Option<u64>,
    /// 📤 Maximum downstream response-body throughput in bytes per second.
    pub download_bytes_per_sec: Option<u64>,
    /// 🌊 Overrides ordinary deadlines for SSE, immediate-flush, and WebSocket traffic.
    #[serde(default)]
    pub long_connections: LongConnectionLimits,
}

/// 🌊 Deadline overrides for intentionally long-lived responses and tunnels.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct LongConnectionLimits {
    /// 💤 Long-connection inactivity timeout; zero explicitly disables it.
    pub idle_timeout_ms: Option<u64>,
    /// ⌛ Long-connection wall-clock timeout; zero explicitly disables it.
    pub request_timeout_ms: Option<u64>,
}

/// 🔐 Configures downstream TLS for one server.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsConfig {
    /// 🌐 Enables automatic public certificate management.
    #[serde(default)]
    pub auto: bool,

    /// 🏛️ Enables certificates signed by Pingclair's persistent local authority.
    #[serde(default)]
    pub internal: bool,

    /// 📜 Identifies the certificate file path.
    pub cert: Option<String>,

    /// 🔑 Identifies the private key file path.
    pub key: Option<String>,

    /// 📧 Identifies the ACME account email for Let's Encrypt.
    pub acme_email: Option<String>,

    /// 🚀 Enables HTTP/3.
    #[serde(default)]
    pub http3: bool,
}

/// Route configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Path pattern to match
    pub path: String,

    /// Handler for this route
    pub handler: HandlerConfig,

    /// Allowed methods (None = all)
    #[serde(default)]
    pub methods: Option<Vec<String>>,

    /// Matcher for this route
    #[serde(default)]
    pub matcher: Option<Matcher>,
}

/// Route matcher
///
/// 🏗️ SERIALIZATION: **externally tagged** — `{"not": {"path": {"patterns":
/// ["/admin/*"]}}}`. The tag is what makes the enum recoverable. Under the
/// `untagged` representation this type used to carry, a variant was
/// identified purely by the shape of its payload, and half of these variants
/// do not have a distinguishable shape:
///
/// - `Not(inner)` serialized as *just the inner matcher*, so a round trip
///   read it back as the inner matcher and **dropped the negation** — the
///   one transformation that inverts a routing decision.
/// - `Or` and `And` are both two-element arrays, so every `Or` came back
///   as an `And`.
/// - `Query` and `Header` are both `{name, condition}`, so every `Query`
///   came back as a `Header`.
/// - `RemoteIp` and `Protocol` are both arrays of strings, like `Host`.
///
/// A Pingclairfile never went through this path — the compiler builds these
/// values directly — but JSON/TOML configs and Admin API hot reload did.
///
/// Deserialization still accepts the old shapes so `0.1.7` configs load
/// unchanged; see the `Deserialize` impl.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Matcher {
    /// Match by path
    Path { patterns: Vec<String> },

    /// Match by header
    Header {
        name: String,
        condition: MatcherCondition,
    },

    /// Match by HTTP method
    Method { methods: Vec<String> },

    /// Match by query parameter
    Query {
        name: String,
        condition: MatcherCondition,
    },

    /// Match by host
    Host(Vec<String>),

    /// Match by remote IP
    RemoteIp(Vec<String>),

    /// Match by protocol
    Protocol(Vec<String>),

    /// AND combination
    And(Box<Matcher>, Box<Matcher>),

    /// OR combination
    Or(Box<Matcher>, Box<Matcher>),

    /// NOT
    Not(Box<Matcher>),
}

impl<'de> Deserialize<'de> for Matcher {
    /// Reads the tagged form, falling back to the shapes a `0.1.7` config
    /// could hold.
    ///
    /// The two forms cannot be confused: a tagged matcher is a map whose only
    /// key is a variant name, and no legacy shape has a key called `path`,
    /// `host`, `not`, and so on. The tagged form is tried first so a config
    /// that has been rewritten always wins.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Mirrors `Matcher` purely to borrow serde's derived externally
        // tagged reader. Kept inside the function so the two lists cannot
        // drift apart unnoticed and so it never reaches the public API.
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Tagged {
            Path {
                patterns: Vec<String>,
            },
            Header {
                name: String,
                condition: MatcherCondition,
            },
            Method {
                methods: Vec<String>,
            },
            Query {
                name: String,
                condition: MatcherCondition,
            },
            Host(Vec<String>),
            RemoteIp(Vec<String>),
            Protocol(Vec<String>),
            And(Box<Matcher>, Box<Matcher>),
            Or(Box<Matcher>, Box<Matcher>),
            Not(Box<Matcher>),
        }

        /// The shapes a `0.1.7` config could actually contain.
        ///
        /// Deliberately *not* one variant per matcher: several matchers
        /// shared a shape back then, and the reading below reproduces the
        /// one `0.1.7` performed rather than guessing at the author's
        /// intent. A file that has always been read as a `Header` must not
        /// quietly start behaving as a `Query` because this code now knows
        /// the difference — the tagged form is how you say which you meant.
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Legacy {
            Path {
                patterns: Vec<String>,
            },
            Method {
                methods: Vec<String>,
            },
            /// Also how a `Query` was written; `0.1.7` read it as a `Header`.
            Header {
                name: String,
                condition: MatcherCondition,
            },
            /// Also how `RemoteIp` and `Protocol` were written.
            Host(Vec<String>),
            /// Also how an `Or` was written.
            And(Box<Matcher>, Box<Matcher>),
        }

        #[derive(Deserialize)]
        #[serde(
            untagged,
            expecting = "a tagged matcher such as {\"path\": {\"patterns\": [\"/api/*\"]}}, or a 0.1.7 untagged matcher"
        )]
        enum Repr {
            Tagged(Tagged),
            Legacy(Legacy),
        }

        Ok(match Repr::deserialize(deserializer)? {
            Repr::Tagged(Tagged::Path { patterns }) => Matcher::Path { patterns },
            Repr::Tagged(Tagged::Header { name, condition }) => Matcher::Header { name, condition },
            Repr::Tagged(Tagged::Method { methods }) => Matcher::Method { methods },
            Repr::Tagged(Tagged::Query { name, condition }) => Matcher::Query { name, condition },
            Repr::Tagged(Tagged::Host(hosts)) => Matcher::Host(hosts),
            Repr::Tagged(Tagged::RemoteIp(ips)) => Matcher::RemoteIp(ips),
            Repr::Tagged(Tagged::Protocol(protocols)) => Matcher::Protocol(protocols),
            Repr::Tagged(Tagged::And(left, right)) => Matcher::And(left, right),
            Repr::Tagged(Tagged::Or(left, right)) => Matcher::Or(left, right),
            Repr::Tagged(Tagged::Not(inner)) => Matcher::Not(inner),

            Repr::Legacy(Legacy::Path { patterns }) => Matcher::Path { patterns },
            Repr::Legacy(Legacy::Method { methods }) => Matcher::Method { methods },
            Repr::Legacy(Legacy::Header { name, condition }) => Matcher::Header { name, condition },
            Repr::Legacy(Legacy::Host(hosts)) => Matcher::Host(hosts),
            Repr::Legacy(Legacy::And(left, right)) => Matcher::And(left, right),
        })
    }
}

/// Matcher condition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatcherCondition {
    Exists,
    Equals(String),
    Contains(String),
    StartsWith(String),
    EndsWith(String),
    Regex(String),
}

/// 🔑 Selects the identity charged by one rate-limit policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKey {
    /// 🌐 Charges each verified client IP independently.
    Ip,
    /// 🌍 Charges every request reaching this limiter to one shared bucket.
    Global,
    /// 🛣️ Charges the matched route as one bucket.
    Route,
    /// 🎫 Charges the bearer token or `X-API-Key` value without retaining the secret.
    ApiKey,
    /// 🏷️ Charges the value of an arbitrary request header.
    Header(String),
    /// 🏢 Charges the value of a tenant header.
    Tenant(String),
}

/// Handler configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HandlerConfig {
    /// Static file server
    FileServer {
        root: String,
        #[serde(default)]
        index: Vec<String>,
        #[serde(default)]
        browse: bool,
        #[serde(default = "default_bool_true")]
        compress: bool,
    },

    /// Reverse proxy
    ReverseProxy(ReverseProxyConfig),

    /// Redirect
    Redirect {
        to: String,
        #[serde(default = "default_redirect_code")]
        code: u16,
    },

    /// URI rewrite (internal - does not send redirect to client)
    /// Similar to Caddy's uri and rewrite directives
    Rewrite {
        /// Strip prefix from path (e.g., "/api" removes "/api/users" -> "/users")
        #[serde(default)]
        strip_prefix: Option<String>,
        /// Strip suffix from path
        #[serde(default)]
        strip_suffix: Option<String>,
        /// Replace path entirely with this value (supports {placeholders})
        #[serde(default)]
        replace: Option<String>,
        /// Regex pattern to match
        #[serde(default)]
        regex: Option<String>,
        /// Replacement string for regex (supports capture groups $1, $2, etc)
        #[serde(default)]
        regex_replace: Option<String>,
    },

    /// Respond with static content
    Respond {
        #[serde(default = "default_status_code")]
        status: u16,
        body: Option<String>,
        #[serde(default)]
        headers: HashMap<String, String>,
    },

    /// Headers modification
    Headers {
        #[serde(default)]
        set: HashMap<String, String>,
        #[serde(default)]
        add: HashMap<String, String>,
        #[serde(default)]
        remove: Vec<String>,
    },

    /// Pipeline of handlers
    Pipeline { handlers: Vec<HandlerConfig> },

    /// Exclusive routing group
    Handle { handlers: Vec<HandlerConfig> },

    /// HTTP Basic Authentication
    /// Requires valid credentials before allowing access
    BasicAuth {
        /// Realm name shown to user
        #[serde(default = "default_auth_realm")]
        realm: String,
        /// List of allowed username:password_hash pairs
        /// Password should be bcrypt hashed for security
        credentials: Vec<BasicAuthCredential>,
    },

    /// Rate limiting handler
    /// Limits requests per time window with optional burst
    RateLimit {
        /// Maximum requests per window
        #[serde(default = "default_rate_limit_requests")]
        requests: u64,
        /// Window duration in seconds
        #[serde(default = "default_rate_limit_window")]
        window_secs: u64,
        /// Rate limit by IP address (default: true)
        #[serde(default = "default_bool_true")]
        by_ip: bool,
        /// Extra burst allowance
        #[serde(default)]
        burst: u64,
        /// 🔑 Overrides the legacy `by_ip` switch with an explicit key source.
        #[serde(default)]
        key: Option<RateLimitKey>,
        /// 🧪 Reports exact quota state without rejecting over-limit requests.
        #[serde(default)]
        dry_run: bool,
    },

    /// Error handling
    /// Define handlers for specific error codes
    HandleErrors {
        /// Map of internal error codes to handlers
        /// Note: This is a placeholder for future implementation
        #[serde(default)]
        errors: HashMap<u16, Vec<HandlerConfig>>,
    },

    /// Handle with path stripping
    /// Strips the prefix from the path before executing valid handlers
    /// Similar to Caddy's handle_path directive
    HandlePath {
        /// Prefix to strip
        prefix: String,
        /// Handlers to execute with stripped path
        handlers: Vec<HandlerConfig>,
    },

    /// CORS (Cross-Origin Resource Sharing) handler
    /// Automatically handles preflight OPTIONS requests and adds CORS headers
    Cors {
        /// Allowed origins (e.g., ["https://example.com", "*"])
        #[serde(default)]
        allowed_origins: Vec<String>,
        /// Allowed methods (e.g., ["GET", "POST"])
        #[serde(default = "default_cors_methods")]
        allowed_methods: Vec<String>,
        /// Allowed headers
        #[serde(default = "default_cors_headers")]
        allowed_headers: Vec<String>,
        /// Exposed headers
        #[serde(default)]
        exposed_headers: Vec<String>,
        /// Allow credentials
        #[serde(default)]
        allow_credentials: bool,
        /// Max age in seconds for preflight cache
        #[serde(default = "default_cors_max_age")]
        max_age: u64,
    },

    /// Request access control evaluated before the route's terminal handler.
    /// Deny rules take precedence; populated allow lists are mandatory.
    AccessControl(AccessControlConfig),

    /// Try files — attempt to serve from a list of paths, fall through if none match
    /// Similar to Nginx's try_files directive
    TryFiles {
        /// List of file paths to try (supports {path} and {uri} variables)
        files: Vec<String>,
        /// Fallback handler if no file is found
        fallback: Option<Box<HandlerConfig>>,
    },

    /// Plugin invocation
    Plugin { name: String, args: Vec<String> },
}

fn default_bool_true() -> bool {
    true
}

fn default_redirect_code() -> u16 {
    302
}

fn default_cors_methods() -> Vec<String> {
    vec![
        "GET".into(),
        "POST".into(),
        "PUT".into(),
        "DELETE".into(),
        "OPTIONS".into(),
    ]
}

fn default_cors_headers() -> Vec<String> {
    vec![
        "Content-Type".into(),
        "Authorization".into(),
        "X-Requested-With".into(),
    ]
}

fn default_cors_max_age() -> u64 {
    86400 // 24 hours
}

fn default_status_code() -> u16 {
    200
}

fn default_auth_realm() -> String {
    "Restricted".to_string()
}

fn default_rate_limit_requests() -> u64 {
    100
}

fn default_rate_limit_window() -> u64 {
    60
}

/// 🔐 Basic Auth credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuthCredential {
    /// 👤 Username presented by the client.
    pub username: String,
    /// 🔑 Bcrypt hash or legacy plain-text password.
    pub password: String,
    /// 🛡️ Indicates that `password` contains a bcrypt hash.
    #[serde(default)]
    pub hashed: bool,
}

/// Reverse proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReverseProxyConfig {
    /// Upstream URLs
    pub upstreams: Vec<String>,

    /// Per-upstream weight and backup role. When empty, every address in
    /// `upstreams` is a primary with weight one (the legacy JSON form).
    #[serde(default)]
    pub upstream_options: Vec<ProxyUpstream>,

    /// Load balancing configuration
    #[serde(default)]
    pub load_balance: LoadBalanceConfig,

    /// 🩺 Active upstream health-check configuration.
    #[serde(default)]
    pub health_check: Option<Box<HealthCheckConfig>>,

    /// Headers to add to upstream request
    #[serde(default)]
    pub headers_up: HashMap<String, String>,

    /// Headers to add to downstream response
    #[serde(default)]
    pub headers_down: HashMap<String, String>,

    /// Flush interval in milliseconds (-1 for immediate)
    pub flush_interval: Option<i64>,

    /// Read timeout in milliseconds
    pub read_timeout: Option<i64>,

    /// Write timeout in milliseconds
    pub write_timeout: Option<i64>,

    /// 🔌 Maximum time allowed for upstream connection establishment.
    pub connect_timeout: Option<i64>,

    /// ⏱️ Maximum time allowed before the upstream response header arrives.
    pub first_byte_timeout: Option<i64>,

    /// 🌊 Maximum pause allowed between upstream response-body reads.
    pub between_reads_timeout: Option<i64>,

    /// 🔁 Bounded redispatch policy for this reverse-proxy route.
    #[serde(default)]
    pub retry: Box<RetryConfig>,

    /// 🚦 Route and per-upstream admission limits.
    #[serde(default)]
    pub overload: Box<OverloadConfig>,

    /// 🔌 Per-upstream circuit-breaker policy.
    #[serde(default)]
    pub circuit_breaker: Box<CircuitBreakerConfig>,

    /// 🔐 How this route authenticates and verifies its TLS upstreams.
    #[serde(default)]
    pub upstream_tls: Box<UpstreamTlsConfig>,

    /// 🗄️ Response caching for this route, off unless configured.
    #[serde(default)]
    pub cache: Option<Box<CacheConfig>>,
}

/// 🗄️ Stores upstream responses so identical requests skip the origin.
///
/// Caching is opt-in per route. There is no global default because a wrong
/// cache does not fail loudly — it serves the wrong bytes to the wrong person,
/// and keeps doing it until the entry expires.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheConfig {
    /// ⏳ How long a stored response stays fresh, in seconds.
    ///
    /// Required rather than defaulted: picking a lifetime for someone else's
    /// content is exactly the decision an operator has to make deliberately.
    pub ttl_secs: u64,
}

/// 🔁 Controls safe, request-local upstream redispatch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetryConfig {
    /// 🔢 Maximum upstream attempts, including the initial attempt.
    #[serde(default = "default_retry_attempts")]
    pub max_attempts: usize,
    /// ⌛ Maximum elapsed time across every attempt and backoff.
    #[serde(default)]
    pub total_timeout_ms: Option<u64>,
    /// 💤 Fixed delay before each retry.
    #[serde(default)]
    pub backoff_ms: u64,
    /// 🔄 Upstream status codes that trigger redispatch before response commit.
    #[serde(default)]
    pub status_codes: Vec<u16>,
    /// 🛡️ Idempotent methods eligible for status-code redispatch.
    #[serde(default = "default_retry_methods")]
    pub methods: Vec<String>,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_retry_attempts(),
            total_timeout_ms: None,
            backoff_ms: 0,
            status_codes: Vec::new(),
            methods: default_retry_methods(),
        }
    }
}

fn default_retry_attempts() -> usize {
    16
}

fn default_retry_methods() -> Vec<String> {
    ["GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// 🚦 Bounds concurrent work before an upstream request starts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OverloadConfig {
    /// 🧱 Maximum requests executing inside this reverse-proxy route.
    #[serde(default)]
    pub max_in_flight: Option<usize>,
    /// 🕰️ Maximum requests waiting for one route execution slot.
    #[serde(default)]
    pub max_pending: usize,
    /// ⌛ Maximum time a pending request may wait.
    #[serde(default = "default_pending_timeout_ms")]
    pub pending_timeout_ms: u64,
    /// 🔌 Maximum requests simultaneously occupying one selected upstream.
    #[serde(default)]
    pub upstream_max_connections: Option<usize>,
}

impl Default for OverloadConfig {
    fn default() -> Self {
        Self {
            max_in_flight: None,
            max_pending: 0,
            pending_timeout_ms: default_pending_timeout_ms(),
            upstream_max_connections: None,
        }
    }
}

fn default_pending_timeout_ms() -> u64 {
    1_000
}

/// 🔌 Opens a per-upstream circuit after bounded failure evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircuitBreakerConfig {
    /// 🔻 Consecutive failures required to open the circuit.
    #[serde(default)]
    pub consecutive_failures: Option<u32>,
    /// 📉 Failure percentage required to open the circuit.
    #[serde(default)]
    pub error_rate_percent: Option<u8>,
    /// 🧪 Minimum observations required before error-rate evaluation.
    #[serde(default = "default_breaker_minimum_requests")]
    pub minimum_requests: usize,
    /// 🪟 Maximum observations retained in the rolling error window.
    #[serde(default = "default_breaker_window_requests")]
    pub window_requests: usize,
    /// ⏳ Time an open circuit waits before admitting half-open probes.
    #[serde(default = "default_breaker_open_duration_ms")]
    pub open_duration_ms: u64,
    /// 🚪 Successful half-open probes required to close the circuit.
    #[serde(default = "default_breaker_half_open_requests")]
    pub half_open_requests: usize,
    /// 🚨 Response statuses counted as failures; empty means every 5xx status.
    #[serde(default)]
    pub failure_statuses: Vec<u16>,
}

impl CircuitBreakerConfig {
    /// 🔌 Reports whether either opening threshold enables the breaker.
    pub fn enabled(&self) -> bool {
        self.consecutive_failures.is_some() || self.error_rate_percent.is_some()
    }
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            consecutive_failures: None,
            error_rate_percent: None,
            minimum_requests: default_breaker_minimum_requests(),
            window_requests: default_breaker_window_requests(),
            open_duration_ms: default_breaker_open_duration_ms(),
            half_open_requests: default_breaker_half_open_requests(),
            failure_statuses: Vec::new(),
        }
    }
}

fn default_breaker_minimum_requests() -> usize {
    20
}

fn default_breaker_window_requests() -> usize {
    100
}

fn default_breaker_open_duration_ms() -> u64 {
    30_000
}

fn default_breaker_half_open_requests() -> usize {
    1
}

/// 🔐 Describes how a reverse-proxy route speaks TLS to its upstreams.
///
/// Every field is inert unless the connection is actually TLS — either the
/// upstream address carries an `https://`/`h2://` scheme, or [`Self::enable`]
/// forces it. The defaults verify the upstream chain against the system trust
/// store and present no client certificate, which is what a plain
/// `reverse_proxy https://host` already did before this block existed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct UpstreamTlsConfig {
    /// 🔒 Speaks TLS even when the upstream address declares no scheme.
    #[serde(default)]
    pub enable: bool,

    /// 🏷️ Overrides the SNI sent and the name the upstream chain must match.
    ///
    /// Without this the proxy uses the upstream's configured hostname, which is
    /// the correct default; set it only when the address is an IP or an
    /// internal alias that the certificate does not name.
    #[serde(default)]
    pub server_name: Option<String>,

    /// 📜 PEM bundles that **replace** the system trust store for this route.
    ///
    /// Replacement, not addition: naming a private CA here means public CAs no
    /// longer verify for this route. That is deliberate — an internal upstream
    /// should not be satisfiable by a publicly issued certificate.
    #[serde(default)]
    pub trusted_ca_certs: Vec<String>,

    /// 🎫 PEM chain presented to the upstream for mutual TLS.
    #[serde(default)]
    pub client_cert: Option<String>,

    /// 🔑 PEM private key matching [`Self::client_cert`].
    #[serde(default)]
    pub client_key: Option<String>,

    /// ⚠️ Disables upstream certificate and hostname verification.
    ///
    /// This turns the upstream leg into unauthenticated encryption: anything
    /// able to answer on the upstream address is trusted. It exists for
    /// bootstrapping against a self-signed origin; `trusted_ca_certs` is the
    /// correct answer in every other case.
    #[serde(default)]
    pub insecure_skip_verify: bool,
}

impl UpstreamTlsConfig {
    /// 🔍 Reports whether anything here changes the default TLS behaviour.
    ///
    /// A route whose block is entirely defaults needs no compiled state, so the
    /// runtime can keep using the shared system-trust path.
    pub fn is_customized(&self) -> bool {
        self.enable
            || self.server_name.is_some()
            || !self.trusted_ca_certs.is_empty()
            || self.client_cert.is_some()
            || self.client_key.is_some()
            || self.insecure_skip_verify
    }

    /// 🎫 Returns the client certificate and key when mutual TLS is requested.
    ///
    /// Returns an error describing the missing half when only one is present,
    /// because a half-configured client identity silently degrades to an
    /// anonymous handshake and the upstream's rejection looks like a network
    /// fault.
    pub fn client_identity(&self) -> Result<Option<(&str, &str)>, &'static str> {
        match (self.client_cert.as_deref(), self.client_key.as_deref()) {
            (Some(cert), Some(key)) => Ok(Some((cert, key))),
            (None, None) => Ok(None),
            (Some(_), None) => {
                Err("tls_client_auth needs a key file, but only a certificate was configured")
            }
            (None, Some(_)) => {
                Err("tls_client_auth needs a certificate file, but only a key was configured")
            }
        }
    }
}

/// Load balancing configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LoadBalanceConfig {
    /// Strategy: round_robin, random, least_conn, ip_hash, first
    #[serde(default = "default_lb_strategy")]
    pub strategy: String,
}

/// An upstream's selection properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyUpstream {
    /// Dial address, including an optional http/https scheme.
    pub address: String,
    /// Relative selection weight among primary (or backup) peers.
    #[serde(default = "default_upstream_weight")]
    pub weight: u32,
    /// Backup peers are only selected after every primary is unavailable.
    #[serde(default)]
    pub backup: bool,
}

fn default_upstream_weight() -> u32 {
    1
}

/// Route-level IP, Referer-host, and User-Agent access policy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccessControlConfig {
    /// CIDR or literal IP ranges that may access the route.
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// CIDR or literal IP ranges that are always rejected.
    #[serde(default)]
    pub denied_ips: Vec<String>,
    /// Referer hosts that may access the route. `*.example.com` matches
    /// subdomains; an empty Referer does not satisfy a populated allow list.
    #[serde(default)]
    pub allowed_referers: Vec<String>,
    /// Referer hosts that are always rejected.
    #[serde(default)]
    pub denied_referers: Vec<String>,
    /// Regular expressions that may match the User-Agent header.
    #[serde(default)]
    pub allowed_user_agents: Vec<String>,
    /// Regular expressions that always reject the User-Agent header.
    #[serde(default)]
    pub denied_user_agents: Vec<String>,
}

fn default_lb_strategy() -> String {
    "round_robin".to_string()
}

/// 🩺 Active upstream health-check configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// 🛣️ Request path sent to the probe endpoint.
    pub path: String,

    /// ⏲️ Base interval between probe rounds, in seconds.
    #[serde(default = "default_health_interval")]
    pub interval: u64,

    /// ⌛ Hard timeout for one probe, in seconds.
    #[serde(default = "default_health_timeout")]
    pub timeout: u64,

    /// 🧯 Legacy failure threshold retained for JSON compatibility.
    #[serde(default = "default_health_threshold")]
    pub threshold: u32,

    /// 📨 HTTP method used for the probe.
    #[serde(default = "default_health_method")]
    pub method: String,

    /// 🏷️ Optional Host header and TLS server name override.
    #[serde(default)]
    pub host: Option<String>,

    /// 🧾 Additional request headers sent by the probe.
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// ✅ Exact response statuses accepted as healthy.
    #[serde(default = "default_health_statuses")]
    pub expected_statuses: Vec<u16>,

    /// 🔎 Optional UTF-8 response-body fragment required for success.
    #[serde(default)]
    pub expected_body: Option<String>,

    /// 🔌 Optional health endpoint port on each backend IP.
    #[serde(default)]
    pub port: Option<u16>,

    /// 🌱 Consecutive successful probes required before recovery.
    #[serde(default = "default_health_success_threshold")]
    pub consecutive_success: u32,

    /// 🧯 Consecutive failed probes required before removal.
    #[serde(default)]
    pub consecutive_failure: Option<u32>,

    /// ♻️ Whether probes may reuse an established upstream connection.
    #[serde(default)]
    pub reuse_connection: bool,

    /// 🧱 Maximum response-body bytes a probe may read.
    #[serde(default = "default_health_body_limit")]
    pub max_response_body_bytes: usize,

    /// 🌤️ Time in milliseconds for a recovered backend to regain full traffic.
    #[serde(default)]
    pub slow_start_ms: u64,
}

fn default_health_interval() -> u64 {
    30
}

fn default_health_timeout() -> u64 {
    5
}

fn default_health_threshold() -> u32 {
    3
}

fn default_health_method() -> String {
    "GET".to_string()
}

fn default_health_statuses() -> Vec<u16> {
    vec![200]
}

fn default_health_success_threshold() -> u32 {
    1
}

fn default_health_body_limit() -> usize {
    64 * 1024
}

/// Admin API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    /// Listen address
    pub listen: String,

    /// Enable admin API
    #[serde(default = "default_admin_enabled")]
    pub enabled: bool,

    /// API key for authentication
    pub api_key: Option<String>,
}

fn default_admin_enabled() -> bool {
    true
}

/// Global logging configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LoggingConfig {
    /// Log level
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log format (json, pretty)
    #[serde(default = "default_log_format")]
    pub format: String,

    /// Log file path
    pub file: Option<String>,
}

/// Security headers configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityConfig {
    /// Enable basic security headers
    #[serde(default = "default_security_enabled")]
    pub enabled: bool,

    /// X-Frame-Options header
    #[serde(default = "default_x_frame_options")]
    pub x_frame_options: String,

    /// X-Content-Type-Options header
    #[serde(default = "default_x_content_type_options")]
    pub x_content_type_options: String,

    /// X-XSS-Protection header
    #[serde(default = "default_x_xss_protection")]
    pub x_xss_protection: String,

    /// X-Permitted-Cross-Domain-Policies header
    #[serde(default = "default_x_permitted_cross_domain")]
    pub x_permitted_cross_domain: String,

    /// Referrer-Policy header
    #[serde(default = "default_referrer_policy")]
    pub referrer_policy: String,

    /// Permissions-Policy header
    #[serde(default = "default_permissions_policy")]
    pub permissions_policy: String,

    /// Strict-Transport-Security header
    #[serde(default)]
    pub hsts: Option<HstsConfig>,

    /// Content-Security-Policy header
    #[serde(default)]
    pub csp: Option<String>,
}

/// HSTS (HTTP Strict Transport Security) configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HstsConfig {
    /// Max age in seconds
    #[serde(default = "default_hsts_max_age")]
    pub max_age: u64,

    /// Include subdomains
    #[serde(default = "default_hsts_include_subdomains")]
    pub include_subdomains: bool,

    /// Preload directive
    #[serde(default = "default_hsts_preload")]
    pub preload: bool,
}

fn default_security_enabled() -> bool {
    true
}

fn default_x_frame_options() -> String {
    "DENY".to_string()
}

fn default_x_content_type_options() -> String {
    "nosniff".to_string()
}

fn default_x_xss_protection() -> String {
    "1; mode=block".to_string()
}

fn default_x_permitted_cross_domain() -> String {
    "none".to_string()
}

fn default_referrer_policy() -> String {
    "strict-origin-when-cross-origin".to_string()
}

fn default_permissions_policy() -> String {
    "geolocation=(), microphone=(), camera=()".to_string()
}

fn default_hsts_max_age() -> u64 {
    31536000 // 1 year
}

fn default_hsts_include_subdomains() -> bool {
    true
}

fn default_hsts_preload() -> bool {
    false
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "pretty".to_string()
}

/// Per-server log configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Log output destination
    pub output: LogOutput,

    /// Log format
    pub format: LogFormat,

    /// Log level (overrides global)
    pub level: Option<String>,

    /// 🙈 Access-log field names to omit, from
    /// `format filter { fields { <name> delete } }`.
    ///
    /// `#[serde(default)]` so configs written before this field existed
    /// still load.
    #[serde(default)]
    pub exclude_fields: Vec<String>,
}

/// Log output destination
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogOutput {
    File(String),
    Stdout,
    Stderr,
}

/// Log format
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PingclairConfig::default();
        assert!(!config.debug);
        assert!(config.servers.is_empty());
    }

    #[test]
    fn test_json_deserialize() {
        let json = r#"{
            "debug": true,
            "servers": []
        }"#;
        let config: PingclairConfig = serde_json::from_str(json).unwrap();
        assert!(config.debug);
    }

    #[test]
    fn test_server_config() {
        let config = ServerConfig {
            name: Some("example.com".to_string()),
            names: vec!["example.com".to_string()],
            bind: None,
            listen: vec!["127.0.0.1:8080".to_string()],
            proxy_protocol_listen: Vec::new(),
            tls: None,
            routes: vec![],
            log: None,
            client_max_body_size: 1024 * 1024,
            limits: ResourceLimitsConfig::default(),
            security: Default::default(),
            gzip_types: default_gzip_types(),
            encodings: default_encodings(),
            error_pages: Default::default(),
        };
        assert_eq!(config.name, Some("example.com".to_string()));
    }

    #[test]
    fn test_legacy_server_config_receives_default_gzip_types() {
        let config: ServerConfig = serde_json::from_str(r#"{"name":"example.com"}"#).unwrap();
        assert_eq!(config.gzip_types, default_gzip_types());
        assert!(config.gzip_types.contains(&"text/*".to_string()));
        assert_eq!(config.limits, ResourceLimitsConfig::default());
    }

    /// 🗜️ A `0.1.7` JSON config predates the `encodings` field entirely. It
    /// must keep compressing exactly as it did — gzip — rather than silently
    /// losing compression on upgrade.
    #[test]
    fn test_legacy_server_config_keeps_gzip_compression() {
        let config: ServerConfig = serde_json::from_str(r#"{"name":"example.com"}"#).unwrap();
        assert_eq!(config.encodings, vec![Encoding::Gzip]);
    }

    /// An explicitly empty list is `encode off`, and must survive a
    /// round-trip as "no compression" rather than being re-defaulted.
    #[test]
    fn test_empty_encodings_round_trips_as_compression_off() {
        let config: ServerConfig =
            serde_json::from_str(r#"{"name":"example.com","encodings":[]}"#).unwrap();
        assert!(config.encodings.is_empty());

        let round_tripped: ServerConfig =
            serde_json::from_str(&serde_json::to_string(&config).unwrap()).unwrap();
        assert!(round_tripped.encodings.is_empty());
    }

    #[test]
    fn test_encodings_serialize_as_wire_tokens() {
        let json = serde_json::to_string(&vec![Encoding::Zstd, Encoding::Gzip]).unwrap();
        assert_eq!(json, r#"["zstd","gzip"]"#);
    }

    /// `ServerConfig::default()` must agree with deserializing `{}` — a
    /// derived `Default` silently disagrees with the `#[serde(default = ...)]`
    /// attributes and hands out an unlimited body limit and no compression.
    #[test]
    fn test_default_matches_deserializing_an_empty_object() {
        let defaulted = ServerConfig::default();
        let deserialized: ServerConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(
            defaulted.client_max_body_size,
            deserialized.client_max_body_size
        );
        assert_eq!(defaulted.client_max_body_size, 1024 * 1024);
        assert_eq!(defaulted.encodings, deserialized.encodings);
        assert_eq!(defaulted.gzip_types, deserialized.gzip_types);
    }

    #[test]
    fn test_reverse_proxy_config() {
        let config = ReverseProxyConfig {
            upstreams: vec!["http://localhost:3000".to_string()],
            flush_interval: Some(-1),
            ..Default::default()
        };
        assert_eq!(config.flush_interval, Some(-1));
    }

    #[test]
    fn legacy_reverse_proxy_json_keeps_timeout_behavior() {
        let config: ReverseProxyConfig =
            serde_json::from_str(r#"{"upstreams":["127.0.0.1:9000"],"read_timeout":250}"#).unwrap();
        assert_eq!(config.read_timeout, Some(250));
        assert_eq!(config.connect_timeout, None);
        assert_eq!(config.first_byte_timeout, None);
        assert_eq!(config.between_reads_timeout, None);
        assert_eq!(*config.retry, RetryConfig::default());
        assert_eq!(config.retry.max_attempts, 16);
        assert!(config.retry.status_codes.is_empty());
        assert_eq!(*config.overload, OverloadConfig::default());
        assert_eq!(*config.circuit_breaker, CircuitBreakerConfig::default());
    }

    #[test]
    fn test_global_http3_defaults_to_true() {
        assert!(GlobalConfig::default().http3);
        assert!(GlobalConfig::default().trusted_proxies.is_empty());

        // Configs written before the switch existed must keep H3 enabled.
        let legacy: GlobalConfig = serde_json::from_str(r#"{"email":null}"#).unwrap();
        assert!(legacy.http3);

        let disabled: GlobalConfig = serde_json::from_str(r#"{"http3":false}"#).unwrap();
        assert!(!disabled.http3);
    }

    // ---- Matcher serialization ----

    fn round_trip(matcher: &Matcher) -> Matcher {
        let json = serde_json::to_string(matcher).expect("serialize");
        serde_json::from_str(&json).unwrap_or_else(|error| panic!("{json}: {error}"))
    }

    fn path(pattern: &str) -> Matcher {
        Matcher::Path {
            patterns: vec![pattern.to_string()],
        }
    }

    #[test]
    fn every_matcher_survives_a_json_round_trip() {
        let condition = MatcherCondition::Equals("v".into());
        for matcher in [
            path("/api/*"),
            Matcher::Header {
                name: "X-Test".into(),
                condition: condition.clone(),
            },
            Matcher::Method {
                methods: vec!["GET".into()],
            },
            Matcher::Query {
                name: "q".into(),
                condition: condition.clone(),
            },
            Matcher::Host(vec!["example.com".into()]),
            Matcher::RemoteIp(vec!["10.0.0.1".into()]),
            Matcher::Protocol(vec!["https".into()]),
            Matcher::And(Box::new(path("/a")), Box::new(path("/b"))),
            Matcher::Or(Box::new(path("/a")), Box::new(path("/b"))),
            Matcher::Not(Box::new(path("/admin/*"))),
        ] {
            assert_eq!(round_trip(&matcher), matcher, "{matcher:?}");
        }
    }

    #[test]
    fn a_negation_is_not_lost_in_the_round_trip() {
        // The specific failure that motivated the tagged representation: an
        // untagged `Not` serialized as its own inner matcher, so `not path
        // /admin/*` came back as `path /admin/*` — the exact inversion of the
        // decision the operator wrote down.
        let matcher = Matcher::Not(Box::new(path("/admin/*")));
        let json = serde_json::to_string(&matcher).unwrap();

        assert_eq!(json, r#"{"not":{"path":{"patterns":["/admin/*"]}}}"#);
        assert!(
            matches!(round_trip(&matcher), Matcher::Not(_)),
            "the negation must still be there"
        );
    }

    #[test]
    fn matchers_that_share_a_payload_shape_stay_distinct() {
        // Each pair was indistinguishable under the untagged representation:
        // the first of the two always won on the way back in.
        let condition = MatcherCondition::Exists;
        let query = Matcher::Query {
            name: "q".into(),
            condition: condition.clone(),
        };
        let header = Matcher::Header {
            name: "q".into(),
            condition,
        };
        assert_eq!(round_trip(&query), query);
        assert_eq!(round_trip(&header), header);
        assert_ne!(round_trip(&query), header);

        let or = Matcher::Or(Box::new(path("/a")), Box::new(path("/b")));
        let and = Matcher::And(Box::new(path("/a")), Box::new(path("/b")));
        assert!(matches!(round_trip(&or), Matcher::Or(..)));
        assert!(matches!(round_trip(&and), Matcher::And(..)));

        let addresses = vec!["10.0.0.1".to_string()];
        assert!(matches!(
            round_trip(&Matcher::RemoteIp(addresses.clone())),
            Matcher::RemoteIp(_)
        ));
        assert!(matches!(
            round_trip(&Matcher::Protocol(addresses.clone())),
            Matcher::Protocol(_)
        ));
        assert!(matches!(
            round_trip(&Matcher::Host(addresses)),
            Matcher::Host(_)
        ));
    }

    #[test]
    fn deeply_nested_matchers_round_trip() {
        let matcher = Matcher::Not(Box::new(Matcher::And(
            Box::new(Matcher::Or(
                Box::new(path("/a")),
                Box::new(Matcher::Not(Box::new(Matcher::Host(vec![
                    "example.com".into(),
                ])))),
            )),
            Box::new(Matcher::Not(Box::new(Matcher::Method {
                methods: vec!["POST".into()],
            }))),
        )));

        assert_eq!(round_trip(&matcher), matcher);
    }

    #[test]
    fn legacy_untagged_configs_still_load() {
        // Every shape a `0.1.7` config could actually hold. These must keep
        // loading unchanged, tag or no tag.
        let cases: [(&str, Matcher); 5] = [
            (r#"{"patterns":["/api/*"]}"#, path("/api/*")),
            (
                r#"{"methods":["GET","POST"]}"#,
                Matcher::Method {
                    methods: vec!["GET".into(), "POST".into()],
                },
            ),
            (
                r#"{"name":"X-Test","condition":{"equals":"v"}}"#,
                Matcher::Header {
                    name: "X-Test".into(),
                    condition: MatcherCondition::Equals("v".into()),
                },
            ),
            (
                r#"["example.com","www.example.com"]"#,
                Matcher::Host(vec!["example.com".into(), "www.example.com".into()]),
            ),
            (
                r#"[{"patterns":["/a"]},{"patterns":["/b"]}]"#,
                Matcher::And(Box::new(path("/a")), Box::new(path("/b"))),
            ),
        ];

        for (json, expected) in cases {
            let parsed: Matcher =
                serde_json::from_str(json).unwrap_or_else(|e| panic!("{json}: {e}"));
            assert_eq!(parsed, expected, "{json}");
        }
    }

    #[test]
    fn a_legacy_shape_keeps_the_reading_it_always_had() {
        // `{name, condition}` was written by both `Header` and `Query`, and
        // `0.1.7` read it as a `Header`. Re-reading it as a `Query` now would
        // silently change how an existing config routes; the tagged form is
        // how an author says which one they meant.
        let legacy: Matcher = serde_json::from_str(r#"{"name":"q","condition":"exists"}"#).unwrap();
        assert!(matches!(legacy, Matcher::Header { .. }));

        let tagged: Matcher =
            serde_json::from_str(r#"{"query":{"name":"q","condition":"exists"}}"#).unwrap();
        assert!(matches!(tagged, Matcher::Query { .. }));
    }

    #[test]
    fn an_unrecognised_matcher_does_not_blow_the_stack() {
        // Regression, and the reason this is more than a correctness fix.
        //
        // `Not(Box<Matcher>)` was a *newtype* variant of an untagged enum, so
        // testing it meant deserializing the whole payload as a `Matcher`
        // again — with no input consumed. Any value that matched no other
        // variant therefore recursed forever, and since serde's untagged
        // replay does not go back through serde_json's parser, serde_json's
        // own recursion limit never saw it. A single unrecognised matcher
        // posted to the Admin API aborted the process with a stack overflow.
        //
        // The tagged form terminates because the tag selects one variant, and
        // the legacy fallback only recurses through a sequence, which always
        // consumes input.
        assert!(serde_json::from_str::<Matcher>(r#"{"nonsense":["/x"]}"#).is_err());

        // Deep nesting must still be refused rather than ridden all the way
        // down: serde_json caps parse depth, and every recursion here costs
        // one array level.
        let deep = format!("{}{}", "[".repeat(400), "]".repeat(400));
        assert!(serde_json::from_str::<Matcher>(&deep).is_err());
    }

    #[test]
    fn a_matcher_that_is_neither_form_is_rejected() {
        // Fail closed: an unreadable matcher must not degrade into one that
        // matches everything.
        for json in [
            r#"{"nope":{"patterns":["/a"]}}"#,
            r#"{"path":{"wrong_field":[]}}"#,
            r#""just-a-string""#,
            r#"42"#,
        ] {
            assert!(
                serde_json::from_str::<Matcher>(json).is_err(),
                "{json} should not parse"
            );
        }
    }

    #[test]
    fn matchers_round_trip_through_toml_too() {
        // The loader accepts TOML as well as JSON, and external tagging has
        // to survive both.
        let config = PingclairConfig {
            servers: vec![ServerConfig {
                name: Some("example.com".into()),
                routes: vec![RouteConfig {
                    path: "/*".into(),
                    handler: HandlerConfig::Respond {
                        status: 200,
                        body: None,
                        headers: HashMap::new(),
                    },
                    methods: None,
                    matcher: Some(Matcher::Not(Box::new(path("/admin/*")))),
                }],
                ..Default::default()
            }],
            ..Default::default()
        };

        let toml_text = toml::to_string(&config).expect("serialize TOML");
        let parsed: PingclairConfig = toml::from_str(&toml_text).expect("parse TOML");

        assert_eq!(
            parsed.servers[0].routes[0].matcher.as_ref().unwrap(),
            &Matcher::Not(Box::new(path("/admin/*"))),
            "\n{toml_text}"
        );
    }
}
