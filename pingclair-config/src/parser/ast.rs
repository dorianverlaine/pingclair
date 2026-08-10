// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌳 Abstract syntax tree for the Pingclair configuration DSL.
//!
//! This module defines every node produced by the parser.

use crate::parser::lexer::Location;
use pingclair_core::config::BasicAuthAlgorithm;
use std::collections::{BTreeMap, HashMap};

/// A node with source location information
#[derive(Debug, Clone, PartialEq)]
pub struct Node<T> {
    pub inner: T,
    pub span: Location,
}

impl<T> Node<T> {
    pub fn new(inner: T, span: Location) -> Self {
        Self { inner, span }
    }
}

/// 🌐 Root AST node representing an entire configuration.
#[derive(Debug, Clone, Default)]
pub struct Ast {
    /// Global configuration block
    pub global: Option<Node<GlobalBlock>>,

    /// Macro definitions
    pub macros: Vec<Node<MacroDef>>,

    /// Server definitions
    pub servers: Vec<Node<ServerBlock>>,
}

// ============================================================
// Global Configuration
// ============================================================

/// Global configuration block
#[derive(Debug, Clone, Default)]
pub struct GlobalBlock {
    pub protocols: Vec<Protocol>,
    pub debug: Option<bool>,
    pub logging: Option<LoggingConfig>,
    pub email: Option<String>,
    /// 🌐 Plaintext HTTP port override (Caddy `http_port`).
    pub http_port: Option<u16>,
    /// 🔐 HTTPS port override (Caddy `https_port`).
    pub https_port: Option<u16>,
    /// 🚰 How long shutdown waits for in-flight requests (Caddy `grace_period`).
    pub grace_period_secs: Option<u64>,
    /// 📊 Metrics toggle (Caddy `metrics`).
    pub metrics: Option<bool>,
    pub auto_https: Option<AutoHttpsMode>,
    pub admin: Option<AdminDirective>,
    /// 🔐 Caddy's global `local_certs` toggle: default automation uses the
    /// built-in local authority instead of public ACME.
    pub local_certs: bool,
    /// 💾 Caddy's `persist_config off` toggle. Pingclair never persists the
    /// admin config, so the only accepted spelling is the one that matches
    /// the behaviour we already have.
    pub persist_config_off: bool,
    /// 🛡️ Proxy IP or CIDR ranges allowed to supply client identity headers.
    pub trusted_proxies: Vec<String>,
    /// 🔄 Upstream re-resolution interval in seconds; `Some(0)` disables it.
    /// `None` means the directive was absent and the default applies.
    pub dns_refresh_secs: Option<u64>,
    /// 🏷️ Server name assumed when a client sends no SNI, for every site that
    /// does not name its own.
    pub default_sni: Option<String>,
    /// 📡 The DNS provider named by the global `dns` option.
    pub dns: Option<pingclair_core::config::DnsProviderConfig>,
    /// 📡 The global `acme_dns` option. `Some(None)` is the bare spelling,
    /// which means "use the provider `dns` named" — a different answer from
    /// "not asked for", and only one of the two is an error without `dns`.
    pub acme_dns: Option<Option<pingclair_core::config::DnsProviderConfig>>,
    /// 🔎 Resolvers every DNS-01 propagation check asks (`tls_resolvers`).
    pub tls_resolvers: Vec<String>,
    pub directives: Vec<Directive>,
}

/// Admin API configuration (from the global `admin` directive)
#[derive(Debug, Clone)]
pub struct AdminDirective {
    /// Listen address (e.g. "127.0.0.1:2019")
    pub listen: String,

    /// Enable the admin API (`admin off` disables it)
    pub enabled: bool,

    /// Bearer token required for admin API requests
    pub api_key: Option<String>,

    /// 🌐 Origins allowed to reach the admin API.
    pub origins: Vec<String>,

    /// 🛡️ Enforce the origin check even for loopback callers.
    pub enforce_origin: bool,
}

/// Auto-HTTPS modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoHttpsMode {
    On,
    Off,
    DisableRedirects,
}

/// Protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    H1,
    H2,
    H3,
}

// ============================================================
// Macros
// ============================================================

/// Macro definition
#[derive(Debug, Clone)]
pub struct MacroDef {
    /// Macro name (without !)
    pub name: String,

    /// Parameters: ($name: type)
    pub params: Vec<MacroParam>,

    /// Body directives
    pub body: Vec<Directive>,
}

/// Macro parameter
#[derive(Debug, Clone)]
pub struct MacroParam {
    pub name: String,
    pub ty: Option<String>, // Optional type annotation
}

/// Macro invocation
#[derive(Debug, Clone)]
pub struct MacroCall {
    /// Macro name (without !)
    pub name: String,

    /// Arguments
    pub args: Vec<Expr>,
}

// ============================================================
// Server Block
// ============================================================

/// Server block definition
#[derive(Debug, Clone)]
pub struct ServerBlock {
    /// Server name / hostname
    pub name: String,

    /// 🏠 Every hostname this site serves. A Caddy site block may list
    /// several addresses (`example.com, www.example.com`) that share one
    /// configuration; the runtime registers each name as a virtual host.
    pub names: Vec<String>,

    /// Listen addresses
    pub listens: Vec<ListenAddr>,

    /// Bind address
    pub bind: Option<String>,

    /// 📂 Site root set by the `root` directive; `file_server` handlers that
    /// do not name their own root inherit this path.
    pub root: Option<String>,

    /// Content codings from the `encode` directive, in the order written —
    /// that order is the server's preference when negotiating.
    ///
    /// `None` means the directive was absent (inherit the default), which is
    /// a different thing from `Some(vec![])`, meaning `encode off`.
    pub compress: Option<Vec<CompressionAlgo>>,

    /// 🗜️ MIME patterns eligible for reverse-proxy gzip compression.
    pub gzip_types: Vec<String>,

    /// Log configuration
    pub log: Option<Node<LogBlock>>,

    /// 🪵 Global channel names this server also writes to (`log <name>`).
    pub log_channels: Vec<String>,

    /// 🪵 Named per-site access loggers from `log <name> { … }`.
    pub named_logs: Vec<Node<LogBlock>>,

    /// TLS configuration (from the `tls` directive)
    pub tls: Option<TlsDirective>,

    /// Route definitions
    pub routes: Option<Node<RouteBlock>>,

    /// Named matcher definitions
    pub matchers: HashMap<String, Matcher>,

    /// Custom error pages: HTTP status code → file path (`error_page` directive)
    pub error_pages: Vec<(u16, String)>,

    /// 🚨 Status-selective error routes from `handle_errors` blocks.
    pub error_routes: Vec<ErrorRouteConfig>,

    /// 🧰 Site-level `vars` rules, least specific first.
    pub vars_routes: Vec<VarsRule>,

    /// Other directives (including macro calls)
    pub directives: Vec<Directive>,

    /// 🧱 Downstream time, size, connection, and bandwidth bounds.
    pub limits: ResourceLimitsConfig,
}

/// 🚨 One `handle_errors [<codes…>]` block, adapted to a status-selective
/// error route whose handlers run like a route body.
#[derive(Debug, Clone)]
pub struct ErrorRouteConfig {
    /// Exact status codes; empty means the catch-all error route.
    pub codes: Vec<u16>,
    /// `Nxx` ranges (`4xx` selects 400..=499) when the block wrote them.
    pub hundreds: Vec<u8>,
    /// 🧭 Matcher-guarded handlers in file order.
    pub handlers: Vec<HandlerElement>,
}

/// 🧰 One site-level `vars [<matcher>] <name> <value>` rule.
#[derive(Debug, Clone)]
pub struct VarsRule {
    /// Optional matcher; `None` runs for every request.
    pub matcher: Option<Matcher>,
    /// 🧩 Variable names to values.
    pub values: BTreeMap<String, String>,
}

/// 🧱 Typed server resource limits produced by the Caddyfile adapter.
#[derive(Debug, Clone, Default)]
pub struct ResourceLimitsConfig {
    pub header_timeout_ms: Option<u64>,
    pub body_timeout_ms: Option<u64>,
    pub idle_timeout_ms: Option<u64>,
    pub request_timeout_ms: Option<u64>,
    pub max_header_count: Option<usize>,
    pub max_header_bytes: Option<usize>,
    pub max_connections: Option<usize>,
    pub upload_bytes_per_sec: Option<u64>,
    pub download_bytes_per_sec: Option<u64>,
    pub long_connections: LongConnectionLimits,
}

/// 🌊 Typed overrides for SSE, immediate-flush, and WebSocket traffic.
#[derive(Debug, Clone, Default)]
pub struct LongConnectionLimits {
    pub idle_timeout_ms: Option<u64>,
    pub request_timeout_ms: Option<u64>,
}

/// 🔐 Represents downstream TLS configuration from a server directive.
#[derive(Debug, Clone, Default)]
pub struct TlsDirective {
    /// 📴 Explicitly disables TLS through `tls off`.
    pub off: bool,

    /// 🌐 Enables automatic public certificate management through `tls auto`.
    pub auto: bool,

    /// 🏛️ Enables certificates signed by Pingclair's persistent local authority.
    pub internal: bool,

    /// 📜 Identifies the certificate file path.
    pub cert: Option<String>,

    /// 🔑 Identifies the private key file path.
    pub key: Option<String>,

    /// 📧 Identifies the ACME account email.
    pub acme_email: Option<String>,

    /// 🚀 Overrides HTTP/3 for this server.
    pub http3: Option<bool>,

    /// 🏷️ The server name assumed when a client sends no SNI.
    pub default_sni: Option<String>,

    /// 🪪 Mutual TLS: what to ask of the client's own certificate.
    pub client_auth: Option<pingclair_core::config::ClientAuthConfig>,

    /// 📡 DNS-01 settings. Present means this site asks for the DNS challenge
    /// rather than HTTP-01 — which a wildcard site has no alternative to.
    pub dns_challenge: Option<pingclair_core::config::DnsChallengeConfig>,
}

/// Listen address
#[derive(Debug, Clone)]
pub struct ListenAddr {
    pub scheme: Scheme,
    pub host: String,
    pub port: Option<u16>,
    /// 📴 Forces this exact listener to remain plaintext because the site
    /// address explicitly used `http://`. The compiler applies `tls off` to
    /// every listener after this address-level policy is collected.
    pub force_plaintext: bool,
    /// 🧭 Requires a PROXY protocol header on this listener, as nginx spells
    /// `listen 443 proxy_protocol`. It is per-listener because a deployment
    /// commonly has one port behind an L4 balancer and another reached
    /// directly; a single global switch would break the direct one.
    pub proxy_protocol: bool,
}

/// URL scheme
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

/// Compression algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgo {
    Gzip,
    Br,
    Zstd,
}

// ============================================================
// Logging
// ============================================================

/// Logging configuration (global)
#[derive(Debug, Clone, Default)]
pub struct LoggingConfig {
    pub level: LogLevel,
    pub format: LogFormat,
    /// 🪵 Named channels from `log <name> { … }` in the global block.
    pub channels: BTreeMap<String, LogBlock>,
    /// 🪵 Default logger from an unnamed global `log { … }` block.
    pub default: Option<LogBlock>,
}

/// Log level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

/// Log block (per-server)
#[derive(Debug, Clone)]
pub struct LogBlock {
    /// 🔖 Logger name from `log <name> { … }`; `None` for the site's default
    /// access logger.
    pub name: Option<String>,
    /// 🔄 File rotation policy from `roll { … }`.
    pub rotation: LogRotationBlock,
    /// 🏷️ Header names to record, from `format filter { headers { … } }`.
    pub request_headers: Vec<String>,
    pub response_headers: Vec<String>,
    /// 🔐 Record negotiated TLS version and cipher.
    pub include_tls: bool,
    pub output: LogOutput,
    pub format: LogFormat,
    /// 🚦 Minimum level for this server's access log, when configured.
    pub level: Option<LogLevel>,
    /// 🏠 Hostnames this logger serves, from `log { hostnames … }`.
    pub hostnames: Vec<String>,
    /// 🔌 Log sources this logger accepts, from global `log { include … }`.
    pub include: Vec<String>,
    /// 🚫 Log sources this logger excludes, from global `log { exclude … }`.
    pub exclude: Vec<String>,
    /// 🎲 Sampling policy from `log { sampling { … } }`.
    pub sampling: Option<LogSampling>,
}

/// 🎲 Sampling policy declared by a `sampling` block.
#[derive(Debug, Clone, Copy)]
pub struct LogSampling {
    pub interval_secs: u64,
    pub first: usize,
    pub thereafter: usize,
}

/// 🔄 Typed `roll` policy produced by the adapter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogRotationBlock {
    pub max_size_bytes: Option<u64>,
    pub max_age_secs: Option<u64>,
    pub keep: Option<usize>,
    pub compress: bool,
    pub mode: Option<String>,
    pub dir_mode: Option<String>,
    pub roll_local_time: bool,
    pub roll_interval_secs: Option<u64>,
    pub roll_at: Option<String>,
    pub roll_minutes: Option<String>,
    pub roll_compression: Option<String>,
}

impl LogRotationBlock {
    /// Whether any rotation trigger was written.
    pub fn is_enabled_block(&self) -> bool {
        self.max_size_bytes.is_some() || self.max_age_secs.is_some()
    }
}

/// Log output destination
#[derive(Debug, Clone)]
pub enum LogOutput {
    File(String),
    Stdout,
    Stderr,
}

/// Log format
#[derive(Debug, Clone, Default)]
pub struct LogFormat {
    pub format_type: LogFormatType,
    pub filter: Option<LogFilter>,
}

/// Log format type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormatType {
    #[default]
    Text,
    Json,
}

/// Log filter
#[derive(Debug, Clone, Default)]
pub struct LogFilter {
    pub exclude: Vec<String>,
}

// ============================================================
// Routing
// ============================================================

/// Route block containing match arms
#[derive(Debug, Clone)]
pub struct RouteBlock {
    pub arms: Vec<Node<RouteArm>>,
}

/// A single route match arm
#[derive(Debug, Clone)]
pub struct RouteArm {
    /// Match condition (None = default/wildcard `_`)
    pub matcher: Option<Matcher>,

    /// Handler for this route
    pub handler: Handler,
}

/// Route matcher
#[derive(Debug, Clone)]
pub enum Matcher {
    /// Match by path pattern: path("/api/*")
    Path(PathMatcher),

    /// Match by header: header("X-Foo", exists) or header("X-Foo", "value")
    Header(HeaderMatcher),

    /// Match by method: method(GET | POST)
    Method(Vec<HttpMethod>),

    /// Match by query parameter
    Query(QueryMatcher),

    /// Match by host: host("example.com" | "*.example.com")
    Host(Vec<String>),

    /// Match by remote IP: remote_ip("1.2.3.4" | "192.168.1.0/24")
    RemoteIp(Vec<String>),

    /// Match by protocol: protocol("https" | "http")
    Protocol(Vec<String>),

    /// Match by request-scoped variable: vars("name", "value" | ...)
    Vars { name: String, values: Vec<String> },

    /// Match the request path against a regular expression; an optional name
    /// makes captures readable as `{re.<name>.N}` placeholders.
    PathRegexp {
        name: Option<String>,
        pattern: String,
    },

    /// Match a header against a regular expression; an optional name makes
    /// captures readable as `{re.<name>.N}` placeholders.
    HeaderRegexp {
        name: Option<String>,
        field: String,
        pattern: String,
    },

    /// 📂 Match by file existence: `file { try_files …; split_path … }`.
    File {
        /// URI candidates tried in order; `{path}` expands per request.
        try_files: Vec<String>,
        /// Filesystem root; `None` inherits the site root at compile time.
        root: Option<String>,
        /// Selection policy; `None` means `first_exist`.
        try_policy: Option<String>,
        /// ASCII path split delimiters.
        split_path: Vec<String>,
    },

    /// Combined matchers with AND
    And(Box<Matcher>, Box<Matcher>),

    /// Combined matchers with OR
    Or(Box<Matcher>, Box<Matcher>),

    /// Negated matcher
    Not(Box<Matcher>),

    /// Named matcher reference: @api
    Named(String),
}

/// Path matcher
#[derive(Debug, Clone)]
pub struct PathMatcher {
    /// Path patterns (can be multiple with |)
    pub patterns: Vec<String>,
}

/// Header matcher
#[derive(Debug, Clone)]
pub struct HeaderMatcher {
    pub name: String,
    pub condition: HeaderCondition,
}

/// Header match condition
#[derive(Debug, Clone)]
pub enum HeaderCondition {
    Exists,
    Equals(String),
    Contains(String),
    StartsWith(String),
    EndsWith(String),
    Regex(String),
}

/// Query parameter matcher
#[derive(Debug, Clone)]
pub struct QueryMatcher {
    pub name: String,
    pub condition: HeaderCondition, // Reuse same conditions
}

/// HTTP methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
}

// ============================================================
// Handlers
// ============================================================

/// 🧭 One matcher-guarded element inside a `route`/`handle`/`handle_path`
/// block, mirroring the core config type.
#[derive(Debug, Clone)]
pub struct HandlerElement {
    /// 🎯 Optional matcher; `None` runs the handler for every request.
    pub matcher: Option<Matcher>,
    /// 🧩 The guarded handler.
    pub handler: Handler,
}

/// Route handler
#[derive(Debug, Clone)]
pub enum Handler {
    /// Reverse proxy
    Proxy(Box<ProxyConfig>),

    /// 🧭 Wraps the response of later handlers with response handlers.
    Intercept(Vec<pingclair_core::config::ResponseHandlerConfig>),

    /// 🔐 Caddy's `forward_auth` shortcut: one auth round trip, then continue.
    ForwardAuth(pingclair_core::config::ForwardAuthConfig),

    /// Static response
    Respond(ResponseConfig),

    /// Redirect
    Redirect(RedirectConfig),

    /// Headers modification only
    Headers(HeadersConfig),

    /// 🚫 Excludes the request from access logging (`log_skip`).
    LogSkip,

    /// 🧰 Sets request-scoped variables (`vars` handler).
    Vars(VarsConfig),

    /// Multiple matcher-guarded elements (pipeline, file order preserved)
    Pipeline(Vec<HandlerElement>),

    /// File server (future)
    FileServer(FileServerConfig),

    /// Caddy-compatible template rendering
    Templates,

    /// Exclusive routing group of matcher-guarded elements (sorted)
    Handle(Vec<HandlerElement>),

    /// 🛣️ Exclusive routing group that strips the matched prefix first.
    ///
    /// The prefix is the same path the group matches on, which is why it is
    /// stored rather than derived: by the time a handler runs, the matcher is
    /// somewhere else entirely.
    HandlePath {
        prefix: String,
        handlers: Vec<HandlerElement>,
    },

    /// HTTP Basic authentication gate
    BasicAuth(BasicAuthConfig),

    /// 🚦 Exact local rate-limit policy.
    RateLimit(RateLimitConfig),

    /// Internal URI rewrite.
    Rewrite(RewriteConfig),

    /// 🗂️ Rewrite to the first candidate path that exists on disk.
    TryFiles(Vec<String>),

    /// Cross-origin resource sharing policy.
    Cors(CorsConfig),

    /// 🚨 Static error response: the status this handler raises.
    Error(ErrorConfig),

    /// IP, Referer-host, and User-Agent access policy.
    AccessControl(AccessControlConfig),

    /// Plugin invocation
    Plugin { name: String, args: Vec<Expr> },
}

/// 🔐 Basic authentication configuration.
#[derive(Debug, Clone)]
pub struct BasicAuthConfig {
    /// 🪪 Realm shown in the `WWW-Authenticate` challenge.
    pub realm: Option<String>,

    /// 🔑 Hash algorithm every credential in this block declares.
    pub algorithm: BasicAuthAlgorithm,

    /// 🔑 Username and password-hash pairs, one per block line.
    pub credentials: Vec<(String, String)>,
}

/// 🚦 Typed rate-limit policy produced by the Pingclairfile adapter.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests: u64,
    pub window_ms: u64,
    pub burst: u64,
    pub key: RateLimitKey,
    pub dry_run: bool,
}

/// 🔑 Selects the request identity charged by a rate-limit policy.
#[derive(Debug, Clone)]
pub enum RateLimitKey {
    Ip,
    Global,
    Route,
    ApiKey,
    Header(String),
    Tenant(String),
}

/// Proxy configuration
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Upstream URLs
    pub upstreams: Vec<String>,

    /// 🧭 DNS-driven upstream discovery; when present the fixed list is
    /// usually empty, but the two may coexist.
    pub dynamic: Option<pingclair_core::config::DynamicUpstreamConfig>,

    /// 🧭 Request method change applied before proxying.
    pub rewrite_method: Option<String>,

    /// 🧭 URI template applied to the upstream request target.
    pub rewrite_uri: Option<String>,

    /// 🧱 Request body buffer ceiling in bytes (`-1` unlimited).
    pub request_buffer_bytes: Option<i64>,

    /// 🧱 Response body buffer ceiling in bytes (`-1` unlimited).
    pub response_buffer_bytes: Option<i64>,

    /// 🧭 Transport tuning options without a runtime equivalent.
    pub transport_options: BTreeMap<String, String>,

    /// 🧵 FastCGI transport selected by `transport fastcgi` or
    /// `php_fastcgi`; `None` means the HTTP transports.
    pub fastcgi: Option<pingclair_core::config::FastCgiTransportConfig>,

    /// 🧭 Response handlers evaluated before the client sees the response.
    pub handle_response: Vec<pingclair_core::config::ResponseHandlerConfig>,

    /// Per-upstream options, including weighted and backup peers.
    pub upstream_options: Vec<ProxyUpstreamConfig>,

    /// Load-balancing strategy selected by `lb_policy`.
    pub lb_policy: Option<String>,

    /// 🔑 Field name hashed by the `header`／`cookie`／`query` strategies.
    pub lb_hash_key: Option<String>,

    /// 🩺 Active health-check policy for this upstream pool.
    pub health_check: Option<HealthCheckConfig>,

    /// Flush interval
    pub flush_interval: Option<FlushInterval>,

    /// Headers to add to upstream request
    pub header_up: BTreeMap<String, Expr>,

    /// Transport configuration
    pub transport: Option<TransportConfig>,

    /// 🗄️ Response caching for this route, absent unless configured.
    pub cache: Option<CacheConfig>,

    /// 🔁 Request-local redispatch policy.
    pub retry: RetryConfig,

    /// 🚦 Route and per-upstream admission limits.
    pub overload: OverloadConfig,

    /// 🔌 Per-upstream circuit-breaker policy.
    pub circuit_breaker: CircuitBreakerConfig,

    /// Macro calls (use xxx!())
    pub macro_calls: Vec<MacroCall>,
}

/// A reverse-proxy upstream declared with a `to` block.
#[derive(Debug, Clone)]
pub struct ProxyUpstreamConfig {
    pub address: String,
    pub weight: u32,
    pub backup: bool,
}

/// 🩺 Typed active health-check policy produced by the Pingclairfile adapter.
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    pub path: String,
    pub interval_secs: u64,
    pub timeout_secs: u64,
    pub method: String,
    pub host: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub expected_statuses: Vec<u16>,
    pub expected_body: Option<String>,
    pub port: Option<u16>,
    pub consecutive_success: u32,
    pub consecutive_failure: u32,
    pub reuse_connection: bool,
    pub max_response_body_bytes: usize,
    pub slow_start_ms: u64,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            interval_secs: 30,
            timeout_secs: 5,
            method: "GET".to_string(),
            host: None,
            headers: BTreeMap::new(),
            expected_statuses: vec![200],
            expected_body: None,
            port: None,
            consecutive_success: 1,
            consecutive_failure: 3,
            reuse_connection: false,
            max_response_body_bytes: 64 * 1024,
            slow_start_ms: 0,
        }
    }
}

/// Rewrite configuration. A two-argument `rewrite` directive is a regex
/// rewrite; the replacement follows Rust-regex `$1` capture syntax.
///
/// 📌 Every field is optional and unset means "do not touch", so `Default` is
/// the identity rewrite. That is what lets each `uri` operation name only the
/// field it is about instead of spelling out four `None`s it has no opinion on.
#[derive(Debug, Clone)]
pub struct RewriteConfig {
    /// 🪚 Remove this prefix from the path. Only `uri strip_prefix` sets it.
    pub strip_prefix: Option<String>,
    /// 🪚 Remove this suffix from the path. Only `uri strip_suffix` sets it.
    pub strip_suffix: Option<String>,
    pub replace: Option<String>,
    pub regex: Option<String>,
    pub regex_replace: Option<String>,
    /// 🏷️ Which directive produced this rewrite, `rewrite` or `uri`.
    ///
    /// Both compile to the same handler, and the shared directive order runs
    /// them in adjacent but distinct positions — `rewrite`, then `uri`. Without
    /// this the two would tie, and a site writing `uri` above `rewrite` would
    /// execute them in the order written rather than the order the format
    /// defines. Nothing else reads it.
    pub directive: &'static str,
}

impl Default for RewriteConfig {
    fn default() -> Self {
        Self {
            strip_prefix: None,
            strip_suffix: None,
            replace: None,
            regex: None,
            regex_replace: None,
            directive: "rewrite",
        }
    }
}

/// CORS policy declared by the `cors` directive.
#[derive(Debug, Clone, Default)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub exposed_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age: Option<u64>,
}

/// Route access policy declared by the `access_control` directive.
#[derive(Debug, Clone, Default)]
pub struct AccessControlConfig {
    pub allowed_ips: Vec<String>,
    pub denied_ips: Vec<String>,
    pub allowed_referers: Vec<String>,
    pub denied_referers: Vec<String>,
    pub allowed_user_agents: Vec<String>,
    pub denied_user_agents: Vec<String>,
}

/// Flush interval
#[derive(Debug, Clone, Copy)]
pub enum FlushInterval {
    Immediate,     // -1 in Caddy
    Duration(u64), // milliseconds
}

/// Transport configuration
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// 🔌 Connection-establishment timeout in milliseconds.
    pub connect_timeout: Option<u64>,
    /// ⏱️ Response-header timeout in milliseconds.
    pub first_byte_timeout: Option<u64>,
    /// 🌊 Between-response-read timeout in milliseconds.
    pub between_reads_timeout: Option<u64>,
    pub read_timeout: Option<u64>,  // milliseconds
    pub write_timeout: Option<u64>, // milliseconds
    /// 🔐 Upstream TLS trust, identity, and SNI for this transport.
    pub tls: UpstreamTlsConfig,
}

/// 🔐 Upstream TLS settings collected from a `transport http` block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpstreamTlsConfig {
    /// 🔒 `tls` — speak TLS regardless of the upstream address scheme.
    pub enable: bool,
    /// 🏷️ `tls_server_name <name>` — SNI and verification name override.
    pub server_name: Option<String>,
    /// 📜 `tls_trusted_ca_certs <pem>...` — trust roots replacing the system store.
    pub trusted_ca_certs: Vec<String>,
    /// 🎫 `tls_client_auth <cert> <key>` — certificate half of mutual TLS.
    pub client_cert: Option<String>,
    /// 🔑 `tls_client_auth <cert> <key>` — key half of mutual TLS.
    pub client_key: Option<String>,
    /// ⚠️ `tls_insecure_skip_verify` — accept any upstream certificate.
    pub insecure_skip_verify: bool,
}

/// 🗄️ Typed cache policy produced by the Pingclairfile adapter.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// ⏳ How long a stored response stays fresh, in seconds.
    pub ttl_secs: u64,
    /// 📏 Hard ceiling on stored response bytes, process-wide.
    pub max_size_bytes: usize,
}

/// 🔁 Typed retry policy produced by the Pingclairfile adapter.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: usize,
    pub total_timeout_ms: Option<u64>,
    pub backoff_ms: u64,
    pub status_codes: Vec<u16>,
    pub methods: Vec<String>,
    pub path_patterns: Vec<String>,
    pub expressions: Vec<String>,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 16,
            total_timeout_ms: None,
            backoff_ms: 0,
            status_codes: Vec::new(),
            methods: ["GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            path_patterns: Vec::new(),
            expressions: Vec::new(),
        }
    }
}

/// 🚦 Typed overload policy produced by the Pingclairfile adapter.
#[derive(Debug, Clone)]
pub struct OverloadConfig {
    pub max_in_flight: Option<usize>,
    pub max_pending: usize,
    pub pending_timeout_ms: u64,
    pub upstream_max_connections: Option<usize>,
}

impl Default for OverloadConfig {
    fn default() -> Self {
        Self {
            max_in_flight: None,
            max_pending: 0,
            pending_timeout_ms: 1_000,
            upstream_max_connections: None,
        }
    }
}

/// 🔌 Typed circuit-breaker policy produced by the Pingclairfile adapter.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    pub consecutive_failures: Option<u32>,
    pub error_rate_percent: Option<u8>,
    pub minimum_requests: usize,
    pub window_requests: usize,
    pub open_duration_ms: u64,
    pub half_open_requests: usize,
    pub failure_statuses: Vec<u16>,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            consecutive_failures: None,
            error_rate_percent: None,
            minimum_requests: 20,
            window_requests: 100,
            open_duration_ms: 30_000,
            half_open_requests: 1,
            failure_statuses: Vec::new(),
        }
    }
}

/// Static response configuration
#[derive(Debug, Clone)]
pub struct ResponseConfig {
    pub status: u16,
    pub body: Option<Expr>,
    pub headers: BTreeMap<String, String>,
}

/// Static error configuration produced by the `error` directive.
#[derive(Debug, Clone)]
pub struct ErrorConfig {
    /// 🚨 Status code the error carries; 500 when the directive says nothing.
    pub status: u16,
    /// 💬 Optional message, rendered as the response body.
    pub message: Option<String>,
}

/// 🧰 Variable assignments produced by the `vars` directive.
#[derive(Debug, Clone)]
pub struct VarsConfig {
    pub values: BTreeMap<String, String>,
}

/// Redirect configuration
#[derive(Debug, Clone)]
pub struct RedirectConfig {
    pub to: String,
    pub code: u16,
}

/// Headers modification configuration
#[derive(Debug, Clone, Default)]
pub struct HeadersConfig {
    pub set: BTreeMap<String, String>,
    pub add: BTreeMap<String, String>,
    pub remove: Vec<String>,
}

/// File server configuration (placeholder)
#[derive(Debug, Clone)]
pub struct FileServerConfig {
    pub root: String,
    pub index: Vec<String>,
    pub browse: bool,
    pub compress: bool,
}

// ============================================================
// Expressions
// ============================================================

/// Expression types
#[derive(Debug, Clone)]
pub enum Expr {
    /// String literal
    String(String),

    /// Integer literal
    Integer(i64),

    /// Boolean literal
    Bool(bool),

    /// Duration value (in milliseconds)
    Duration(u64),

    /// Variable reference: ${req.header["X"]}
    Variable(Variable),

    /// Array literal: [a, b, c]
    Array(Vec<Expr>),

    /// Map literal: { "key": "value" }
    Map(HashMap<String, Expr>),

    /// Identifier reference
    Ident(String),
}

/// Variable reference
#[derive(Debug, Clone)]
pub struct Variable {
    /// Full variable path: req.header["X-Foo"]
    pub path: String,
}

impl Variable {
    /// Parse a variable path into components
    pub fn components(&self) -> Vec<&str> {
        self.path.split('.').collect()
    }
}

// ============================================================
// Directives
// ============================================================

/// Generic directive (for extensibility)
#[derive(Debug, Clone)]
pub enum Directive {
    /// Macro call: use xxx!()
    MacroCall(MacroCall),

    /// Headers block
    Headers(HeadersConfig),

    /// Key-value setting
    Setting { key: String, value: Expr },

    /// Nested block
    Block { name: String, body: Vec<Directive> },
}

// ============================================================
// Utility Implementations
// ============================================================

impl Ast {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ServerBlock {
    pub fn new(name: String) -> Self {
        Self {
            name,
            names: Vec::new(),
            listens: Vec::new(),
            bind: None,
            root: None,
            compress: None,
            gzip_types: Vec::new(),
            log: None,
            log_channels: Vec::new(),
            named_logs: Vec::new(),
            tls: None,
            routes: None,
            matchers: HashMap::new(),
            error_pages: Vec::new(),
            error_routes: Vec::new(),
            vars_routes: Vec::new(),
            directives: Vec::new(),
            limits: ResourceLimitsConfig::default(),
        }
    }
}

impl ProxyConfig {
    pub fn new(upstreams: Vec<String>) -> Self {
        Self {
            upstream_options: upstreams
                .iter()
                .map(|address| ProxyUpstreamConfig {
                    address: address.clone(),
                    weight: 1,
                    backup: false,
                })
                .collect(),
            upstreams,
            dynamic: None,
            rewrite_method: None,
            rewrite_uri: None,
            request_buffer_bytes: None,
            response_buffer_bytes: None,
            transport_options: BTreeMap::new(),
            fastcgi: None,
            handle_response: Vec::new(),
            lb_policy: None,
            lb_hash_key: None,
            health_check: None,
            flush_interval: None,
            header_up: BTreeMap::new(),
            transport: None,
            cache: None,
            retry: RetryConfig::default(),
            overload: OverloadConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            macro_calls: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variable_components() {
        let var = Variable {
            path: r#"req.header["CF-Connecting-IP"]"#.to_string(),
        };
        let components = var.components();
        assert_eq!(components.len(), 2);
        assert_eq!(components[0], "req");
    }

    #[test]
    fn test_ast_default() {
        let ast = Ast::default();
        assert!(ast.global.is_none());
        assert!(ast.macros.is_empty());
        assert!(ast.servers.is_empty());
    }

    #[test]
    fn test_server_block_new() {
        let server = ServerBlock::new("example.com".to_string());
        assert_eq!(server.name, "example.com");
        assert!(server.listens.is_empty());
        // `None`, not `Some(vec![])` — a fresh block has no `encode`
        // directive, which inherits the default rather than meaning "off".
        assert!(server.compress.is_none());
    }
}
