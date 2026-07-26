//! 🌳 Abstract syntax tree for the Pingclair configuration DSL.
//!
//! This module defines every node produced by the parser.

use crate::parser::lexer::Location;
use std::collections::HashMap;

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
    pub auto_https: Option<AutoHttpsMode>,
    pub admin: Option<AdminDirective>,
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

    /// Listen addresses
    pub listens: Vec<ListenAddr>,

    /// Bind address
    pub bind: Option<String>,

    /// Compression algorithms
    pub compress: Vec<CompressionAlgo>,

    /// Log configuration
    pub log: Option<Node<LogBlock>>,

    /// TLS configuration (from the `tls` directive)
    pub tls: Option<TlsDirective>,

    /// Route definitions
    pub routes: Option<Node<RouteBlock>>,

    /// Named matcher definitions
    pub matchers: HashMap<String, Matcher>,

    /// Custom error pages: HTTP status code → file path (`error_page` directive)
    pub error_pages: Vec<(u16, String)>,

    /// Other directives (including macro calls)
    pub directives: Vec<Directive>,
}

/// TLS configuration for a server block (from the `tls` directive)
#[derive(Debug, Clone, Default)]
pub struct TlsDirective {
    /// Explicitly disable TLS (`tls off`)
    pub off: bool,

    /// Automatic certificate management (`tls auto`)
    pub auto: bool,

    /// Certificate file path
    pub cert: Option<String>,

    /// Private key file path
    pub key: Option<String>,

    /// ACME account email
    pub acme_email: Option<String>,

    /// Enable HTTP/3
    pub http3: Option<bool>,
}

/// Listen address
#[derive(Debug, Clone)]
pub struct ListenAddr {
    pub scheme: Scheme,
    pub host: String,
    pub port: Option<u16>,
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
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    pub level: LogLevel,
    pub format: LogFormat,
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
    pub output: LogOutput,
    pub format: LogFormat,
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

/// Route handler
#[derive(Debug, Clone)]
pub enum Handler {
    /// Reverse proxy
    Proxy(Box<ProxyConfig>),

    /// Static response
    Respond(ResponseConfig),

    /// Redirect
    Redirect(RedirectConfig),

    /// Headers modification only
    Headers(HeadersConfig),

    /// Multiple handlers (pipeline)
    Pipeline(Vec<Handler>),

    /// File server (future)
    FileServer(FileServerConfig),

    /// Exclusive routing group
    Handle(Vec<Handler>),

    /// HTTP Basic authentication gate
    BasicAuth(BasicAuthConfig),

    /// Internal URI rewrite.
    Rewrite(RewriteConfig),

    /// Cross-origin resource sharing policy.
    Cors(CorsConfig),

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

    /// 🔑 Username and plain-text or bcrypt password pairs.
    pub credentials: Vec<(String, String)>,
}

/// Proxy configuration
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Upstream URLs
    pub upstreams: Vec<String>,

    /// Per-upstream options, including weighted and backup peers.
    pub upstream_options: Vec<ProxyUpstreamConfig>,

    /// Load-balancing strategy selected by `lb_policy`.
    pub lb_policy: Option<String>,

    /// Flush interval
    pub flush_interval: Option<FlushInterval>,

    /// Headers to add to upstream request
    pub header_up: HashMap<String, Expr>,

    /// Transport configuration
    pub transport: Option<TransportConfig>,

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

/// Rewrite configuration. A two-argument `rewrite` directive is a regex
/// rewrite; the replacement follows Rust-regex `$1` capture syntax.
#[derive(Debug, Clone)]
pub struct RewriteConfig {
    pub replace: Option<String>,
    pub regex: Option<String>,
    pub regex_replace: Option<String>,
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
    pub read_timeout: Option<u64>,  // milliseconds
    pub write_timeout: Option<u64>, // milliseconds
}

/// Static response configuration
#[derive(Debug, Clone)]
pub struct ResponseConfig {
    pub status: u16,
    pub body: Option<Expr>,
    pub headers: HashMap<String, String>,
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
    pub set: HashMap<String, String>,
    pub add: HashMap<String, String>,
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
            listens: Vec::new(),
            bind: None,
            compress: Vec::new(),
            log: None,
            tls: None,
            routes: None,
            matchers: HashMap::new(),
            error_pages: Vec::new(),
            directives: Vec::new(),
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
            lb_policy: None,
            flush_interval: None,
            header_up: HashMap::new(),
            transport: None,
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
        assert!(server.compress.is_empty());
    }
}
