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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalConfig {
    /// Global ACME email
    pub email: Option<String>,
    
    /// Global auto-HTTPS setting
    #[serde(default)]
    pub auto_https: AutoHttpsMode,
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

/// Server (virtual host) configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerConfig {
    /// Server name / hostname
    pub name: Option<String>,

    /// Listen addresses
    #[serde(default)]
    pub listen: Vec<String>,

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
}

fn default_body_limit() -> u64 {
    1024 * 1024 // 1MB
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsConfig {
    /// Auto HTTPS mode
    #[serde(default)]
    pub auto: bool,

    /// Certificate file path
    pub cert: Option<String>,

    /// Key file path
    pub key: Option<String>,

    /// ACME email for Let's Encrypt
    pub acme_email: Option<String>,

    /// Enable HTTP/3
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Matcher {
    /// Match by path
    Path {
        patterns: Vec<String>,
    },
    
    /// Match by header
    Header {
        name: String,
        condition: MatcherCondition,
    },
    
    /// Match by HTTP method
    Method {
        methods: Vec<String>,
    },
    
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

/// Matcher condition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatcherCondition {
    Exists,
    Equals(String),
    Contains(String),
    StartsWith(String),
    EndsWith(String),
    Regex(String),
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
    Pipeline(Vec<HandlerConfig>),

    /// Exclusive routing group
    Handle(Vec<HandlerConfig>),

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

    /// Plugin invocation
    Plugin { name: String, args: Vec<String> },
}

fn default_bool_true() -> bool {
    true
}

fn default_redirect_code() -> u16 {
    302
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

/// Basic auth credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuthCredential {
    /// Username
    pub username: String,
    /// Password hash (bcrypt recommended) or plain text (not recommended for production)
    pub password: String,
    /// If true, password is bcrypt hashed; if false, plain text comparison
    #[serde(default)]
    pub hashed: bool,
}

/// Reverse proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReverseProxyConfig {
    /// Upstream URLs
    pub upstreams: Vec<String>,

    /// Load balancing configuration
    #[serde(default)]
    pub load_balance: LoadBalanceConfig,

    /// Health check configuration
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,

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
}

/// Load balancing configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LoadBalanceConfig {
    /// Strategy: round_robin, random, least_conn, ip_hash, first
    #[serde(default = "default_lb_strategy")]
    pub strategy: String,
}

fn default_lb_strategy() -> String {
    "round_robin".to_string()
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Health check path
    pub path: String,

    /// Check interval in seconds
    #[serde(default = "default_health_interval")]
    pub interval: u64,

    /// Timeout in seconds
    #[serde(default = "default_health_timeout")]
    pub timeout: u64,

    /// Number of failures before marking unhealthy
    #[serde(default = "default_health_threshold")]
    pub threshold: u32,
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
            listen: vec!["127.0.0.1:8080".to_string()],
            tls: None,
            routes: vec![],
            log: None,
            client_max_body_size: 1024 * 1024,
        };
        assert_eq!(config.name, Some("example.com".to_string()));
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
}
