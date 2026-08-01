// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Pingclair - A modern web server built on Pingora
//!
//! This is the main entry point for the Pingclair CLI.

use boring::pkey::{PKey, Private};
use boring::ssl::NameType;
use boring::x509::X509;
use clap::{Parser, Subcommand};
use parking_lot::RwLock;
use pingclair_tls::manager::TlsManager;
use pingora_core::listeners::TlsAccept;
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::protocols::tls::TlsRef;
use pingora_core::services::Service as PingoraService;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod resource_guard;

#[cfg(unix)]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// Cached BoringSSL certificate with expiration tracking
struct CachedSslCert {
    /// 🔗 The leaf first, then every intermediate the CA issued alongside it.
    ///
    /// This is a whole chain rather than a single certificate because a TLS
    /// server has to hand the client everything between its leaf and a trusted
    /// root. Keeping only the leaf here is exactly the bug this field replaced.
    chain: Vec<X509>,
    pkey: PKey<Private>,
    /// Unix timestamp when this cache entry expires
    expires_at: u64,
}

/// Cache TTL for parsed certificates (1 hour)
const CERT_CACHE_TTL_SECS: u64 = 3600;

/// Resolves certificates dynamically using TlsManager with BoringSSL caching
struct DynamicCertResolver {
    tls_manager: Arc<TlsManager>,
    /// Cache for parsed BoringSSL objects to avoid PEM parsing on every TLS handshake
    ssl_cache: Arc<RwLock<HashMap<String, CachedSslCert>>>,
}

// Manual Debug because TlsManager might not implement it
impl std::fmt::Debug for DynamicCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicCertResolver")
            .field("cache_size", &self.ssl_cache.read().len())
            .finish()
    }
}

impl DynamicCertResolver {
    /// Create a new resolver with caching
    fn new(tls_manager: Arc<TlsManager>) -> Self {
        Self {
            tls_manager,
            ssl_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get current unix timestamp
    fn current_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs()
    }

    /// Clean expired cache entries
    #[allow(dead_code)]
    fn cleanup_expired(&self) {
        let current = Self::current_time();
        let mut cache = self.ssl_cache.write();
        let before = cache.len();
        cache.retain(|_, entry| entry.expires_at > current);
        let removed = before - cache.len();
        if removed > 0 {
            tracing::debug!("🧹 Cleaned {} expired certificate cache entries", removed);
        }
    }
}

/// 🔗 Parses a PEM bundle into the leaf plus every intermediate that follows it.
///
/// The distinction that matters: `X509::from_pem` stops at the first
/// `-----END CERTIFICATE-----` and silently discards the rest, while
/// `stack_from_pem` returns all of them. A CA-issued bundle is leaf-then-
/// intermediates, so the first parser quietly produces a certificate that no
/// strict client can build a trust path from.
fn parse_certificate_chain(cert_pem: &str) -> Result<Vec<X509>, String> {
    let chain = X509::stack_from_pem(cert_pem.as_bytes()).map_err(|e| e.to_string())?;
    if chain.is_empty() {
        // 🚫 An empty bundle must fail closed: handing BoringSSL no leaf at all
        // would otherwise surface as a confusing handshake error much later.
        return Err("the PEM bundle contained no certificate".to_string());
    }
    Ok(chain)
}

/// 🔗 Installs one leaf, its intermediates, and the matching key on a handshake.
///
/// Sending only the leaf still completes a handshake against any client that
/// already happens to hold the intermediate — browsers cache them and will even
/// fetch a missing one over AIA. That is precisely why a missing chain hides so
/// well: it looks fine in a browser and fails hard in `curl`, Go, and Java.
fn install_certificate_chain(
    ssl: &mut TlsRef,
    chain: &[X509],
    pkey: &PKey<Private>,
) -> Result<(), boring::error::ErrorStack> {
    let (leaf, intermediates) = chain.split_first().expect("chain is never empty");
    ssl.set_certificate(leaf)?;
    for intermediate in intermediates {
        ssl.add_chain_cert(intermediate)?;
    }
    ssl.set_private_key(pkey)?;
    Ok(())
}

#[async_trait::async_trait]
impl TlsAccept for DynamicCertResolver {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        // Get SNI
        let sni = ssl
            .servername(NameType::HOST_NAME)
            .unwrap_or("")
            .to_string();
        if sni.is_empty() {
            return;
        }

        tracing::debug!("🔐 Resolving cert for SNI: {}", sni);

        // Step 1: Check cache first (fast path)
        let current_time = Self::current_time();
        {
            let cache = self.ssl_cache.read();
            if let Some(cached) = cache.get(&sni)
                && cached.expires_at > current_time
            {
                // Cache hit - use cached BoringSSL objects
                tracing::debug!("🚀 Using cached cert for {}", sni);
                if let Err(e) = install_certificate_chain(ssl, &cached.chain, &cached.pkey) {
                    tracing::error!("Failed to install cached certificate chain: {}", e);
                }
                return;
            }
        }

        // Step 2: Cache miss or expired - fetch and parse PEM
        if let Some((cert_pem, key_pem)) = self.tls_manager.resolve_pem(&sni).await {
            let chain = match parse_certificate_chain(&cert_pem) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("Failed to parse cert PEM: {}", e);
                    return;
                }
            };

            let pkey = match PKey::private_key_from_pem(key_pem.as_bytes()) {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!("Failed to parse key PEM: {}", e);
                    return;
                }
            };

            // Step 3: Set the leaf, its intermediates, and the key
            if let Err(e) = install_certificate_chain(ssl, &chain, &pkey) {
                tracing::error!("Failed to install certificate chain: {}", e);
                return;
            }

            // Step 4: Cache the parsed BoringSSL objects for future handshakes
            let expires_at = current_time + CERT_CACHE_TTL_SECS;
            let cached_entry = CachedSslCert {
                chain,
                pkey,
                expires_at,
            };

            self.ssl_cache.write().insert(sni.clone(), cached_entry);
            tracing::info!(
                "🔐 Cached cert for {} (expires in {}s)",
                sni,
                CERT_CACHE_TTL_SECS
            );
        }
    }
}

/// Pingclair - Modern web server inspired by Caddy, powered by Pingora
#[derive(Parser)]
#[command(name = "pingclair")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

/// 📂 Resolves the default configuration path the way Caddy does: prefer the
/// project's own `Pingclairfile`, then fall back to a conventional
/// `Caddyfile` so a migrated config works without flags.
fn resolve_config_path(explicit: Option<&str>) -> String {
    if let Some(path) = explicit.filter(|p| !p.is_empty()) {
        return path.to_string();
    }
    for candidate in ["Pingclairfile", "Caddyfile"] {
        if std::path::Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    "Pingclairfile".to_string()
}

/// 🔐 Resolves the persistent TLS/config store directory.
///
/// The Admin API autosaves the active document under this directory so
/// `--resume` can restore an API-driven configuration after a restart.
fn tls_store_dir() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("PINGCLAIR_TLS_STORE") {
        return std::path::PathBuf::from(path);
    }
    // 🧭 Caddy stores data under the user's data directory; a hard-coded
    // `/var/lib/pingclair/certs` made an unprivileged first run impossible.
    let data_home = std::env::var("XDG_DATA_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|_| {
            std::env::var("HOME").map(|home| {
                #[cfg(target_os = "macos")]
                {
                    std::path::PathBuf::from(home).join("Library/Application Support")
                }
                #[cfg(not(target_os = "macos"))]
                {
                    std::path::PathBuf::from(home).join(".local/share")
                }
            })
        })
        .unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/pingclair"));
    data_home.join("pingclair")
}

/// 🚀 Collects the hostnames that need eager ACME issuance: `tls auto` sites
/// that are not covered by the internal authority or manual certificates, are
/// concretely named, and are not wildcards (which would need DNS-01).
fn eager_issuance_domains(config: &pingclair_core::config::PingclairConfig) -> Vec<String> {
    config
        .servers
        .iter()
        .filter(|server| {
            server
                .tls
                .as_ref()
                .is_some_and(|tls| tls.auto && !tls.internal && tls.cert.is_none())
        })
        .flat_map(|server| {
            // 🧭 JSON documents may carry hostnames in `names` while `name`
            // stays the listener label; issuance must honor both shapes.
            if server.names.is_empty() {
                server.name.clone().into_iter().collect::<Vec<_>>()
            } else {
                server.names.clone()
            }
        })
        .filter(|name| !name.is_empty() && name != "_" && !name.contains('*'))
        .collect()
}

/// 🧾 Parses a `Field: value` CLI argument into a header pair, like Caddy's
/// `--header-up "X-Foo: bar"`.
fn parse_header_pair(raw: &str) -> Result<(String, String), String> {
    let Some((name, value)) = raw.split_once(':') else {
        return Err(format!(
            "expected `Field: value`, got `{raw}` (the colon is required)"
        ));
    };
    Ok((name.trim().to_string(), value.trim().to_string()))
}

/// 📡 Minimal HTTP/1.1 client for the Admin API (`reload`/`stop`).
///
/// The production binary has no HTTP client dependency; a tiny request is
/// enough for these two commands and keeps the dependency tree unchanged.
fn admin_request(
    method: &str,
    path: &str,
    content_type: Option<&str>,
    body: Option<&str>,
    address: &str,
) -> anyhow::Result<(u16, String)> {
    use std::io::{Read, Write};

    let body_bytes = body.unwrap_or("");
    let mut stream = std::net::TcpStream::connect(address)
        .map_err(|error| anyhow::anyhow!("❌ Cannot reach admin API at {address}: {error}"))?;
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n");
    if let Some(content_type) = content_type {
        request.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    request.push_str(&format!("Content-Length: {}\r\n\r\n", body_bytes.len()));
    stream.write_all(request.as_bytes())?;
    if !body_bytes.is_empty() {
        stream.write_all(body_bytes.as_bytes())?;
    }

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    Ok((status, response))
}

/// 🌐 Splits `host:port` into (host, port), honoring bracketed IPv6.
fn host_and_port(address: &str) -> (&str, Option<u16>) {
    let trimmed = address
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    match trimmed.rfind(']') {
        Some(bracket) => match trimmed[bracket..].rfind(':') {
            Some(offset) => (
                &trimmed[..bracket + 1],
                trimmed[bracket + offset + 1..].parse::<u16>().ok(),
            ),
            None => (trimmed, None),
        },
        None => match trimmed.rfind(':') {
            // 🧭 The last colon separates host and port when the tail parses
            // as a port; a bare `:9000` yields an empty host (loopback).
            Some(index) => (&trimmed[..index], trimmed[index + 1..].parse::<u16>().ok()),
            None => (trimmed, None),
        },
    }
}

/// 🧭 Derives a concrete listen address from a Caddy-style `--from`/site
/// address: a bare hostname gets the scheme's default port, a bare `:port`
/// binds the wildcard, and an explicit host:port passes through.
fn listen_for_site(address: &str, https: bool) -> String {
    let default_port = if https { 443 } else { 80 };
    match host_and_port(address) {
        ("", Some(port)) => format!("[::]:{port}"),
        ("", None) => format!("[::]:{default_port}"),
        (host, port) => {
            // 🌐 A hostname is a virtual host, not a bind address: Caddy
            // binds every interface and routes by Host/SNI. Only an IP
            // literal pins the socket to one interface.
            if host.parse::<std::net::IpAddr>().is_ok() {
                match port {
                    Some(port) => format!("{host}:{port}"),
                    None => format!("{host}:{default_port}"),
                }
            } else {
                format!("[::]:{}", port.unwrap_or(default_port))
            }
        }
    }
}

/// 🏷️ Returns the hostname portion of an address (`example.com:8443` → `example.com`).
fn host_only(address: &str) -> &str {
    let (host, _) = host_and_port(address);
    host
}

/// 🧭 Renders an upstream address as a Host header value, like Caddy's
/// `--change-host-header` shortcut.
fn upstream_hostport(address: &str) -> String {
    let (scheme, rest) = if let Some(rest) = address.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = address.strip_prefix("h2://") {
        (true, rest)
    } else {
        (
            false,
            address
                .strip_prefix("http://")
                .or_else(|| address.strip_prefix("h2c://"))
                .unwrap_or(address),
        )
    };
    match host_and_port(rest) {
        ("", Some(port)) => format!("127.0.0.1:{port}"),
        ("", None) => format!("127.0.0.1:{}", if scheme { 443 } else { 80 }),
        (host, Some(port)) => format!("{host}:{port}"),
        (host, None) => format!("{host}:{}", if scheme { 443 } else { 80 }),
    }
}

/// ✍️ Renders parsed directives back to canonical Pingclairfile text: two
/// spaces per block level, one directive per line, arguments re-quoted only
/// when whitespace or a comment marker demands it.
fn format_directives(directives: &[pingclair_config::parser::caddy_ast::Directive]) -> String {
    fn quote_argument(argument: &str) -> String {
        if argument.contains([' ', '\t', '#', '"']) {
            format!("\"{}\"", argument.replace('"', "\\\""))
        } else {
            argument.to_string()
        }
    }

    fn format_block(
        directives: &[pingclair_config::parser::caddy_ast::Directive],
        indent: usize,
        out: &mut String,
    ) {
        let padding = " ".repeat(indent);
        for directive in directives {
            out.push_str(&padding);
            out.push_str(&directive.name);
            for argument in &directive.args {
                out.push(' ');
                out.push_str(&quote_argument(argument));
            }
            if let Some(block) = &directive.block {
                out.push_str(" {\n");
                format_block(&block.directives, indent + 2, out);
                out.push_str(&padding);
                out.push_str("}\n");
            } else {
                out.push('\n');
            }
        }
    }

    let mut out = String::new();
    format_block(directives, 0, &mut out);
    out
}

/// 🛠️ Manages the systemd unit (Linux) or explains that service management is
/// unavailable (other platforms). systemctl itself is Linux-only, so the
/// non-Linux branch is the one local macOS tests exercise.
fn manage_system_service(action: ServiceAction) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let cmd = match action {
            ServiceAction::Start => "start",
            ServiceAction::Stop => "stop",
            ServiceAction::Restart => "restart",
            ServiceAction::Reload => "reload",
            ServiceAction::Status => "status",
        };

        tracing::info!("🛠️ Managing service: {}", cmd);
        let status = std::process::Command::new("systemctl")
            .arg(cmd)
            .arg("pingclair")
            .status();

        match status {
            Ok(s) if s.success() => {
                let past_tense = match action {
                    ServiceAction::Start => "started",
                    ServiceAction::Stop => "stopped",
                    ServiceAction::Restart => "restarted",
                    ServiceAction::Reload => "reloaded",
                    ServiceAction::Status => "queried",
                };
                println!("✅ Service {past_tense} successfully");
            }
            Ok(s) => {
                anyhow::bail!("❌ Failed to {cmd} service (exit code: {s})");
            }
            Err(e) => {
                anyhow::bail!("❌ Failed to execute systemctl: {e}");
            }
        }
        return Ok(());
    }

    // 🚫 macOS and other non-Linux platforms have no systemctl; the systemd
    // unit shipped in scripts/ is the deployment contract instead.
    #[cfg(not(target_os = "linux"))]
    {
        let _ = action;
        anyhow::bail!("❌ Service management is only supported on Linux (systemd).");
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Run the server with a configuration file
    Run {
        /// Path to the configuration file (defaults to Pingclairfile or
        /// Caddyfile in the current directory)
        config: Option<String>,

        /// Use the config autosaved by the Admin API, like `caddy run
        /// --resume` (overrides the config path when present)
        #[arg(short, long)]
        resume: bool,

        /// Watch the config file and reload automatically after changes
        /// (local development only, like `caddy run --watch`)
        #[arg(short, long)]
        watch: bool,
    },

    /// Reload the running server through the Admin API, like `caddy reload`
    Reload {
        /// Config file to apply (defaults to Pingclairfile/Caddyfile)
        #[arg(short, long)]
        config: Option<String>,

        /// Admin API address
        #[arg(long, default_value = "127.0.0.1:2019")]
        address: String,
    },

    /// Start the server in the background, like `caddy start`
    Start {
        /// Config file to load
        #[arg(short, long)]
        config: Option<String>,
    },

    /// Stop the running server through the Admin API, like `caddy stop`
    Stop {
        /// Admin API address
        #[arg(long, default_value = "127.0.0.1:2019")]
        address: String,
    },

    /// Start one or more simple hard-coded HTTP servers for development
    Respond {
        /// HTTP status code to return
        #[arg(short, long)]
        status: Option<u16>,

        /// Response header (`Field: value`), repeatable
        #[arg(short = 'H', long = "header", value_parser = parse_header_pair)]
        headers: Vec<(String, String)>,

        /// Response body
        #[arg(short, long)]
        body: Option<String>,

        /// Listener address (defaults to a random loopback port)
        #[arg(short, long)]
        listen: Option<String>,
    },

    /// Start a quick reverse proxy
    #[command(name = "reverse-proxy")]
    ReverseProxy {
        /// Address to listen on
        #[arg(long, default_value = "localhost")]
        from: String,

        /// Upstream address to proxy to (repeatable)
        #[arg(long, required = true)]
        to: Vec<String>,

        /// Set a request header to send upstream (Field: value)
        #[arg(long = "header-up", value_parser = parse_header_pair)]
        headers_up: Vec<(String, String)>,

        /// Set a response header to send downstream (Field: value)
        #[arg(long = "header-down", value_parser = parse_header_pair)]
        headers_down: Vec<(String, String)>,

        /// Disable TLS verification with the upstream
        #[arg(long)]
        insecure: bool,

        /// Use the internal CA instead of attempting public certificates
        #[arg(long)]
        internal_certs: bool,

        /// Do not provision the automatic HTTP redirect listener
        #[arg(long)]
        disable_redirects: bool,

        /// Set the upstream Host header to the upstream address, like Caddy
        #[arg(short = 'c', long)]
        change_host_header: bool,
    },

    /// Start a quick file server
    #[command(name = "file-server")]
    FileServer {
        /// Address to listen on
        #[arg(long, default_value = ":80")]
        listen: String,

        /// Root directory to serve
        #[arg(long, default_value = ".")]
        root: String,

        /// Enable directory listings
        #[arg(short, long)]
        browse: bool,

        /// Serve this domain over HTTPS (requires --listen to be a port)
        #[arg(short, long)]
        domain: Option<String>,

        /// Enable the access log
        #[arg(long)]
        access_log: bool,

        /// Disable response compression
        #[arg(long)]
        no_compress: bool,

        /// Maximum files shown in a directory listing
        #[arg(long)]
        file_limit: Option<usize>,

        /// Enable template rendering for `.html` files, like Caddy
        #[arg(long)]
        templates: bool,
    },

    /// Validate a configuration file
    Validate {
        /// Path to the configuration file (defaults to Pingclairfile or
        /// Caddyfile in the current directory)
        config: Option<String>,
    },

    /// Adapt a Pingclairfile to JSON and print it, like `caddy adapt`
    Adapt {
        /// Path to the configuration file (defaults to Pingclairfile or
        /// Caddyfile in the current directory)
        #[arg(short, long)]
        config: Option<String>,

        /// Format the JSON output with indentation
        #[arg(short, long)]
        pretty: bool,

        /// Validate the adapted configuration (certificate files etc.)
        #[arg(long)]
        validate: bool,
    },

    /// Format a Pingclairfile and print the result, like `caddy fmt`
    Fmt {
        /// Path to the configuration file (`-` reads stdin)
        #[arg(default_value = "Pingclairfile")]
        path: String,

        /// Overwrite the input file instead of printing
        #[arg(short, long)]
        overwrite: bool,

        /// Print a visual diff instead of the formatted output
        #[arg(short, long)]
        diff: bool,
    },

    /// Hash a password for basic_auth (bcrypt)
    #[command(name = "hash-password")]
    HashPassword {
        /// Password to hash; read from stdin if omitted
        #[arg(short, long)]
        plaintext: Option<String>,

        /// Hashing algorithm: `bcrypt` (default) or `argon2id`
        #[arg(long, default_value = "bcrypt")]
        algorithm: String,

        /// bcrypt cost (4..=31); default 14
        #[arg(long)]
        bcrypt_cost: Option<u32>,

        /// argon2id time cost (iterations); default 1
        #[arg(long)]
        argon2id_time: Option<u32>,

        /// argon2id memory cost in KiB; default 65536
        #[arg(long)]
        argon2id_memory: Option<u32>,

        /// argon2id parallelism (threads); default 4
        #[arg(long)]
        argon2id_threads: Option<u32>,

        /// argon2id output key length in bytes; default 32
        #[arg(long)]
        argon2id_keylen: Option<usize>,
    },

    /// Show version information
    Version,

    /// Manage the system service (Linux only)
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Start the service
    Start,
    /// Stop the service
    Stop,
    /// Restart the service
    Restart,
    /// Reload the service
    Reload,
    /// Show service status
    Status,
}

fn main() -> anyhow::Result<()> {
    // 🧭 `pingclair` with no subcommand prints help and exits 0, like Caddy.
    if std::env::args().len() <= 1 {
        use clap::CommandFactory;
        Cli::command().print_help().ok();
        println!();
        return Ok(());
    }

    // Install a process-level rustls CryptoProvider before any TLS code runs.
    // Both the `aws-lc-rs` and `ring` features end up enabled through the
    // workspace dependency graph, so rustls cannot pick one automatically and
    // panics on the first TLS handshake without an explicit default.
    // `install_default` returns Err if a provider is already installed (e.g. by
    // a library we depend on); that is fine, so the result is discarded.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    if cli.verbose {
        tracing::info!("Verbose mode enabled");
    }

    match cli.command {
        Commands::Run {
            config: config_path,
            resume,
            watch,
        } => {
            let mut config_path = resolve_config_path(config_path.as_deref());
            if resume {
                let autosave = tls_store_dir().join("autosave.json");
                if autosave.is_file() {
                    tracing::info!(
                        "📥 Resuming configuration from autosave: {}",
                        autosave.display()
                    );
                    config_path = autosave.to_string_lossy().to_string();
                } else {
                    tracing::warn!(
                        "⚠️ --resume requested but no autosave exists at {}; \
                         falling back to the config path",
                        autosave.display()
                    );
                }
            }
            tracing::info!("Starting Pingclair with config: {}", config_path);

            // Load configuration - support both single file and directory
            let config = if std::path::Path::new(&config_path).is_dir() {
                tracing::info!("📁 Loading configuration from directory: {}", config_path);
                match pingclair_config::compile_directory(&config_path) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!("❌ Failed to load config from directory: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                match pingclair_config::compile_file(&config_path) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!("❌ Failed to load config: {}", e);
                        std::process::exit(1);
                    }
                }
            };

            if watch {
                // 👀 `--watch` reloads the config file after every change,
                // like Caddy's local-development flag. Polling the mtime is
                // deliberately simple: correctness matters, latency does not.
                let watch_path = config_path.clone();
                std::thread::spawn(move || {
                    let mut last_modified = std::fs::metadata(&watch_path)
                        .and_then(|meta| meta.modified())
                        .ok();
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(1));
                        let modified = std::fs::metadata(&watch_path)
                            .and_then(|meta| meta.modified())
                            .ok();
                        if modified.is_some() && modified != last_modified {
                            last_modified = modified;
                            let _ = std::process::Command::new("kill")
                                .args(["-USR1", &std::process::id().to_string()])
                                .status();
                        }
                    }
                });
            }

            run_server(config_path.clone(), config)?;
        }

        Commands::Reload { config, address } => {
            let path = resolve_config_path(config.as_deref());
            let source = std::fs::read_to_string(&path)
                .map_err(|error| anyhow::anyhow!("❌ Failed to read {path}: {error}"))?;
            let (content_type, body) = if path.ends_with(".json") {
                ("application/json".to_string(), source)
            } else {
                ("text/caddyfile".to_string(), source)
            };
            let (status, response) =
                admin_request("POST", "/load", Some(&content_type), Some(&body), &address)?;
            if status != 200 {
                let detail = response.lines().next().unwrap_or("").to_string();
                anyhow::bail!("❌ Reload failed ({status}): {detail}");
            }
            println!("✅ Configuration reloaded successfully");
        }

        Commands::Start { config } => {
            let path = resolve_config_path(config.as_deref());
            let executable = std::env::current_exe()?;
            let mut command = std::process::Command::new(executable);
            command
                .arg("run")
                .arg(&path)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                command.process_group(0);
            }
            let child = command.spawn()?;
            println!(
                "✅ Pingclair started in the background (pid {})",
                child.id()
            );
        }

        Commands::Stop { address } => {
            let (status, response) = admin_request("POST", "/stop", None, None, &address)?;
            if status != 200 {
                let detail = response.lines().next().unwrap_or("").to_string();
                anyhow::bail!("❌ Stop failed ({status}): {detail}");
            }
            println!("✅ Pingclair stopped");
        }

        Commands::Respond {
            status,
            headers,
            body,
            listen,
        } => {
            use pingclair_core::config::{HandlerConfig, RouteConfig, ServerConfig};

            let listen_addr =
                listen_for_site(&listen.unwrap_or_else(|| "127.0.0.1:0".to_string()), false);
            let probe = std::net::TcpListener::bind(&listen_addr)?;
            let bound = probe.local_addr()?;
            drop(probe);
            println!("Server address: {bound}");

            let server = ServerConfig {
                name: Some("_".to_string()),
                listen: vec![bound.to_string()],
                routes: vec![RouteConfig {
                    path: "/*".to_string(),
                    handler: HandlerConfig::Respond {
                        status: status.unwrap_or(200),
                        body,
                        headers: headers.into_iter().collect(),
                    },
                    methods: None,
                    matcher: None,
                }],
                ..Default::default()
            };
            let mut config = pingclair_core::config::PingclairConfig::default();
            config.servers.push(server);
            run_server(String::new(), config)?;
        }

        Commands::ReverseProxy {
            from,
            to,
            headers_up,
            headers_down,
            insecure,
            internal_certs,
            disable_redirects,
            change_host_header,
        } => {
            // 🌐 Caddy expands `--to :9000-9003` into one peer per port; the
            // CLI must not ship an address the runtime cannot dial.
            let to = pingclair_config::adapter::expand_upstream_port_ranges(to);
            tracing::info!("Starting reverse proxy: {} -> {:?}", from, to);
            // Create dynamic config
            let mut config = pingclair_core::config::PingclairConfig::default();
            if disable_redirects {
                config.global.auto_https = pingclair_core::config::AutoHttpsMode::DisableRedirects;
            }

            // 🌐 A hostname `--from` names a virtual host and asks for HTTPS,
            // like Caddy's reverse-proxy command.
            let https = !from.starts_with(':') && !from.starts_with("http://");
            let listen = listen_for_site(&from, https);
            let host = host_only(&from);
            let name = if host.is_empty() {
                "_".to_string()
            } else {
                host.to_string()
            };
            let tls = if internal_certs {
                Some(pingclair_core::config::TlsConfig {
                    internal: true,
                    ..Default::default()
                })
            } else if name != "_" {
                let internal = name == "localhost" || name.ends_with(".localhost");
                Some(pingclair_core::config::TlsConfig {
                    auto: !internal,
                    internal,
                    ..Default::default()
                })
            } else {
                None
            };

            use pingclair_core::config::{
                HandlerConfig, LoadBalanceConfig, ReverseProxyConfig, RouteConfig, ServerConfig,
            };

            let mut server = ServerConfig {
                name: Some(name.clone()),
                names: if name == "_" { Vec::new() } else { vec![name] },
                bind: None,
                proxy_protocol_listen: Vec::new(),
                listen: vec![listen],
                routes: Vec::new(),
                tls,
                log: None,
                client_max_body_size: 10 * 1024 * 1024, // 10MB
                limits: Default::default(),
                security: Default::default(),
                gzip_types: pingclair_core::config::default_gzip_types(),
                encodings: pingclair_core::config::default_encodings(),
                error_pages: Default::default(),
            };

            let mut upstream_tls = pingclair_core::config::UpstreamTlsConfig::default();
            if insecure {
                upstream_tls.enable = true;
                upstream_tls.insecure_skip_verify = true;
            }
            let mut headers_up: HashMap<String, String> = headers_up.into_iter().collect();
            if change_host_header && let Some(upstream) = to.first() {
                headers_up.insert("Host".to_string(), upstream_hostport(upstream));
            }
            let handler = HandlerConfig::ReverseProxy(ReverseProxyConfig {
                upstreams: to,
                upstream_options: Vec::new(),
                // 🗄️ `pingclair reverse-proxy` is a throwaway one-liner; caching
                // is a deliberate per-route decision, so it stays off here.
                cache: None,
                load_balance: LoadBalanceConfig::default(),
                health_check: None,
                headers_up,
                headers_down: headers_down.into_iter().collect(),
                flush_interval: None,
                read_timeout: None,
                write_timeout: None,
                connect_timeout: None,
                first_byte_timeout: None,
                between_reads_timeout: None,
                retry: Default::default(),
                overload: Default::default(),
                circuit_breaker: Default::default(),
                upstream_tls: Box::new(upstream_tls),
            });

            server.routes.push(RouteConfig {
                path: "/*".to_string(),
                handler,
                methods: None,
                matcher: None,
            });

            config.servers.push(server);

            run_server("".to_string(), config)?;
        }

        Commands::FileServer {
            listen,
            root,
            browse,
            domain,
            access_log,
            no_compress,
            file_limit,
            templates,
        } => {
            tracing::info!(
                "Starting file server on {} serving {} (browse: {})",
                listen,
                root,
                browse
            );
            // Create dynamic config
            let mut config = pingclair_core::config::PingclairConfig::default();

            // 🌐 `--domain` names a virtual host and serves HTTPS (internal
            // CA for localhost), like Caddy's file-server command.
            let listen_addr = if let Some(domain) = &domain {
                let base = if listen == ":80" {
                    format!("{domain}:443")
                } else {
                    listen.clone()
                };
                listen_for_site(&base, true)
            } else if listen.starts_with(':') {
                format!("[::]{listen}")
            } else if listen.parse::<u16>().is_ok() {
                format!("[::]:{listen}")
            } else {
                listen.clone()
            };
            let domain_name = domain.clone().unwrap_or_else(|| "_".to_string());
            let tls = domain.as_ref().map(|domain| {
                let internal = domain == "localhost" || domain.ends_with(".localhost");
                pingclair_core::config::TlsConfig {
                    auto: !internal,
                    internal,
                    ..Default::default()
                }
            });

            use pingclair_core::config::{HandlerConfig, RouteConfig, ServerConfig};

            let mut server = ServerConfig {
                name: Some(domain_name.clone()),
                names: domain.clone().map_or_else(Vec::new, |d| vec![d]),
                bind: None,
                proxy_protocol_listen: Vec::new(),
                listen: vec![listen_addr],
                routes: Vec::new(),
                tls,
                log: access_log.then(|| pingclair_core::config::LogConfig {
                    output: pingclair_core::config::LogOutput::Stdout,
                    format: pingclair_core::config::LogFormat::Text,
                    level: None,
                    exclude_fields: Vec::new(),
                }),
                client_max_body_size: 10 * 1024 * 1024,
                limits: Default::default(),
                security: Default::default(),
                gzip_types: pingclair_core::config::default_gzip_types(),
                encodings: if no_compress {
                    Vec::new()
                } else {
                    pingclair_core::config::default_encodings()
                },
                error_pages: Default::default(),
            };

            // Resolve absolute path
            let root_path = std::fs::canonicalize(&root)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or(root.clone());

            let template_root = root_path.clone();
            let file_handler = HandlerConfig::FileServer {
                root: root_path,
                index: vec!["index.html".to_string()],
                browse,
                browse_limit: file_limit,
                compress: !no_compress,
            };
            let handler = if templates {
                HandlerConfig::Pipeline {
                    handlers: vec![
                        HandlerConfig::Templates {
                            root: Some(template_root),
                        },
                        file_handler,
                    ],
                }
            } else {
                file_handler
            };

            server.routes.push(RouteConfig {
                path: "/*".to_string(),
                handler,
                methods: None,
                matcher: None,
            });

            // 🛑 SAFETY: Push the server that contains the FileServer route,
            // not a duplicate empty ServerConfig.
            config.servers.push(server);

            run_server("".to_string(), config)?;
        }

        Commands::Validate { config } => {
            // 🧭 Caddy reads a config from stdin when the path is `-`; do the
            // same so scripts can validate generated Caddyfiles.
            let (compiled, label) = if config.as_deref() == Some("-") {
                use std::io::Read;
                let mut source = String::new();
                std::io::stdin()
                    .read_to_string(&mut source)
                    .map_err(|error| anyhow::anyhow!("❌ Failed to read stdin: {error}"))?;
                (
                    pingclair_config::compile(&source)
                        .map_err(|error| anyhow::anyhow!("❌ Configuration Error: {error}"))?,
                    "<stdin>".to_string(),
                )
            } else {
                let config = resolve_config_path(config.as_deref());
                tracing::info!("Validating config: {}", config);
                let result = if std::path::Path::new(&config).is_dir() {
                    tracing::info!("📁 Validating configuration directory: {}", config);
                    pingclair_config::compile_directory(&config)
                } else {
                    pingclair_config::compile_file(&config)
                };
                (
                    result.map_err(|error| anyhow::anyhow!("❌ Configuration Error: {error}"))?,
                    config,
                )
            };

            // 🛡️ Provisioning checks: files the server will need at startup
            // must exist now, not fail mid-flight later.
            for server in &compiled.servers {
                let Some(tls) = &server.tls else {
                    continue;
                };
                let (Some(cert), Some(key)) = (&tls.cert, &tls.key) else {
                    continue;
                };
                for (kind, path) in [("certificate", cert), ("key", key)] {
                    if !std::path::Path::new(path).is_file() {
                        eprintln!("❌ TLS {kind} file does not exist: {path}");
                        std::process::exit(1);
                    }
                }
            }
            println!("✅ Configuration '{label}' is valid!");
        }

        Commands::Adapt {
            config,
            pretty,
            validate,
        } => {
            // 🧭 Caddy reads a config from stdin when the path is `-`; keep
            // `pingclair adapt -c -` usable in the same pipelines.
            let config = if config.as_deref() == Some("-") {
                use std::io::Read;
                let mut source = String::new();
                std::io::stdin()
                    .read_to_string(&mut source)
                    .map_err(|error| anyhow::anyhow!("❌ Failed to read stdin: {error}"))?;
                pingclair_config::compile(&source)
                    .map_err(|error| anyhow::anyhow!("❌ Failed to adapt <stdin>: {error}"))?
            } else {
                let config_path = resolve_config_path(config.as_deref());
                (if std::path::Path::new(&config_path).is_dir() {
                    pingclair_config::compile_directory(&config_path)
                } else {
                    pingclair_config::compile_file(&config_path)
                })
                .map_err(|error| anyhow::anyhow!("❌ Failed to adapt {config_path}: {error}"))?
            };
            if validate {
                pingclair_config::compiler::validate_config(&config)
                    .map_err(|error| anyhow::anyhow!("❌ Validation failed: {error}"))?;
            }
            let json = if pretty {
                serde_json::to_string_pretty(&config)
            } else {
                serde_json::to_string(&config)
            }
            .map_err(|error| anyhow::anyhow!("❌ Failed to serialize config: {error}"))?;
            println!("{json}");
        }

        Commands::Fmt {
            path,
            overwrite,
            diff,
        } => {
            let source = if path == "-" {
                use std::io::Read;
                let mut buffer = String::new();
                std::io::stdin()
                    .read_to_string(&mut buffer)
                    .map_err(|error| anyhow::anyhow!("❌ Failed to read stdin: {error}"))?;
                buffer
            } else {
                std::fs::read_to_string(&path)
                    .map_err(|error| anyhow::anyhow!("❌ Failed to read {path}: {error}"))?
            };
            let directives = pingclair_config::parser::parse(&source)
                .map_err(|error| anyhow::anyhow!("❌ Failed to parse {path}: {error}"))?;
            let formatted = format_directives(&directives);
            if overwrite {
                if path == "-" {
                    anyhow::bail!("❌ --overwrite cannot be used with stdin");
                }
                std::fs::write(&path, formatted)
                    .map_err(|error| anyhow::anyhow!("❌ Failed to write {path}: {error}"))?;
            } else if diff {
                for (left, right) in source.lines().zip(formatted.lines()) {
                    if left != right {
                        println!("-{left}");
                        println!("+{right}");
                    }
                }
            } else {
                print!("{formatted}");
            }
        }

        Commands::HashPassword {
            plaintext,
            algorithm,
            bcrypt_cost,
            argon2id_time,
            argon2id_memory,
            argon2id_threads,
            argon2id_keylen,
        } => {
            use std::io::IsTerminal;
            let password = match plaintext {
                Some(password) => password,
                None if std::io::stdin().is_terminal() => {
                    eprint!("Password: ");
                    use std::io::Read;
                    let mut buffer = String::new();
                    std::io::stdin()
                        .read_to_string(&mut buffer)
                        .map_err(|error| anyhow::anyhow!("❌ Failed to read password: {error}"))?;
                    buffer.trim_end_matches(['\r', '\n']).to_string()
                }
                None => {
                    use std::io::Read;
                    let mut buffer = String::new();
                    std::io::stdin()
                        .read_to_string(&mut buffer)
                        .map_err(|error| anyhow::anyhow!("❌ Failed to read password: {error}"))?;
                    buffer.trim_end_matches(['\r', '\n']).to_string()
                }
            };

            match algorithm.as_str() {
                "bcrypt" => {
                    let cost = bcrypt_cost.unwrap_or(pingclair_core::server::MAX_BCRYPT_COST);
                    if !(4..=31).contains(&cost) {
                        anyhow::bail!("❌ bcrypt cost must be between 4 and 31");
                    }
                    let hash = bcrypt::hash(password, cost)
                        .map_err(|error| anyhow::anyhow!("❌ Failed to hash password: {error}"))?;
                    println!("{hash}");
                }
                "argon2id" => {
                    use argon2::password_hash::rand_core::OsRng;
                    use argon2::password_hash::{PasswordHasher, SaltString};
                    use argon2::{Argon2, Params};

                    let params = Params::new(
                        argon2id_memory.unwrap_or(64 * 1024),
                        argon2id_time.unwrap_or(1),
                        argon2id_threads.unwrap_or(4),
                        Some(argon2id_keylen.unwrap_or(32)),
                    )
                    .map_err(|error| anyhow::anyhow!("❌ Invalid argon2id parameters: {error}"))?;
                    let argon = Argon2::new(Default::default(), Default::default(), params);
                    let salt = SaltString::generate(&mut OsRng);
                    let hash = argon
                        .hash_password(password.as_bytes(), &salt)
                        .map_err(|error| anyhow::anyhow!("❌ Failed to hash password: {error}"))?
                        .to_string();
                    println!("{hash}");
                }
                other => {
                    anyhow::bail!("❌ Unknown algorithm `{other}` (expected bcrypt or argon2id)")
                }
            }
        }

        Commands::Version => {
            println!("v{}", env!("CARGO_PKG_VERSION"));
        }

        Commands::Service { action } => manage_system_service(action)?,
    }

    Ok(())
}

/// Populate the HTTP/3 SNI certificate table from the TLS manager.
///
/// Uses `peek_pem`, which only returns certificates that already exist
/// (manual certs and previously issued ACME certs) and never triggers an
/// ACME issuance — issuance stays on the lazy HTTP/1.1 handshake path.
/// Called once at startup and then periodically, so renewed certificates
/// reach new QUIC handshakes without a restart.
async fn refresh_h3_cert_table(
    table: &pingclair_proxy::quic::CertTable,
    tls_manager: &TlsManager,
    domains: &[String],
) {
    for domain in domains {
        if let Some((cert_pem, key_pem)) = tls_manager.peek_pem(domain).await
            && let Err(e) = table.upsert_pem(domain, &cert_pem, &key_pem)
        {
            tracing::warn!("⚠️ H3: skipping certificate for {}: {}", domain, e);
        }
    }
}

/// 🌐 Pingora requires a full `IP:port` socket address.
///
/// This helper accepts Caddy-style `:port` shorthand by binding the wildcard
/// address, so JSON configurations match the Pingclair DSL adapter's behavior.
fn normalize_listen_addr(addr: &str) -> String {
    match addr.strip_prefix(':') {
        Some(port) => format!("[::]:{port}"),
        None => addr.to_string(),
    }
}

/// 🧭 Reserves a unique private loopback address for one PROXY protocol ingress hop.
fn reserve_private_listener_address()
-> anyhow::Result<(std::net::TcpListener, std::net::SocketAddr)> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    Ok((listener, address))
}

/// 🚫 Port 80 is plaintext HTTP and never carries TLS, whatever the block says.
///
/// 🔁 Builds the plaintext-HTTP companion site for an HTTPS site, as Caddy does.
///
/// The idea in one sentence: a visitor who types `example.com` without a scheme
/// arrives over plain HTTP, so something has to be listening there to send them
/// to HTTPS — and the CA needs that same port in the clear to validate the
/// certificate. Caddy provisions both automatically, which is why a Caddyfile
/// never mentions `listen` or port 80 at all.
///
/// Returns `None` when there is nothing to provision:
///
/// - `auto_https off` — the operator opted out of all of this.
/// - the site serves no TLS, so there is no HTTPS to redirect to.
/// - the site has no concrete name; a redirect needs a host to send them to,
///   and a wildcard would guess wrong.
/// - the site already listens on the HTTP port, meaning the operator has said what
///   they want served there and we must not overrule it.
///
/// Under `auto_https disable_redirects` the listener is still provisioned but
/// carries no routes: the ACME challenge path is answered before routing, so
/// validation keeps working while ordinary requests get no redirect. That is
/// precisely what the mode asks for, and until now it did nothing at all.
fn automatic_http_companion(
    server_config: &pingclair_core::config::ServerConfig,
    mode: pingclair_core::config::AutoHttpsMode,
    listen_addrs: &[String],
    http_port: u16,
    https_port: u16,
) -> Option<pingclair_core::config::ServerConfig> {
    use pingclair_core::config::AutoHttpsMode;

    if mode == AutoHttpsMode::Off || server_config.tls.is_none() {
        return None;
    }

    let name = server_config.name.as_deref()?;
    if name.is_empty() || name.contains('*') {
        return None;
    }

    let already_serving_http = listen_addrs.iter().any(|addr| {
        addr.rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            == Some(http_port)
    });
    if already_serving_http {
        return None;
    }

    let routes = if mode == AutoHttpsMode::DisableRedirects {
        Vec::new()
    } else {
        // 🧭 The redirect target must land on the HTTPS port, not whatever
        // port the client used for plaintext HTTP. The default 443 needs no
        // suffix; a custom `https_port` does.
        let redirect_target = if https_port == 443 {
            "https://{host}{uri}".to_string()
        } else {
            format!("https://{{host}}:{https_port}{{uri}}")
        };
        vec![pingclair_core::config::RouteConfig {
            path: "/*".to_string(),
            // 🧭 308 rather than 302: the redirect is permanent, and unlike 301
            // it forbids a client from rewriting POST into GET, so a form
            // submitted over HTTP survives the hop to HTTPS.
            handler: pingclair_core::config::HandlerConfig::Redirect {
                to: redirect_target,
                code: 308,
            },
            methods: None,
            matcher: None,
        }]
    };

    Some(pingclair_core::config::ServerConfig {
        name: server_config.name.clone(),
        listen: vec![format!("[::]:{http_port}")],
        proxy_protocol_listen: Vec::new(),
        tls: None,
        routes,
        ..Default::default()
    })
}

/// 🔎 Reports whether this process can actually take the plaintext HTTP port.
///
/// Port 80 is privileged on Unix and is often already taken, and Pingora binds
/// its listeners far later — at which point a failure aborts a server that was
/// otherwise ready to serve HTTPS perfectly well. Probing first lets the
/// automatic listener be skipped with an explanation instead.
fn can_bind_automatic_http_port(http_port: u16) -> bool {
    std::net::TcpListener::bind(("0.0.0.0", http_port)).is_ok()
}

/// 🔐 Treats explicit TLS configuration as authoritative, except on the
/// plaintext HTTP port.
///
/// Everything except the HTTP port keeps the previous rule: an explicit `tls`
/// block enables TLS anywhere, and the HTTPS port (plus 8443, the legacy
/// convention) implies it even without one.
fn server_requires_tls(
    config: &pingclair_core::config::ServerConfig,
    addr: &str,
    http_port: u16,
    https_port: u16,
) -> bool {
    let port = addr
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok());

    // 🛡️ The plaintext HTTP port must never become a TLS listener: ACME's
    // HTTP-01 probe arrives in the clear and would fail a TLS handshake.
    if port == Some(http_port) {
        return false;
    }

    config.tls.is_some() || port.is_some_and(|port| port == https_port || port == 8443)
}

/// 🧭 Runtime listener manager: `/load` can create and tear down listeners
/// after startup, like Caddy.
///
/// Pingora's `Server` cannot add services once `run_forever` has started, so
/// every dynamically added listener runs its own `Service` accept loop on the
/// shared background runtime. The proxy map is updated first so `/load`
/// resolution and traffic both see the listener immediately.
struct RuntimeListeners {
    port_proxies: Arc<RwLock<HashMap<String, pingclair_proxy::server::PingclairProxy>>>,
    server_conf: Arc<pingora::server::configuration::ServerConf>,
    tls_manager: Arc<TlsManager>,
    trusted_proxies: Vec<String>,
    blocked_ips: Vec<String>,
    proxy_protocol_addresses: HashSet<String>,
    http_port: u16,
    https_port: u16,
    running: RwLock<HashMap<String, tokio::task::JoinHandle<()>>>,
    shutdowns: RwLock<HashMap<String, tokio::sync::watch::Sender<bool>>>,
    dynamic_addrs: RwLock<HashSet<String>>,
}

impl pingclair_proxy::server::DynamicListeners for RuntimeListeners {
    fn start_listener(
        &self,
        addr: &str,
        server: &pingclair_core::config::ServerConfig,
    ) -> Result<(), String> {
        if self.running.read().contains_key(addr) {
            return Ok(());
        }

        let is_https = server_requires_tls(server, addr, self.http_port, self.https_port);
        // 🚫 Bind first so permission and privileged-port failures surface
        // synchronously to `/load` instead of panicking the accept task later
        // (the accept loop re-binds immediately after this probe).
        std::net::TcpListener::bind(addr)
            .map_err(|error| format!("cannot bind {addr}: {error}"))?;
        let proxy = {
            let mut guard = self.port_proxies.write();
            guard
                .entry(addr.to_string())
                .or_insert_with(|| {
                    pingclair_proxy::server::PingclairProxy::with_tls_and_trusted_proxies(
                        self.tls_manager.clone(),
                        &self.trusted_proxies,
                        self.proxy_protocol_addresses.contains(addr),
                    )
                })
                .clone()
        };
        proxy.add_server(server.clone());

        let listener_limits = proxy.listener_limits();
        let http_proxy = pingora_proxy::HttpProxy::new(proxy, self.server_conf.clone());
        let mut server_options = pingora_core::apps::HttpServerOptions::default();
        server_options.h2c = !is_https;
        let app =
            resource_guard::ResourceGuardedProxy::new(http_proxy, listener_limits, server_options);
        let mut service = pingora_core::services::listening::Service::new(
            "Pingclair Dynamic HTTP Service".to_string(),
            app,
        );
        if !self.blocked_ips.is_empty() {
            let filter = std::sync::Arc::new(pingclair_proxy::PingclairConnectionFilter::new(
                &self.blocked_ips,
            ));
            service.set_connection_filter(filter);
        }
        if is_https {
            let acceptor = DynamicCertResolver::new(self.tls_manager.clone());
            let mut tls_settings =
                TlsSettings::with_callbacks(Box::new(acceptor)).map_err(|e| e.to_string())?;
            tls_settings.enable_h2();
            service.add_tls_with_settings(addr, None, tls_settings);
        } else {
            service.add_tcp(addr);
        }

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = tokio::runtime::Handle::current().spawn(async move {
            #[cfg(unix)]
            PingoraService::start_service(&mut service, None, shutdown_rx, 1).await;
            #[cfg(not(unix))]
            PingoraService::start_service(&mut service, shutdown_rx, 1).await;
        });
        self.running.write().insert(addr.to_string(), handle);
        self.shutdowns.write().insert(addr.to_string(), shutdown_tx);
        self.dynamic_addrs.write().insert(addr.to_string());
        tracing::info!("🧭 Dynamically listening on {} (TLS: {})", addr, is_https);
        Ok(())
    }

    fn stop_listener(&self, addr: &str) {
        if let Some(tx) = self.shutdowns.write().remove(addr) {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.running.write().remove(addr) {
            handle.abort();
        }
        self.port_proxies.write().remove(addr);
        self.dynamic_addrs.write().remove(addr);
        tracing::info!("🛑 Dynamically stopped listener {}", addr);
    }

    fn is_dynamic(&self, addr: &str) -> bool {
        self.dynamic_addrs.read().contains(addr)
    }
}

/// 🧭 Maps every server (and its automatic HTTP companion) to the concrete
/// bind addresses it serves, exactly like the startup listener derivation.
///
/// Reload used to key on `listen.first()` alone, which put a hostname site
/// on `0.0.0.0:80` and never touched the TLS listener that actually served
/// it — the reload reported success while behavior stayed frozen.
fn servers_by_bind_address(
    config: &pingclair_core::config::PingclairConfig,
) -> HashMap<String, Vec<pingclair_core::config::ServerConfig>> {
    let http_port = config.global.http_port;
    let https_port = config.global.https_port;
    let mut by_port: HashMap<String, Vec<pingclair_core::config::ServerConfig>> = HashMap::new();
    for server in &config.servers {
        let addrs: Vec<String> = if server.listen.is_empty() {
            let host = server
                .bind
                .as_deref()
                .filter(|host| !host.is_empty())
                .unwrap_or("[::]");
            let port = if server.tls.is_some() {
                https_port
            } else {
                http_port
            };
            vec![format!("{host}:{port}")]
        } else {
            server
                .listen
                .iter()
                .map(|addr| normalize_listen_addr(addr))
                .collect()
        };
        for addr in &addrs {
            by_port
                .entry(addr.clone())
                .or_default()
                .push(server.clone());
        }
        if let Some(companion) = automatic_http_companion(
            server,
            config.global.auto_https.clone(),
            &addrs,
            http_port,
            https_port,
        ) {
            let addr = format!("[::]:{http_port}");
            by_port.entry(addr).or_default().push(companion);
        }
    }
    by_port
}

fn run_server(
    config_path: String,
    config: pingclair_core::config::PingclairConfig,
) -> anyhow::Result<()> {
    // Create a background Tokio runtime for async tasks (HTTP/3, SIGHUP, etc.)
    // We do this in a separate thread to avoid conflicts with Pingora's runtime.
    let bg_runtime = tokio::runtime::Runtime::new().expect("Failed to create background runtime");
    let bg_handle = bg_runtime.handle().clone();

    std::thread::spawn(move || {
        bg_runtime.block_on(async {
            // Keep the runtime alive
            std::future::pending::<()>().await;
        });
    });

    // Enhanced diagnostic logging
    tracing::info!("🚀 Starting Pingclair v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("📄 Loaded configuration from: {}", config_path);
    tracing::info!("🔧 Configured {} server(s)", config.servers.len());

    // 📊 Register Prometheus metrics with the global registry so the admin
    // /metrics endpoint has data to expose. `{ metrics }` can turn collection
    // on explicitly; it stays on by default for existing deployments.
    if config.global.metrics {
        pingclair_proxy::metrics::init();
    }

    if config.global.auto_https != pingclair_core::config::AutoHttpsMode::Off {
        tracing::info!("🔐 Auto HTTPS: enabled");
        if let Some(email) = &config.global.email {
            tracing::info!("📧 ACME email: {}", email);
        }
    } else {
        tracing::info!("🔐 Auto HTTPS: disabled");
    }

    if config.servers.is_empty() {
        tracing::warn!("⚠️ No servers configured!");
        return Ok(());
    }

    // Create Pingora Server.
    //
    // We build `ServerConf` explicitly (rather than passing `conf: None`
    // and letting Pingora fall back to its own implicit default) so the
    // upstream keepalive connection pool size is always a deliberate,
    // known value — not an invisible one an operator only discovers when
    // a slow upstream under load starts exhausting connections.
    let mut server_conf = pingora::server::configuration::ServerConf::default();
    server_conf.upstream_keepalive_pool_size = config
        .global
        .upstream_keepalive_pool_size
        .unwrap_or(server_conf.upstream_keepalive_pool_size);
    // Pingora defaults to ONE thread per service — on a multi-core box that
    // leaves the machine idle while nginx runs one worker per core. Scale
    // with available parallelism instead (still overridable via config).
    server_conf.threads = config.global.worker_threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    });
    tracing::info!(
        "🔗 Upstream keepalive pool size: {} connections/thread",
        server_conf.upstream_keepalive_pool_size
    );
    tracing::info!("🧵 Worker threads per service: {}", server_conf.threads);
    tracing::info!(
        "🛡️ Trusted proxy networks: {}",
        config.global.trusted_proxies.len()
    );
    {
        let required: Vec<&str> = config
            .servers
            .iter()
            .flat_map(|server| server.proxy_protocol_listen.iter())
            .map(String::as_str)
            .collect();
        tracing::info!(
            "🧭 PROXY protocol listeners: {}",
            if required.is_empty() {
                "none".to_string()
            } else {
                required.join(", ")
            }
        );
    }

    let mut server = pingora::server::Server::new_with_opt_and_conf(
        Some(pingora::server::configuration::Opt {
            upgrade: false,
            daemon: false,
            nocapture: false,
            test: false,
            conf: None, // We build ServerConf ourselves above; no file to load.
        }),
        server_conf,
    );
    let server_conf_arc = server.configuration.clone();

    server.bootstrap();
    // 🩺 One Pingora-owned driver follows weak pool registrations across hot reloads.
    server.add_service(pingora::services::background::background_service(
        "Pingclair active health checks",
        pingclair_proxy::health_check::HealthCheckDriver,
    ));

    // 🔐 Initialize every certificate source below one configurable persistent store.
    let tls_store_path_str = tls_store_dir().to_string_lossy().to_string();
    let tls_store_path = std::path::Path::new(&tls_store_path_str);
    if !tls_store_path.exists() {
        std::fs::create_dir_all(tls_store_path).map_err(|error| {
            anyhow::anyhow!(
                "🔐 TLS store {tls_store_path_str} cannot be created: {error} \
                 (set PINGCLAIR_TLS_STORE to a writable, persistent directory)"
            )
        })?;
    }
    // 💾 Probe writeability before any ACME or internal-CA work: a store that
    // cannot persist certificates must fail startup with a clear message, not
    // a confusing mid-flight error later.
    let probe = tls_store_path.join(format!(".write-probe-{}", std::process::id()));
    std::fs::write(&probe, b"ok").map_err(|error| {
        anyhow::anyhow!(
            "🔐 TLS store {tls_store_path_str} is not writable: {error} \
             (set PINGCLAIR_TLS_STORE to a writable, persistent directory)"
        )
    })?;
    let _ = std::fs::remove_file(&probe);

    let mut auto_https_config = pingclair_tls::auto_https::AutoHttpsConfig::default();
    if let Some(email) = &config.global.email {
        auto_https_config.email = Some(email.clone());
    }
    if config.global.auto_https == pingclair_core::config::AutoHttpsMode::Off {
        auto_https_config.enabled = false;
    }

    // 🧰 Reuse one temporary runtime for manager initialization and eager local issuance.
    let tls_runtime = tokio::runtime::Runtime::new()
        .expect("Failed to create runtime for TLS manager initialization");
    let tls_manager = std::sync::Arc::new(tls_runtime.block_on(async {
        pingclair_tls::manager::TlsManager::new(Some(auto_https_config), tls_store_path)
            .await
            .expect("Failed to create TLS manager with persistent challenge handler")
    }));

    // 🔐 Prepare configured certificate sources before any listener can accept a handshake.
    for server_config in &config.servers {
        let Some(tls) = &server_config.tls else {
            continue;
        };

        if tls.internal {
            let name = server_config.name.as_deref().unwrap_or_default();
            match tls_runtime.block_on(tls_manager.enable_internal_domain(name)) {
                Ok(_) => {
                    tracing::info!("🏛️ Prepared an internal TLS certificate for {}", name);
                }
                Err(error) => {
                    anyhow::bail!(
                        "failed to prepare the internal TLS certificate for {name}: {error}"
                    );
                }
            }
        }

        let (Some(cert_path), Some(key_path)) = (&tls.cert, &tls.key) else {
            continue;
        };

        let Some(name) = server_config.name.as_deref() else {
            tracing::warn!(
                "⚠️ TLS cert/key configured on an unnamed server, skipping manual certificate load"
            );
            continue;
        };
        if name.is_empty() || name == "_" {
            tracing::warn!(
                "⚠️ Skipping manual TLS certificate for wildcard/unnamed server '{}'",
                name
            );
            continue;
        }

        let cert_pem = match std::fs::read_to_string(cert_path) {
            Ok(pem) => pem,
            Err(e) => {
                tracing::error!("❌ Failed to read TLS cert file {}: {}", cert_path, e);
                continue;
            }
        };
        let key_pem = match std::fs::read_to_string(key_path) {
            Ok(pem) => pem,
            Err(e) => {
                tracing::error!("❌ Failed to read TLS key file {}: {}", key_path, e);
                continue;
            }
        };

        tls_manager.add_manual_cert(name, cert_pem, key_pem);
        tracing::info!("🔐 Loaded manual TLS certificate for {}", name);
    }

    // 🚀 Kick off the background certificate machinery: renewals plus eager
    // issuance for every `tls auto` hostname. Domains already covered by
    // internal or manual certificates are excluded — those paths are eager
    // already, and ACME must never race a local authority.
    let eager_domains = eager_issuance_domains(&config);
    // 🚀 The background tasks need a Tokio reactor; the dedicated background
    // runtime already exists for H3 and SIGHUP work.
    let tls_manager_for_tasks = tls_manager.clone();
    bg_handle.spawn(async move {
        tls_manager_for_tasks.start_background_issuance(eager_domains);
    });

    // Group servers by listen address
    let port_proxies = std::collections::HashMap::new();
    let port_proxies = std::sync::Arc::new(parking_lot::RwLock::new(port_proxies));

    // HTTP/3 startup inputs, captured before `config.servers` is consumed:
    // - the global on/off switch (HTTPS ports only ever start H3),
    // - the domains whose certificates seed the SNI cert table,
    // - the upstream pool size + L4 blocklist kept consistent with H1/H2.
    let http3_globally_enabled = config.global.http3;
    let h3_domains: Vec<String> = config
        .servers
        .iter()
        .filter_map(|s| s.name.clone())
        .filter(|n| !n.is_empty() && n != "_" && n != "*" && !n.starts_with(':'))
        .collect();
    let h3_pool_size = config.global.upstream_keepalive_pool_size.unwrap_or(128);
    let h3_blocked_ips = config.global.blocked_ips.clone();
    let trusted_proxies = config.global.trusted_proxies.clone();
    // 🧭 Which listen addresses require a PROXY header, resolved once. The
    // compiler has already rejected any address two servers disagree about, so
    // membership here is the whole answer for a given socket.
    let proxy_protocol_addresses: std::collections::HashSet<String> = config
        .servers
        .iter()
        .flat_map(|server| server.proxy_protocol_listen.iter().cloned())
        .collect();
    let proxy_protocol_networks =
        pingclair_proxy::proxy_protocol::parse_networks(&trusted_proxies)?;
    let blocked_client_networks =
        pingclair_proxy::proxy_protocol::parse_networks(&config.global.blocked_ips)?;

    // Track binding information for diagnostic logging
    let mut binding_info: HashMap<String, Vec<String>> = HashMap::new();
    let mut tls_listeners = HashSet::new();

    // 🔎 Probed once, before any listener is registered: whether an automatic
    // port-80 companion is even possible here. Doing it per site would probe a
    // privileged port repeatedly for one unchanging answer.
    let auto_https_mode = config.global.auto_https.clone();
    let http_port = config.global.http_port;
    let https_port = config.global.https_port;
    let automatic_http_available = auto_https_mode != pingclair_core::config::AutoHttpsMode::Off
        && config.servers.iter().any(|server| server.tls.is_some())
        && can_bind_automatic_http_port(http_port);

    for server_config in &config.servers {
        tracing::debug!(
            "🚀 Processing ServerConfig: name={:?}, listens={:?}",
            server_config.name,
            server_config.listen
        );

        let listen_addrs: Vec<String> = if server_config.listen.is_empty() {
            // 🔐 A site that configures TLS but no port means HTTPS, so it
            // belongs on 443. Defaulting it to 80 would quietly serve a site
            // the operator asked to encrypt on the plaintext port instead.
            let host = server_config
                .bind
                .as_deref()
                .filter(|h| !h.is_empty())
                .unwrap_or("[::]");
            if server_config.tls.is_some() {
                vec![format!("{host}:{https_port}")]
            } else {
                vec![format!("{host}:{http_port}")]
            }
        } else {
            server_config
                .listen
                .iter()
                .map(|a| normalize_listen_addr(a))
                .collect()
        };

        // 🔁 Automatic HTTPS: give an HTTPS site its plaintext port-80 companion
        // so ACME validation and the HTTP→HTTPS redirect both work unattended.
        let companion = automatic_http_companion(
            server_config,
            auto_https_mode.clone(),
            &listen_addrs,
            http_port,
            https_port,
        )
        .filter(|_| {
            if automatic_http_available {
                true
            } else {
                tracing::warn!(
                    "🚫 Automatic HTTPS could not take {} for {:?}: HTTP→HTTPS \
                     redirects and ACME HTTP-01 validation are unavailable. \
                     Free the port, run with CAP_NET_BIND_SERVICE, or add an \
                     explicit `listen` for the plaintext port.",
                    format!("[::]:{http_port}"),
                    server_config.name
                );
                false
            }
        });

        for addr in listen_addrs {
            if server_requires_tls(server_config, &addr, http_port, https_port) {
                tls_listeners.insert(addr.clone());
            }
            let mut proxies_guard = port_proxies.write();
            let proxy = proxies_guard.entry(addr.clone()).or_insert_with(|| {
                pingclair_proxy::server::PingclairProxy::with_tls_and_trusted_proxies(
                    tls_manager.clone(),
                    &trusted_proxies,
                    proxy_protocol_addresses.contains(&addr),
                )
            });

            // Track what sites are bound to what addresses
            let site_name = server_config
                .name
                .clone()
                .unwrap_or_else(|| "default".to_string());
            binding_info
                .entry(addr.clone())
                .or_default()
                .push(site_name);

            proxy.add_server(server_config.clone());
        }

        if let Some(companion) = companion {
            let addr = format!("[::]:{http_port}");
            let mut proxies_guard = port_proxies.write();
            let proxy = proxies_guard.entry(addr.clone()).or_insert_with(|| {
                pingclair_proxy::server::PingclairProxy::with_tls_and_trusted_proxies(
                    tls_manager.clone(),
                    &trusted_proxies,
                    proxy_protocol_addresses.contains(&addr),
                )
            });
            binding_info.entry(addr).or_default().push(format!(
                "{} (automatic HTTP)",
                companion.name.as_deref().unwrap_or("default")
            ));
            proxy.add_server(companion);
        }
    }

    // Log binding information for diagnostics
    tracing::info!("🌐 Server binding information:");
    for (addr, sites) in &binding_info {
        tracing::info!("   📍 {} -> [{}]", addr, sites.join(", "));
    }

    // Create services for each proxy
    let mut https_ports = Vec::new();
    let mut private_listener_reservations = Vec::new();
    {
        let proxies_guard = port_proxies.read();
        for (addr, proxy_logic) in proxies_guard.iter() {
            let is_https = tls_listeners.contains(addr);
            let requires_proxy_protocol = proxy_protocol_addresses.contains(addr);
            let internal_reservation = requires_proxy_protocol
                .then(reserve_private_listener_address)
                .transpose()?;
            let internal_address = internal_reservation.as_ref().map(|(_, address)| *address);
            let service_address = internal_address
                .map(|address| address.to_string())
                .unwrap_or_else(|| addr.clone());
            // 🌐 Enables prior-knowledge h2c only on plaintext listeners while TLS uses ALPN.
            let mut server_options = pingora_core::apps::HttpServerOptions::default();
            server_options.h2c = !is_https;
            let listener_limits = proxy_logic.listener_limits();
            // 🧱 Captured before the guard consumes the limits, so the public
            // PROXY ingress can carry the same ceiling as the private hop.
            let ingress_max_connections = listener_limits.max_connections;
            let proxy =
                pingora_proxy::HttpProxy::new(proxy_logic.clone(), server.configuration.clone());
            let app =
                resource_guard::ResourceGuardedProxy::new(proxy, listener_limits, server_options);
            let mut service = pingora_core::services::listening::Service::new(
                "Pingclair HTTP Proxy Service".to_string(),
                app,
            );

            // Add L4 Connection Filter (Global Blocked IPs)
            let blocked_ips = &config.global.blocked_ips;
            if !requires_proxy_protocol && !blocked_ips.is_empty() {
                let filter = std::sync::Arc::new(pingclair_proxy::PingclairConnectionFilter::new(
                    blocked_ips,
                ));
                service.set_connection_filter(filter);
            }

            // 🔐 Explicit TLS configuration supports HTTPS and H3 on non-standard ports.
            let mut tls_enabled = false;
            let mut http3_enabled = false;

            if is_https {
                // 🔐 Enable dynamic certificates and advertise HTTP/2 plus HTTP/1.1 over ALPN.
                let acceptor = DynamicCertResolver::new(tls_manager.clone());
                match TlsSettings::with_callbacks(Box::new(acceptor)) {
                    Ok(mut tls_settings) => {
                        tls_settings.enable_h2();
                        service.add_tls_with_settings(&service_address, None, tls_settings);
                        tls_enabled = true;
                    }
                    Err(e) => {
                        tracing::error!("❌ Failed to create TlsSettings for {}: {}", addr, e);
                    }
                }

                // Enable HTTP/3 for HTTPS ports when the global switch is on:
                // advertise Alt-Svc on this listener and queue the port for
                // a QUIC socket.
                if http3_globally_enabled {
                    https_ports.push(addr.clone());
                    http3_enabled = true;

                    if let Some(port) = addr.rsplit(':').next().and_then(|p| p.parse::<u16>().ok())
                    {
                        proxy_logic.set_alt_svc(port);
                    }
                }
            } else {
                service.add_tcp(&service_address);
            }

            if let Some(internal_address) = internal_address {
                let public_listener = std::net::TcpListener::bind(addr).map_err(|error| {
                    anyhow::anyhow!("failed to bind PROXY protocol ingress on {addr}: {error}")
                })?;
                let registry = proxy_logic.proxy_protocol_registry();
                let trusted = proxy_protocol_networks.clone();
                let blocked = blocked_client_networks.clone();
                bg_handle.spawn(async move {
                    if let Err(error) = pingclair_proxy::proxy_protocol::run_ingress(
                        public_listener,
                        internal_address,
                        registry,
                        trusted,
                        blocked,
                        ingress_max_connections,
                    )
                    .await
                    {
                        tracing::error!(
                            %error,
                            "❌ PROXY protocol ingress stopped unexpectedly"
                        );
                    }
                });
            }
            if let Some((reservation, _)) = internal_reservation {
                private_listener_reservations.push(reservation);
            }

            // Enhanced diagnostic logging for each binding
            tracing::info!(
                "   🌐 Server listening on {} (TLS: {}, HTTP/3: {})",
                addr,
                if tls_enabled { "enabled" } else { "disabled" },
                if http3_enabled { "enabled" } else { "disabled" }
            );

            server.add_service(service);
        }
    }

    // Start HTTP/3 (QUIC) servers for HTTPS ports
    if !https_ports.is_empty() {
        tracing::info!(
            "🚀 Starting HTTP/3 (quiche) servers for {} port(s)",
            https_ports.len()
        );

        // Shared SNI certificate table: populated from the TLS manager
        // (manual certs + already-issued ACME certs), then refreshed
        // periodically so renewals reach new handshakes without a restart.
        let cert_table = std::sync::Arc::new(pingclair_proxy::quic::CertTable::new());
        let table_for_task = cert_table.clone();
        let tls_for_task = tls_manager.clone();
        let proxies_for_task = port_proxies.clone();
        let domains_for_task = h3_domains.clone();
        let blocked_for_task = h3_blocked_ips.clone();

        bg_handle.spawn(async move {
            // Populate the table before serving so the first handshake can
            // already find its certificate.
            refresh_h3_cert_table(&table_for_task, &tls_for_task, &domains_for_task).await;

            for addr_str in &https_ports {
                let Ok(socket_addr) = addr_str.parse::<std::net::SocketAddr>() else {
                    tracing::error!("❌ Invalid HTTP/3 listen address: {}", addr_str);
                    continue;
                };

                let proxy = {
                    let guard = proxies_for_task.read();
                    guard.get(addr_str).map(|p| std::sync::Arc::new(p.clone()))
                };
                let Some(proxy) = proxy else {
                    tracing::error!("❌ No proxy found for HTTP/3 address {}", addr_str);
                    continue;
                };

                let server = pingclair_proxy::quic::QuicServer::new(
                    socket_addr,
                    proxy,
                    table_for_task.clone(),
                    h3_pool_size,
                    blocked_for_task.clone(),
                );

                tokio::spawn(async move {
                    if let Err(e) = server.run().await {
                        tracing::error!("HTTP/3 server on {} failed: {}", socket_addr, e);
                    }
                });
            }

            // Periodic refresh: picks up ACME issuances and renewals.
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                refresh_h3_cert_table(&table_for_task, &tls_for_task, &domains_for_task).await;
            }
        });
    }

    // 🛑 `POST /stop` notifies this; the shutdown task treats it like SIGTERM.
    let admin_shutdown = Arc::new(tokio::sync::Notify::new());
    // 🚫 Caddy disables SIGUSR1 reloads once the Admin API has changed the
    // config; this flag records that transition.
    let api_changed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // 🧭 `/load` can create listeners at runtime; the manager is handed to
    // the admin server so a document naming a new address is honored.
    let dynamic_listeners: Arc<dyn pingclair_proxy::server::DynamicListeners> =
        Arc::new(RuntimeListeners {
            port_proxies: port_proxies.clone(),
            server_conf: server_conf_arc,
            tls_manager: tls_manager.clone(),
            trusted_proxies: trusted_proxies.clone(),
            blocked_ips: h3_blocked_ips.clone(),
            proxy_protocol_addresses: proxy_protocol_addresses.clone(),
            http_port,
            https_port,
            running: RwLock::new(HashMap::new()),
            shutdowns: RwLock::new(HashMap::new()),
            dynamic_addrs: RwLock::new(HashSet::new()),
        });

    // Start Admin API if enabled
    if let Some(admin_config) = &config.admin
        && admin_config.enabled
    {
        let listen = admin_config.listen.clone();
        let api_key = admin_config.api_key.clone();
        let proxies = port_proxies.clone();
        let shutdown_for_admin = admin_shutdown.clone();
        let autosave = tls_store_dir().join("autosave.json");
        // 🧭 The admin traversal endpoints read and write one shared config
        // document; it starts as the exact configuration that was loaded.
        let document = Arc::new(RwLock::new(
            serde_json::to_value(config.clone())
                .unwrap_or_else(|_| serde_json::Value::Object(Default::default())),
        ));
        let dynamic_listeners_for_admin = dynamic_listeners.clone();
        let api_changed_for_admin = api_changed.clone();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create admin runtime");
            rt.block_on(async {
                let addr = listen.parse().expect("Invalid admin listen address");
                let options = pingclair_api::AdminServerOptions {
                    proxies,
                    document,
                    shutdown: shutdown_for_admin,
                    autosave: Some(autosave),
                    listeners: Some(dynamic_listeners_for_admin),
                    api_changed: api_changed_for_admin,
                    api_key,
                };
                if let Err(e) = pingclair_api::run_admin_server(addr, options).await {
                    tracing::error!("Admin server error: {}", e);
                }
            });
        });
    }

    // ========================================
    // 🔔 Signal Handling for SIGUSR1 (Reload)
    // ========================================
    #[cfg(unix)]
    if !config_path.is_empty() {
        let config_path = config_path.clone();
        let port_proxies = port_proxies.clone();
        let dynamic_listeners_for_reload = dynamic_listeners.clone();
        let api_changed_for_reload = api_changed.clone();
        // 🧭 Snapshot the global settings the process started with, so a
        // reload that changes them can say so instead of silently ignoring
        // the difference.
        let original_global = config.global.clone();

        bg_handle.spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};

            // 🚦 SIGUSR1 is Caddy's reload signal; SIGHUP is deliberately
            // ignored, matching Caddy's signal table.
            // 🙈 Claiming the stream registers the handler, so the default
            // terminate-on-SIGHUP action never fires; the signal is dropped.
            let mut _hup_ignored = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("❌ Failed to create SIGHUP listener: {}", e);
                    return;
                }
            };
            let mut usr1_stream = match signal(SignalKind::user_defined1()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("❌ Failed to create SIGUSR1 listener: {}", e);
                    return;
                }
            };

            tracing::info!("📡 Reload listener active (SIGUSR1, Config: {})", config_path);

            loop {
                let signal_name = tokio::select! {
                    _ = usr1_stream.recv() => "SIGUSR1",
                };
                if api_changed_for_reload.load(std::sync::atomic::Ordering::SeqCst) {
                    tracing::warn!(
                        "🚫 SIGUSR1 reload disabled: the configuration was changed through \
                         the Admin API after startup (Caddy semantics)"
                    );
                    continue;
                }
                let reload_start = std::time::Instant::now();
                tracing::info!("🔔 Received {signal_name}, reloading configuration from: {}", config_path);
                // 🛑 Let the new configuration start its own ACME transactions
                // immediately instead of waiting on the old config's in-flight
                // issuance markers.
                tls_manager.cancel_pending_issuance().await;

                // Step 1: Validate and load new configuration
                tracing::info!("📋 Step 1/3: Validating configuration...");
                let result = if std::path::Path::new(&config_path).is_dir() {
                    pingclair_config::compile_directory(&config_path)
                } else {
                    pingclair_config::compile_file(&config_path)
                };

                match result {
                    Ok(new_config) => {
                        // 🚩 Global options (email, auto_https, trusted
                        // proxies, ports, ...) only take effect at startup.
                        // Detecting the difference here keeps a reload from
                        // looking successful while the operator's global
                        // change silently never happened.
                        if new_config.global != original_global {
                            tracing::warn!(
                                "🚫 Reloaded configuration changes global options; \
                                 global settings only take effect after a restart \
                                 (old={:?}, new={:?})",
                                original_global,
                                new_config.global
                            );
                        }
                        tracing::info!("✅ Step 1/3: Configuration validation successful");
                        tracing::info!("📋 Step 2/3: Preparing configuration update...");

                        // 🧭 Derive every bind address the same way startup
                        // does (including the automatic HTTP companion), so a
                        // hostname site updates its TLS listener and not just
                        // a phantom `:80` entry.
                        let new_config_by_port = servers_by_bind_address(&new_config);

                        tracing::info!("📋 Step 3/3: Applying configuration to {} port(s)...", new_config_by_port.len());
                        let mut success_count = 0;
                        let mut warnings: Vec<String> = Vec::new();

                        for (addr, servers) in new_config_by_port {
                            let proxy = port_proxies.read().get(&addr).cloned();
                            if let Some(proxy) = proxy {
                                proxy.update_config(servers);
                                success_count += 1;
                                tracing::debug!("   ✓ Updated configuration for {}", addr);
                            } else {
                                // 🧭 Caddy's reload applies new listeners too;
                                // the runtime listener manager makes that true
                                // here instead of demanding a restart.
                                match dynamic_listeners_for_reload.start_listener(&addr, &servers[0]) {
                                    Ok(()) => {
                                        for extra in &servers[1..] {
                                            if let Some(proxy) =
                                                port_proxies.read().get(&addr)
                                            {
                                                proxy.add_server(extra.clone());
                                            }
                                        }
                                        success_count += 1;
                                    }
                                    Err(error) => {
                                        warnings.push(format!("{addr}: {error}"));
                                    }
                                }
                            }
                        }

                        let reload_duration = reload_start.elapsed();

                        if warnings.is_empty() {
                            tracing::info!("✅ Configuration reload completed successfully in {:?}", reload_duration);
                            tracing::info!("   📊 {} server(s) updated", success_count);
                            println!("✅ Configuration reloaded successfully ({success_count} servers updated in {reload_duration:?})");
                        } else {
                            for warning in &warnings {
                                tracing::warn!("⚠️ Reload listener warning: {warning}");
                            }
                            tracing::warn!("⚠️ Configuration reload completed with warnings in {:?}", reload_duration);
                            tracing::warn!("   📊 {} server(s) updated, {} warning(s)", success_count, warnings.len());
                            println!("⚠️ Configuration partially reloaded ({success_count} servers updated, {} warnings in {reload_duration:?})", warnings.len());
                        }
                    }
                    Err(e) => {
                        let reload_duration = reload_start.elapsed();
                        tracing::error!("❌ Configuration reload failed after {:?}: {}", reload_duration, e);
                        tracing::error!("   💡 Previous configuration remains active");
                        eprintln!("❌ Configuration reload failed: {e}");
                        eprintln!("   💡 Previous configuration remains active");
                    }
                }
            }
        });
    }

    // ========================================
    // 🔄 Upstream DNS re-resolution
    // ========================================
    // Every route was resolved once while its ProxyState was built. Container
    // addresses do not stay put, so one shared task re-resolves the hostname
    // pools on an interval; pools built from IP literals never registered and
    // cost nothing here.
    //
    // The task runs even when no pool has registered yet: a hot reload can
    // introduce the first hostname upstream, and it would have no refresher
    // if starting one depended on the boot-time config.
    let dns_refresh_secs = config.global.dns_refresh_secs;
    if dns_refresh_secs == 0 {
        tracing::info!("🔄 Upstream DNS re-resolution disabled (dns_refresh off)");
    } else {
        bg_handle.spawn(pingclair_proxy::dns::run(std::time::Duration::from_secs(
            dns_refresh_secs,
        )));
    }

    // ========================================
    // 🛑 Signal Handling for Shutdown (SIGINT/SIGTERM)
    // ========================================
    // Pingora's `run_forever()` blocks indefinitely, so without explicit
    // handlers the process only dies on SIGKILL. Install shutdown handlers
    // on the background runtime before entering it.
    let shutdown_for_task = admin_shutdown.clone();
    bg_handle.spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};

            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("❌ Failed to create SIGTERM listener: {}", e);
                    // Fall back to SIGINT-only handling.
                    let _ = tokio::signal::ctrl_c().await;
                    tracing::info!("🛑 Received SIGINT, shutting down");
                    std::process::exit(0);
                }
            };
            let mut sigquit = match signal(SignalKind::quit()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("❌ Failed to create SIGQUIT listener: {}", e);
                    return;
                }
            };

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("🛑 Received SIGINT, shutting down");
                }
                _ = sigterm.recv() => {
                    tracing::info!("🛑 Received SIGTERM, shutting down");
                }
                _ = sigquit.recv() => {
                    // 🏃 Caddy exits immediately on SIGQUIT (code 2) after
                    // cleaning storage locks; Pingora has no equivalent lock
                    // step, so a prompt exit is the faithful behavior.
                    tracing::info!("🏃 Received SIGQUIT, forced exit");
                    std::process::exit(2);
                }
                _ = shutdown_for_task.notified() => {
                    tracing::info!("🛑 Admin API requested shutdown");
                }
            }
        }

        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("🛑 Received Ctrl-C, shutting down");
        }

        std::process::exit(0);
    });

    println!("🚀 Pingclair running...");
    // 🔓 Releases every unique private address immediately before Pingora binds it.
    drop(private_listener_reservations);
    server.run_forever();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    /// 🚫 On non-Linux platforms (including local macOS), the service
    /// subcommand must fail with a clear message instead of pretending to run
    /// systemctl.
    #[test]
    #[cfg(not(target_os = "linux"))]
    fn service_management_reports_linux_only() {
        let error = manage_system_service(ServiceAction::Start)
            .expect_err("service management must fail outside Linux");
        assert!(
            error.to_string().contains("Linux"),
            "the message must explain the platform limit: {error}"
        );
    }

    /// 🚀 Only `tls auto` hostnames qualify for eager issuance; internal,
    /// manual and wildcard sites are excluded.
    #[test]
    fn eager_issuance_domains_excludes_internal_manual_and_wildcards() {
        use pingclair_core::config::{ServerConfig, TlsConfig};

        let auto = ServerConfig {
            name: Some("auto.example".to_string()),
            tls: Some(TlsConfig {
                auto: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let internal = ServerConfig {
            name: Some("internal.example".to_string()),
            tls: Some(TlsConfig {
                auto: true,
                internal: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let manual = ServerConfig {
            name: Some("manual.example".to_string()),
            tls: Some(TlsConfig {
                auto: true,
                cert: Some("/certs/fullchain.pem".to_string()),
                key: Some("/certs/key.pem".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let wildcard = ServerConfig {
            name: Some("*.example.com".to_string()),
            tls: Some(TlsConfig {
                auto: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let plain = ServerConfig {
            name: Some("plain.example".to_string()),
            tls: None,
            ..Default::default()
        };
        let json_shape = ServerConfig {
            name: Some("default".to_string()),
            names: vec!["json.example".to_string()],
            tls: Some(TlsConfig {
                auto: true,
                ..Default::default()
            }),
            ..Default::default()
        };

        let config = pingclair_core::config::PingclairConfig {
            servers: vec![auto, internal, manual, wildcard, plain, json_shape],
            ..Default::default()
        };
        assert_eq!(
            eager_issuance_domains(&config),
            vec!["auto.example", "json.example"]
        );
    }

    #[test]
    fn normalize_listen_addr_expands_bare_port() {
        assert_eq!(normalize_listen_addr(":8443"), "[::]:8443");
        assert_eq!(normalize_listen_addr(":80"), "[::]:80");
        // Full socket addresses pass through untouched.
        assert_eq!(normalize_listen_addr("127.0.0.1:9000"), "127.0.0.1:9000");
        assert_eq!(normalize_listen_addr("[::]:443"), "[::]:443");
        // The normalized form must parse as a SocketAddr (Pingora + H3 both
        // require this).
        assert!(
            normalize_listen_addr(":8443")
                .parse::<std::net::SocketAddr>()
                .is_ok()
        );
    }

    /// 🧭 Caddy-style address derivation used by the quick commands.
    #[test]
    fn cli_site_addresses_derive_like_caddy() {
        assert_eq!(listen_for_site(":2080", false), "[::]:2080");
        assert_eq!(listen_for_site("localhost", true), "[::]:443");
        assert_eq!(listen_for_site("example.com:8443", true), "[::]:8443");
        assert_eq!(listen_for_site("http://example.com", false), "[::]:80");
        assert_eq!(listen_for_site("127.0.0.1:9000", false), "127.0.0.1:9000");
        assert_eq!(host_only("example.com:8443"), "example.com");
        assert_eq!(host_only(":9000"), "");
        assert_eq!(
            upstream_hostport("https://localhost:9443"),
            "localhost:9443"
        );
        assert_eq!(upstream_hostport(":9000"), "127.0.0.1:9000");
        assert_eq!(upstream_hostport("backend.internal"), "backend.internal:80");
    }

    #[test]
    fn explicit_tls_enables_nonstandard_https_listener() {
        let config = pingclair_core::config::ServerConfig {
            listen: vec!["127.0.0.1:21209".to_string()],
            tls: Some(Default::default()),
            ..Default::default()
        };
        assert!(server_requires_tls(&config, "127.0.0.1:21209", 80, 443));

        let plain = pingclair_core::config::ServerConfig::default();
        assert!(!server_requires_tls(&plain, "127.0.0.1:21209", 80, 443));
        assert!(server_requires_tls(&plain, "[::]:443", 80, 443));
        assert!(server_requires_tls(&plain, "[::]:8443", 80, 443));
    }

    /// 🚫 A `tls` block must not drag port 80 into TLS along with it.
    ///
    /// `example.com { listen :80  listen :443  tls auto }` is the config anyone
    /// writes first, and it used to make port 80 a TLS listener. Let's Encrypt
    /// then sent its plaintext HTTP-01 probe into a TLS handshake, the listener
    /// logged `[HTTP_REQUEST]`, and the order failed — automatic HTTPS could
    /// never obtain the certificate it was trying to install.
    #[test]
    fn port_80_stays_plaintext_even_with_an_explicit_tls_block() {
        let config = pingclair_core::config::ServerConfig {
            listen: vec!["[::]:80".to_string(), "[::]:443".to_string()],
            tls: Some(Default::default()),
            ..Default::default()
        };

        assert!(
            !server_requires_tls(&config, "[::]:80", 80, 443),
            "ACME HTTP-01 validation is plaintext on port 80 and must reach the proxy"
        );
        assert!(
            server_requires_tls(&config, "[::]:443", 80, 443),
            "the TLS block must still apply to the HTTPS listener"
        );
    }

    /// 🔗 A CA bundle carries the leaf and its intermediates; keep all of them.
    #[test]
    fn parsing_a_bundle_keeps_every_certificate_after_the_leaf() {
        let leaf = certificate_pem("leaf.test");
        let intermediate = certificate_pem("intermediate.test");

        let single = parse_certificate_chain(&leaf).expect("a lone leaf parses");
        assert_eq!(single.len(), 1);

        let bundle = format!("{leaf}{intermediate}");
        let chain = parse_certificate_chain(&bundle).expect("a bundle parses");
        assert_eq!(
            chain.len(),
            2,
            "the intermediate was dropped; clients cannot build a trust path without it"
        );

        // 🚫 An empty bundle fails closed rather than reaching BoringSSL with
        // no leaf and surfacing as a confusing handshake error much later.
        assert!(parse_certificate_chain("").is_err());
    }

    /// 🔁 An HTTPS site gets a plaintext port-80 companion, like Caddy's.
    #[test]
    fn automatic_https_provisions_a_redirecting_http_listener() {
        use pingclair_core::config::{AutoHttpsMode, HandlerConfig};

        let site = pingclair_core::config::ServerConfig {
            name: Some("example.com".to_string()),
            listen: vec!["[::]:443".to_string()],
            tls: Some(Default::default()),
            ..Default::default()
        };

        let companion =
            automatic_http_companion(&site, AutoHttpsMode::On, &["[::]:443".to_string()], 80, 443)
                .expect("an HTTPS site needs its plaintext companion");

        assert_eq!(companion.listen, vec!["[::]:80".to_string()]);
        assert!(
            companion.tls.is_none(),
            "the companion carries ACME validation traffic and must stay plaintext"
        );
        match &companion.routes.as_slice() {
            [route] => match &route.handler {
                HandlerConfig::Redirect { to, code } => {
                    assert_eq!(to, "https://{host}{uri}");
                    assert_eq!(*code, 308);
                }
                other => panic!("expected a redirect, got {other:?}"),
            },
            other => panic!("expected exactly one catch-all route, got {other:?}"),
        }
    }

    /// 🚫 Every reason to provision nothing at all.
    #[test]
    fn automatic_https_leaves_these_sites_alone() {
        use pingclair_core::config::AutoHttpsMode;

        let https = |name: Option<&str>| pingclair_core::config::ServerConfig {
            name: name.map(str::to_string),
            listen: vec!["[::]:443".to_string()],
            tls: Some(Default::default()),
            ..Default::default()
        };
        let ports = vec!["[::]:443".to_string()];

        assert!(
            automatic_http_companion(
                &https(Some("example.com")),
                AutoHttpsMode::Off,
                &ports,
                80,
                443,
            )
            .is_none(),
            "`auto_https off` opts out of all of this"
        );
        assert!(
            automatic_http_companion(&https(None), AutoHttpsMode::On, &ports, 80, 443).is_none(),
            "a redirect needs a concrete host to send the client to"
        );
        assert!(
            automatic_http_companion(
                &https(Some("*.example.com")),
                AutoHttpsMode::On,
                &ports,
                80,
                443,
            )
            .is_none(),
            "a wildcard would have to guess which host to redirect to"
        );

        let plaintext = pingclair_core::config::ServerConfig {
            name: Some("example.com".to_string()),
            listen: vec!["0.0.0.0:8080".to_string()],
            ..Default::default()
        };
        assert!(
            automatic_http_companion(
                &plaintext,
                AutoHttpsMode::On,
                &["0.0.0.0:8080".to_string()],
                80,
                443,
            )
            .is_none(),
            "there is no HTTPS to redirect to"
        );

        // 🛡️ An operator who wrote `listen :80` has said what belongs there.
        assert!(
            automatic_http_companion(
                &https(Some("example.com")),
                AutoHttpsMode::On,
                &["[::]:80".to_string(), "[::]:443".to_string()],
                80,
                443,
            )
            .is_none(),
            "an explicit port 80 listener must not be overruled"
        );
    }

    /// 🔁 `disable_redirects` keeps the listener but drops the redirect.
    ///
    /// Before this existed the mode parsed, compiled, and then went unread —
    /// a setting that validated and silently did nothing.
    #[test]
    fn disable_redirects_keeps_acme_reachable_without_redirecting() {
        use pingclair_core::config::AutoHttpsMode;

        let site = pingclair_core::config::ServerConfig {
            name: Some("example.com".to_string()),
            listen: vec!["[::]:443".to_string()],
            tls: Some(Default::default()),
            ..Default::default()
        };

        let companion = automatic_http_companion(
            &site,
            AutoHttpsMode::DisableRedirects,
            &["[::]:443".to_string()],
            80,
            443,
        )
        .expect("ACME still needs to be reachable on port 80");

        assert_eq!(companion.listen, vec!["[::]:80".to_string()]);
        assert!(
            companion.routes.is_empty(),
            "the challenge path is answered before routing, so no route means no redirect"
        );
    }

    /// 🎫 Generates one throwaway self-signed certificate in PEM form.
    #[cfg(test)]
    fn certificate_pem(common_name: &str) -> String {
        let mut params =
            rcgen::CertificateParams::new(vec![common_name.to_string()]).expect("parameters");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        let key = rcgen::KeyPair::generate().expect("key pair");
        params.self_signed(&key).expect("certificate").pem()
    }
}
