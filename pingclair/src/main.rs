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
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod resource_guard;

#[cfg(target_os = "linux")]
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
        .filter_map(|server| server.name.clone())
        .filter(|name| !name.is_empty() && name != "_" && !name.contains('*'))
        .collect()
}

#[derive(Subcommand)]
enum Commands {
    /// Run the server with a configuration file
    Run {
        /// Path to the configuration file (defaults to Pingclairfile or
        /// Caddyfile in the current directory)
        config: Option<String>,
    },

    /// Start a quick reverse proxy
    #[command(name = "reverse-proxy")]
    ReverseProxy {
        /// Address to listen on
        #[arg(long, default_value = ":8080")]
        from: String,

        /// Upstream address to proxy to
        #[arg(long)]
        to: String,
    },

    /// Start a quick file server
    #[command(name = "file-server")]
    FileServer {
        /// Address to listen on
        #[arg(long, default_value = ":8080")]
        listen: String,

        /// Root directory to serve
        #[arg(long, default_value = ".")]
        root: String,
    },

    /// Validate a configuration file
    Validate {
        /// Path to the configuration file (defaults to Pingclairfile or
        /// Caddyfile in the current directory)
        config: Option<String>,
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
        } => {
            let config_path = resolve_config_path(config_path.as_deref());
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

            run_server(config_path.clone(), config)?;
        }

        Commands::ReverseProxy { from, to } => {
            tracing::info!("Starting reverse proxy: {} -> {}", from, to);
            // Create dynamic config
            let mut config = pingclair_core::config::PingclairConfig::default();

            // Parse listen address
            let listen = if from.starts_with(':') {
                format!("0.0.0.0{from}")
            } else {
                from.clone()
            };

            use pingclair_core::config::{
                HandlerConfig, LoadBalanceConfig, ReverseProxyConfig, RouteConfig, ServerConfig,
            };

            let mut server = ServerConfig {
                name: Some("_".to_string()),
                names: Vec::new(),
                bind: None,
                proxy_protocol_listen: Vec::new(),
                listen: vec![listen],
                routes: Vec::new(),
                tls: None,
                log: None,
                client_max_body_size: 10 * 1024 * 1024, // 10MB
                limits: Default::default(),
                security: Default::default(),
                gzip_types: pingclair_core::config::default_gzip_types(),
                encodings: pingclair_core::config::default_encodings(),
                error_pages: Default::default(),
            };

            let handler = HandlerConfig::ReverseProxy(ReverseProxyConfig {
                upstreams: vec![to.clone()],
                upstream_options: Vec::new(),
                // 🗄️ `pingclair reverse-proxy` is a throwaway one-liner; caching
                // is a deliberate per-route decision, so it stays off here.
                cache: None,
                load_balance: LoadBalanceConfig::default(),
                health_check: None,
                headers_up: std::collections::HashMap::new(),
                headers_down: std::collections::HashMap::new(),
                flush_interval: None,
                read_timeout: None,
                write_timeout: None,
                connect_timeout: None,
                first_byte_timeout: None,
                between_reads_timeout: None,
                retry: Default::default(),
                overload: Default::default(),
                circuit_breaker: Default::default(),
                upstream_tls: Default::default(),
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

        Commands::FileServer { listen, root } => {
            tracing::info!("Starting file server on {} serving {}", listen, root);

            // Create dynamic config
            let mut config = pingclair_core::config::PingclairConfig::default();

            // Parse listen address
            let listen_addr = if listen.starts_with(':') {
                format!("0.0.0.0{listen}")
            } else {
                listen.clone()
            };

            use pingclair_core::config::{HandlerConfig, RouteConfig, ServerConfig};

            let mut server = ServerConfig {
                name: Some("_".to_string()),
                names: Vec::new(),
                bind: None,
                proxy_protocol_listen: Vec::new(),
                listen: vec![listen_addr],
                routes: Vec::new(),
                tls: None,
                log: None,
                client_max_body_size: 10 * 1024 * 1024,
                limits: Default::default(),
                security: Default::default(),
                gzip_types: pingclair_core::config::default_gzip_types(),
                encodings: pingclair_core::config::default_encodings(),
                error_pages: Default::default(),
            };

            // Resolve absolute path
            let root_path = std::fs::canonicalize(&root)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or(root.clone());

            let handler = HandlerConfig::FileServer {
                root: root_path,
                index: vec!["index.html".to_string()],
                browse: true,
                compress: true,
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
            let config = resolve_config_path(config.as_deref());
            tracing::info!("Validating config: {}", config);

            // Support both file and directory validation
            let result = if std::path::Path::new(&config).is_dir() {
                tracing::info!("📁 Validating configuration directory: {}", config);
                pingclair_config::compile_directory(&config)
            } else {
                pingclair_config::compile_file(&config)
            };

            match result {
                Ok(_) => {
                    println!("✅ Configuration '{config}' is valid!");
                }
                Err(e) => {
                    eprintln!("❌ Configuration Error: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Version => {
            println!("Pingclair v{}", env!("CARGO_PKG_VERSION"));
            println!("Built with ❤️ in Rust");
        }

        Commands::Service { action } => {
            #[cfg(not(target_os = "linux"))]
            {
                let _ = action;
                eprintln!("❌ Service management is only supported on Linux.");
            }

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
                        eprintln!("❌ Failed to {cmd} service (exit code: {s})");
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to execute systemctl: {e}");
                    }
                }
            }

            #[cfg(not(target_os = "linux"))]
            {
                eprintln!("❌ Service management is only supported on Linux.");
                std::process::exit(1);
            }
        }
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
        Some(port) => format!("0.0.0.0:{port}"),
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
        listen: vec![format!("0.0.0.0:{http_port}")],
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

fn run_server(
    config_path: String,
    config: pingclair_core::config::PingclairConfig,
) -> anyhow::Result<()> {
    #[cfg(not(target_os = "linux"))]
    let _ = config_path;
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

    // Register Prometheus metrics with the global registry so the admin
    // /metrics endpoint has data to expose.
    pingclair_proxy::metrics::init();

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

    server.bootstrap();
    // 🩺 One Pingora-owned driver follows weak pool registrations across hot reloads.
    server.add_service(pingora::services::background::background_service(
        "Pingclair active health checks",
        pingclair_proxy::health_check::HealthCheckDriver,
    ));

    // 🔐 Initialize every certificate source below one configurable persistent store.
    let tls_store_path_str = std::env::var("PINGCLAIR_TLS_STORE")
        .unwrap_or_else(|_| "/var/lib/pingclair/certs".to_string());
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
    let mut binding_info = std::collections::HashMap::new();
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

    for server_config in config.servers {
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
                .unwrap_or("0.0.0.0");
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
            &server_config,
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
                    format!("0.0.0.0:{http_port}"),
                    server_config.name
                );
                false
            }
        });

        for addr in listen_addrs {
            if server_requires_tls(&server_config, &addr, http_port, https_port) {
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
                .or_insert_with(Vec::new)
                .push(site_name);

            proxy.add_server(server_config.clone());
        }

        if let Some(companion) = companion {
            let addr = format!("0.0.0.0:{http_port}");
            let mut proxies_guard = port_proxies.write();
            let proxy = proxies_guard.entry(addr.clone()).or_insert_with(|| {
                pingclair_proxy::server::PingclairProxy::with_tls_and_trusted_proxies(
                    tls_manager.clone(),
                    &trusted_proxies,
                    proxy_protocol_addresses.contains(&addr),
                )
            });
            binding_info
                .entry(addr)
                .or_insert_with(Vec::new)
                .push(format!(
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

    // Start Admin API if enabled
    if let Some(admin_config) = config.admin
        && admin_config.enabled
    {
        let listen = admin_config.listen.clone();
        let api_key = admin_config.api_key.clone();
        let proxies = port_proxies.clone();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create admin runtime");
            rt.block_on(async {
                let addr = listen.parse().expect("Invalid admin listen address");
                if let Err(e) = pingclair_api::run_admin_server(addr, proxies, api_key).await {
                    tracing::error!("Admin server error: {}", e);
                }
            });
        });
    }

    // ========================================
    // 🔔 Signal Handling for SIGHUP (Reload)
    // ========================================
    #[cfg(target_os = "linux")]
    if !config_path.is_empty() {
        let config_path = config_path.clone();
        let port_proxies = port_proxies.clone();

        bg_handle.spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};

            let mut stream = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("❌ Failed to create SIGHUP listener: {}", e);
                    return;
                }
            };

            tracing::info!("📡 SIGHUP listener active (Config: {})", config_path);

            while let Some(()) = stream.recv().await {
                let reload_start = std::time::Instant::now();
                tracing::info!("🔔 Received SIGHUP, reloading configuration from: {}", config_path);
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
                        tracing::info!("✅ Step 1/3: Configuration validation successful");
                        tracing::info!("📋 Step 2/3: Preparing configuration update...");

                        let mut new_config_by_port = std::collections::HashMap::new();
                        for s in new_config.servers {
                            let addr = s.listen.first().map(|a| normalize_listen_addr(a)).unwrap_or_else(|| "0.0.0.0:80".to_string());
                            new_config_by_port.entry(addr).or_insert_with(Vec::new).push(s);
                        }

                        tracing::info!("📋 Step 3/3: Applying configuration to {} port(s)...", new_config_by_port.len());

                        // Use read lock to get existing proxies (safe because we only read)
                        let proxies_guard = port_proxies.read();
                        let mut success_count = 0;
                        let mut error_count = 0;

                        for (addr, servers) in new_config_by_port {
                            if let Some(proxy) = proxies_guard.get(&addr) {
                                proxy.update_config(servers);
                                success_count += 1;
                                tracing::debug!("   ✓ Updated configuration for {}", addr);
                            } else {
                                tracing::warn!("⚠️ New listen address {} found in config during reload. Restart required for new ports.", addr);
                                error_count += 1;
                            }
                        }

                        let reload_duration = reload_start.elapsed();

                        if error_count == 0 {
                            tracing::info!("✅ Configuration reload completed successfully in {:?}", reload_duration);
                            tracing::info!("   📊 {} server(s) updated", success_count);
                            println!("✅ Configuration reloaded successfully ({success_count} servers updated in {reload_duration:?})");
                        } else {
                            tracing::warn!("⚠️ Configuration reload completed with warnings in {:?}", reload_duration);
                            tracing::warn!("   📊 {} server(s) updated, {} warning(s)", success_count, error_count);
                            println!("⚠️ Configuration partially reloaded ({success_count} servers updated, {error_count} warnings in {reload_duration:?})");
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

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("🛑 Received SIGINT, shutting down");
                }
                _ = sigterm.recv() => {
                    tracing::info!("🛑 Received SIGTERM, shutting down");
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

        let config = pingclair_core::config::PingclairConfig {
            servers: vec![auto, internal, manual, wildcard, plain],
            ..Default::default()
        };
        assert_eq!(eager_issuance_domains(&config), vec!["auto.example"]);
    }

    #[test]
    fn normalize_listen_addr_expands_bare_port() {
        assert_eq!(normalize_listen_addr(":8443"), "0.0.0.0:8443");
        assert_eq!(normalize_listen_addr(":80"), "0.0.0.0:80");
        // Full socket addresses pass through untouched.
        assert_eq!(normalize_listen_addr("127.0.0.1:9000"), "127.0.0.1:9000");
        assert_eq!(normalize_listen_addr("0.0.0.0:443"), "0.0.0.0:443");
        // The normalized form must parse as a SocketAddr (Pingora + H3 both
        // require this).
        assert!(
            normalize_listen_addr(":8443")
                .parse::<std::net::SocketAddr>()
                .is_ok()
        );
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
        assert!(server_requires_tls(&plain, "0.0.0.0:443", 80, 443));
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
            listen: vec!["0.0.0.0:80".to_string(), "0.0.0.0:443".to_string()],
            tls: Some(Default::default()),
            ..Default::default()
        };

        assert!(
            !server_requires_tls(&config, "0.0.0.0:80", 80, 443),
            "ACME HTTP-01 validation is plaintext on port 80 and must reach the proxy"
        );
        assert!(
            server_requires_tls(&config, "0.0.0.0:443", 80, 443),
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
            listen: vec!["0.0.0.0:443".to_string()],
            tls: Some(Default::default()),
            ..Default::default()
        };

        let companion = automatic_http_companion(
            &site,
            AutoHttpsMode::On,
            &["0.0.0.0:443".to_string()],
            80,
            443,
        )
        .expect("an HTTPS site needs its plaintext companion");

        assert_eq!(companion.listen, vec!["0.0.0.0:80".to_string()]);
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
            listen: vec!["0.0.0.0:443".to_string()],
            tls: Some(Default::default()),
            ..Default::default()
        };
        let ports = vec!["0.0.0.0:443".to_string()];

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
                &["0.0.0.0:80".to_string(), "0.0.0.0:443".to_string()],
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
            listen: vec!["0.0.0.0:443".to_string()],
            tls: Some(Default::default()),
            ..Default::default()
        };

        let companion = automatic_http_companion(
            &site,
            AutoHttpsMode::DisableRedirects,
            &["0.0.0.0:443".to_string()],
            80,
            443,
        )
        .expect("ACME still needs to be reachable on port 80");

        assert_eq!(companion.listen, vec!["0.0.0.0:80".to_string()]);
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
