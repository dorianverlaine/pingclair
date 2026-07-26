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
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// Cached BoringSSL certificate with expiration tracking
struct CachedSslCert {
    x509: X509,
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
                if let Err(e) = ssl.set_certificate(&cached.x509) {
                    tracing::error!("Failed to set cached certificate: {}", e);
                    return;
                }
                if let Err(e) = ssl.set_private_key(&cached.pkey) {
                    tracing::error!("Failed to set cached private key: {}", e);
                    return;
                }
                return;
            }
        }

        // Step 2: Cache miss or expired - fetch and parse PEM
        if let Some((cert_pem, key_pem)) = self.tls_manager.resolve_pem(&sni).await {
            let x509 = match X509::from_pem(cert_pem.as_bytes()) {
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

            // Step 3: Set the certificate and key
            if let Err(e) = ssl.set_certificate(&x509) {
                tracing::error!("Failed to set certificate: {}", e);
                return;
            }
            if let Err(e) = ssl.set_private_key(&pkey) {
                tracing::error!("Failed to set private key: {}", e);
                return;
            }

            // Step 4: Cache the parsed BoringSSL objects for future handshakes
            let expires_at = current_time + CERT_CACHE_TTL_SECS;
            let cached_entry = CachedSslCert {
                x509,
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

#[derive(Subcommand)]
enum Commands {
    /// Run the server with a configuration file
    Run {
        /// Path to the Pingclairfile
        #[arg(default_value = "Pingclairfile")]
        config: String,
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
        /// Path to the Pingclairfile
        #[arg(default_value = "Pingclairfile")]
        config: String,
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

            run_server(config_path.clone(), config);
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
                listen: vec![listen],
                routes: Vec::new(),
                tls: None,
                log: None,
                client_max_body_size: 10 * 1024 * 1024, // 10MB
                security: Default::default(),
                gzip_types: pingclair_core::config::default_gzip_types(),
                error_pages: Default::default(),
            };

            let handler = HandlerConfig::ReverseProxy(ReverseProxyConfig {
                upstreams: vec![to.clone()],
                upstream_options: Vec::new(),
                load_balance: LoadBalanceConfig::default(),
                health_check: None,
                headers_up: std::collections::HashMap::new(),
                headers_down: std::collections::HashMap::new(),
                flush_interval: None,
                read_timeout: None,
                write_timeout: None,
            });

            server.routes.push(RouteConfig {
                path: "/*".to_string(),
                handler,
                methods: None,
                matcher: None,
            });

            config.servers.push(server);

            run_server("".to_string(), config);
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
                listen: vec![listen_addr],
                routes: Vec::new(),
                tls: None,
                log: None,
                client_max_body_size: 10 * 1024 * 1024,
                security: Default::default(),
                gzip_types: pingclair_core::config::default_gzip_types(),
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

            run_server("".to_string(), config);
        }

        Commands::Validate { config } => {
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

fn run_server(config_path: String, config: pingclair_core::config::PingclairConfig) {
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
        return;
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

    // Initialize TLS Manager with global settings
    // Use environment variable for testing, fallback to default path
    let tls_store_path_str = std::env::var("PINGCLAIR_TLS_STORE")
        .unwrap_or_else(|_| "/var/lib/pingclair/certs".to_string());
    let tls_store_path = std::path::Path::new(&tls_store_path_str);
    if !tls_store_path.exists() {
        let _ = std::fs::create_dir_all(tls_store_path);
    }

    let mut auto_https_config = pingclair_tls::auto_https::AutoHttpsConfig::default();
    if let Some(email) = &config.global.email {
        auto_https_config.email = Some(email.clone());
    }
    if config.global.auto_https == pingclair_core::config::AutoHttpsMode::Off {
        auto_https_config.enabled = false;
    }

    // Create TLS manager with persistent challenge handler
    let tls_manager = std::sync::Arc::new(
        tokio::runtime::Runtime::new()
            .expect("Failed to create runtime for TLS manager initialization")
            .block_on(async {
                pingclair_tls::manager::TlsManager::new(Some(auto_https_config), tls_store_path)
                    .await
                    .expect("Failed to create TLS manager with persistent challenge handler")
            }),
    );

    // Load manually configured TLS certificates (tls.cert + tls.key file pairs)
    // into the TLS manager. Manual certs take precedence over ACME-issued ones.
    for server_config in &config.servers {
        let Some(tls) = &server_config.tls else {
            continue;
        };
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

    // Track binding information for diagnostic logging
    let mut binding_info = std::collections::HashMap::new();

    for server_config in config.servers {
        tracing::debug!(
            "🚀 Processing ServerConfig: name={:?}, listens={:?}",
            server_config.name,
            server_config.listen
        );

        let listen_addrs = if server_config.listen.is_empty() {
            vec!["0.0.0.0:80".to_string()]
        } else {
            server_config
                .listen
                .iter()
                .map(|a| normalize_listen_addr(a))
                .collect()
        };

        for addr in listen_addrs {
            let mut proxies_guard = port_proxies.write();
            let proxy = proxies_guard.entry(addr.clone()).or_insert_with(|| {
                pingclair_proxy::server::PingclairProxy::with_tls_and_trusted_proxies(
                    tls_manager.clone(),
                    &trusted_proxies,
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
    }

    // Log binding information for diagnostics
    tracing::info!("🌐 Server binding information:");
    for (addr, sites) in &binding_info {
        tracing::info!("   📍 {} -> [{}]", addr, sites.join(", "));
    }

    // Create services for each proxy
    let mut https_ports = Vec::new();
    {
        let proxies_guard = port_proxies.read();
        for (addr, proxy_logic) in proxies_guard.iter() {
            let proxy_service =
                pingora::proxy::http_proxy_service(&server.configuration, proxy_logic.clone());

            let mut service = proxy_service;

            // Add L4 Connection Filter (Global Blocked IPs)
            let blocked_ips = &config.global.blocked_ips;
            if !blocked_ips.is_empty() {
                let filter = std::sync::Arc::new(pingclair_proxy::PingclairConnectionFilter::new(
                    blocked_ips,
                ));
                service.set_connection_filter(filter);
            }

            // Determine if this is an HTTPS port
            let is_https = addr.ends_with(":443") || addr.ends_with(":8443");
            let mut tls_enabled = false;
            let mut http3_enabled = false;

            if is_https {
                // 🔐 Enable dynamic certificates and advertise HTTP/2 plus HTTP/1.1 over ALPN.
                let acceptor = DynamicCertResolver::new(tls_manager.clone());
                match TlsSettings::with_callbacks(Box::new(acceptor)) {
                    Ok(mut tls_settings) => {
                        tls_settings.enable_h2();
                        service.add_tls_with_settings(addr, None, tls_settings);
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
                service.add_tcp(addr);
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
}
