//! Pingclair - A modern web server built on Pingora
//!
//! This is the main entry point for the Pingclair CLI.

use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::sync::Arc;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::listeners::TlsAccept;
use pingora_core::protocols::tls::TlsRef;
use pingclair_tls::manager::TlsManager;
use openssl::ssl::NameType;
use openssl::x509::X509;
use openssl::pkey::{PKey, Private};
use parking_lot::RwLock;

#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// Cached OpenSSL certificate with expiration tracking
struct CachedOpenSslCert {
    x509: X509,
    pkey: PKey<Private>,
    /// Unix timestamp when this cache entry expires
    expires_at: u64,
}

/// Cache TTL for OpenSSL certificates (1 hour)
const OPENSSL_CACHE_TTL_SECS: u64 = 3600;

/// Resolves certificates dynamically using TlsManager with OpenSSL caching
struct DynamicCertResolver {
    tls_manager: Arc<TlsManager>,
    /// Cache for parsed OpenSSL objects to avoid PEM parsing on every TLS handshake
    openssl_cache: Arc<RwLock<HashMap<String, CachedOpenSslCert>>>,
}

// Manual Debug because TlsManager might not implement it
impl std::fmt::Debug for DynamicCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicCertResolver")
            .field("cache_size", &self.openssl_cache.read().len())
            .finish()
    }
}

impl DynamicCertResolver {
    /// Create a new resolver with caching
    fn new(tls_manager: Arc<TlsManager>) -> Self {
        Self {
            tls_manager,
            openssl_cache: Arc::new(RwLock::new(HashMap::new())),
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
    fn cleanup_expired(&self) {
        let current = Self::current_time();
        let mut cache = self.openssl_cache.write();
        let before = cache.len();
        cache.retain(|_, entry| entry.expires_at > current);
        let removed = before - cache.len();
        if removed > 0 {
            tracing::debug!("🧹 Cleaned {} expired OpenSSL cache entries", removed);
        }
    }
}

#[async_trait::async_trait]
impl TlsAccept for DynamicCertResolver {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        // Get SNI
        let sni = ssl.servername(NameType::HOST_NAME).unwrap_or("").to_string();
        if sni.is_empty() {
            return;
        }

        tracing::debug!("🔐 Resolving cert for SNI: {}", sni);

        // Step 1: Check cache first (fast path)
        let current_time = Self::current_time();
        {
            let cache = self.openssl_cache.read();
            if let Some(cached) = cache.get(&sni) {
                if cached.expires_at > current_time {
                    // Cache hit - use cached OpenSSL objects
                    tracing::debug!("🚀 Using cached OpenSSL cert for {}", sni);
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

            // Step 4: Cache the parsed OpenSSL objects for future handshakes
            let expires_at = current_time + OPENSSL_CACHE_TTL_SECS;
            let cached_entry = CachedOpenSslCert {
                x509,
                pkey,
                expires_at,
            };

            self.openssl_cache.write().insert(sni.clone(), cached_entry);
            tracing::info!("🔐 Cached OpenSSL cert for {} (expires in {}s)", sni, OPENSSL_CACHE_TTL_SECS);
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
        Commands::Run { config: config_path } => {
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
                format!("0.0.0.0{}", from)
            } else {
                 from.clone()
            };

            use pingclair_core::config::{
                ServerConfig, RouteConfig, HandlerConfig, 
                ReverseProxyConfig, LoadBalanceConfig
            };

            let mut server = ServerConfig {
                name: Some("_".to_string()),
                listen: vec![listen],
                routes: Vec::new(),
                tls: None,
                log: None,
                client_max_body_size: 10 * 1024 * 1024, // 10MB
                security: Default::default(),
            };

            let handler = HandlerConfig::ReverseProxy(ReverseProxyConfig {
                upstreams: vec![to.clone()],
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
                format!("0.0.0.0{}", listen)
            } else {
                 listen.clone()
            };

            use pingclair_core::config::{ServerConfig, RouteConfig, HandlerConfig};

            let mut server = ServerConfig {
                name: Some("_".to_string()),
                listen: vec![listen_addr],
                routes: Vec::new(),
                tls: None,
                log: None,
                client_max_body_size: 10 * 1024 * 1024,
                security: Default::default(),
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

            config.servers.push(ServerConfig {
                name: Some("_".to_string()),
                listen: vec![listen],
                routes: Vec::new(),
                tls: None,
                log: None,
                client_max_body_size: 10 * 1024 * 1024, // 10MB
                security: Default::default(),
            });
            
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
                    println!("✅ Configuration '{}' is valid!", config);
                },
                Err(e) => {
                     eprintln!("❌ Configuration Error: {}", e);
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

                tracing::info!("Managing service: {}", cmd);
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
                        println!("✅ Service {} successfully", past_tense);
                    }
                    Ok(s) => {
                        eprintln!("❌ Failed to {} service (exit code: {})", cmd, s);
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to execute systemctl: {}", e);
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

    // Create Pingora Server
    let mut server = pingora::server::Server::new(Some(pingora::server::configuration::Opt {
        upgrade: false,
        daemon: false,
        nocapture: false,
        test: false,
        conf: None, // We handle config manually
    })).expect("Failed to create Pingora server");
    
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
            })
    );

    // Group servers by listen address
    let port_proxies = std::collections::HashMap::new();
    let port_proxies = std::sync::Arc::new(parking_lot::RwLock::new(port_proxies));

    // Track binding information for diagnostic logging
    let mut binding_info = std::collections::HashMap::new();
    
        for server_config in config.servers {
            tracing::debug!("🚀 Processing ServerConfig: name={:?}, listens={:?}", server_config.name, server_config.listen);
            
            let listen_addrs = if server_config.listen.is_empty() {
                vec!["0.0.0.0:80".to_string()]
            } else {
                server_config.listen.clone()
            };

            for addr in listen_addrs {
                let mut proxies_guard = port_proxies.write();
                let proxy = proxies_guard.entry(addr.clone()).or_insert_with(|| {
                    pingclair_proxy::server::PingclairProxy::with_tls(tls_manager.clone())
                });
                
                // Track what sites are bound to what addresses
                let site_name = server_config.name.clone().unwrap_or_else(|| "default".to_string());
                binding_info.entry(addr.clone()).or_insert_with(Vec::new).push(site_name);
                
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
            let proxy_service = pingora::proxy::http_proxy_service(
                &server.configuration,
                proxy_logic.clone(),
            );

            let mut service = proxy_service;

            // Determine if this is an HTTPS port
            let is_https = addr.ends_with(":443") || addr.ends_with(":8443");
            let mut tls_enabled = false;
            let mut http3_enabled = false;

            if is_https {
                 // Setup TLS with dynamic resolver (OpenSSL) and certificate caching
                 let acceptor = DynamicCertResolver::new(tls_manager.clone());
                 match TlsSettings::with_callbacks(Box::new(acceptor)) {
                    Ok(tls_settings) => {
                         service.add_tls_with_settings(addr, None, tls_settings);
                         tls_enabled = true;
                    }
                    Err(e) => {
                        tracing::error!("❌ Failed to create TlsSettings for {}: {}", addr, e);
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
                if http3_enabled { "enabled" } else { "pending" }
            );

            server.add_service(service);

            // Check if this port should also support HTTP/3
            if is_https {
                https_ports.push(addr.clone());
                http3_enabled = true;
            }
        }
    }

    // Start HTTP/3 (QUIC) servers for HTTPS ports
    if !https_ports.is_empty() {
        tracing::info!("🚀 Starting HTTP/3 (QUIC) servers for {} port(s)", https_ports.len());
    }

    for _addr in https_ports {
        if let Ok(socket_addr) = _addr.parse::<std::net::SocketAddr>() {
            let _tls_m = tls_manager.clone();
            let port_proxies = port_proxies.clone();
            let addr_str = _addr.clone();
            
            bg_handle.spawn(async move {
                let mut quic_config = pingclair_proxy::quic::QuicConfig::default();
                quic_config.listen = socket_addr;
                
                let mut quic_server = pingclair_proxy::quic::QuicServer::new(quic_config);
                
                // Inject proxy logic
                if let Some(proxy) = port_proxies.read().get(&addr_str) {
                    quic_server.set_proxy(std::sync::Arc::new(proxy.clone()));
                }

                tracing::info!("🚀 Starting HTTP/3 server on {}", socket_addr);
                
                if let Err(e) = quic_server.start().await {
                    tracing::error!("HTTP/3 server failed: {}", e);
                }
            });
        }
    }
    
    // Start Admin API if enabled
    if let Some(admin_config) = config.admin {
            if admin_config.enabled {
                let listen = admin_config.listen.clone();
                let proxies = port_proxies.clone();
                
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Runtime::new().expect("Failed to create admin runtime");
                    rt.block_on(async {
                        let addr = listen.parse().expect("Invalid admin listen address");
                        if let Err(e) = pingclair_api::run_admin_server(addr, proxies).await {
                            tracing::error!("Admin server error: {}", e);
                        }
                    });
                });
            }
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
                            let addr = s.listen.first().cloned().unwrap_or_else(|| "0.0.0.0:80".to_string());
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
                            println!("✅ Configuration reloaded successfully ({} servers updated in {:?})", success_count, reload_duration);
                        } else {
                            tracing::warn!("⚠️ Configuration reload completed with warnings in {:?}", reload_duration);
                            tracing::warn!("   📊 {} server(s) updated, {} warning(s)", success_count, error_count);
                            println!("⚠️ Configuration partially reloaded ({} servers updated, {} warnings in {:?})", success_count, error_count, reload_duration);
                        }
                    }
                    Err(e) => {
                        let reload_duration = reload_start.elapsed();
                        tracing::error!("❌ Configuration reload failed after {:?}: {}", reload_duration, e);
                        tracing::error!("   💡 Previous configuration remains active");
                        eprintln!("❌ Configuration reload failed: {}", e);
                        eprintln!("   💡 Previous configuration remains active");
                    }
                }
            }
        });
    }
    
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
}
