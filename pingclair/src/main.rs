//! Pingclair - A modern web server built on Pingora
//!
//! This is the main entry point for the Pingclair CLI.

use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

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
            
            // Load configuration
            let config = match pingclair_config::compile_file(&config_path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("❌ Failed to load config: {}", e);
                    std::process::exit(1);
                }
            };
            
            run_server(config);
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
            
            run_server(config);
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

            config.servers.push(server);
            
            run_server(config);
        }

        Commands::Validate { config } => {
            tracing::info!("Validating config: {}", config);
            match pingclair_config::compile_file(&config) {
                Ok(_) => {
                    println!("✅ Configuration file '{}' is valid!", config);
                },
                Err(e) => {
                     eprintln!("❌ Configuration Error: {}", e);
                     std::process::exit(1);
                }
            }
        }

        Commands::Version => {
            println!("Pingclair {}", env!("CARGO_PKG_VERSION"));
            println!("Built with Pingora");
        }
    }

    Ok(())
}

fn run_server(config: pingclair_core::config::PingclairConfig) {
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
    
    // Initialize TLS Manager
    let tls_store_path = std::path::Path::new("/var/lib/pingclair/certs");
    if !tls_store_path.exists() {
        let _ = std::fs::create_dir_all(tls_store_path);
    }
    let tls_manager = std::sync::Arc::new(pingclair_tls::manager::TlsManager::new(None, tls_store_path));

    // Group servers by listen address
    let port_proxies = std::collections::HashMap::new();
    let port_proxies = std::sync::Arc::new(parking_lot::RwLock::new(port_proxies));

    for server_config in config.servers {
        let addr = server_config.listen.first().cloned().unwrap_or_else(|| "0.0.0.0:80".to_string());
        let mut proxies_guard = port_proxies.write();
        let proxy = proxies_guard.entry(addr.clone()).or_insert_with(|| {
            pingclair_proxy::server::PingclairProxy::with_tls(tls_manager.clone())
        });
        proxy.add_server(server_config.clone());
    }

    // Create services for each proxy
    let mut https_ports = Vec::new();
    {
        let proxies_guard = port_proxies.read();
        for (addr, proxy_logic) in proxies_guard.iter() {
            tracing::info!("   📡 Listening on {}", addr);
            
            let proxy_service = pingora::proxy::http_proxy_service(
                &server.configuration,
                proxy_logic.clone(),
            );
            
            let mut service = proxy_service;
            service.add_tcp(addr);
            server.add_service(service);

            // Check if this port should also support HTTP/3
            // In a real app we'd check ServerConfigs for this port
            // For now, if port is 443, we assume HTTPS + H3
            if addr.ends_with(":443") || addr.ends_with(":8443") {
                https_ports.push(addr.clone());
            }
        }
    }

    for _addr in https_ports {
        if let Ok(socket_addr) = _addr.parse::<std::net::SocketAddr>() {
            let _tls_m = tls_manager.clone();
            let port_proxies = port_proxies.clone();
            let addr_str = _addr.clone();
            
            tokio::spawn(async move {
                let mut quic_config = pingclair_proxy::quic::QuicConfig::default();
                quic_config.listen = socket_addr;
                
                let mut quic_server = pingclair_proxy::quic::QuicServer::new(quic_config);
                
                // Inject proxy logic
                if let Some(proxy) = port_proxies.read().get(&addr_str) {
                    quic_server.set_proxy(std::sync::Arc::new(proxy.clone()));
                }

                // Bridge: QUIC server needs to resolve certificates
                // TODO: Integrate TlsManager with QuicServer more deeply
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
                        // Parse address
                        let addr = listen.parse().expect("Invalid admin listen address");
                        if let Err(e) = pingclair_api::run_admin_server(addr, proxies).await {
                            tracing::error!("Admin server error: {}", e);
                        }
                    });
                });
            }
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
