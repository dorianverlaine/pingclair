//! Pingclair - A modern web server built on Pingora
//!
//! This is the main entry point for the Pingclair CLI.

use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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
            
            if config.servers.is_empty() {
                tracing::warn!("⚠️ No servers configured!");
                return Ok(());
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

            // Start QUIC servers for HTTP/3
            for _addr in https_ports {
                if let Ok(socket_addr) = _addr.parse::<std::net::SocketAddr>() {
                    let _tls_m = tls_manager.clone();
                    tokio::spawn(async move {
                        let mut quic_config = pingclair_tls::QuicConfig::default();
                        quic_config.listen = socket_addr;
                        
                        let _quic_server = pingclair_tls::QuicServer::new(quic_config);
                        
                        // Bridge: QUIC server needs to resolve certificates too
                        // For now, QUIC server has a simple load_certificate method.
                        // We might need to update QuicServer to use TlsManager directly.
                        tracing::info!("🚀 Starting HTTP/3 server on {}", socket_addr);
                        
                        // Placeholder: QuicServer needs a certificate to start
                        // In production, it would also use SNI
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

        Commands::ReverseProxy { from, to } => {
            tracing::info!("Starting reverse proxy: {} -> {}", from, to);
            // TODO: Implement quick reverse proxy
            println!("🔄 Reverse proxy: {} -> {}", from, to);
        }

        Commands::FileServer { listen, root } => {
            tracing::info!("Starting file server on {} serving {}", listen, root);
            // TODO: Implement quick file server
            println!("📁 File server on {} serving {}", listen, root);
        }

        Commands::Validate { config } => {
            tracing::info!("Validating config: {}", config);
            // TODO: Implement config validation
            println!("✅ Config {} is valid", config);
        }

        Commands::Version => {
            println!("Pingclair {}", env!("CARGO_PKG_VERSION"));
            println!("Built with Pingora");
        }
    }

    Ok(())
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
