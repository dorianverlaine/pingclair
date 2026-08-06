// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Pingclair - A modern web server built on Pingora
//!
//! This is the main entry point for the Pingclair CLI.

use clap::Parser;
use parking_lot::RwLock;
use pingclair_tls::manager::TlsManager;
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::services::Service as PingoraService;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod addr;
mod certs;
mod cli;
mod listen;
mod paths;
mod resource_guard;
mod systemd;

use crate::addr::{host_only, listen_for_site, upstream_hostport};
use crate::certs::{DynamicCertResolver, eager_issuance_domains, refresh_h3_cert_table};
use crate::cli::admin::{admin_request, trust_internal_ca};
use crate::cli::service::manage_system_service;
use crate::cli::{Cli, Commands};
use crate::listen::{
    automatic_http_companion, can_bind_automatic_http_port, normalize_listen_addr,
    reserve_private_listener_address, server_requires_tls, servers_by_bind_address,
};
use crate::paths::{resolve_config_path, tls_store_dir};
use crate::systemd::{notify_systemd_ready, notify_systemd_stopping};

#[cfg(unix)]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

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

        Commands::Completion { shell } => {
            use clap::CommandFactory;
            use clap_complete::generate;
            use clap_complete::shells::Shell;
            let shell: Shell = shell
                .parse()
                .map_err(|_| anyhow::anyhow!("❌ Unknown shell `{shell}`"))?;
            let mut command = Cli::command();
            generate(shell, &mut command, "pingclair", &mut std::io::stdout());
        }

        Commands::Environ => {
            for (key, value) in std::env::vars() {
                println!("{key}={value}");
            }
        }

        Commands::ListModules { json } => {
            let modules = [
                "respond",
                "file_server",
                "reverse_proxy",
                "templates",
                "redirect",
                "headers",
                "basic_auth",
                "rate_limit",
                "rewrite",
                "cors",
                "access_control",
                "try_files",
            ];
            let features = [
                "http/1.1",
                "http/2",
                "http/3",
                "tls",
                "acme",
                "internal-ca",
                "admin-api",
                "metrics",
                "proxy-protocol",
                "templates",
            ];
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "modules": modules, "features": features })
                );
            } else {
                for module in modules {
                    println!("http.handlers.{module}");
                }
                for feature in features {
                    println!("{feature}");
                }
            }
        }

        Commands::BuildInfo => {
            println!("pingclair v{}", env!("CARGO_PKG_VERSION"));
            println!("rust edition 2024");
            println!(
                "profile: {}",
                if cfg!(debug_assertions) {
                    "debug"
                } else {
                    "release"
                }
            );
            println!("features: http/3, tls, acme, admin-api, metrics, templates");
        }

        Commands::Manpage { directory } => {
            use clap::CommandFactory;
            std::fs::create_dir_all(&directory)
                .map_err(|error| anyhow::anyhow!("❌ Cannot create {directory}: {error}"))?;
            let man = clap_mangen::Man::new(Cli::command());
            let mut buffer = Vec::new();
            man.render(&mut buffer)
                .map_err(|error| anyhow::anyhow!("❌ Failed to render man page: {error}"))?;
            let path = std::path::Path::new(&directory).join("pingclair.1");
            std::fs::write(&path, buffer)
                .map_err(|error| anyhow::anyhow!("❌ Failed to write {path:?}: {error}"))?;
            println!("✅ Man page written to {}", path.display());
        }

        Commands::StorageExport { output } => {
            let dir = tls_store_dir();
            if !dir.is_dir() {
                anyhow::bail!("❌ No store found at {}", dir.display());
            }
            if output == "-" {
                let stdout = std::io::stdout();
                let mut builder = tar::Builder::new(stdout);
                builder
                    .append_dir_all("pingclair", &dir)
                    .map_err(|error| anyhow::anyhow!("❌ Export failed: {error}"))?;
                builder
                    .finish()
                    .map_err(|error| anyhow::anyhow!("❌ Export failed: {error}"))?;
            } else {
                let file = std::fs::File::create(&output)
                    .map_err(|error| anyhow::anyhow!("❌ Cannot create {output}: {error}"))?;
                let mut builder = tar::Builder::new(file);
                builder
                    .append_dir_all("pingclair", &dir)
                    .map_err(|error| anyhow::anyhow!("❌ Export failed: {error}"))?;
                builder
                    .finish()
                    .map_err(|error| anyhow::anyhow!("❌ Export failed: {error}"))?;
                println!("✅ Store exported to {output}");
            }
        }

        Commands::StorageImport { input } => {
            let dir = tls_store_dir();
            std::fs::create_dir_all(&dir)
                .map_err(|error| anyhow::anyhow!("❌ Cannot create {}: {error}", dir.display()))?;
            let file: Box<dyn std::io::Read> = if input == "-" {
                Box::new(std::io::stdin())
            } else {
                Box::new(
                    std::fs::File::open(&input)
                        .map_err(|error| anyhow::anyhow!("❌ Cannot open {input}: {error}"))?,
                )
            };
            let mut archive = tar::Archive::new(file);
            archive
                .unpack(&dir)
                .map_err(|error| anyhow::anyhow!("❌ Import failed: {error}"))?;
            println!("✅ Store imported into {}", dir.display());
        }

        Commands::Trust => trust_internal_ca(true)?,
        Commands::Untrust => trust_internal_ca(false)?,

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
                log_channels: Vec::new(),
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
            let mut headers_up: std::collections::BTreeMap<String, String> =
                headers_up.into_iter().collect();
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
                    // 🖥️ The CLI quick-commands log to stdout, which the shell
                    // or the service manager owns; rotating it here would be
                    // rotating somebody else's file.
                    rotation: Default::default(),
                    request_headers: Vec::new(),
                    response_headers: Vec::new(),
                    include_tls: false,
                }),
                log_channels: Vec::new(),
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

    fn probe_listener(&self, addr: &str) -> Result<(), String> {
        // 🔎 Bind and drop. There is an unavoidable gap between this check and
        // the real bind, so another process could still take the port in
        // between — but the failure this prevents is the common one: a reload
        // whose own configuration names a port something else already holds.
        std::net::TcpListener::bind(addr)
            .map(|_| ())
            .map_err(|error| format!("cannot bind {addr}: {error}"))
    }
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

    // 🪵 Named log channels must exist before any ProxyState resolves a
    // reference to one. Registration is idempotent, so a reload that keeps a
    // channel keeps its writer thread and its queue rather than spawning a
    // second writer onto the same file.
    pingclair_proxy::access_log::register_channels(&config.logging.channels);

    // 🔢 The startup configuration is version 1. The number itself is
    // meaningless; two instances behind one balancer reporting *different*
    // versions is the signal — it means a reload reached one and not the other,
    // which is otherwise invisible until they start behaving differently.
    pingclair_proxy::metrics::CONFIG_VERSION.set(1);

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
        // ⚡ 512, not Pingora's 128: an interleaved t4g.small scan of the
        // reverse-proxy path (2026-08-03) measured 128 → 8.1k req/s, 256 →
        // 8.5k, 512 → 8.9k on 100×20 HTTP/2 streams, then a small decline at
        // 768/1024. The idle pool only caps reusable upstream connections, so
        // the cost is bounded by the FD limit; operators can still override
        // the knob per deployment.
        .unwrap_or_else(|| server_conf.upstream_keepalive_pool_size.max(512));
    // Pingora defaults to ONE thread per service — on a multi-core box that
    // leaves the machine idle while nginx runs one worker per core. Scale
    // with available parallelism instead (still overridable via config).
    server_conf.threads = config.global.worker_threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    });
    // 🚰 What happens to a request that is still running when SIGTERM arrives.
    //
    // Pingora's own default gives the runtime five seconds and then stops it,
    // which truncates anything slower than that: measured on 2026-08-05, a
    // 20 MiB download over a rate-limited link arrived as 4.1 MiB, status 200,
    // no error the client could distinguish from a network fault. Every
    // rolling restart did that to every transfer in progress.
    //
    // Caddy waits for them however long they take — its log literally says
    // "eternal grace period" — so that is the default here too, expressed as
    // the largest span Pingora will accept. `grace_period` is how an operator
    // trades that for a bounded restart.
    // ⏱️ 30 seconds, not "forever". The window is an unconditional sleep, so
    // "forever" would mean a process that never exits — and Pingora's own
    // 300-second default means every restart waits five minutes with nothing
    // to drain. 30s is long enough for ordinary requests to land and short
    // enough that a rolling restart still moves.
    const DEFAULT_GRACE_SECS: u64 = 30;
    let grace_period_secs = config
        .global
        .grace_period_secs
        .unwrap_or(DEFAULT_GRACE_SECS);
    // 🕐 Which knob does what, read off pingora-core 0.8.1 `server/mod.rs:771`
    // rather than guessed — the first attempt at this guessed wrong in both
    // directions and shipped a shutdown that hung:
    //
    //   grace_period_seconds          → `thread::sleep(...)` before teardown.
    //                                   The window during which the runtimes
    //                                   are still alive. Unconditional: every
    //                                   shutdown costs exactly this.
    //   graceful_shutdown_timeout_secs → `rt.shutdown_timeout(t)` *and then*
    //                                   `thread::sleep(t)` again. A large value
    //                                   here does not extend the drain; it just
    //                                   makes the process refuse to exit.
    //
    // So the configured grace belongs in the sleep, and the teardown budget
    // stays at Pingora's own small default.
    //
    // 🚧 A bounded window is a deliberate choice, not the finished behaviour, and
    // must not be described as "graceful shutdown works". The alternative —
    // exiting as soon as the last in-flight request finishes, bounded by work
    // remaining rather than by a clock — is not expressible with the knobs the
    // transport exposes. Day 26 also measured that the sleep window does not by
    // itself keep a large download alive, so something in the service layer ends
    // the connection first. Until that is found, this bounds the damage rather
    // than fixing it.
    server_conf.grace_period_seconds = Some(grace_period_secs);
    tracing::info!(
        "🚰 Shutdown grace period: {}s{}",
        grace_period_secs,
        if config.global.grace_period_secs.is_some() {
            ""
        } else {
            " (default; set `grace_period` to change it)"
        }
    );
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
    let mut manual_certs: Vec<(String, String, String)> = Vec::new();
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

        // 🔐 Collected rather than loaded here. Reading them one at a time
        // meant a half-written pair could be installed on its own, and the
        // failure would surface at handshake time to a real client rather than
        // at load time to the operator. `refresh_manual_certs` reads and
        // validates the whole set, then publishes it or nothing.
        manual_certs.push((name.to_string(), cert_path.clone(), key_path.clone()));
    }

    match tls_manager.refresh_manual_certs(&manual_certs) {
        Ok(count) if count > 0 => {
            tracing::info!("🔐 Loaded {count} manual TLS certificate(s)");
        }
        Ok(_) => {}
        Err(problems) => {
            for problem in &problems {
                tracing::error!("❌ Manual TLS certificate rejected: {problem}");
            }
            anyhow::bail!(
                "{} manual TLS certificate(s) could not be loaded; refusing to start with \
                 certificates the operator asked for but that cannot serve",
                problems.len()
            );
        }
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
    let h3_pool_size = config.global.upstream_keepalive_pool_size.unwrap_or(512);
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
        let admin_origins = admin_config.origins.clone();
        let admin_enforce_origin = admin_config.enforce_origin;
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
                    origins: admin_origins,
                    enforce_origin: admin_enforce_origin,
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

                        // 🪵 Register any channel the reload introduced before
                        // the servers that reference it are published, or the
                        // first requests after a reload would resolve to no
                        // channel and their lines would go nowhere.
                        pingclair_proxy::access_log::register_channels(
                            &new_config.logging.channels,
                        );
                        pingclair_proxy::metrics::CONFIG_VERSION.inc();

                        // 🧭 Derive every bind address the same way startup
                        // does (including the automatic HTTP companion), so a
                        // hostname site updates its TLS listener and not just
                        // a phantom `:80` entry.
                        let new_config_by_port = servers_by_bind_address(&new_config);

                        // 🧭 Phase 1 — prepare. Work out what each bind
                        // address needs and prove every fallible step can
                        // succeed, touching nothing.
                        //
                        // The old loop published each port as it went, so a
                        // port that could not be bound left the earlier ones
                        // already serving the new configuration and the
                        // reload reported "partially reloaded" — a state no
                        // operator asked for and none can reason about. Now
                        // the only fallible step (binding) happens for all
                        // new addresses first, and a single failure means
                        // nothing changed at all.
                        let existing: std::collections::HashSet<String> =
                            port_proxies.read().keys().cloned().collect();
                        let mut to_update: Vec<(String, Vec<pingclair_core::config::ServerConfig>)> =
                            Vec::new();
                        let mut to_start: Vec<(String, Vec<pingclair_core::config::ServerConfig>)> =
                            Vec::new();
                        let mut rejected: Vec<String> = Vec::new();

                        for (addr, servers) in new_config_by_port {
                            if existing.contains(&addr) {
                                to_update.push((addr, servers));
                            } else {
                                match dynamic_listeners_for_reload.probe_listener(&addr) {
                                    Ok(()) => to_start.push((addr, servers)),
                                    Err(error) => rejected.push(format!("{addr}: {error}")),
                                }
                            }
                        }

                        // 🔐 Certificates are part of the configuration, so a
                        // reload must pick up a rotation on disk — before this
                        // they were read once at startup and swapping a cert
                        // needed a restart that nothing told the operator
                        // about. Collected here so a bad pair joins the same
                        // rejection set as an unbindable listener: either the
                        // whole reload lands or none of it does.
                        let mut reloaded_certs: Vec<(String, String, String)> = Vec::new();
                        for server in &new_config.servers {
                            let (Some(tls), Some(name)) =
                                (server.tls.as_ref(), server.name.as_deref())
                            else {
                                continue;
                            };
                            if let (Some(cert), Some(key)) = (&tls.cert, &tls.key)
                                && !name.is_empty()
                                && name != "_"
                            {
                                reloaded_certs.push((
                                    name.to_string(),
                                    cert.clone(),
                                    key.clone(),
                                ));
                            }
                        }
                        if let Err(problems) = tls_manager.refresh_manual_certs(&reloaded_certs) {
                            // 🛡️ The previous certificates keep serving. An
                            // operator halfway through copying a new pair sees
                            // exactly which file is wrong instead of a site
                            // that starts failing handshakes.
                            rejected.extend(
                                problems
                                    .into_iter()
                                    .map(|problem| format!("certificate: {problem}")),
                            );
                        }

                        if !rejected.is_empty() {
                            let reload_duration = reload_start.elapsed();
                            for reason in &rejected {
                                tracing::error!("❌ Reload rejected: {reason}");
                            }
                            tracing::error!(
                                "❌ Configuration reload rejected after {:?}: {} problem(s)",
                                reload_duration,
                                rejected.len()
                            );
                            tracing::error!("   💡 Previous configuration remains active, unchanged");
                            eprintln!(
                                "❌ Configuration reload rejected: {}",
                                rejected.join("; ")
                            );
                            eprintln!("   💡 Previous configuration remains active, unchanged");
                            continue;
                        }

                        // 🧭 Phase 2 — publish. Nothing below can fail, so the
                        // configuration lands whole.
                        tracing::info!(
                            "📋 Step 3/3: Applying configuration to {} port(s)...",
                            to_update.len() + to_start.len()
                        );
                        let mut success_count = 0;
                        let mut warnings: Vec<String> = Vec::new();

                        // 🔄 Updates are an ArcSwap store each, so an in-flight
                        // request sees either the old snapshot or the new one
                        // and never a mixture.
                        let mut published: std::collections::HashSet<String> =
                            std::collections::HashSet::new();
                        for (addr, servers) in to_update {
                            if let Some(proxy) = port_proxies.read().get(&addr).cloned() {
                                proxy.update_config(servers);
                                success_count += 1;
                                published.insert(addr.clone());
                                tracing::debug!("   ✓ Updated configuration for {}", addr);
                            }
                        }

                        for (addr, servers) in to_start {
                            match dynamic_listeners_for_reload.start_listener(&addr, &servers[0]) {
                                Ok(()) => {
                                    for extra in &servers[1..] {
                                        if let Some(proxy) = port_proxies.read().get(&addr) {
                                            proxy.add_server(extra.clone());
                                        }
                                    }
                                    success_count += 1;
                                    published.insert(addr.clone());
                                }
                                // 🚩 The probe passed and the real bind still
                                // failed: something else took the port in the
                                // gap. Rare, and reported rather than hidden.
                                Err(error) => warnings.push(format!("{addr}: {error}")),
                            }
                        }

                        // 🧹 Addresses the new configuration no longer names.
                        // Without this the old configuration kept serving on
                        // them forever — a site deleted from the Pingclairfile
                        // stayed reachable until the next restart, which is the
                        // most dangerous direction for this bug to fail in.
                        for stale in existing.difference(&published) {
                            if dynamic_listeners_for_reload.is_dynamic(stale) {
                                tracing::info!("🧹 Stopping listener {stale}: no longer configured");
                                dynamic_listeners_for_reload.stop_listener(stale);
                            } else {
                                // 📌 A listener created at startup cannot be
                                // unbound without a restart, so say so rather
                                // than leaving the operator to discover that
                                // the deleted site still answers.
                                warnings.push(format!(
                                    "{stale}: no longer in the configuration, but it was bound at \
                                     startup and needs a restart to release"
                                ));
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
                    // 🚰 Stop being sent new traffic before the process starts
                    // going away. A load balancer polling /ready gets a 503 on
                    // its next check and routes around, so the connections
                    // still in flight are the last ones this instance has to
                    // finish rather than the first of a fresh wave.
                    pingclair_proxy::readiness::mark_draining();
                    notify_systemd_stopping();
                }
                _ = sigterm.recv() => {
                    tracing::info!("🛑 Received SIGTERM, shutting down");
                    pingclair_proxy::readiness::mark_draining();
                    notify_systemd_stopping();
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

    // 🚦 Ready only now. Every listener has been added to the server and the
    // reservations are released, so the next thing that happens is Pingora
    // binding them. Announcing readiness any earlier — right after parsing the
    // config, say — is what makes a rolling deploy drop requests: the
    // orchestrator believes the instance is serving and sends it traffic while
    // the sockets are still being created.
    //
    // 📣 systemd learns the same fact at the same moment. With `Type=notify`
    // the unit is not considered started until this arrives, so `systemctl
    // start` blocks until the process can actually answer, and anything
    // ordered `After=` it starts against a working proxy rather than a
    // half-open one.
    pingclair_proxy::readiness::mark_ready();
    notify_systemd_ready();

    server.run_forever();
}
