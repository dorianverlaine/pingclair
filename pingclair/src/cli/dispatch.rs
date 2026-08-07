// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🎛️ What each subcommand actually does.
//!
//! One arm per subcommand, in the order [`Commands`](super::Commands) declares
//! them, so the shape of this file follows the shape of `--help`. Anything an
//! arm needs that is more than a few lines lives in a module of its own and is
//! called from here; what stays are the arms themselves.
//!
//! Four of them — `run`, `respond`, `reverse-proxy` and `file-server` — build
//! a `PingclairConfig` in memory and hand it to [`run_server`]. That is worth
//! knowing before changing one: the quick commands are not a separate server,
//! they are the same server with a configuration nobody had to write down.

use super::{Cli, Commands};
use crate::addr::{host_only, listen_for_site, upstream_hostport};
use crate::cli::admin::{admin_request, trust_internal_ca};
use crate::cli::service::manage_system_service;
use crate::paths::{resolve_config_path, tls_store_dir};
use crate::run::run_server;

/// 🧩 The directives `list-modules` reports as request handlers.
///
/// This is a curated subset rather than the whole directive table, because the
/// table also holds site-level names — `root`, `listen`, `tls` — that are not
/// handlers and would be a different kind of wrong under an
/// `http.handlers.` prefix. What keeps the curation honest is
/// [`every_listed_module_is_an_implemented_directive`]: every name here must
/// be one the adapter actually turns into configuration.
///
/// 🤡 Why the test exists: until 2026-08-07 this list was hand-written with no
/// tie to the adapter, and it advertised `try_files` for weeks while a
/// Pingclairfile containing `try_files` was refused. Someone checking what
/// their binary supports would have been told yes by the tool and no by the
/// parser, which is worse than either answer alone.
const HANDLER_MODULES: [&str; 16] = [
    "access_control",
    "basic_auth",
    "cors",
    "file_server",
    "handle",
    "handle_path",
    "header",
    "rate_limit",
    "redir",
    "respond",
    "reverse_proxy",
    "rewrite",
    "route",
    "templates",
    "try_files",
    "uri",
];

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

/// 🎛️ Runs one subcommand.
pub(crate) fn run(command: Commands) -> anyhow::Result<()> {
    match command {
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
            let modules = HANDLER_MODULES;
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

#[cfg(test)]
mod tests {
    use super::HANDLER_MODULES;

    /// 🎯 The check the list cannot do for itself: a module this binary tells
    /// an operator it has must be a directive the adapter accepts.
    #[test]
    fn every_listed_module_is_an_implemented_directive() {
        for module in HANDLER_MODULES {
            assert!(
                pingclair_config::adapter::is_implemented_directive(module),
                "`list-modules` advertises `{module}`, but the Caddyfile adapter does not \
                 implement it — either wire the directive up or stop listing it"
            );
        }
    }

    /// 📌 Sorted so a new handler has one obvious home in the list.
    #[test]
    fn the_module_list_is_sorted() {
        let mut sorted = HANDLER_MODULES;
        sorted.sort_unstable();
        assert_eq!(HANDLER_MODULES, sorted, "the module list is out of order");
    }
}
