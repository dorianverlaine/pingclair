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
use crate::paths::{
    CONFIG_CANDIDATES, DefaultConfig, resolve_config_path, resolve_default_config, tls_store_dir,
    tls_store_dir_with,
};
use crate::run::run_server;

/// 🧩 One capability this build implements, and the Caddy module that provides
/// it in a standard build.
///
/// The two are different strings, and that is the whole point of the pair: the
/// listing exists so a capability check can intersect it with
/// `caddy list-modules`, and printing this project's own directive name under
/// `http.handlers.` made that intersection wrong in both directions. It
/// reported `http.handlers.basic_auth` — a module no Caddy build registers,
/// where Caddy spells the same capability `http.handlers.authentication` — and
/// it reported `http.handlers.cors`, which no Caddy build has at all.
struct HandlerModule {
    /// The Caddyfile directive the adapter accepts. The tie test below checks
    /// this against the adapter, which is what keeps the table from drifting
    /// away from the binary.
    directive: &'static str,
    /// The `http.handlers.*` module providing this capability in Caddy
    /// v2.11.4's standard build, read off `caddy list-modules`; `None` when
    /// no Caddy build has one, which makes this an extension of ours.
    ///
    /// 📌 Several directives map to one module on purpose. `uri` and
    /// `try_files` compile to a rewrite, and `handle`, `handle_path` and
    /// `route` compile to a subroute — so the listing deduplicates rather than
    /// repeating `rewrite` four times. A repeat is what put `templates` in the
    /// list twice.
    caddy_module: Option<&'static str>,
}

/// 🧩 The directives `list-modules` reports as request handlers.
///
/// This is a curated subset rather than the whole directive table, because the
/// table also holds site-level names — `root`, `listen`, `tls` — that are not
/// handlers and would be a different kind of wrong under an
/// `http.handlers.` prefix. What keeps the curation honest is
/// [`every_listed_module_is_an_implemented_directive`]: every name here must
/// be one the adapter actually turns into configuration.
///
/// 🤡 Why that test exists: until 2026-08-07 this list was hand-written with no
/// tie to the adapter, and it advertised `try_files` for weeks while a
/// Pingclairfile containing `try_files` was refused. Someone checking what
/// their binary supports would have been told yes by the tool and no by the
/// parser, which is worse than either answer alone.
const HANDLER_MODULES: [HandlerModule; 16] = [
    HandlerModule {
        directive: "access_control",
        // 🧩 An extension: Caddy has no access-control handler module.
        caddy_module: None,
    },
    HandlerModule {
        directive: "basic_auth",
        caddy_module: Some("authentication"),
    },
    HandlerModule {
        directive: "cors",
        caddy_module: None,
    },
    HandlerModule {
        directive: "file_server",
        caddy_module: Some("file_server"),
    },
    HandlerModule {
        directive: "handle",
        caddy_module: Some("subroute"),
    },
    HandlerModule {
        directive: "handle_path",
        caddy_module: Some("subroute"),
    },
    HandlerModule {
        directive: "header",
        caddy_module: Some("headers"),
    },
    HandlerModule {
        directive: "rate_limit",
        caddy_module: None,
    },
    HandlerModule {
        directive: "redir",
        // 🔁 `redir` and `respond` both compile to a static response upstream.
        caddy_module: Some("static_response"),
    },
    HandlerModule {
        directive: "respond",
        caddy_module: Some("static_response"),
    },
    HandlerModule {
        directive: "reverse_proxy",
        caddy_module: Some("reverse_proxy"),
    },
    HandlerModule {
        directive: "rewrite",
        caddy_module: Some("rewrite"),
    },
    HandlerModule {
        directive: "route",
        caddy_module: Some("subroute"),
    },
    HandlerModule {
        directive: "templates",
        caddy_module: Some("templates"),
    },
    HandlerModule {
        directive: "try_files",
        // 🗂️ Expands to a `file` matcher plus a rewrite, which is what it is
        // upstream, so the module it needs is the rewrite one.
        caddy_module: Some("rewrite"),
    },
    HandlerModule {
        directive: "uri",
        caddy_module: Some("rewrite"),
    },
];

/// 🧩 Capabilities this build has that are **not** `http.handlers.*` modules.
///
/// Each is printed under the Caddy module ID that provides it, because that is
/// the name a capability check looks for. `internal-ca` and `acme` were printed
/// bare before, and neither is a module ID: Caddy spells them
/// `tls.issuance.internal` and `tls.issuance.acme`.
const NON_HANDLER_MODULES: [&str; 6] = [
    // 🔐 Caddy registers the TLS app itself under the bare ID `tls`.
    "tls",
    "tls.issuance.acme",
    "tls.issuance.internal",
    // 🛡️ Both servers accept the PROXY protocol through this listener wrapper.
    "caddy.listeners.proxy_protocol",
    // 🗜️ The codings `encode` accepts, under Caddy's own encoder IDs. Their
    // absence is what made the inventory deny a feature the adapter accepts:
    // `encode gzip` ran while `list-modules` said there was no gzip encoder,
    // and a capability check reading the listing answered "unavailable".
    "http.encoders.gzip",
    "http.encoders.zstd",
];

/// 📊 The admin API modules this build implements, under Caddy's own names.
///
/// 🚫 Caddy's standard build registers four — `load`, `metrics`, `pki` and
/// `reverse_proxy` — and this build has two of them. The other two are **left
/// out** rather than papered over: printing a bare `admin-api` tag, which is
/// what this listing did, says something is there and gives nothing that can be
/// asked a follow-up question. A migration checklist asking "does this build
/// expose the admin pieces I depend on?" got "yes" from the listing and a 404
/// from `/pki/`.
///
/// 📌 The authority for what is in this list is the route match in
/// `pingclair-api/src/server.rs` — that is where `/load` and `/metrics` are
/// answered, and where `/pki/` and `/reverse_proxy/` are not. There is no route
/// table to derive it from, so the tie is a comment and a reviewer's eye rather
/// than a test.
const ADMIN_API_MODULES: [&str; 2] = ["admin.api.load", "admin.api.metrics"];

/// 📡 Modules a Caddy build gains from the DNS-provider plugin ecosystem.
///
/// 📌 Caddy's own listing does not carry these, because a DNS-01 provider is a
/// plugin rather than a standard module — but `dns.providers.<name>` is the
/// name the whole ecosystem uses and the name a migrated Caddyfile's
/// `dns <provider>` corresponds to, so it is the useful answer to "can this
/// build do DNS-01 with Cloudflare?".
///
/// 🛡️ The runtime half is unmeasured here, deliberately: proving an ACME
/// DNS-01 challenge needs a public zone and an API token, and neither was
/// available. What is claimed is narrower and checked — the provider is
/// implemented (`pingclair-tls/src/dns01/cloudflare.rs`), the adapter accepts
/// `dns cloudflare <token>`, and any other provider name is refused by name at
/// startup.
const PLUGIN_MODULES: [&str; 1] = ["dns.providers.cloudflare"];

/// 🚩 Facts about this build that are not modules and have no Caddy module ID.
///
/// They are printed under a `pingclair.features.` prefix rather than bare, so
/// nothing in the listing can be read as a module Caddy would also have. That
/// ambiguity is what let a capability check conclude this build was missing
/// `encode` while it believed a nonexistent `http.handlers.cors` was present.
const FEATURES: [&str; 3] = ["http/1.1", "http/2", "http/3"];

/// 🧩 Every name `list-modules` prints, in the sorted order it prints them.
///
/// Built rather than written out so the three sources cannot disagree with each
/// other, and deduplicated because several handlers share one Caddy module.
fn module_ids() -> Vec<String> {
    let mut ids: Vec<String> = HANDLER_MODULES
        .iter()
        .map(|module| match module.caddy_module {
            Some(name) => format!("http.handlers.{name}"),
            None => format!("pingclair.handlers.{}", module.directive),
        })
        .chain(NON_HANDLER_MODULES.iter().map(|name| name.to_string()))
        .chain(ADMIN_API_MODULES.iter().map(|name| name.to_string()))
        .chain(PLUGIN_MODULES.iter().map(|name| name.to_string()))
        .chain(
            FEATURES
                .iter()
                .map(|name| format!("pingclair.features.{name}")),
        )
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// 🏷️ What kind of thing one printed name is, in Caddy's own vocabulary.
///
/// `standard` means "a module a standard build of the server has", which is the
/// only kind this build has: nothing here is a plugin.
fn module_type(id: &str) -> &'static str {
    if id.starts_with("pingclair.") {
        "pingclair"
    } else {
        "standard"
    }
}

/// 📦 The build string `--versions` prints, in Caddy's `v<version>` shape.
fn module_version() -> String {
    format!("v{}", env!("CARGO_PKG_VERSION"))
}

/// 📦 The package a module comes from, for `--packages`.
///
/// 📌 This build is one package, so every name answers the same thing. The flag
/// exists so a script written for `caddy list-modules --packages` runs against
/// this binary instead of dying on argument parsing — which is what it did
/// before, with exit 2.
const MODULE_PACKAGE: &str = "pingclair";

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
        // 🗂️ One tab per level, which is what `caddy fmt` writes. Two spaces
        // was this formatter's own choice, and it meant the two formatters
        // rewrote each other's output forever: a CI gate that runs `caddy fmt`
        // on a repository formatted by `pingclair fmt` reported a diff on every
        // file.
        let padding = "\t".repeat(indent);
        for directive in directives {
            out.push_str(&padding);
            out.push_str(&directive.name);
            for argument in &directive.args {
                out.push(' ');
                out.push_str(&quote_argument(argument));
            }
            if let Some(block) = &directive.block {
                out.push_str(" {\n");
                format_block(&block.directives, indent + 1, out);
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

/// 🗄️ The store a command should work on.
///
/// 📌 `--config` is Caddy's flag on both storage commands, and it is the only
/// way to say *which* store without the environment: the configuration's
/// `storage file_system <path>` decides, and without a configuration this
/// resolves `$PINGCLAIR_TLS_STORE` and then the platform convention, exactly as
/// it did before the flag existed.
fn store_dir_for(config: Option<&str>) -> anyhow::Result<std::path::PathBuf> {
    let Some(path) = config.filter(|path| !path.is_empty()) else {
        return Ok(tls_store_dir());
    };
    let compiled = pingclair_config::compile_file(path)
        .map_err(|error| anyhow::anyhow!("❌ Cannot read {path}: {error}"))?;
    Ok(tls_store_dir_with(compiled.global.storage_path.as_deref()))
}

/// 📦 `storage export` — one body for both spellings.
fn storage_export(output: &str, config: Option<&str>) -> anyhow::Result<()> {
    let dir = store_dir_for(config)?;
    if !dir.is_dir() {
        anyhow::bail!("❌ No store found at {}", dir.display());
    }
    if output == "-" {
        return crate::cli::storage::export_store(&dir, std::io::stdout()).map(|_| ());
    }
    // 🔐 Owner-only from creation, not from a later `chmod`. This archive
    // contains the TLS store — the internal CA's private key, every issued
    // certificate's key, and the ACME account key. A plain `File::create` makes
    // it `0644` under the ordinary umask, and even a `chmod` straight afterwards
    // leaves a window in which another local user can open it and keep reading
    // through the descriptor after the mode changes.
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(output)
        .map_err(|error| anyhow::anyhow!("❌ Cannot create {output}: {error}"))?;
    // 🧹 An existing file keeps its own mode, because `mode` only applies at
    // creation. Say so rather than leaving the operator to discover that
    // overwriting a `0644` file kept it readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = file
            .metadata()
            .map(|metadata| metadata.permissions().mode() & 0o777)
            .unwrap_or(0);
        if mode & 0o077 != 0 {
            eprintln!(
                "⚠️ {output} already existed with mode {mode:o}; it holds private keys and is \
                 readable beyond its owner. Remove it and export again, or chmod 600 it now."
            );
        }
    }
    let file = crate::cli::storage::export_store(&dir, file)?;
    // 💾 Durable before the success line: an operator who is told the export
    // succeeded will delete the source.
    file.sync_all()
        .map_err(|error| anyhow::anyhow!("❌ Export could not be flushed: {error}"))?;
    println!("✅ Store exported to {output}");
    Ok(())
}

/// 📦 `storage import` — one body for both spellings.
fn storage_import(input: &str, config: Option<&str>) -> anyhow::Result<()> {
    let dir = store_dir_for(config)?;
    std::fs::create_dir_all(&dir)
        .map_err(|error| anyhow::anyhow!("❌ Cannot create {}: {error}", dir.display()))?;
    let file: Box<dyn std::io::Read> = if input == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(
            std::fs::File::open(input)
                .map_err(|error| anyhow::anyhow!("❌ Cannot open {input}: {error}"))?,
        )
    };
    crate::cli::storage::import_store(&dir, file)?;
    println!("✅ Store imported into {}", dir.display());
    Ok(())
}

/// 🎛️ Runs one subcommand.
pub(crate) fn run(command: Commands) -> anyhow::Result<()> {
    match command {
        Commands::Run {
            config,
            resume,
            watch,
        } => {
            let mut config_path = resolve_config_path(config.as_deref());
            // 🚫 No argument and no conventional file is the one case where the
            // generic "Failed to load config: No such file or directory" sends
            // the operator looking in the wrong place — it names no path, and
            // the file its absence describes was never the mistake.
            //
            // 🧭 Caddy starts an empty server here and waits for the Admin API.
            // This build refuses instead, which is the clearer answer for
            // someone who typed `run` in the wrong directory and the wrong one
            // for orchestration that posts its configuration later. The refusal
            // says which of the two this is, and what to do about it.
            if matches!(
                resolve_default_config(config.as_deref()),
                DefaultConfig::Missing
            ) {
                let directory = std::env::current_dir()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|_| "the working directory".to_string());
                let candidates = CONFIG_CANDIDATES.join("`, then `");
                tracing::error!(
                    "❌ No configuration found in {directory}: looked for `{candidates}`. Pass a \
                     path (`pingclair run <path>`), or create one of those files. Caddy starts an \
                     empty server here and waits for the Admin API; this build does not start \
                     with no configuration at all."
                );
                std::process::exit(1);
            }
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
            tracing::info!("🚀 Starting Pingclair with config: {}", config_path);

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

        Commands::ListModules {
            json,
            versions,
            packages,
            skip_standard,
        } => {
            let ids = module_ids();
            // 🚫 Every module here is standard, so `--skip-standard` prints
            // nothing — the same answer a plugin-free Caddy build gives.
            let ids: Vec<String> = ids
                .into_iter()
                .filter(|id| !(skip_standard && module_type(id) == "standard"))
                .collect();
            if json {
                // 🧭 Caddy's own JSON shape, so a parser written for it reads
                // this output too: an array of records, one per module.
                let records: Vec<serde_json::Value> = ids
                    .iter()
                    .map(|id| {
                        serde_json::json!({
                            "module_name": id,
                            "module_type": module_type(id),
                            "version": module_version(),
                            "package_url": MODULE_PACKAGE,
                        })
                    })
                    .collect();
                println!("{}", serde_json::Value::Array(records));
            } else {
                for id in &ids {
                    // 📏 One column more than the plain listing, which is the
                    // shape Caddy's own flags produce.
                    if versions {
                        println!("{id} {}", module_version());
                    } else if packages {
                        println!("{id} {MODULE_PACKAGE}");
                    } else {
                        println!("{id}");
                    }
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

        // 🗄️ The nested spelling, which is Caddy's. Both spellings call the
        // same two functions, so a change to either cannot land on only one.
        Commands::Storage { command } => match command {
            super::StorageCommand::Export { output, config } => {
                storage_export(&output, config.as_deref())?
            }
            super::StorageCommand::Import { input, config } => {
                storage_import(&input, config.as_deref())?
            }
        },

        Commands::StorageExport { output, config } => storage_export(&output, config.as_deref())?,

        Commands::StorageImport { input, config } => storage_import(&input, config.as_deref())?,

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
            tracing::info!("🚀 Starting reverse proxy: {} -> {:?}", from, to);
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
                plaintext_listen: (!https).then(|| listen.clone()).into_iter().collect(),
                error_routes: Vec::new(),
                vars_routes: Vec::new(),
                listen: vec![listen],
                routes: Vec::new(),
                tls,
                log: None,
                log_channels: Vec::new(),
                named_logs: Vec::new(),
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
            let handler = HandlerConfig::ReverseProxy(Box::new(ReverseProxyConfig {
                upstreams: to,
                fastcgi: None,
                dynamic_upstream: None,
                handle_response: Vec::new(),
                subrequest: None,
                rewrite_method: None,
                rewrite_uri: None,
                request_buffer_bytes: None,
                response_buffer_bytes: None,
                upstream_versions: None,
                upstream_options: Vec::new(),
                // 🗄️ `pingclair reverse-proxy` is a throwaway one-liner; caching
                // is a deliberate per-route decision, so it stays off here.
                cache: None,
                load_balance: LoadBalanceConfig::default(),
                health_check: None,
                headers_up,
                headers_down: headers_down.into_iter().collect(),
                // 🚫 The one-liner has no `-Name` spelling to offer, so there
                // is nothing for this to carry.
                headers_up_remove: Vec::new(),
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
            }));

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
                "🚀 Starting file server on {} serving {} (browse: {})",
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
                plaintext_listen: domain
                    .is_none()
                    .then(|| listen_addr.clone())
                    .into_iter()
                    .collect(),
                error_routes: Vec::new(),
                vars_routes: Vec::new(),
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
                    hostnames: Vec::new(),
                    include: Vec::new(),
                    exclude: Vec::new(),
                    sampling: None,
                }),
                log_channels: Vec::new(),
                named_logs: Vec::new(),
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
                // 📄 `pingclair file-server` is the quick one-liner; the
                // subdirectives that shape a served tree belong to a
                // configuration file, so it takes their defaults.
                precompressed: Vec::new(),
                hide: Vec::new(),
                status: None,
                pass_thru: false,
                canonical_uris: true,
                etag_file_extensions: Vec::new(),
            };
            let handler = if templates {
                HandlerConfig::Pipeline {
                    handlers: vec![
                        pingclair_core::config::HandlerElement::plain(HandlerConfig::Templates {
                            root: Some(template_root),
                        }),
                        pingclair_core::config::HandlerElement::plain(file_handler),
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
                tracing::info!("🔍 Validating config: {}", config);
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
                pingclair_config::adapt(&source)
                    .map_err(|error| anyhow::anyhow!("❌ Failed to adapt <stdin>: {error}"))?
            } else {
                let config_path = resolve_config_path(config.as_deref());
                // 🧩 `adapt` converts; it does not validate. That is the whole
                // difference from `validate` and `run`, and it matches
                // upstream's `caddy adapt` — `--validate` runs the checks for
                // anyone who wants them here.
                (if std::path::Path::new(&config_path).is_dir() {
                    pingclair_config::adapt_directory(&config_path)
                } else {
                    pingclair_config::adapt_file(&config_path)
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
            config,
            path,
            overwrite,
            diff,
        } => {
            // 🧭 `--config <path>` is `caddy fmt`'s spelling of the positional
            // path, and a script written against it used to die on argument
            // parsing with exit 2. The positional still wins if both are given,
            // because that is the more specific thing to have typed.
            let path = path
                .or(config)
                .unwrap_or_else(|| "Pingclairfile".to_string());
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
            // 🎯 `caddy fmt` is a linter as well as a formatter: it exits
            // non-zero when the input was not already formatted, which is the
            // whole mechanism behind a `caddy fmt && git diff --exit-code` gate
            // or a bare `caddy fmt --diff` check. This always exited 0, so a
            // pipeline that swapped the two passed no matter what the input
            // looked like.
            //
            // 📌 `--overwrite` is the exception on purpose: it rewrites the file
            // as its job, so fixing the file and then failing would make the
            // command unusable in the one shape the issue's own example uses.
            let already_formatted = source == formatted;
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
            if !overwrite && !already_formatted {
                std::process::exit(1);
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
    use super::{
        FEATURES, HANDLER_MODULES, NON_HANDLER_MODULES, PLUGIN_MODULES, module_ids, module_type,
    };

    /// 🎯 The check the list cannot do for itself: a module this binary tells
    /// an operator it has must be a directive the adapter accepts.
    #[test]
    fn every_listed_module_is_an_implemented_directive() {
        for module in HANDLER_MODULES {
            assert!(
                pingclair_config::adapter::is_implemented_directive(module.directive),
                "`list-modules` advertises `{}`, but the Caddyfile adapter does not \
                 implement it — either wire the directive up or stop listing it",
                module.directive
            );
        }
    }

    /// 🧩 The `http.handlers.*` names this table claims must be modules a real
    /// Caddy build registers.
    ///
    /// 🤡 This is the check the old listing needed and did not have. It printed
    /// `http.handlers.basic_auth`, `http.handlers.cors` and
    /// `http.handlers.rate_limit` — none of which a Caddy build registers — so
    /// a capability check run against `caddy list-modules` reported a
    /// CORS handler the migration target could never provide and missed the
    /// basic-auth module it already has under `authentication`.
    ///
    /// 📌 The reference list is Caddy v2.11.4's `http.handlers.*` output, read
    /// off the binary on 2026-09-23 and frozen here. A name that is not in it
    /// is either a misspelling or a module no Caddy build has; both are things
    /// this listing must not print under Caddy's prefix.
    #[test]
    fn every_claimed_caddy_module_is_one_caddy_registers() {
        const CADDY_HTTP_HANDLERS: [&str; 22] = [
            "acme_server",
            "authentication",
            "copy_response",
            "copy_response_headers",
            "encode",
            "error",
            "file_server",
            "headers",
            "intercept",
            "invoke",
            "log_append",
            "map",
            "metrics",
            "push",
            "request_body",
            "reverse_proxy",
            "rewrite",
            "static_response",
            "subroute",
            "templates",
            "tracing",
            "vars",
        ];
        for module in HANDLER_MODULES {
            let Some(name) = module.caddy_module else {
                continue;
            };
            assert!(
                CADDY_HTTP_HANDLERS.contains(&name),
                "`list-modules` would print `http.handlers.{name}`, which no Caddy build \
                 registers — a capability check reading both listings would look for a \
                 module that does not exist"
            );
        }

        // 🔐 …and the same check for the names outside the handler namespace,
        // each of which was printed bare before and matched nothing.
        const CADDY_OTHER_MODULES: [&str; 6] = [
            "caddy.listeners.proxy_protocol",
            "http.encoders.gzip",
            "http.encoders.zstd",
            "tls",
            "tls.issuance.acme",
            "tls.issuance.internal",
        ];
        for name in PLUGIN_MODULES {
            assert!(
                name.starts_with("dns.providers."),
                "`{name}` is not in the namespace Caddy's DNS providers register"
            );
        }
        for name in NON_HANDLER_MODULES {
            assert!(
                CADDY_OTHER_MODULES.contains(&name),
                "`list-modules` would print `{name}`, which Caddy v2.11.4 does not \
                 register — a capability check reading both listings would look for a \
                 module that does not exist"
            );
        }
    }

    /// 🚩 No name may be printed that Caddy could also print while meaning
    /// something else, and none may be printed twice.
    ///
    /// 🤡 `templates` appeared twice — once as a handler and once as a feature
    /// tag — because the two lists were maintained by hand and nothing compared
    /// them.
    #[test]
    fn the_listing_has_no_duplicate_and_no_bare_ambiguous_name() {
        let ids = module_ids();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids, sorted, "the listing repeats a name");
        for id in &ids {
            assert!(
                id.starts_with("http.handlers.")
                    || id.starts_with("http.encoders.")
                    || id.starts_with("pingclair.")
                    || id.starts_with("tls")
                    || id.starts_with("admin.api.")
                    || id.starts_with("dns.providers.")
                    || id.starts_with("caddy."),
                "`{id}` is neither a Caddy module ID nor namespaced as ours, so a reader \
                 cannot tell it from a module Caddy would also have"
            );
        }
    }

    /// 📌 Sorted so a new handler has one obvious home in the table.
    #[test]
    fn the_module_table_is_sorted() {
        let mut sorted: Vec<&str> = HANDLER_MODULES
            .iter()
            .map(|module| module.directive)
            .collect();
        sorted.sort_unstable();
        let directives: Vec<&str> = HANDLER_MODULES
            .iter()
            .map(|module| module.directive)
            .collect();
        assert_eq!(directives, sorted, "the module table is out of order");
    }

    /// 📊 The admin API half of the listing names what is actually there.
    ///
    /// 🤡 The listing printed a bare `admin-api` tag, so a migration checklist
    /// asking "do you expose `/pki/`?" got "yes, something admin-shaped" from
    /// the inventory and a 404 from the endpoint. The four names Caddy
    /// registers are `admin.api.load`, `admin.api.metrics`, `admin.api.pki` and
    /// `admin.api.reverse_proxy`; this build answers two of them.
    ///
    /// 📌 Measured on 2026-09-23 against a running server: `POST /load` answers
    /// 400 to a bad body — the endpoint exists — and `GET /metrics` answers
    /// 200, while `GET /pki/` and `GET /reverse_proxy/upstreams` both answer
    /// 404. The assertion below is the half of that which can be checked
    /// without a server.
    #[test]
    fn the_admin_api_half_names_only_the_endpoints_that_answer() {
        let ids = module_ids();
        for present in ["admin.api.load", "admin.api.metrics"] {
            assert!(ids.contains(&present.to_string()), "`{present}` is missing");
        }
        for absent in ["admin.api.pki", "admin.api.reverse_proxy"] {
            assert!(
                !ids.contains(&absent.to_string()),
                "`{absent}` is listed, but this build answers 404 for that endpoint — \
                 advertising it is the failure the bare `admin-api` tag already caused"
            );
        }
    }

    /// 🏷️ The three sources are labelled by namespace, not by a marker line,
    /// so nothing has to know where one list ends and the next begins.
    #[test]
    fn every_namespace_reports_the_right_kind() {
        for id in module_ids() {
            let expected = if id.starts_with("pingclair.") {
                "pingclair"
            } else {
                "standard"
            };
            assert_eq!(module_type(&id), expected, "wrong kind for `{id}`");
        }
        // 🚩 And the three sources are all reachable — a listing that quietly
        // lost its feature tags would still pass the checks above.
        let ids = module_ids();
        assert!(
            FEATURES
                .iter()
                .all(|name| ids.contains(&format!("pingclair.features.{name}"))),
            "the feature tags are missing from the listing"
        );
        assert!(
            NON_HANDLER_MODULES
                .iter()
                .all(|name| ids.contains(&name.to_string())),
            "the non-handler modules are missing from the listing"
        );
        assert!(
            PLUGIN_MODULES
                .iter()
                .all(|name| ids.contains(&name.to_string())),
            "the plugin modules are missing from the listing"
        );
    }
}
