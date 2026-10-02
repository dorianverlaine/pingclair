// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧾 Configuration loading preserves an explicit adapter across startup and reload.

use pingclair_core::config::PingclairConfig;

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(crate) enum ConfigAdapter {
    Caddyfile,
    Json,
}

/// 🧾 Explicit adapters override extensions; absent adapters preserve file inference.
pub(crate) fn load(path: &str, adapter: Option<ConfigAdapter>) -> anyhow::Result<PingclairConfig> {
    let file = std::path::Path::new(path);
    if file.is_dir() {
        if adapter.is_some() {
            anyhow::bail!("🚫 --adapter requires a single configuration file, not a directory");
        }
        return Ok(pingclair_config::compile_directory(file)?);
    }
    if path != "-" && adapter.is_none() {
        return Ok(pingclair_config::compile_file(file)?);
    }
    let source = if path == "-" {
        use std::io::Read;
        let mut source = String::new();
        std::io::stdin().read_to_string(&mut source)?;
        source
    } else {
        std::fs::read_to_string(file)?
    };
    match adapter.unwrap_or(ConfigAdapter::Caddyfile) {
        ConfigAdapter::Caddyfile => Ok(pingclair_config::compile_named(
            &source,
            (path != "-").then_some(file),
        )?),
        ConfigAdapter::Json => {
            let config = serde_json::from_str(&source)?;
            pingclair_config::compiler::validate_config(&config)?;
            Ok(config)
        }
    }
}
