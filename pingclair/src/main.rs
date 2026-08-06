// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Pingclair - A modern web server built on Pingora
//!
//! This is the main entry point for the Pingclair CLI.

use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod addr;
mod certs;
mod cli;
mod listen;
mod paths;
mod resource_guard;
mod run;
mod runtime_listeners;
mod systemd;

use crate::cli::Cli;

#[cfg(unix)]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

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

    cli::dispatch::run(cli.command)
}
