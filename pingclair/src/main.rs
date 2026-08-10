// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Pingclair - A modern web server built on Pingora
//!
//! This is the main entry point for the Pingclair CLI.
//!
//! # 🗺️ Why the binary is a set of modules and this file is 57 lines
//!
//! It was one file, and by 2026-08-06 that file was 3,404 lines. Length was
//! not the problem. The problem was that it had no seam: a BoringSSL SNI
//! callback, a clap subcommand definition, and a systemd datagram were
//! neighbours, so a change to any one of them landed in the same place with
//! nothing to check it against. Eight of the last 120 fix commits touched it.
//!
//! The split follows what the binary already does, in the order it does it:
//!
//! | Module | Owns |
//! | --- | --- |
//! | [`cli`] | Every flag, default, and help string — the contract with the operator. |
//! | [`cli::dispatch`] | What each subcommand does. One arm each. |
//! | [`cli::admin`] | The subcommands that reach outside this process: the admin client, the system trust store. |
//! | [`cli::service`] | `pingclair service …`, a thin wrapper over `systemctl`. |
//! | [`run`] | Everything between a compiled configuration and a serving process. |
//! | [`listen`] | Which sockets a configuration actually needs. |
//! | [`runtime_listeners`] | Listeners `/load` creates and destroys after startup. |
//! | [`certs`] | Which certificate a name gets, at each of the three moments that question comes up. |
//! | [`addr`] | What a single Caddy-style address means. |
//! | [`paths`] | The config path and the store directory, both answered by convention. |
//! | [`systemd`] | The two sentences this process says to systemd. |
//! | [`resource_guard`] | Per-listener connection limits, wrapping the Pingora app. |
//!
//! 📌 What stays here is only what has to run before anything can read a flag:
//! the no-argument help path, the rustls provider installed before any TLS code
//! exists, tracing, and the parse. The allocator stays too, because a
//! `#[global_allocator]` is only valid in the crate root.

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
