// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🖥️ The command-line surface, and nothing that acts on it.
//!
//! Every flag, default, and help string the binary exposes lives here, which
//! makes this the file to read to answer "what can this thing be asked to do".
//! The answers — what each subcommand then goes and does — are in
//! [`dispatch`], deliberately separated: a clap definition is a contract with
//! the operator, and a contract is easier to review when it is not interleaved
//! with its implementation.
//!
//! [`verify_cli`](tests::verify_cli) is the guard that matters here. clap
//! validates most of a command tree only when it is built, so a duplicate short
//! flag or a bad default is a runtime panic on first use rather than a compile
//! error. `debug_assert` forces that check in a test instead.

use clap::{Parser, Subcommand};

pub(crate) mod admin;
pub(crate) mod service;

// 🧾 `Field: value` arguments are parsed by the same helper the admin
// commands use, so `--header` and `--header-up` cannot drift apart.
use self::admin::parse_header_pair;

/// Pingclair - Modern web server inspired by Caddy, powered by Pingora
#[derive(Parser)]
#[command(name = "pingclair")]
#[command(author, version, about, long_about = None)]
pub(crate) struct Cli {
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    pub(crate) verbose: bool,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Run the server with a configuration file
    Run {
        /// Path to the configuration file (defaults to Pingclairfile or
        /// Caddyfile in the current directory)
        config: Option<String>,

        /// Use the config autosaved by the Admin API, like `caddy run
        /// --resume` (overrides the config path when present)
        #[arg(short, long)]
        resume: bool,

        /// Watch the config file and reload automatically after changes
        /// (local development only, like `caddy run --watch`)
        #[arg(short, long)]
        watch: bool,
    },

    /// Reload the running server through the Admin API, like `caddy reload`
    Reload {
        /// Config file to apply (defaults to Pingclairfile/Caddyfile)
        #[arg(short, long)]
        config: Option<String>,

        /// Admin API address
        #[arg(long, default_value = "127.0.0.1:2019")]
        address: String,
    },

    /// Start the server in the background, like `caddy start`
    Start {
        /// Config file to load
        #[arg(short, long)]
        config: Option<String>,
    },

    /// Stop the running server through the Admin API, like `caddy stop`
    Stop {
        /// Admin API address
        #[arg(long, default_value = "127.0.0.1:2019")]
        address: String,
    },

    /// Generate shell completion scripts, like `caddy completion`
    Completion {
        /// Shell: bash, zsh, fish, powershell, elvish
        shell: String,
    },

    /// Print the environment as seen by Pingclair, like `caddy environ`
    Environ,

    /// List compiled-in modules and features, like `caddy list-modules`
    #[command(name = "list-modules")]
    ListModules {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Print build information, like `caddy build-info`
    #[command(name = "build-info")]
    BuildInfo,

    /// Generate man pages, like `caddy manpage`
    Manpage {
        /// Directory to write the man pages into
        #[arg(short, long)]
        directory: String,
    },

    /// Export the TLS/config store to a tarball, like `caddy storage export`
    #[command(name = "storage-export")]
    StorageExport {
        /// Output tarball path (`-` for stdout)
        #[arg(short, long)]
        output: String,
    },

    /// Import a previously exported store tarball, like `caddy storage import`
    #[command(name = "storage-import")]
    StorageImport {
        /// Input tarball path (`-` for stdin)
        #[arg(short, long)]
        input: String,
    },

    /// Install the internal CA root certificate into the system trust store
    Trust,

    /// Remove the internal CA root certificate from the system trust store
    Untrust,

    /// Start one or more simple hard-coded HTTP servers for development
    Respond {
        /// HTTP status code to return
        #[arg(short, long)]
        status: Option<u16>,

        /// Response header (`Field: value`), repeatable
        #[arg(short = 'H', long = "header", value_parser = parse_header_pair)]
        headers: Vec<(String, String)>,

        /// Response body
        #[arg(short, long)]
        body: Option<String>,

        /// Listener address (defaults to a random loopback port)
        #[arg(short, long)]
        listen: Option<String>,
    },

    /// Start a quick reverse proxy
    #[command(name = "reverse-proxy")]
    ReverseProxy {
        /// Address to listen on
        #[arg(long, default_value = "localhost")]
        from: String,

        /// Upstream address to proxy to (repeatable)
        #[arg(long, required = true)]
        to: Vec<String>,

        /// Set a request header to send upstream (Field: value)
        #[arg(long = "header-up", value_parser = parse_header_pair)]
        headers_up: Vec<(String, String)>,

        /// Set a response header to send downstream (Field: value)
        #[arg(long = "header-down", value_parser = parse_header_pair)]
        headers_down: Vec<(String, String)>,

        /// Disable TLS verification with the upstream
        #[arg(long)]
        insecure: bool,

        /// Use the internal CA instead of attempting public certificates
        #[arg(long)]
        internal_certs: bool,

        /// Do not provision the automatic HTTP redirect listener
        #[arg(long)]
        disable_redirects: bool,

        /// Set the upstream Host header to the upstream address, like Caddy
        #[arg(short = 'c', long)]
        change_host_header: bool,
    },

    /// Start a quick file server
    #[command(name = "file-server")]
    FileServer {
        /// Address to listen on
        #[arg(long, default_value = ":80")]
        listen: String,

        /// Root directory to serve
        #[arg(long, default_value = ".")]
        root: String,

        /// Enable directory listings
        #[arg(short, long)]
        browse: bool,

        /// Serve this domain over HTTPS (requires --listen to be a port)
        #[arg(short, long)]
        domain: Option<String>,

        /// Enable the access log
        #[arg(long)]
        access_log: bool,

        /// Disable response compression
        #[arg(long)]
        no_compress: bool,

        /// Maximum files shown in a directory listing
        #[arg(long)]
        file_limit: Option<usize>,

        /// Enable template rendering for `.html` files, like Caddy
        #[arg(long)]
        templates: bool,
    },

    /// Validate a configuration file
    Validate {
        /// Path to the configuration file (defaults to Pingclairfile or
        /// Caddyfile in the current directory)
        config: Option<String>,
    },

    /// Adapt a Pingclairfile to JSON and print it, like `caddy adapt`
    Adapt {
        /// Path to the configuration file (defaults to Pingclairfile or
        /// Caddyfile in the current directory)
        #[arg(short, long)]
        config: Option<String>,

        /// Format the JSON output with indentation
        #[arg(short, long)]
        pretty: bool,

        /// Validate the adapted configuration (certificate files etc.)
        #[arg(long)]
        validate: bool,
    },

    /// Format a Pingclairfile and print the result, like `caddy fmt`
    Fmt {
        /// Path to the configuration file (`-` reads stdin)
        #[arg(default_value = "Pingclairfile")]
        path: String,

        /// Overwrite the input file instead of printing
        #[arg(short, long)]
        overwrite: bool,

        /// Print a visual diff instead of the formatted output
        #[arg(short, long)]
        diff: bool,
    },

    /// Hash a password for basic_auth (bcrypt)
    #[command(name = "hash-password")]
    HashPassword {
        /// Password to hash; read from stdin if omitted
        #[arg(short, long)]
        plaintext: Option<String>,

        /// Hashing algorithm: `bcrypt` (default) or `argon2id`
        #[arg(long, default_value = "bcrypt")]
        algorithm: String,

        /// bcrypt cost (4..=31); default 14
        #[arg(long)]
        bcrypt_cost: Option<u32>,

        /// argon2id time cost (iterations); default 1
        #[arg(long)]
        argon2id_time: Option<u32>,

        /// argon2id memory cost in KiB; default 65536
        #[arg(long)]
        argon2id_memory: Option<u32>,

        /// argon2id parallelism (threads); default 4
        #[arg(long)]
        argon2id_threads: Option<u32>,

        /// argon2id output key length in bytes; default 32
        #[arg(long)]
        argon2id_keylen: Option<usize>,
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
pub(crate) enum ServiceAction {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
