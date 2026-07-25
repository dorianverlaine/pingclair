# AGENTS.md — Pingclair

Guidance for AI coding agents working on this repository. Assumes no prior
knowledge of the project.

## Project overview

**Pingclair** is a high-performance web server and reverse proxy written in
Rust, built on top of **Cloudflare's Pingora** framework (v0.8). Its goal is
to combine Pingora's performance with a Caddy-like configuration experience:
a Caddyfile-compatible DSL ("Pingclairfile"), automatic HTTPS via ACME
(Let's Encrypt), native HTTP/3 (QUIC), static file serving with
gzip/Brotli compression, load balancing, Prometheus metrics, and an admin
REST API for runtime inspection and hot-reload.

- Workspace version: `0.1.6` (see `[workspace.package]` in the root `Cargo.toml`)
- Rust edition 2024, minimum toolchain **Rust 1.85**
- License: Apache-2.0
- Repository: https://github.com/dorianverlaine/pingclair

## Workspace layout

Cargo workspace with 8 member crates (all declared in the root `Cargo.toml`):

| Crate | Role |
|-------|------|
| `pingclair` | CLI binary (`pingclair`, `[[bin]]` in `pingclair/Cargo.toml`). Entry point `pingclair/src/main.rs`. Wires all other crates together; also contains the OpenSSL SNI certificate resolver with caching. |
| `pingclair-core` | Core runtime: config types (`src/config/`), error types (`src/error.rs`), HTTP server + router + handlers + redirects (`src/server/`). Other crates depend on this for shared types. |
| `pingclair-config` | Configuration compiler for the Pingclairfile DSL: lexer (logos), parser, AST, semantic analysis, variables (`src/parser/`), compilation to `PingclairConfig` (`src/compiler.rs`), and format adapters (`src/adapter/`, incl. a Caddyfile adapter and JSON passthrough). Public entry points: `compile()`, `compile_file()`, `compile_multiple_files()`, `compile_directory()`. |
| `pingclair-proxy` | Reverse-proxy implementation on Pingora's proxy trait: load balancer, health checks, upstreams, rate limiting, connection filter, QUIC/HTTP/3 listener, Prometheus metrics. |
| `pingclair-static` | Static file serving: file server with range requests, compression (with a byte-bounded LRU cache of compressed bodies keyed on `(path, mtime, encoding)`), MIME inference. |
| `pingclair-tls` | TLS management: certificate store, ACME issuance/renewal, auto-HTTPS redirect logic, persistent ACME challenge handler. |
| `pingclair-api` | Admin REST API (`run_admin_server`): auth, routes, handlers for state inspection and config hot-reload. |
| `pingclair-plugin` | Plugin system (traits, registry, loader). Exposes `Plugin`, `PluginContext`, `PluginInfo`, `PluginRegistry`, `PluginLoader`. Per the README this is still in development. |

Other top-level directories:

- `examples/` — sample configs: `Pingclairfile.example`, `basic.pingclair`,
  `full_featured.pingclair`, `reverse_proxy.pingclair`, plus `public/` static
  assets used by examples.
- `benchmarks/` — reproducible benchmark harness (Pingclair vs Nginx vs Caddy):
  `configs/` per-server config, `scripts/run_local_matrix.sh` /
  `run_remote_matrix.sh` / `run_largebody_only.sh`, `docker-compose.yml`, and a
  detailed writeup in `benchmarks/README.md` (also documents bugs found and
  fixed via benchmarking).
- `deployment/` and `Dockerfile` (root) — multi-stage Docker build
  (rust:1-slim builder → debian:sid-slim runtime) and a systemd unit file.
- `scripts/` — `install.sh` / `uninstall.sh` (Ubuntu/Debian one-line install:
  binary + systemd service + unprivileged `pingclair` user with `setcap`),
  `pingclair.service`.
- `docs/` — `AUDIT_NGINX_PARITY.md`, an nginx-parity/stability audit written
  in Chinese.

## Build and test commands

Prerequisites on Linux: `cmake pkg-config libssl-dev` (Pingora/OpenSSL need
them; see `.github/workflows/rust.yml`). On macOS these generally come from
the system/Homebrew.

```bash
cargo build --workspace           # debug build
cargo build --release --workspace # release build (fat LTO, codegen-units=1,
                                  # panic=abort, stripped — slow to compile)
cargo test --workspace            # run all unit + integration tests
cargo test -p pingclair-config    # tests for one crate
cargo install --path ./pingclair  # install the CLI binary
```

CI (`.github/workflows/rust.yml`) runs exactly `cargo build --verbose` and
`cargo test --verbose` on every push/PR to `main` — keep both green.
`.github/workflows/release.yml` builds release tarballs for Linux x86_64 and
aarch64 on `v*` tags. Note: the release workflow uses a nightly toolchain step
but the code itself needs only stable; the Dockerfile deliberately pins
**stable** Rust because nightly ICEs on aarch64 under this workspace's release
profile — do not reintroduce a nightly pin without checking that.

Important test detail: `pingclair/tests/integration.rs` spawns the compiled
`pingclair` binary (`env!("CARGO_BIN_EXE_pingclair")`) with a JSON config and
a `PINGCLAIR_TLS_STORE` temp dir, then makes real HTTP requests with `reqwest`.
It needs working network on localhost and is the end-to-end smoke test.

## Running the server

```bash
pingclair run Pingclairfile                              # config-file mode (default path: Pingclairfile)
pingclair validate Pingclairfile                         # check config without starting
pingclair reverse-proxy --from :8080 --to localhost:3000 # ad-hoc reverse proxy
pingclair file-server --listen :8080 --root .            # ad-hoc static server
pingclair service start|stop|restart|reload|status       # manage systemd unit (Linux; `pc` is an alias after scripted install)
```

Config file formats: `Pingclairfile` (DSL), `*.pingclair`, `*.json`, or a
directory containing any mix (merged in sorted order). JSON files are
deserialized directly into `PingclairConfig` (used by the integration tests).

## Code style guidelines

- Standard Rust style (`cargo fmt`-compatible), standard naming; comments and
  doc comments in the source are in **English**. Some workspace-level
  `Cargo.toml` dependency-section comments are in Chinese — match the file
  you're editing rather than imposing one language globally.
- Async code is Tokio-based; Pingora traits are implemented with
  `async-trait`. Errors use `thiserror` in libraries and `anyhow` at the CLI
  boundary.
- Performance is a design constraint, not an afterthought. Hot-path code
  avoids locks (`arc-swap` for config reads), avoids per-request syscalls and
  allocations, and streams bodies instead of buffering them (see "Security
  and correctness notes" below). Preserve those properties when editing
  `pingclair-proxy` and `pingclair-static`.
- On Linux, the binary uses jemalloc (`tikv-jemallocator`); on other platforms
  the system allocator. Keep the `cfg(target_os = "linux")` guard intact.
- Make minimal, scoped changes; match the surrounding module's structure
  (each crate keeps a thin `lib.rs` re-exporting its public API).

## Testing instructions

- Tests live inline in each module (`#[cfg(test)] mod tests`) — every crate
  has unit tests, heaviest in `pingclair-config` (lexer/parser/adapter),
  `pingclair-proxy/src/server.rs`, and `pingclair-static/src/file_server.rs`.
  Add tests next to the code you change.
- The only separate integration test is `pingclair/tests/integration.rs`
  (described above). Dev-dependencies for it: `reqwest`, `tempfile`, `uuid`,
  `flate2`.
- Run `cargo test --workspace` before considering work done; that is the CI
  gate. There is no clippy/fmt gate in CI, but keep code warning-clean.
- Benchmarks are manual, not CI: see `benchmarks/README.md` and the scripts
  under `benchmarks/scripts/`. Use `benchmarks/configs/` when comparing
  against nginx/caddy.

## Security considerations

- TLS certificate material lives under a store directory (overridable via the
  `PINGCLAIR_TLS_STORE` env var); never commit certificates or private keys.
- ACME account keys and issued certs are managed by `pingclair-tls`; the
  auto-HTTPS flow redirects HTTP→HTTPS, so changes there affect every site.
- The admin API (`pingclair-api`) can hot-reload configuration — treat its
  auth layer (`src/auth.rs`) as security-critical; do not weaken it.
- Path traversal and streaming correctness matter: `pingclair-static` serves
  arbitrary files from a configured root (validate paths stay under root),
  and both the proxy and static server must stream large bodies rather than
  buffer them fully (past OOM bugs — see `benchmarks/README.md` and
  `docs/AUDIT_NGINX_PARITY.md` for the history).
- The install script runs a root shell script and creates a system user +
  systemd unit + `setcap` on the binary; review any change to
  `scripts/install.sh` with deployment-security eyes.

## Documentation conventions

- Main user docs: `README.md` (English; translations in `README.zh-TW.md`,
  `README.fr.md` — update all three if you change user-facing behavior
  documented there).
- `benchmarks/README.md` is the source of truth for performance claims and
  for the list of load-test-discovered bugs; update it when fixing
  performance-relevant bugs.
- `docs/AUDIT_NGINX_PARITY.md` (Chinese) tracks nginx-parity gaps and P0
  issues; check it before touching proxy/static hot paths.
