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

- Workspace version: `0.1.7` (see `[workspace.package]` in the root `Cargo.toml`)
- Rust edition 2024, minimum toolchain **Rust 1.88** (quiche requires it)
- License: Apache-2.0
- Repository: https://github.com/dorianverlaine/pingclair

## Workspace layout

Cargo workspace with 8 member crates (all declared in the root `Cargo.toml`):

| Crate | Role |
|-------|------|
| `pingclair` | CLI binary (`pingclair`, `[[bin]]` in `pingclair/Cargo.toml`). Entry point `pingclair/src/main.rs`. Wires all other crates together; also contains the BoringSSL SNI certificate resolver with caching. |
| `pingclair-core` | Core runtime: config types (`src/config/`), error types (`src/error.rs`), HTTP server + router + handlers + redirects (`src/server/`). Other crates depend on this for shared types. |
| `pingclair-config` | Configuration compiler for the Pingclairfile DSL: lexer (logos), parser, AST, semantic analysis, variables (`src/parser/`), compilation to `PingclairConfig` (`src/compiler.rs`), and format adapters (`src/adapter/`, incl. a Caddyfile adapter and JSON passthrough). Public entry points: `compile()`, `compile_file()`, `compile_multiple_files()`, `compile_directory()`. |
| `pingclair-proxy` | Reverse-proxy implementation on Pingora's proxy trait: load balancer, health checks, upstreams, rate limiting, connection filter, HTTP/3 listener, Prometheus metrics. |
| `pingclair-static` | Static file serving: file server with range requests, compression (with a byte-bounded LRU cache of compressed bodies keyed on `(path, mtime, encoding)`), MIME inference. |
| `pingclair-tls` | TLS management: certificate store, ACME issuance/renewal, auto-HTTPS redirect logic, persistent ACME challenge handler. |
| `pingclair-api` | Admin REST API (`run_admin_server`): auth, routes, handlers for state inspection and config hot-reload. |
| `pingclair-plugin` | Plugin system (traits, registry, loader). Exposes `Plugin`, `PluginContext`, `PluginInfo`, `PluginRegistry`, `PluginLoader`. Currently a stub: the loader is unimplemented and nothing is wired into the runtime; it is not advertised as a user-facing feature. |

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
  in Traditional Chinese; `TODO.md`, the running list of known issues, feature
  gaps, DSL gaps, and test gaps (Traditional Chinese). **Read `docs/TODO.md`
  before planning new work and update it whenever you fix or discover an
  issue** — it is the project's durable memory across sessions.

## Build and test commands

Prerequisites on Linux: `cmake pkg-config` and a C++ toolchain (BoringSSL is
built from source via the `boring-sys` crate; see `.github/workflows/rust.yml`,
which also installs the now-unneeded `libssl-dev`). On macOS these generally
come from the system/Homebrew.

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
aarch64 on `v*` tags. Both it and the Dockerfile pin **stable** Rust: the code
needs only stable, and nightly ICEs (rustc_codegen_ssa "not immediate" while
compiling tokio) under this workspace's release profile — do not reintroduce
a nightly pin without checking that.

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

## HTTP/3 (QUIC) stack

HTTP/3 is built on **quiche 0.29** (Cloudflare's QUIC implementation, on
BoringSSL via the `boring` crate) — the earlier quinn + h3 stack was
removed, and tokio-quiche was evaluated and rejected because its
server-side accept API is `pub(crate)` (only the client API is public).

`pingclair-proxy/src/quic.rs` runs one UDP socket + one tokio task per
HTTPS listen port, single-threading a `HashMap<ConnectionId, ConnState>`
(no locks on the QUIC path). Key design points:

- **SNI multi-certificate**: BoringSSL's `select_certificate_callback`
  resolves against a `CertTable` (an `ArcSwap`-published map) fed from
  `TlsManager::peek_pem` — manual certs plus already-issued ACME certs.
  `peek_pem` never triggers issuance; issuance stays on the lazy H1
  handshake path. A background task in `main.rs` refreshes the table
  every 60s so renewals reach new handshakes without a restart.
- **Request handling** reuses `PingclairProxy::match_route` (same entry
  point as H1/H2). Each request runs in a tokio task; response bytes flow
  back to the event loop over a channel and are written through quiche
  with real flow control — static files (`serve_auto` Stream branch) and
  upstream responses are streamed in chunks, never buffered whole.
  **The h3 event pump must run from the maintenance pass too, not only on
  packet receipt**: `recv_body` queues the `Finished` event internally once
  the last body bytes are consumed, so a backpressure-deferred drain can
  produce events without any new packet arriving — polling only on packet
  receipt deadlocks large request bodies.
- **Reverse proxying** goes through Pingora's `Connector` (same keepalive
  pool, HTTPS-upstream support, and route timeouts as H1/H2). The request
  body is streamed: headers are sent upstream first, body chunks are
  forwarded as they arrive, bounded by a small channel with QUIC flow
  control as backpressure. HTTP/3 carries no framing headers, but the
  HTTP/1 upstream body writer derives its mode from the forwarded headers,
  so the client's `content-length` is forwarded (and verified against the
  streamed byte count) or `Transfer-Encoding: chunked` is synthesized for
  body-capable methods without one.
- **Alt-Svc** advertisement is a Pingora downstream module
  (`pingclair-proxy/src/alt_svc.rs`) registered in
  `init_downstream_modules`, so it covers locally generated responses as
  well as proxied ones. It is only armed on HTTPS listeners where HTTP/3
  is enabled (`PingclairProxy::set_alt_svc`).
- **Switch**: `global.http3` (JSON config, serde default `true`) gates
  whether HTTPS ports start QUIC listeners. The Pingclairfile DSL has no
  directive for it yet.
- **Single TLS stack**: the whole workspace uses BoringSSL (Pingora via its
  `boringssl` feature on the `pingora` crate, quiche via the `boring` crate —
  both unify on the same `boring` 4.x build). This is load-bearing: an
  OpenSSL stack statically linked next to quiche's BoringSSL collides on
  libcrypto symbol names (`X509_STORE_free`, `OBJ_nid2sn`, …) and the binary
  SIGBUSed at startup. Do not reintroduce Pingora's `openssl` feature; note
  that `pingora-openssl` force-enables `openssl/vendored`. rustls (ACME) is
  unaffected — it has no C symbols.

## Code style guidelines

- Standard Rust style (`cargo fmt`-compatible), standard naming; comments and
  doc comments in the source are in **English only** (Apple-style: complete
  sentences, proper punctuation). No Chinese in code comments, `Cargo.toml`
  comments, or shell scripts. Any Chinese prose in the repository (user docs
  such as `README.zh.md` and `docs/AUDIT_NGINX_PARITY.md`) must be written in
  **Traditional Chinese (Taiwan usage)**.
- Async code is Tokio-based; Pingora traits are implemented with
  `async-trait`. Errors use `thiserror` in libraries and `anyhow` at the CLI
  boundary.
- Performance is a design constraint, not an afterthought. Hot-path code
  avoids locks (`arc-swap` for config reads), avoids per-request syscalls and
  allocations, and streams bodies instead of buffering them (see "Security
  and correctness notes" below). Preserve those properties when editing
  `pingclair-proxy` and `pingclair-static`.
- **Never use `tokio::fs` on a per-request hot path.** Every `tokio::fs`
  call is a `spawn_blocking` cross-thread round-trip (~futex wake+wait
  each way); on the static path that cost ~8 futexes/request and halved
  throughput. Use synchronous `std::fs` for local regular files — page-
  cache reads don't meaningfully block, same model as nginx (measured:
  18.7k → 50k req/s on 2 vCPU; see `benchmarks/README.md`).
- **Any framework default that decides runtime topology must be set
  explicitly and logged at startup.** Pingora's `ServerConf.threads`
  defaults to 1 (single-threaded server!); we set it to
  `available_parallelism()`, overridable via `global.worker_threads`.
  Same principle behind the explicit `upstream_keepalive_pool_size`.
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
  arbitrary files from a configured root. Confinement is **lexical**
  (`resolve_path` rejects `..` escaping the root with no syscalls — the
  nginx/Caddy model); symlinks inside the docroot are followed, like both of
  those servers by default, so do not treat the docroot as a security
  boundary against someone who can plant symlinks in it. Do not reintroduce
  per-request `canonicalize` — it measurably hurt static throughput. Both
  the proxy and static server must stream large bodies rather than buffer
  them fully (past OOM bugs — see `benchmarks/README.md` and
  `docs/AUDIT_NGINX_PARITY.md` for the history).
- The install script runs a root shell script and creates a system user +
  systemd unit + `setcap` on the binary; review any change to
  `scripts/install.sh` with deployment-security eyes.

## Documentation conventions

- Main user docs: `README.md` (English; translations in `README.zh.md`,
  `README.fr.md` — update all three if you change user-facing behavior
  documented there).
- `benchmarks/README.md` is the source of truth for performance claims and
  for the list of load-test-discovered bugs; update it when fixing
  performance-relevant bugs.
- `docs/AUDIT_NGINX_PARITY.md` (Traditional Chinese) tracks nginx-parity gaps
  and P0 issues; check it before touching proxy/static hot paths.
- `docs/TODO.md` (Traditional Chinese) is the canonical list of known issues,
  unshipped features, DSL gaps, and test gaps. Keep it current: mark items
  done (with the date) when fixed, add new ones when found.
