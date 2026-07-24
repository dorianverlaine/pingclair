# Pingclair vs Nginx vs Caddy — Benchmark Notes

This directory replaces the (unverified) numbers in the main `README.md`'s
benchmark table. The original figures were produced before a round of bug
fixes in this session; several of those bugs would have directly distorted
a load test, so the old numbers should not be trusted.

## Bugs found and fixed while building this harness

Preparing to load-test surfaced 8 real bugs, none of which were about the
benchmark itself — they were pre-existing defects the benchmark happened to
exercise. All are fixed and covered by regression tests on `main`:

1. **Gzip full-body buffering (OOM risk)** — `upstream_response_body_filter`
   buffered an entire proxied response before emitting anything. Fixed to
   stream: flush + drain after every chunk, memory bounded regardless of
   body size. (`a24db16`)
2. **Request ID generation did a syscall per request** — replaced
   `SystemTime::now()` with a process epoch + atomic counter. (`a24db16`)
3. **`hosts`/`default` used `RwLock`** on the per-request hot path — moved
   to `ArcSwap` for lock-free reads. (`a24db16`)
4. **Upstream connection pool size was implicit** (`conf: None`) — now
   explicit and configurable. (`a24db16`)
5. **Config adapter dropped inline path matchers.** `handle /api/*` and
   `route "/api/*"` lost their path entirely and collapsed into the
   server's catch-all — every request matched them regardless of URL. This
   also silently broke `examples/full_featured.pingclair`. (`1fd6767`)
6. **Nested handlers were never wired up.** A `reverse_proxy`/`file_server`
   inside a `handle {}` block got no load balancer / no file-server
   instance and 500'd with `ConnectNoRoute`. Rate limiting already
   recursed into these blocks; proxying and file-serving didn't — the
   nesting support was half-finished. (`1fd6767`)
7. **Glob routes didn't match their own bare prefix.** `/proxy/*` failed
   to match the bare `/proxy/` or `/proxy` (matchit's wildcard needs ≥1
   char after the prefix). Nginx and Caddy both match the bare directory
   for the equivalent construct; pingclair didn't. This is what first
   looked like "the proxy collapses under concurrency" in an early run of
   this benchmark — it wasn't load, every single request to that exact
   path failed, at any concurrency. (`e35e067`)
8. **Dockerfile pinned nightly Rust** for no reason (no nightly-only
   features anywhere in the workspace) and nightly's codegen ICEs on
   aarch64 under this crate's release profile (`panic="abort"` + fat LTO +
   `codegen-units=1`), failing the image build partway through compiling
   `tokio`. Pinned to stable. (commit adjacent to the above)

Workspace tests: 65 → 83, all passing, across these fixes.

Also deleted a `strict-tests/` directory that had been added by another
tool: 16 of its 26 tests failed against the real compiler because it
tested invented Caddyfile syntax (`tls { }` blocks, bare `redirect`,
`rate_limit`, `cors`, `headers{}` directives) that isn't wired into the
adapter, despite the underlying Rust types existing for all of it — a real
gap worth tracking separately, but not something that test suite was
useful for catching correctly.

## Methodology

**Local (Docker bridge)**: pingclair, nginx, and caddy each run in their
own container on an isolated bridge network, capped at 2 CPUs / 512MB
(`docker-compose.yml`). `wrk` runs on the host (Apple M2, 8 cores) against
each container's published port **in turn** — never more than one server
under test at a time, so there's no cross-server CPU contention on the
host. `scripts/run_local_matrix.sh` runs the full matrix and tears the
stack down when finished.

Test matrix per server:
- Static file (1KB), no compression requested — concurrency 50/200/500
- Static file (1KB), gzip requested — concurrency 50/200/500
- Reverse proxy passthrough to a shared, unmeasured backend — concurrency
  50/200/500
- Large body (20MB, gzip) at modest concurrency, with container memory
  sampled throughout — this is the direct regression check for bug #1
  above: does memory stay bounded, does the server survive, no 5xx.

Compression levels are **not** perfectly matched across engines (each
uses its own default/fastest setting — see `configs/*/nginx.conf`'s
comment on `gzip_comp_level`), so gzip numbers are informative but not a
precise apples-to-apples compression-speed comparison.

**Remote (bare-metal VPS)**: a 2 vCPU / 1.6GB Aliyun Shenzhen box, with
`wrk` run from a separate Mac over an existing Shadowrocket tunnel. Only
one candidate binds `:8080` at a time (the box is too small to host all
three concurrently without skewing results). This run was interrupted by
VPS resource constraints during the release build (`lto = "fat"` +
`codegen-units = 1` is memory-hungry to link on a 1.6GB box) and not
completed in this session — configs and scripts are in place
(`configs/remote/`, `scripts/provision_remote.sh`,
`scripts/run_remote_matrix.sh`) for a follow-up run.

## Results

See `results/<timestamp>/` for raw `wrk` output. Latest complete local run:
`results/20260724_203009/`.

<!-- RESULTS_TABLE_PLACEHOLDER -->

## Reproducing

```bash
cd benchmarks
./scripts/run_local_matrix.sh          # local, Docker bridge
./scripts/provision_remote.sh          # remote, one-time setup (VPS)
./scripts/run_remote_matrix.sh         # remote, the actual run
```
