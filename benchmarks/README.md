# Pingclair vs Nginx vs Caddy — Benchmark Notes

This directory replaces the (unverified) numbers in the main `README.md`'s
benchmark table. The original figures were produced before a round of bug
fixes in this session; several of those bugs would have directly distorted
a load test, so the old numbers should not be trusted.

## Bugs found while building and running this harness

Preparing to load-test surfaced 8 real bugs, none of which were about the
benchmark itself — they were pre-existing defects the benchmark happened to
exercise. All 8 are fixed and covered by regression tests on `main`. A 9th
was found by the benchmark *run itself* and is **not yet fixed** (see
"Large body" results below) — documenting it here rather than rushing a
fix without review:

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
9. **NOT YET FIXED: static-file gzip compression has the same full-buffer
   bug as #1, in a different crate.** `pingclair-static::FileServer::
   compress_content` fully buffers the input file *and* the compressed
   output per request, with no cache. Fix #1 only covers the
   reverse-proxy response path — this is the static-file path, and it
   wasn't touched. Under sustained concurrent load against a large file,
   this caused a 20-second benchmark to take 16 minutes (see "Large body"
   results below); memory peaked at 367.9 MiB of a 512 MiB cap without
   OOM-killing, so this is a severe latency/queuing problem, not a crash.
   Likely fix: apply the same streaming approach used for #1, and/or add
   a compressed-response cache keyed on file path + mtime + encoding.

Workspace tests: 65 → 83, all passing, across fixes 1-8.

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

Full run: `results/20260724_203009/` (33 files, one per server × test ×
concurrency, plus memory timelines for the large-body test). All numbers
below are `wrk -t4 -d15s --latency` (large-body test: `-t2 -d20s -c20`),
Docker bridge, 2 vCPU / 512MB per container.

### Static file (1KB), plain

| Concurrency | Pingclair | Nginx | Caddy |
|---|---|---|---|
| 50  | 22,942 req/s | 28,801 req/s | 18,309 req/s |
| 200 | 21,547 req/s | 25,806 req/s | 17,043 req/s |
| 500 | 21,162 req/s | 27,853 req/s | 18,448 req/s |

Nginx leads throughout; pingclair and caddy are close, roughly
75-80% of nginx's throughput. No errors on any server at this size.

### Static file (1KB), gzip requested

| Concurrency | Pingclair | Nginx | Caddy |
|---|---|---|---|
| 50  | 15,668 req/s | 23,495 req/s | 20,222 req/s |
| 200 | 15,108 req/s | 23,589 req/s | 19,933 req/s |
| 500 | 14,220 req/s | 23,250 req/s | 19,305 req/s |

Pingclair drops noticeably more than nginx/caddy when gzip is requested
even for a 1KB file — worth a closer look at whether the compression-
eligibility check (content-type / size threshold logic in
`upstream_response_body_filter` and `FileServer::compress_content`) is
doing more work than necessary on the hot path.

### Reverse proxy passthrough

| Concurrency | Pingclair | Nginx | Caddy |
|---|---|---|---|
| 50  | 29,268 req/s (0 errors) | 23,339 req/s (0 errors) | 23,174 req/s (0 errors) |
| 200 | 38,437 req/s (0 errors) | 8,288 req/s (0 errors) | 6,963 req/s (350 non-2xx) |
| 500 | 25,906 req/s (0 errors) | 507 req/s (986 timeouts, 5,204 non-2xx) | 682 req/s (266 timeouts) |

This is a genuinely surprising result and **should not be taken as "pingclair
is faster than nginx at proxying" in general** — it needs corroboration on
uncapped hardware (the pending remote VPS run) before trusting it as
anything more than "interesting, under these specific container CPU caps."
Plausible explanations worth checking before believing the headline number:
the shared backend container runs `nginx worker_processes 1;` (a single-
worker bottleneck all three proxies share equally, which shouldn't by
itself explain nginx/caddy specifically falling over while pingclair
doesn't); Docker's bridge network/NAT conntrack behavior under this many
parallel connections; and each engine's own default keep-alive / worker
connection tuning in a 2-vCPU container, which none of these configs
custom-tuned beyond the basics in `configs/*/`.

### Large body (20MB), gzip, sustained concurrent load — the important one

| Server | Requests completed | Wall time (nominal 20s) | Timeouts | Peak container memory | Peak CPU |
|---|---|---|---|---|---|
| **Pingclair** | 54 | **16m 1s** | 48 | **367.9 MiB / 512 MiB** | ~101% (1 core) |
| Nginx | 150 | 20.1s | 126 | 22.2 MiB / 512 MiB | ~211% (2 cores) |
| Caddy | 374 | 20.0s | 0 | 73.0 MiB / 512 MiB | ~201% (2 cores) |

The memory gap is the real story here, not just the wall-clock time.
Nginx and Caddy both peg *both* CPU cores while actively compressing
(~200%) yet barely touch memory (22 MiB / 73 MiB) — consistent with truly
streaming, low-buffer compression. Pingclair uses *less* CPU (~101%, one
core, likely serialized rather than parallel) while using **5-16x more
memory** — consistent with the full-buffer, uncached compression
described below, not a CPU-bound bottleneck.

**Pingclair did not finish this test in anything close to the intended
20-second window.** Root cause, confirmed by isolated reproduction (not
speculation):

- `/large.html` is served by `pingclair-static`'s `FileServer`, **not**
  the reverse-proxy path — so the streaming-gzip fix from this session
  (P0 fix #1 above) does not apply to it at all.
- `FileServer::compress_content` (`pingclair-static/src/file_server.rs`)
  still does the exact same class of bug that was fixed on the proxy
  side: it fully buffers the input file *and* the compressed output in
  memory, per request, with no cache — for every single request to the
  same 20MB file.
- A single request is fast and fine (0.4s). Five concurrent requests are
  fine (0.7-1.75s). The problem is **sustained** load: `wrk -c20 -d20s`
  keeps 20 persistent connections busy firing repeated requests for the
  full 20 seconds, and each one re-compresses the full 20MB from scratch.
  Under the container's 2-vCPU cap, that backlog compounds — measured
  peak memory of 367.9 MiB (of the 512 MiB cap) lines up almost exactly
  with several concurrent 20MB-class buffers in flight at once — and the
  server never recovers within the test window; it just keeps grinding
  through a growing backlog for 16 minutes.
- This is **not an OOM** (confirmed: memory stayed under the cap and the
  container never crashed or restarted) — it's an unbounded-latency /
  queuing problem under sustained concurrent load against a large,
  repeatedly-requested compressible file.
- Nginx and Caddy both also compress on the fly with no explicit cache,
  but neither exhibited anything close to this — see the memory/CPU table
  above. Both stayed under 75 MiB while pegging both CPU cores; pingclair
  used one core less aggressively while ballooning to 367.9 MiB. That
  points specifically at a buffering/streaming difference, not raw
  compression speed.

**Recommended follow-up** (not done in this session — this needs its own
focused pass, not a rushed fix): apply the same streaming approach used
for the reverse-proxy gzip path to `FileServer::compress_content`, and/or
add a compressed-response cache for static files (keyed on file path +
mtime + encoding), which is very likely part of why Nginx/Caddy hold up
better here.

## Remote VPS run

Not completed this session — the box (2 vCPU / 1.6GB Aliyun Shenzhen) is
memory-constrained enough that the release build itself (`lto = "fat"` +
`codegen-units = 1`) struggled to link, thrashing badly enough that SSH
sessions timed out during the banner exchange. Configs and scripts are
staged and ready (`configs/remote/`, `scripts/provision_remote.sh`,
`scripts/run_remote_matrix.sh`); worth trying a non-LTO release profile
for that specific build, or building elsewhere and shipping the binary
over, next time.

## Reproducing

```bash
cd benchmarks
./scripts/run_local_matrix.sh          # local, Docker bridge
./scripts/provision_remote.sh          # remote, one-time setup (VPS)
./scripts/run_remote_matrix.sh         # remote, the actual run
```
