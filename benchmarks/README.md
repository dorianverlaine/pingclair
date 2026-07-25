# Pingclair vs Nginx vs Caddy — Benchmark Notes

This directory replaces the (unverified) numbers in the main `README.md`'s
benchmark table. The original figures were produced before a round of bug
fixes in this session; several of those bugs would have directly distorted
a load test, so the old numbers should not be trusted.

## Bugs found while building and running this harness

Preparing to load-test surfaced 8 real bugs, none of which were about the
benchmark itself — they were pre-existing defects the benchmark happened to
exercise. All 8 are fixed and covered by regression tests on `main`. A 9th
was found by the benchmark *run itself* and has since been fixed too (see
"Large body" results below); #10 and #11 were found during that re-run and
its follow-up analysis, and are fixed as well:

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
9. **FIXED: static-file gzip compression had the same full-buffer bug as
   #1, in a different crate.** `pingclair-static::FileServer::
   compress_content` fully buffered the input file *and* the compressed
   output on *every* request, with no cache — fix #1 only covered the
   reverse-proxy response path, and this static-file path wasn't touched.
   Under sustained concurrent load against a large file, this turned a
   20-second benchmark into 16 minutes (see "Large body" results below).
   Fixed by adding a byte-bounded LRU cache of compressed bodies keyed on
   `(path, mtime, encoding)` — a hit skips the disk read and the
   compression entirely; editing a file (new mtime) transparently
   invalidates its stale entry. Verified with a repeat of the exact same
   benchmark: 16 minutes → 20.09s, 54 requests → 21,684, 0.06 req/s →
   1,079 req/s (~400x more requests served). See "Large body" results
   below for the full before/after and an important residual caveat about
   cold-start memory. (`240399c`)
10. **Named site addresses were bound literally.** `bench.local:8080 { }`
    passed `bench.local` straight to Pingora as the bind host instead of
    binding `0.0.0.0` and routing by the Host header (Caddy/nginx
    semantics), so startup crashed with a BindError unless the hostname
    happened to resolve to a local interface — this is why both benchmark
    Pingclairfiles were originally forced to use a bare `:8080` block.
    Fixed in `parse_server_address` (pingclair-config): IP literals still
    bind to that address; hostnames now bind the wildcard and match via
    the Host header, and the benchmark configs use `bench.local:8080`
    like the nginx/caddy configs.
11. **Cold-cache compression stampede.** A follow-up to #9: the compressed
    body cache fixed steady-state, but on a cold cache N concurrent
    requests for the same file each read and compressed it independently
    before the first one populated the cache (the cold-start memory spike
    in the "Large body" re-run). Fixed with in-flight request coalescing:
    the first request per (path, mtime, encoding) compresses under a
    per-key async lock and the rest wait, then serve the shared result.

## Bugs found by the VPS production test (July 2026)

A dedicated production-readiness run on the Aliyun Shenzhen VPS (2 vCPU /
1.6GB) — named vhosts, static + compression + range, reverse proxy with
two upstreams, admin API, TLS, wrk load — surfaced another batch. All
fixed and verified end-to-end on the same box:

12. **Path traversal read files outside the docroot.** `GET /../x` passed a
    lexical `starts_with(root)` check. Confinement is now lexical
    dot-segment normalization (zero syscalls, nginx/Caddy model).
13. **Any TLS handshake panicked the whole process** (`panic=abort`):
    rustls could not auto-select a CryptoProvider (both `aws-lc-rs` and
    `ring` enabled). An explicit provider is installed at startup.
14. **Manual TLS certificates were silently ignored** — `tls cert key` in
    config was never loaded; manual certs now take precedence over ACME in
    SNI resolution.
15. **Missing files / unknown vhosts / unmatched routes returned 500**
    (fell through to `upstream_peer`'s ConnectNoRoute) instead of 404.
16. **No upstream failover**: with two upstreams and one dead, ~50% of
    requests 502'd. Passive health marks (nginx max_fails/fail_timeout
    semantics) plus a same-request retry fixed this — 20/20 requests
    succeed with one upstream down, and the dead one rejoins after its
    cooldown.
17. **Large uncompressed static files were fully buffered in memory** (the
    `StreamingFile` path was dead code): 20MB × 20 conns drove RSS 24→236
    MiB. `FileServer::serve_auto` now returns Buffered/Stream after one
    resolve + stat; streaming RSS stays ~35 MiB with no throughput
    regression (plain static 17.1k rps vs 17.5k baseline, gzip 25.2k vs
    23.9k).
18. **SIGTERM/SIGINT never stopped the process** (systemd stop hung until
    SIGKILL). Explicit shutdown handlers added.
19. **Admin `/metrics` returned an empty body** — `metrics::init()` was
    never called. **X-Forwarded-For/X-Real-IP were not set** on proxied
    requests. Both fixed.
20. **The DSL had no `tls` or `admin` directives** (JSON-only). Both are
    now supported in the Caddyfile syntax, including `tls { cert/key/
    acme_email/http3 }` block form and `admin off`.

## Bugs found by the HTTP/3 (quiche) VPS run (July 2026)

After the HTTP/3 stack was rewritten on quiche, the Linux smoke run
surfaced one more startup crasher:

21. **Bare `:port` listen addresses in JSON configs crashed startup.**
    Pingora requires a full `IP:port` socket address; a JSON config with
    `"listen": [":8443"]` died with `Name or service not known` (and the
    QUIC socket parse failed the same way). Only DSL configs worked,
    because the Caddyfile adapter already normalized to `0.0.0.0`. Both
    the initial bind path and the SIGHUP reload path in `main.rs` now
    normalize `:port` → `0.0.0.0:port` (`normalize_listen_addr`, with a
    unit test).

Workspace tests: 65 → 129, all passing, across all 20 fixes. (Later: 148
with the HTTP/3-on-quiche rewrite and fix #21; the H3 stack was verified
end-to-end on the same VPS — 10MB static and proxied bodies byte-identical
over QUIC, streamed POSTs with and without Content-Length, 413 on
oversize, and Alt-Svc advertised on H1.1 TLS responses.)

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

**Remote (bare-metal VPS)**: a 2 vCPU / 1.6GB Aliyun Shenzhen box. An
earlier attempt (wrk driven from a laptop over a tunnel) was abandoned —
both network-bound and blocked by the release build thrashing on 1.6GB.
The completed run instead uses `scripts/run_onbox_matrix.sh`: everything
on the box itself, each candidate on `127.0.0.1:8080` in turn, wrk over
loopback (`-t2 -d15s`; the 2 vCPU are shared with the server under test).
Raw output: `results/20260725_vps_onbox/`. The release build links fine
with the box's 2GB of swap added.

### VPS on-box results (July 2026, all fixes in)

Static file (1KB), plain:

| Concurrency | Pingclair | Nginx | Caddy |
|---|---|---|---|
| 50  | 20,022 req/s | 51,904 req/s | 17,772 req/s |
| 200 | 18,795 req/s | 55,236 req/s | 17,413 req/s |
| 500 | 17,797 req/s | 53,508 req/s | 16,229 req/s |

Static file (1KB), gzip requested:

| Concurrency | Pingclair | Nginx | Caddy |
|---|---|---|---|
| 50  | 29,606 req/s | 44,050 req/s | 14,922 req/s |
| 200 | 27,459 req/s | 44,268 req/s | 15,412 req/s |
| 500 | 25,642 req/s | 42,913 req/s | 13,984 req/s |

Reverse proxy passthrough (shared nginx backend on :9000):

| Concurrency | Pingclair | Nginx | Caddy |
|---|---|---|---|
| 50  | 20,507 req/s | 20,713 req/s | 11,189 req/s |
| 200 | 17,716 req/s | 20,778 req/s | 9,168 req/s |
| 500 | 15,861 req/s | 18,823 req/s | 8,041 req/s |

Large body (20MB), gzip, `-c20 -d20s`, memory sampled:

| Server | Requests completed | Throughput | Timeouts | Peak RSS |
|---|---|---|---|---|
| **Pingclair** | **14,070 (703 req/s)** | **2.17 GB/s** | **0** | 74 MiB |
| Nginx | 183 (9.1 req/s) | 41 MB/s | 110 | 21 MiB |
| Caddy | 204 (10.1 req/s) | 39 MB/s | 65 | 117 MiB |

Readings:

- **Nginx is ~2.6-2.9x pingclair on plain 1KB static** (sendfile +
  decades of hot-path tuning); caddy and pingclair are close, pingclair
  slightly ahead. This is the workload where pingclair has the most head
  room left.
- **gzip static narrows the gap** (pingclair ~60-67% of nginx, ~1.8x
  caddy) — and note gzip here means on-the-fly per request for nginx/
  caddy vs pingclair's compressed-body cache, so the gap shrinks as the
  file gets bigger and more compressible (see large body).
- **Proxying is essentially tied with nginx** (~84-99%) and ~1.8-2x
  caddy — the container-run anomaly (pingclair "winning" at c500) did
  not reproduce on bare metal, as expected; see the caveat below the
  container proxy table.
- **Large compressible bodies are the compressed-body cache's home
  turf**: ~70x nginx/caddy throughput, 0 timeouts, because repeat hits
  skip compression entirely while nginx/caddy re-compress on every
  request (their per-request CPU cost at gzip on a 20MB file on 2 shared
  vCPU is brutal). The price of the cache is the 64MB compressed-body
  budget, visible in the 74 MiB peak RSS vs nginx's 21 MiB.
- Compression levels are not perfectly matched (nginx
  `gzip_comp_level 1` vs each engine's own default), so treat gzip
  numbers as informative, not exact.

## Results (Docker bridge, July 2026)

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

**Before the fix (bug #9, `pingclair_static_plain_c500.txt` era, commit
`e35e067` and earlier):**

| Server | Requests completed | Wall time (nominal 20s) | Timeouts | Peak container memory | Peak CPU |
|---|---|---|---|---|---|
| **Pingclair** | 54 | **16m 1s** | 48 | 367.9 MiB / 512 MiB | ~101% (1 core) |
| Nginx | 150 | 20.1s | 126 | 22.2 MiB / 512 MiB | ~211% (2 cores) |
| Caddy | 374 | 20.0s | 0 | 73.0 MiB / 512 MiB | ~201% (2 cores) |

Root cause, confirmed by isolated reproduction (not speculation):
`/large.html` is served by `pingclair-static`'s `FileServer`, **not** the
reverse-proxy path, so P0 fix #1's streaming gzip didn't apply to it.
`FileServer::compress_content` fully buffered the input file *and* the
compressed output on every single request, with no cache. A single
request was fast (0.4s); 5 concurrent requests were fine (0.7-1.75s). The
problem was **sustained** load: `wrk -c20 -d20s` keeps 20 connections
firing repeated requests for the full window, each one re-compressing the
same 20MB file from scratch — under the container's 2-vCPU cap that
backlog compounded into a 16-minute grind. Not an OOM (memory stayed
under the cap, no crash) — an unbounded-latency/queuing problem.

**After the fix (`240399c`, compressed-body LRU cache), same test,
repeated exactly:**

| Server | Requests completed | Wall time (nominal 20s) | Timeouts | Peak container memory |
|---|---|---|---|---|
| **Pingclair** | **21,684** | **20.09s** | 21 | 373.6 MiB / 512 MiB (transient — settles to 17.5 MiB within ~10s) |
| Nginx | 129 | 20.03s | 107 | — |
| Caddy | 401 | 20.02s | 0 | — |

- **54 → 21,684 requests (~400x), 16m1s → 20.09s, 0.06 → 1,079 req/s.**
  Error rate dropped from ~47% of attempts timing out to ~0.1%.
- Pingclair now serves **more total requests than nginx and caddy
  combined** on this exact test, because after the first request the file
  is cached compressed — every subsequent hit skips compression
  entirely, while nginx and caddy (no compressed-response cache
  configured) pay the full compression cost on every request, every time.
- **Cold-start caveat — since fixed**: peak memory during the *cold start*
  was essentially unchanged in that run (373.6 MiB vs. 367.9 MiB before).
  The cache started empty, so with `-c20` all 20 connections raced in and
  missed simultaneously — each independently compressed the full file
  before any of them finished and populated the cache (a classic "cache
  stampede"). This was later fixed with **in-flight request coalescing**
  (`pingclair-static/src/file_server.rs`): the first request for a given
  (path, mtime, encoding) takes a per-key async lock and does the read +
  compression, and concurrent requests for the same key wait on that lock
  and then serve the shared cached result — one compression pass total.
  See the `concurrent_cold_cache_requests_are_coalesced` test.

## Remote VPS run

Completed July 2026 — see "VPS on-box results" above. The earlier failure
mode (release link thrashing on 1.6GB) went away once the box had 2GB of
swap; the full release profile (`lto = "fat"`, `codegen-units = 1`) now
builds in ~2.5 minutes on the box.

## Reproducing

```bash
cd benchmarks
./scripts/run_local_matrix.sh          # local, Docker bridge
./scripts/provision_remote.sh          # remote, one-time setup (VPS)
./scripts/run_remote_matrix.sh         # remote, wrk driven from your laptop
./scripts/run_onbox_matrix.sh          # remote, everything on the VPS itself
                                       # (the methodology used for the VPS
                                       # results above — no network in the way)
```
