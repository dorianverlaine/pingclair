# Pingclair benchmarks

No benchmark results are published in this repository; all historical data
was cleared on 2026-08-03.

The reusable measurement harness lives in `benchmarks/aws-h3/`. Per-run
evidence is kept only in the local `benchmarks/results/` directory, which is
not committed. The single-machine container matrix behind the documentation
site's performance page is documented below.

## 🧪 The local container matrix (OrbStack, Apple silicon)

The comparison on the documentation site is produced by a single-machine
matrix: every candidate, the load generator, and the shared backend run as
containers inside one OrbStack Linux VM on the maintainer's Mac. One host
removes the cross-machine confounds the two-host harness cannot rule out, and
the quantity the matrix reports is the ratio between candidates under
identical limits — never a capacity claim.

Environment, as run on 2026-10-11/12:

- 🖥️ Host: MacBook Pro (2022), Apple M2, 16 GB memory, macOS 27.0.1.
- 🐳 VM: OrbStack 2.2.3, kernel 7.0.14-orbstack, 8 vCPU, 8 GB memory shared
  by every container. Servers, clients, and the backend all live inside the
  VM, so the traffic never leaves it; the host takes no part in row control.
- 🌉 Engine: Docker 29.4.0 with a dedicated bridge network, `bench-net`
  (192.168.97.0/24).

### 📦 Candidates and images

- **pingclair `main@0476be4a`** (`0.0.0-dev`): built from source with rustup
  1.99.0 and `cargo build --release --locked -p pingclair`.
- **pingclair `v0.2.2`**: the official `pingclair-linux-aarch64` release
  artifact, verified against its `SHA256SUMS`.
- **nginx 1.31.6**: built from the official tarball with
  `--with-http_ssl_module --with-http_v2_module --with-http_v3_module
  --with-http_realip_module --with-http_stub_status_module` and
  `tokers/zstd-nginx-module` at `057a7d3` (OpenSSL 3.5.5, GCC 15.2; the
  `-Werror` in `auto/cc/gcc` is stripped because the GCC 15 build does not
  survive it).
- **Caddy 2.11.7**, **Traefik v3.7.14**: official images
  (`caddy:2.11.7`, `traefik:v3.7.14`), `linux/arm64`.

### ⚙️ Container and server setup

Every candidate runs inside the same envelope:

```text
docker run -d --name sut --network bench-net --cpus=2 \
  --tmpfs /logs:size=512m --tmpfs /var/cache/nginx:size=512m \
  -v <bench>/configs:/conf:ro -v <bench>/payloads:/payloads:ro -v <bench>/certs:/certs:ro \
  <image> <server command>
```

- 📌 Two CPUs per server is the point of the exercise: each candidate's own
  default worker or thread settings apply, and nothing else does.
- 🔐 TLS uses a self-signed certificate (CN `sut`; SAN `sut`, `localhost`,
  `127.0.0.1`). HTTPS listens on 8443/TCP; the HTTP/3 rows also use 8443/UDP.
- 📄 Payloads: `index.html` (226 B), `small.bin` (10 KiB), `medium.bin`
  (2 MiB).
- 🧱 Backend: one `node:22-slim` container runs four Node.js HTTP servers on
  ports 3001–3004 with a `listen` backlog of 4096, returning a fixed 16-byte
  JSON body. Every proxy balances round-robin; nginx and Traefik hold the
  upstream pool at 64 idle connections (`keepalive 64`,
  `maxIdleConnsPerHost: 64`).
- 🧾 Throughput rows disable access logs. The logging row writes JSON access
  logs to a 512 MB tmpfs (`escape=json` in nginx, `format json` in
  pingclair).
- 🗜️ Compression: nginx `zstd_comp_level 3` with `zstd_min_length 256` and
  `zstd_types *`; Caddy `encode zstd better` with an
  `application/octet-stream` response match; pingclair `encode zstd` with the
  same match.

### 🏎️ Load generators

HTTP/2 rows come from `h2load` (nghttp2 1.68.0) in a `client-lite` container
on the same bridge:

- Fixed point: `h2load -n 500000 -c 100 -t 16 -m 8 <url>`.
- Static and logging rows use the same shape against `/index.html` and
  `/small.bin` (500,000 requests) and `/medium.bin` (5,000 requests); the
  Zstd rows add `-H 'Accept-Encoding: zstd'`.
- The concurrency sweep walks `c = 1…9,901` in steps of 100 with one 20,000
  request run per step: `h2load -n 20000 -c <c> -t min(c, 8) -m 8 -T 5 -N 5`.

HTTP/3 rows come from `tquic_client` (Tencent tquic `develop@938e90a`,
crate version 1.6.0, built against BoringSSL):

- `tquic_client -t 8 --max-concurrent-conns 25 --max-concurrent-requests 25
  --total-requests-per-thread 0 -d 10 <url>`
- ⚠️ `--total-requests-per-thread 0` is load-bearing: the default ends a
  worker once one request completes, so `-d 10` would never fire and the run
  would finish in about a second with a meaningless rate.
- 📌 The client's other default — one request per connection — is kept, so
  the HTTP/3 row measures connection churn, not steady-state keep-alive.
- 🪵 Every pingclair connection sends one GREASE unidirectional stream
  (RFC 9114 §6.2.3; quiche's `open_grease_stream`). The tquic client ignores
  the stream and shuts it down with `H3_NO_ERROR`, but logs it at ERROR level
  — roughly 26,000 lines per run. That flood is client-side noise, not an
  interop failure: every request in those rows completed.

Long runs — the sweep, and every multi-round row — are driven by a supervisor
container inside the VM (Ubuntu 26.04 plus the Docker CLI, mounted on the host
`docker.sock`). It starts one candidate, runs one row, retries the row on
failure, and records raw output; the host only aggregates.

### 📏 Sampling and exclusion rules

- One run per fixed point and per sweep step; medians of two rounds for the
  static and logging rows; medians of two to four rounds for HTTP/3 (nginx
  showed enough round-to-round spread to justify two extra rounds).
- 🚫 A row with any failed request is voided and re-run. The first nginx
  sweep surfaced the default `keepalive_requests 1000` closing connections
  under load; all nginx configurations now set `keepalive_requests 1000000`,
  and the comparison was re-run from that fix.
- ⚠️ High-concurrency steps are capacity-bound by construction — two CPUs per
  server sharing an 8 GB VM with the client — so error rates there describe
  that envelope, not a production limit.

### 🗃️ Evidence

Raw results, scripts, and the incident log live in the local, uncommitted
`benchmarks/results/20261011_orbstack-matrix/` directory, consistent with the
no-published-results rule at the top of this file. The documentation site's
performance page is written from those files.

## 🔌 L4 address selection and resource bounds

`just bench -- dns::benchmarks` compares the private production static single-address
path with dynamic one- and four-address snapshots, using one, four and eight
concurrent workers. Pools and per-worker timer drivers are initialized outside
timing. Each iteration includes timer-context entry, snapshot/deadline/cursor work
and an immediately ready injected dial; it performs no DNS or socket I/O.
Divan's allocator profiler measures timed allocations. These results describe
source selection overhead, not whole-server throughput or network latency.

On an idle Linux host, supply a freshly built release binary to the resource drill:

```bash
just l4-resources --binary /path/to/release/pingclair --commit FULL_COMMIT_SHA \
    --results /tmp/l4-resource-run --sessions 128 --reloads 64 --tls
```

The drill holds two listeners' quotas across route reloads, checks excess admission,
and retires controlled pending DNS TCP work while streams remain connected.
It records RSS, descriptors, sessions, queries and peak DNS TCP concurrency,
then checks that sessions and DNS sockets drain and descriptors return near baseline.
`--tls` sends a complete ClientHello before forwarding; without it, routes use
plain TCP. All endpoints are unique localhost ports and cleanup targets only
the child created by the drill. Results directories must be new, so failed
evidence cannot be overwritten. Preserve the harness, full source SHA, binary
hash, toolchain and build settings with each run; `--profile` records supplied
build metadata. Keep the output in the local evidence ledger and exclude test
TLS storage when copying it. This bounded workload does not validate the default
4096 process ceiling as a safe production capacity.

## 📏 What has to be true before a number counts

Three rules, and every one of them exists because the harness produced a
*successful-looking wrong number* that was caught afterwards by reading the
output rather than by anything refusing to record it.

**1. The machine has to be idle.** A background compile made every round of one
re-baseline monotonically worse — proxy H2 went 53,836 → 39,447 → 36,172 rps —
and nothing in the table said the machine was busy. `require_quiet_machine` in
`scripts/lib.sh` now refuses to start when the load average is above 30% of the
core count. Override it with `BENCH_ALLOW_BUSY=1` when the other load is known
and wanted, so it becomes a decision rather than an accident.

**2. Every row prints its success count, and a row that did not fully succeed is
voided.** `h2load -H "host: …"` cannot set an HTTP/1.1 `Host` — that comes from
the URL authority — so a virtual-host mismatch turned all 30,000 requests into
4xx. The comparison point has no virtual hosts and answered 200. The table
showed us winning by four times, and both sides were measuring the cost of a
404. The harness now voids such a row and renames its file to `*.VOID.txt`; a
voided file must never be quoted.

**3. A cross-machine comparison is only valid between two runs that differ in
nothing but the machine — and the cipher counts.** Concurrency, client threads
and container CPU limits all varied between two hosts once and the difference
was read as a generational effect. On a CPU without AES-NI the two servers also
negotiated *different* ciphers — Pingclair on BoringSSL got
`TLS_CHACHA20_POLY1305_SHA256`, the comparison point on OpenSSL got
`TLS_AES_256_GCM_SHA384` — which are very different amounts of work without
hardware AES. That is not a fair comparison in either direction: neither "we lost
anyway" nor "we won fairly" can be claimed until both sides are pinned.

The TLS half of rule 3 is now enforced. `BENCH_TLS13_CIPHER` (default
`TLS_CHACHA20_POLY1305_SHA256`, chosen because it is fast in software on every
machine) is passed to the client, and `assert_cipher_pinned` voids any row whose
handshake did not actually use it — pinning alone is not enough, because a client
that ignored the flag would produce an ordinary-looking number.

⚠️ **Any TLS ratio measured on a machine without AES-NI before this was in place
is not quotable.** The suite was uncontrolled, so those numbers answer a question
nobody asked. They need re-measuring on that hardware, which is the one part of
these three rules a script cannot do for you.

The rest of rule 3 — matching concurrency, client threads and CPU limits — cannot
be enforced by a script either, and is why this section exists.

## 🎯 The static path has no line to fix

A `perf` profile of 30,000 static requests served directly on athlon put the
largest single user-space symbol at **`memcpy`, 0.96 %**. Nothing else reached
1 %. Self time was 61.5 % in `pingclair`, 7.4 % in `libc` and 30.5 % in the
kernel, and that 69 % of user space is spread across several hundred small
functions — the ordinary shape of monomorphised, inlined async state machines.

📌 **So the success criterion here cannot be "find the line and fix it".** There
is no line. It is "re-measure a ratio that the section above says is
trustworthy". A session that opens with `perf` and has no end condition will not
converge, which is why this is written down rather than rediscovered.

Two supporting measurements, both of which make the ratio *flatter* than the
truth rather than more flattering:

- `strace -f -c` shows **fewer syscalls per request than nginx** (5 versus 6),
  spending the same time in them (0.118 s versus 0.117 s) once
  `epoll_wait`/`clock_nanosleep`/`futex` are discounted on our side. The gap is
  neither I/O nor any single function.
- Container bridge networking eats nearly half the throughput — about
  10,000 req/s inside the container against 18,695 on the host, with
  `conntrack`/`seccomp` visible in the profile. Both candidates pay that fixed
  cost, so **the real gap is worse than the measured one, not better**.
