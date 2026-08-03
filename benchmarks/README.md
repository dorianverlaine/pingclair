# Pingclair benchmarks

The current public benchmark is the 2026-08-03 AWS Oregon matrix, measured on
the optimized HTTP/3 branch at commit `36bf860`. The reusable harness lives
in `benchmarks/aws-h3/`; raw per-run evidence is kept locally under
`benchmarks/results/` and is not part of the repository.

## Current results (2026-08-03)

Medians of valid rounds. Higher is better. Environment: two AWS Oregon
`t3.small` instances in one subnet (private IPv4), Ubuntu 26.04, candidates
run one at a time as containers sharing the same files, backend, certificate,
ports, and client. H1S/H2/H3 all use the same h2load; H1 uses wrk.

### 1 KiB static files

| Protocol | Pingclair | nginx 1.31.3 | Caddy 2.11.4 |
| --- | ---: | ---: | ---: |
| H1 (wrk) | 33,920 | 43,971 | 14,252 |
| HTTPS/H1 | 23,533 | 22,538 | 15,384 |
| H2 | 26,638 | 42,332 | 10,394 |
| H3 | 28,448 | 39,683* | 12,304 |

### 1 KiB reverse proxy (nginx backend on :9000)

| Protocol | Pingclair | nginx 1.31.3 | Caddy 2.11.4 | pingap |
| --- | ---: | ---: | ---: | ---: |
| H1 (wrk) | 10,979 | 18,734 | 6,794 | 13,028 |
| HTTPS/H1 | 9,691 | 15,230 | 6,297 | 9,776 |
| H2 | 9,649 | 14,892 | 4,102 | 10,484 |
| H3 | 9,939 | 16,376 | 3,871 | n/a |

Pingap has no HTTP/3 listener and no native static file server, so its rows
are proxy-only and its H3 cells are skipped.

### 1 MiB files (clean round-1 values)

| Mode | Protocol | Pingclair | nginx | Caddy | pingap |
| --- | --- | ---: | ---: | ---: | ---: |
| static | HTTPS/H1 | 589 | 589 | 543 | — |
| static | H2 | 578 | 573 | 529 | — |
| static | H3 | 218 | 250 | 245 | — |
| proxy | HTTPS/H1 | 533 | 588 | 575 | 522 |
| proxy | H2 | 560 | 557 | 418 | 523 |
| proxy | H3 | 217 | 238 | 242 | n/a |

### aioquic parity rows (1 KiB static, client-bound)

Pingclair 2,330 req/s (reused connections) and 1,778 (pipelined); nginx 2,243
and a client timeout; Caddy 2,053 and 1,574. The aioquic client is
single-threaded and caps around 2k req/s on this hardware, so these rows
verify correctness more than throughput.

\* nginx H3 was 55,423 req/s in the clean round and 23,853 after the network
degradation described below; Pingclair was stable across rounds. The
large-file rows come from round 1 only: round 2 was invalidated by exhausted
burstable-network capacity on both hosts after roughly two hours of sustained
traffic (cwnd collapse with ~25% retransmission while both hosts were idle).
Single-connection transfers remained fast throughout.

## 2026-08-03 allocation-pass follow-up (retracted tables, see correction)

⚠️ **Correction**: the first t4g matrix measured with the host-process harness
on this branch was invalidated by a harness bug. The patched
`start-candidate.sh` only killed a leftover host-process pingclair when
switching *to* pingclair; every nginx/caddy/pingap segment that followed
therefore measured the stale pingclair process (container candidates exited
on `Address already in use` while readiness still answered from the old
listener). The earlier "static parity" and "beats pingap on every proxy row"
tables were retracted. What remains valid from that session:

- The upstream keepalive-pool scan (pool 128 → 256 → 512 → 768 → 1024 =
  8,118 → 8,549 → 8,924 → 8,205 → 8,565 req/s, t4g, proxy H2 100×20,
  explicit kill between runs) — this moved the product default from 128 to
  512 (`3586884`).
- A standalone nginx repro run (13,136 req/s, proxy H2 100×20, pingclair
  killed first) and pingclair's own rows (8,123–8,701 req/s).
- Host-process `nofile` 1024 wedges the reverse-proxy path at ~1,000
  upstream connections (5xx after ~900 requests); raise the FD limit.
- The t4g profile run (before this branch): pingclair baseline 29,054 req/s
  at 126.6k cycles/request vs nginx 39,900 at 92.8k — a real server-side
  per-request gap of ~36 %.

### t3.small x86 re-check (50×10 + perf, after the harness fix)

A fresh-pair t3.small run with 50×10 concurrency (client headroom) measured
the H2 static per-request cost with `perf stat` (t3 exposes no hardware PMU
events, so task-clock/request stands in for cycles/request):

| Candidate | path | req/s | task-clock/req |
| --- | --- | ---: | ---: |
| Pingclair HEAD `3586884` | H2 static | 29,659 | **52.1 µs** |
| nginx 1.31.3 | H2 static | 42,999 | **36.6 µs** |
| Pingclair HEAD | H2 proxy | 9,798 | **109.2 µs** |

The server-side per-request cost gap to nginx is real and still ~+42 % on
static H2 at low concurrency, consistent with the t4g cycles profile. Proxy
H2 at 50×10 was a three-way tie (pingclair ≈9.8k ≈ nginx 9.4k ≈ pingap 9.6k,
single sample). t3.small shared-CPU noise and burst-credit exhaustion make
single-round throughput comparisons unreliable (see
`benchmarks/results/20260803_t3_lowconc/RESULT.md`); the published t3 matrix
above remains the primary cross-server reference, and the t4g
cycles/request method remains the better server-side metric. The H3 rows
from the earlier t3 matrix remain the current published H3 evidence.

## Test topology and workloads (2026-08-03)

- AWS Oregon (`us-west-2a`), one x86 `t3.small` client and one x86 `t3.small`
  server, same subnet, private IPv4 traffic, Ubuntu 26.04, 2 vCPU / 2 GiB
  each, `unlimited` CPU credit mode.
- Pingclair: production Dockerfile (Rust 1.97.1, locked dependencies,
  fat-LTO release), `linux/amd64` via OrbStack; x86-64 ELF SHA-256
  `a09d7d033a3a35981ebc1efa9c7b0a64065330b9ebdac1bdfe9c0d6f445f86d8`.
- nginx 1.31.3 (alpine) and Caddy 2.11.4 (alpine) official images; pingap
  `latest`. All candidates pinned to 2 worker threads/processes.
- H1: `wrk -t2 -c100 -d30s` on :8080. H1S/H2: host `h2load` 1.68.0 on :8443
  with SNI `h3.local`, 100 connections × 20 streams for 1 KiB and 50 × 4 for
  1 MiB. H3: `goodideal/nghttp2` 1.64.0-DEV h2load (ngtcp2) with the same
  concurrency. Two interleaved rounds per candidate/mode.
- The reverse-proxy backend is a dedicated nginx container on :9000 serving
  the same payloads. All recorded rounds completed with zero failed, errored
  or timed-out requests except the rows flagged above.
- Configs and orchestration: `benchmarks/aws-h3/` (`run-aws-matrix.sh`,
  `summarize-matrix.py`, candidate configs under `configs/`). The harness
  parameterizes host addresses and SSH key via environment variables.

## Findings from this run

- **Pingclair buffered static files below 5 MiB in memory** (2,000 in-flight
  1 MiB responses OOM-killed the 2 GiB host, RSS 1.47 GB). Fixed on this
  branch by lowering the streaming threshold to 256 KiB; local A/B shows no
  throughput change and a ~200 MiB peak-RSS reduction at 500 in-flight
  requests (evidence in `benchmarks/results/20260803_h3perf_streaming/`,
  not committed).
- **Containers default to `nofile` 1024**, which wedged the reverse-proxy
  path at ~1,000 upstream connections with 502s until the harness added
  `--ulimit nofile=65535:65535`. Worth documenting as a deployment default.
- **Caddy with `auto_https off` rejects IP-based TLS connects** because its
  certificate is bound to a hostname SNI; TLS loads must keep `h3.local` as
  the SNI.
- **Burstable instances are not sustained-throughput benches.** The t3.small
  network token bucket ran out after ~420 GB of server TX (~470 Mbps average);
  subsequent multi-connection large transfers collapsed while single
  connections stayed fast.

## Local H3 optimization A/B (2026-08-03)

An OrbStack optimization pass (branch `codex/h3-perf`) recorded interleaved
h2load/HTTP-3 measurements against the baseline and the optimized binary;
evidence lives under `benchmarks/results/20260803_h3perf_opt/` (not
committed). The optimizations — a 16 KiB per-connection GSO send buffer,
response-event batching in the H3 worker, and a HeaderMap-free H3 framing
check — measured about +14–16% on the 1 KiB static workload at 500–2000
concurrent streams and about +61% on the 1 MiB static workload, inside
OrbStack Linux containers (2 vCPU each). The AWS rows above are the remote
confirmation of that binary against other servers.

## Historical baseline (2026-08-02)

The previously published rows were measured at commit
`ca773affad998eb6439319236dd904fc20b4785f` with a different methodology and
are kept for reference only. They are not directly comparable with the
2026-08-03 rows: the binary changed (baseline vs optimized H3 branch), H3
used the single-threaded aioquic client instead of ngtcp2 h2load, and the
nginx reverse-proxy configuration used plain `proxy_pass` (HTTP/1.0, no
upstream keepalive), which understates nginx in proxy scenarios. Evidence:
`benchmarks/results/20260802_aws_x86_ca773af/` (not committed).

| Scenario | Unit | Pingclair | nginx 1.28.3 | Caddy 2.11.4 |
| --- | --- | ---: | ---: | ---: |
| H1 static, 1 KiB | req/s | 38,862.71 | 61,178.61 | 14,442.93 |
| HTTPS/H1 static, 1 KiB | req/s | 31,018.40 | 43,806.16 | 14,617.83 |
| H2 static, 1 KiB | req/s | 33,004.03 | 57,487.59 | 10,212.16 |
| H1 reverse proxy, 1 KiB | req/s | 11,474.42 | 11,876.71 | 6,998.97 |
| H2 reverse proxy, 1 KiB | req/s | 10,471.76 | 10,537.69 | 4,300.58 |
| H3 fresh connection, 1 KiB static | req/s | 128.93 | 143.14 | 151.84 |
| H3 reused connections, 1 KiB static | req/s | 1,550.21 | 1,694.08 | 1,834.92 |
| H3 reused connections, reverse proxy | req/s | 1,396.32 | 1,447.61 | 1,914.65 |
| H1 static, 1 MiB random | MiB/s | 590.91 | 590.62 | 590.74 |
| H1 warm gzip, 1 MiB compressible | req/s | 44,966.58 | 833.18 | 2,374.64 |
| WSS echo, 50 connections × 64 B | msg/s | 14,029.97 | 14,937.19 | 13,461.07 |

That run used wrk `-t2 -c100` with a 2-second warm-up and three 8-second
rounds, h2load `-t2 -c50 -m10` with a 10,000-request warm-up and three
fixed-count rounds, and aioquic 1.3.0 with three recorded rounds. All
published rounds completed with zero failures. These are comparative results
on small burstable instances, not universal product limits.
