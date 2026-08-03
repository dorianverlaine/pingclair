# Pingclair benchmarks

The latest verified comparison is the 2026-08-03 t3.small (x86)
low-concurrency run on branch `codex/h3-perf` at `3586884`. Raw per-run
evidence is kept locally under `benchmarks/results/` (not committed); the
reusable harness lives in `benchmarks/aws-h3/`.

## Latest results (2026-08-03, t3.small x86, 50×10)

Environment: two fresh `t3.small` (2 vCPU, unlimited credits, Ubuntu 26.04)
in one subnet, private traffic. Pingclair HEAD `3586884` (amd64 fat-LTO,
SHA-256 `327ccd29…`) runs as a host process with `ulimit -n 65535`; nginx
1.31.3, Caddy 2.11.4 and pingap run in containers with the same FD limit;
shared nginx backend on :9000. H2 uses `h2load -t2 -c50 -m10`; H1 uses
`wrk -t2 -c100`; 1 KiB file. t3 exposes no hardware PMU events, so per-request
cost is measured with `task-clock`.

### H2 static (perf-stat phase, 14 s windows)

| Candidate | req/s | task-clock/request |
| --- | ---: | ---: |
| Pingclair HEAD | 29,659 | 52.1 µs |
| nginx 1.31.3 | 42,999 | 36.6 µs |

### H2 reverse proxy (perf-stat phase)

| Candidate | req/s | task-clock/request |
| --- | ---: | ---: |
| Pingclair HEAD | 9,798 | 109.2 µs |

### Single-round matrix (same hosts, fixed harness, 15 s / 50 k requests)

| Scenario | Pingclair | nginx | caddy | pingap |
| --- | ---: | ---: | ---: | ---: |
| H2 static 50×10 | 12,353 | 18,691 | 6,297 | — |
| H1 proxy | 7,839 | 18,052 | 6,475 | 11,146 |
| H2 proxy 50×10 | 8,174 | 9,433 | 3,748 | 9,583 |
| H1S proxy | 6,998 | 14,582 | 6,151 | 7,271 |

Single rounds on shared t3.small vary by several times (the same H2-static
workload measured 12.4k and 29.7k req/s minutes apart); cells are directional.

### Upstream keepalive pool scan (t4g, proxy H2 100×20)

| Pool size | 128 | 256 | 512 | 768 | 1024 |
| --- | ---: | ---: | ---: | ---: | ---: |
| req/s | 8,118 | 8,549 | **8,924** | 8,205 | 8,565 |

The product default was raised from 128 to 512 in `3586884`.

## Evidence

- `benchmarks/results/20260803_t3_lowconc/` — latest t3 x86 run and perf data.
- `benchmarks/results/20260803_t4g_matrix/` — pool scan and standalone rows.
- `benchmarks/results/20260803_h3perf_opt/` — local OrbStack H3 A/B.
