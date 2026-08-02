# AWS x86 benchmark — 2026-08-02

Pingclair commit: `ca773affad998eb6439319236dd904fc20b4785f`

The figures below are the median of three recorded rounds. Higher is better.
Every candidate served the same verified payload and ran alone on the server.

| Scenario | Unit | Pingclair | nginx 1.28.3 | Caddy 2.11.4 | Pingclair / nginx |
| --- | --- | ---: | ---: | ---: | ---: |
| H1 static, 1 KiB | req/s | 38,862.71 | 61,178.61 | 14,442.93 | 63.5% |
| HTTPS/H1 static, 1 KiB | req/s | 31,018.40 | 43,806.16 | 14,617.83 | 70.8% |
| H2 static, 1 KiB | req/s | 33,004.03 | 57,487.59 | 10,212.16 | 57.4% |
| H1 reverse proxy, 1 KiB | req/s | 11,474.42 | 11,876.71 | 6,998.97 | 96.6% |
| H2 reverse proxy, 1 KiB | req/s | 10,471.76 | 10,537.69 | 4,300.58 | 99.4% |
| H3 fresh connection, 1 KiB static | req/s | 128.93 | 143.14 | 151.84 | 90.1% |
| H3 reused connections, 1 KiB static | req/s | 1,550.21 | 1,694.08 | 1,834.92 | 91.5% |
| H3 reused connections, reverse proxy | req/s | 1,396.32 | 1,447.61 | 1,914.65 | 96.5% |
| H1 static, 1 MiB random | MiB/s | 590.91 | 590.62 | 590.74 | 100.0% |
| H1 warm gzip, 1 MiB compressible | req/s | 44,966.58 | 833.18 | 2,374.64 | 5,396.0% |
| WSS echo, 50 connections × 64 B | msg/s | 14,029.97 | 14,937.19 | 13,461.07 | 93.9% |

## Environment

- Region and topology: AWS `us-west-2`, one client and one server in the same
  `us-west-2a` subnet, communicating only over their private IPv4 addresses.
- Hosts: two `t3.small` instances, each 2 vCPU and 2 GiB RAM, running Ubuntu
  26.04 (`ami-0f36ac8ec57bd2125`, Canonical build dated 2026-07-31).
- CPU observed on both hosts: Intel Xeon Platinum 8259CL, x86-64.
- Pingclair: Linux amd64 ELF built locally with OrbStack using
  `docker build --platform linux/amd64 -f deployment/Dockerfile .`. The
  production Dockerfile pins Rust 1.88, uses `cargo build --release --locked`,
  and therefore uses the workspace fat-LTO release profile. Binary SHA-256:
  `0e27a136a037ba2cd9564f94abf12227187b584b7baddc71f4a976309aa9b5ec`.
- Other servers: Ubuntu nginx 1.28.3, built with `--with-http_v3_module`, and
  official Caddy 2.11.4 linux-amd64.
- Clients: wrk 4.1.0, h2load/nghttp2 1.68.0, aioquic 1.3.0, and a native amd64
  Go WebSocket echo/client tool. All TLS candidates used the same short-lived
  ECDSA P-256 certificate and TLS 1.3.

## Workloads

- H1 and HTTPS/H1: wrk, 2 threads and 100 connections; 2-second warm-up,
  followed by three 8-second rounds.
- H2: h2load, 2 threads, 50 clients and 10 concurrent streams per connection;
  10,000-request warm-up, then 300,000 static or 100,000 proxy requests per
  round. nginx `keepalive_requests` was raised to 1,000,000 so its default
  1,000-request connection cap would not terminate a fixed-count run early.
- H3 fresh: 300 requests at concurrency 30, one request per QUIC connection.
  H3 reuse: 3,000 requests over 30 persistent connections. Each had a separate
  100-request warm-up and three rounds.
- Large static: a verified, incompressible 1 MiB file with 32 connections.
  The roughly 591 MiB/s equality indicates this case reached the instance
  network ceiling, so it is an end-to-end throughput ceiling rather than a
  file-handler CPU ranking.
- Gzip: a verified 1 MiB compressible file, 32 connections, and an explicit
  `Accept-Encoding: gzip`. This is a warm-serving test: Pingclair caches the
  compressed static representation, whereas the tested nginx and Caddy
  configurations compress on each request. It measures the shipped serving
  strategies, not raw codec speed.
- Reverse proxy: every server forwarded to the same nginx backend. Its direct
  private-network preflight was 63,314.27 req/s, well above every proxied
  result. WSS used the same native Go echo backend; its direct median was
  27,364.98 msg/s.
- WSS: 50 persistent connections, synchronous 64-byte binary echoes, a
  2-second warm-up and three 8-second rounds.

## Correctness and interpretation

The H1/H2/H3 static and proxy bodies matched the expected SHA-256, gzip
decompressed to the source SHA-256, and all published H2, H3 and WSS rounds
completed with zero client-reported failures. HTTP versions were checked with
curl before load was applied.

The test uses small burstable instances and a user-space aioquic H3 client, so
the absolute figures are not universal product limits. The identical topology,
payloads, certificate and client make the within-row comparison meaningful.
The raw tree is kept privately; `SHA256SUMS` authenticates every preserved raw
result, configuration and harness file.
