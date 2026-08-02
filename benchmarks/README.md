# Pingclair benchmarks

The current public benchmark is the 2026-08-02 AWS x86 run, measured
at Pingclair commit `ca773affad998eb6439319236dd904fc20b4785f` (raw per-run
evidence is kept locally and is not part of the repository).

## Current results

Each value is the median of three recorded rounds. Higher is better.

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

## Test topology

- AWS Oregon (`us-west-2a`), with one x86 `t3.small` client and one x86
  `t3.small` server in the same subnet. All load used private IPv4 traffic.
- Ubuntu 26.04 on both hosts, with 2 vCPU and 2 GiB RAM each. Both instances
  reported an Intel Xeon Platinum 8259CL.
- Pingclair, nginx, and Caddy ran one at a time on the server. They shared the
  same files, backend, short-lived ECDSA P-256 certificate, ports and client.
- Pingclair was built locally through OrbStack as `linux/amd64`, using the
  production Dockerfile's Rust 1.97, locked dependencies and fat-LTO release
  profile. The x86-64 ELF SHA-256 was
  `0e27a136a037ba2cd9564f94abf12227187b584b7baddc71f4a976309aa9b5ec`.
- nginx was Ubuntu 1.28.3 with HTTP/3 enabled; Caddy was the official 2.11.4
  linux-amd64 release.

## Workloads

### H1, HTTPS and reverse proxy

wrk used 2 threads and 100 connections. A 2-second warm-up preceded three
8-second recorded rounds. Large-file and gzip tests used 32 connections.

The reverse-proxy backend was a separate nginx listener returning the same
verified 1 KiB body. Its direct private-network preflight reached 63,314.27
req/s, well above all proxy results.

### H2

h2load 1.68.0 used 2 threads, 50 clients and 10 concurrent streams per
connection. Each candidate received a 10,000-request warm-up, followed by
three fixed-count rounds: 300,000 requests for static serving and 100,000 for
reverse proxying.

nginx's `keepalive_requests` was set to 1,000,000. Its default of 1,000 closes
each H2 connection after exactly 50,000 aggregate successes in this topology,
which would make the remaining requests client errors rather than measure
steady-state throughput. The published rounds all completed with zero failed,
errored or timed-out requests.

### H3

The client used aioquic 1.3.0. The fresh-connection workload made 300 requests
at concurrency 30 with one request per QUIC connection. Reuse workloads made
3,000 requests over 30 persistent connections. Each scenario had a separate
100-request warm-up and three recorded rounds. Every published response had
status 200, the expected 1 KiB body, and zero failures.

### Static files and gzip

The large static fixture was an incompressible 1 MiB file. All three servers
clustered at about 591 MiB/s, indicating the instance network ceiling.

The gzip fixture was a 1 MiB compressible file requested with an explicit
`Accept-Encoding: gzip`. This is deliberately a warm-serving workload:
Pingclair caches the compressed static representation, while the tested nginx
and Caddy configurations compress on every request. The row compares those
serving strategies, not raw compression-codec speed.

### WebSocket

A native amd64 Go tool ran both the echo backend and the client. The backend's
direct median was 27,364.98 msg/s. Published WSS rounds used 50 persistent
connections, synchronous 64-byte binary echoes, a 2-second warm-up and three
8-second measurements. All three candidates completed with zero client errors.

Representative recorded commands (repeated three times after warm-up) were:

```bash
wrk -t2 -c100 -d8s http://bench.local:8080/small.txt
wrk -t2 -c100 -d8s https://bench.local:8443/small.txt
h2load -t2 -c50 -m10 -n300000 https://bench.local:8443/small.txt
h2load -t2 -c50 -m10 -n100000 https://bench.local:8443/proxy/bench
python h3_bench.py --host SERVER_PRIVATE_IP --mode fresh --requests 300 --concurrency 30 --expect-bytes 1024
python h3_bench.py --host SERVER_PRIVATE_IP --mode reuse --requests 3000 --concurrency 30 --expect-bytes 1024
wsbench client --url wss://bench.local:8443/ws --connections 50 --duration 8s --payload-bytes 64 --insecure
```

## Correctness and evidence

Before load, curl verified H1, HTTPS/H1 and H2 negotiation. Static and proxy
bodies matched SHA-256
`5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef`;
decompressed gzip matched
`30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58`.

The result directory publishes:

- `RESULT.md`: complete environment, method, medians and interpretation;
- `commit.txt`: the full Pingclair commit under test;
- `SHA256SUMS`: hashes for every privately archived raw round, configuration,
  payload check and harness source.

Raw output stays out of Git to avoid republishing incidental infrastructure
details. The checksum ledger allows the private archive to be verified later.

These are comparative results on small burstable instances, not universal
product limits. In particular, the aioquic client contributes to absolute H3
throughput and the 1 MiB result is network-bound.
