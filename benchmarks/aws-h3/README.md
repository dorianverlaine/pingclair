# AWS H3 comparison harness

Reusable benchmark harness for comparing Pingclair against nginx, Caddy,
and pingap over HTTP/1.1, HTTPS, HTTP/2, and HTTP/3, for static files and
reverse proxying. It was built for two Linux instances in one VPC subnet
(the original run used two `t3.small` in `us-west-2a`) and is driven from a
macOS host over SSH.

## Layout

- `run-aws-matrix.sh` — orchestrator: switches the server-side candidate,
  runs every workload from the client, and stores raw output under the
  result directory (two interleaved rounds per candidate/mode).
- `summarize-matrix.py` — turns a result directory into median comparison
  tables; pass the result directory as the first argument.
- `setup-server.sh` / `setup-client.sh` — install Docker and the load tools
  on the two hosts (curl, wrk, h2load, an aioquic venv, and the
  `goodideal/nghttp2` image for the H3-capable h2load).
- `configs/` — candidate configurations and `start-candidate.sh`, the
  server-side runner that starts the shared backend plus one candidate.
- `h3_bench.py` / `h3_bench_pipeline.py` — aioquic HTTP/3 clients used for
  the parity rows (single-threaded, ~2k req/s on t3.small; client-bound).
- `scripts/make-payloads.sh` — creates `www/` with 1 KiB and 1 MiB files.
- `scripts/make-cert.sh` — creates the throwaway `bench.crt`/`bench.key`
  for `h3.local`.

## Prerequisites

- Two Ubuntu Linux instances in the same subnet, SSH reachable as `ubuntu@`.
  The security group must allow SSH from your machine and all TCP/UDP
  traffic between the two hosts.
- Docker on both hosts (the setup scripts install it).
- A local SSH key with access to both hosts.
- A curl build with HTTP/3 is not required: HTTP/3 load comes from the
  `goodideal/nghttp2` h2load image and the aioquic venv on the client.

## Usage

```bash
./scripts/make-payloads.sh /tmp/bench-www
./scripts/make-cert.sh                     # writes bench.crt/bench.key in cwd

scp -r /tmp/bench-www ubuntu@<server>:/home/ubuntu/bench/
scp bench.crt bench.key ubuntu@<server>:/home/ubuntu/bench/certs/
scp -r configs/. backend-nginx.conf ubuntu@<server>:/home/ubuntu/bench/configs/
scp h3_bench.py h3_bench_pipeline.py ubuntu@<client>:/home/ubuntu/bench/

AWS_SSH_KEY=~/.ssh/bench.pem \
AWS_SERVER_PUB=<server-public-ip> \
AWS_SERVER_PRIV=<server-private-ip> \
AWS_CLIENT_PUB=<client-public-ip> \
./run-aws-matrix.sh /tmp/aws-run

python3 summarize-matrix.py /tmp/aws-run
```

Server-side paths are fixed by `start-candidate.sh`:
`/home/ubuntu/bench/{www,certs,configs}` and `/home/ubuntu/h3-venv` on the
client. `run-aws-matrix.sh` accepts a result directory as `$1` and an
optional 1-based resume segment as `$2`.

## What the matrix covers

Per candidate (pingclair, nginx, caddy, pingap) and mode (static, proxy):

- HTTP/1.1 on :8080 via wrk (1 KiB).
- HTTPS/1.1 and HTTP/2 on :8443 via h2load (1 KiB and 1 MiB).
- HTTP/3 on :8443 via the ngtcp2-enabled h2load image (1 KiB and 1 MiB).
- aioquic reuse and pipelined-parity rows (1 KiB).

Pingap has no HTTP/3 listener and no native static file server, so its rows
are proxy-only and its H3 cells are skipped. The reverse-proxy backend is a
dedicated nginx container on :9000.

## Hard-won harness rules

- **SNI matters**: Caddy with `auto_https off` only has a certificate for
  the configured hostname, so TLS loads must keep `h3.local` as the SNI
  (`--connect-to` for h2load, `--resolve` for curl). Connecting by IP fails
  the handshake with an opaque `tlsv1 alert internal error`.
- **Containers default to `nofile` 1024**: reverse-proxy loads open ~1,000
  upstream connections, which exhausts file descriptors and wedges the
  proxy with 502s. Every container in `start-candidate.sh` runs with
  `--ulimit nofile=65535:65535`.
- **Pingclair buffers static files below 5 MiB**: a 1 MiB payload with 2,000
  in-flight requests OOMs a 2 GiB host. The harness caps large-file
  concurrency at 50 connections × 4 streams; the buffering itself is the
  top optimization candidate (see the local ledger).
- **Burstable instances are not sustained-throughput benches**: after
  roughly two hours and a few hundred GB, t3.small network tokens run out
  and multi-connection transfers collapse (cwnd 2, ~25% retransmission)
  while single connections stay fast. Treat round-2 large-file rows from
  such hosts with suspicion.
- **Raw output stays local**: result directories under
  `benchmarks/results/` are deliberately git-ignored. Commit the harness,
  not the per-run output.
