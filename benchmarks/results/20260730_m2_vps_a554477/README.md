# M2 remote verification — production origin, `a554477`

Host `aqeonet-aws-tw-xray`, Amazon Linux 2023, **aarch64, 2 vCPU, 916 MB**.
Image `pingclair:rc-a554477`, the same linux/arm64 release build used for the
Docker matrix, transferred with `docker save | ssh docker load`.

Topology unchanged: `Cloudflare Tunnel → https://aqeo-pingclair:6688 → app:8080`,
origin publishes no host port.

## 1. M1 regression — 27/27

The full M1 differential drill re-run against this RC, in a parallel container,
with Caddy still up and live traffic untouched. This is the check that matters
most for a release that touched the request path everywhere: `build_http_peer`
now packs a TLS identity into the peer group key, admission control sits in
front of upstream selection, and a health-check background service runs for the
first time.

Nothing regressed. `drill.txt` has the full list; the load-bearing ones:

- Content-Security-Policy **byte-identical** to Caddy's
- `/` and `/api/ping` bodies **byte-identical** to Caddy's
- gzip body decodes byte-exact; zstd/gzip/identity negotiation unchanged
- internal CA reuses its leaf across a restart rather than re-issuing
- HTTP/2 negotiated to the origin (what the tunnel asks for)
- SIGTERM exits 0 with no SIGKILL

## 2. Live cutover

```
old: pingclair:rc-3d4dd53   10.07 MiB after 39 h
new: pingclair:rc-a554477    8.81 MiB at start
```

Swapped in place, same name, network, binds, and restart policy. The container
came back on **the same address (172.18.0.5)**, so the tunnel did not even need
to re-resolve. After the swap:

- `GET /` → **200, HTTP/2**
- cloudflared: no origin errors
- pingclair: no warnings or errors

The previous container is retained as `aqeo-pingclair-rollback`, stopped.
Rollback is a stop, a rename, and a start — no image pull.

## 3. Soak, running

`~/soak/sample.sh` samples RSS, CPU and liveness every five minutes into
`~/soak/soak.csv`. This release added five long-lived maps — rate-limit
buckets, per-backend circuit state, health recovery slots, the PROXY identity
registry, and DNS pools. A leak in any of them appears over hours, not in a
short load run, so the live site is the right instrument for this one thing
even though it is the wrong instrument for fault injection.

Baseline: `soak_start.csv`.

```
2026-07-29T17:13:29Z, 8.77MiB, 0.34%, 200
```

CPU is worth watching specifically: the health-check driver polls every 100 ms
whether or not any route configures a probe, and this server configures none.

## A harness trap fixed on the way

The drill mounts `$RESULTS_DIR/Pingclairfile` but never staged it, so Docker
silently created an **empty directory** at the mount point and the container
exited without a word — the drill reported only "never became ready". This is
the bind-mount trap already in GUARDRAILS, arriving from a new direction. The
script now stages the config itself and fails loudly if the source is missing.
