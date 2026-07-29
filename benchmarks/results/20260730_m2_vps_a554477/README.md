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

### Result after 4.1 hours: not a leak — it peaked and came back down

Two instruments, because `docker stats` reports cgroup memory and can include
page cache, while `VmRSS` from `/proc` is the process's own resident set and is
not ambiguous. `soak.csv` and `soak_rss.csv`.

| | start | peak | end |
|---|---|---|---|
| VmRSS | 18.98 MiB | 19.29 MiB (min 150) | **17.66 MiB** |
| docker MemUsage | 8.77 MiB | 10.47 MiB (min 132) | **9.48 MiB** |

Both series turn at roughly the same point and decline. **A leak's derivative
is positive; this one went negative.** VmRSS ends 1.32 MiB *below* where it
started, and docker's figure ends below its own one-hour value. The last hour
oscillates inside a 0.32 MiB band.

The shape is warm-up, peak, allocator returning dirty pages, then an
oscillating steady state — which is what jemalloc does. Reading only the rising
段 for the first eighty minutes made it look linear; it was not.

- Threads: **11–12 for the whole run**, so no task accumulated either.
- Liveness: **50/50 samples returned 200**.
- Container: `RestartCount=0`, `OOMKilled=false`.

The structural argument agrees and is worth repeating: this server's
configuration uses none of the new features — no `rate_limit`, no
`health_check`, no `proxy_protocol`, one plain `reverse_proxy app:8080`. Four
of the five new long-lived maps are empty by construction and the fifth holds
one backend. There was nothing here for a leak to accumulate *in*.

> ⚠️ **What this does not establish.** 4.1 hours is not 24, and this box serves
> light traffic. It rules out the fast leak the rising 段 suggested; it does not
> rule out something with a period longer than four hours, nor anything that
> only appears once the new features are actually configured. Day 30's soak has
> to exercise `rate_limit`, `health_check` and `proxy_protocol` under load,
> because those are the maps this run left empty.

### Idle CPU

Old build 0.23%; this one averages **0.332%** across 50 samples (range
0.23–0.38). About a tenth of a percentage point, consistent with the
health-check driver's 100 ms poll running whether or not any route configures a
probe — which this one does not. Small, real, and paid by every deployment.
Worth removing by letting the driver sleep until the next due probe.

## A harness trap fixed on the way

The drill mounts `$RESULTS_DIR/Pingclairfile` but never staged it, so Docker
silently created an **empty directory** at the mount point and the container
exited without a word — the drill reported only "never became ready". This is
the bind-mount trap already in GUARDRAILS, arriving from a new direction. The
script now stages the config itself and fails loudly if the source is missing.
