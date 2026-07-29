# M2 guardrail matrix — 23/23

- Commit: `a5544770f3b889981c1f8bee09874c9b26ce6b9c`
- Image: `pingclair:rc-a554477` (linux/arm64 release build, `Dockerfile`)
- Runner: `benchmarks/scripts/run_m2_matrix.sh`
- Config: `benchmarks/fixtures/m2/Pingclairfile`

Every guardrail in M2 engages only when something goes wrong, so this runs
against controllable origins whose failure mode is changed from outside while
the proxy keeps running. It is deliberately not run against the production
site: M1 asked whether the proxy is faithful and the live site is the answer
key for that; M2 asks whether it holds when the upstream misbehaves, and that
cannot be asked of a site meant to stay up.

| Day | Checked | Result |
|---|---|---|
| 12 | Both origins in rotation while healthy | ✅ |
| 12 | **Idle failed origin removed with no request having reached it** | ✅ |
| 12 | Recovered origin rejoined | ✅ |
| 9 | 503 origin redispatched to a healthy one | ✅ |
| 9 | All candidates exhausted surfaces 503, does not hang | ✅ |
| 9 | A request with a body completes without replay | ✅ |
| 10 | Over the route ceiling refused fast (429) | ✅ |
| 10 | Slot released when the holder finished | ✅ |
| 10 | Open circuit fails fast (15 ms) | ✅ |
| 10 | Half-open probing closed the circuit after recovery | ✅ |
| 8 | Silent origin hit the first-byte timer (2050 ms → 504) | ✅ |
| 8 | Over `max_headers` refused (431) | ✅ |
| 8 | Over `max_header_bytes` refused (431) | ✅ |
| 8 | Slow-header client released by the header timer (3 ms) | ✅ |
| 13 | Burst exact: five allowed, sixth refused | ✅ |
| 13 | `RateLimit-*` and `Retry-After` present and exact | ✅ |
| 14 | Direct listener serves with no PROXY header | ✅ |
| 14 | PROXY listener serves through HAProxy `send-proxy` | ✅ |
| 14 | PROXY listener refuses a header-less connection | ✅ |
| 14 | Identity reaches the origin through the PROXY hop | ✅ |
| 14 | **Untrusted `X-Forwarded-For` replaced with the socket peer** | ✅ |

## The two assertions that carry the most weight

**Active health checking really is active.** origin-b's health is taken down
and *no traffic is sent to it*. Eight subsequent requests all reach origin-a
and all return 200. Passive marking cannot produce that result, because
passive marking requires a request to fail first.

**Identity is differential, not asserted once.** The same header from two
sources:

```
untrusted source  → x-forwarded-for: 10.88.0.1          (the forged 203.0.113.99 is gone)
trusted balancer  → x-forwarded-for: 10.88.0.1, 10.88.0.6
                    x-real-ip:       10.88.0.1
```

## Exact rate-limit numbers

`rate_limit 3 10s { burst 2 }` advertises capacity 5, not an estimate:

```
ratelimit-limit: 5
ratelimit-remaining: 0
ratelimit-reset: 17
retry-after: 4
```

## Earlier runs kept

`../20260730_m2_a554477/` holds the first run (20/23) and `HARNESS_BUGS.md`
explaining that all three failures were defects in the runner, not the proxy.

One of those is worth repeating here because it is the more dangerous kind:
the run-2 identity check passed **vacuously**. `trusted_proxies` was written as
`10.88.0.0/24`, which includes the Docker gateway the test client arrives
through — so honouring the forged header was correct behaviour and the
assertion could not fail. Trust is now `10.88.0.6/32`, the balancer alone.
A negative assertion that cannot fail is not a test.
