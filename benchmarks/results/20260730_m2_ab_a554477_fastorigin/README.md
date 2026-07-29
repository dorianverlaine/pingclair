# M2 A/B throughput regression — `39c5623` → `a554477`

Three alternating repetitions, same host, 2 CPU / 512 MB per side, one side at
a time, nginx origin, `wrk -t2 -c50 -d20s` after an unmeasured 5 s warm-up.
Raw wrk output per repetition in `../20260730_m2_ab_rep{1,2,3}/`.

The question is not "how fast is Pingclair" — that needs a quiet dedicated box
and belongs to release day. It is narrower: **did seven days of guardrails make
every request more expensive?** The new work is not opt-in. A reverse-proxy
route gets a `RouteProtection` whether or not it configures anything, upstream
selection goes through admission, peers carry a packed group key, and a
health-check driver polls on a timer with no probe configured.

## Result: no regression detectable above the noise floor

| | before | after | delta |
|---|---|---|---|
| static `/` | 53,766 req/s (spread 3.0%) | 53,283 req/s (spread 5.1%) | −0.9% |
| proxy `/proxy/x` | 31,956 req/s (spread 8.7%) | 30,939 req/s (spread 11.6%) | −3.2% |

Both deltas sit **inside** the run-to-run spread of the measurement itself, so
neither is evidence of anything. What can honestly be said: there is no
regression larger than roughly 5% on the static path or 10% on the proxy path.
Resolving anything finer needs more repetitions on a quieter machine.

## A methodology error worth keeping

The first run used the Python fixture from the functional matrix as the origin
and reported the proxy path at **1,119 req/s**. That is `ThreadingHTTPServer`'s
ceiling, not Pingclair's — both sides were measuring the origin, and the proxy
leg (which is where all the new work lives) measured nothing at all. Switching
to nginx moved the same leg to ~31,000 req/s.

An A/B whose bottleneck is the fixture will report "no change" no matter how
large the real change is.

## Idle cost: sign is consistent, magnitude is not measurable this way

Idle CPU and memory were higher for the new build in **3 of 3** repetitions,
which is a consistent sign. The magnitudes are not usable: they come from a
single `docker stats` snapshot taken ten seconds after a heavy load run, and
the spread across repetitions is ~100% for CPU and ~50% for memory. Post-load
allocator retention dominates.

The production soak is the better instrument for this and is reported in
`../20260730_m2_vps_a554477/`. It shows old 0.23% against new 0.28–0.37% at
idle, consistent with a 100 ms poll that runs whether or not any route
configures a probe.
