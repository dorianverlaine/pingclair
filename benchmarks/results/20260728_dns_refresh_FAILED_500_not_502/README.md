# FAILED run — kept deliberately

First run of `scripts/run_dns_refresh_e2e.sh`, before the fix. Preserved
because it is the evidence for a real defect, not a flake.

Every DNS case passed. The one failure was the very first assertion:

```
❌ no backend yet → 502 rather than a crash or a hang — wanted HTTP 502, last saw '500'
```

A route that matched a `reverse_proxy` but had no selectable backend returned
**500** (`ConnectNoRoute`), contradicting the comment in `load_balancer.rs`
("all down → None (caller answers 502, nginx-style)") and telling operators
the proxy had broken when the upstream was simply not there.

That mattered more after this change than before it: with re-resolution, "the
hostname has not resolved yet" is an ordinary transient state — the proxy may
legitimately start before its app container. `upstream_peer` now answers
`HTTPStatus(502)` for that case; the two genuine no-route branches above it are
unchanged.

The passing run is in `../20260728_dns_refresh_pass/`.
