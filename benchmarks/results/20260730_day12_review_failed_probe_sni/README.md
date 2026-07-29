# Day 12 review: health probes used the first backend's name for every backend

- Reviewed commit: `e5efe2384d484cbe646b5792e1abd4f0c4aa1c31` (Day 12)
- Toolchain: Rust `1.88.0`
- Command: `cargo +1.88.0 test -p pingclair-proxy --lib health_check::tests::each_backend`

## What was wrong

`HealthChecker::check_inner` cloned `peer_template` and substituted only the
socket address, which is all Pingora's health check does. The template is built
from `load_balancer.first_backend()`, so its `sni` and `Host` are the **first**
backend's name.

A pool of differently named origins:

```
reverse_proxy {
    to https://a.internal:443
    to https://b.internal:443
    transport http { tls_trusted_ca_certs /internal-ca.pem }
}
```

would probe `b.internal`'s address while presenting `a.internal` as SNI.
Hostname verification fails, `b` is marked down permanently, and the route
loses half its capacity while `b` is serving ordinary traffic perfectly well —
ordinary traffic uses each backend's own name via `build_http_peer`.

This never appears in a single-backend pool, in a pool of same-named backends,
or in any plaintext pool, which is every test that existed.

## Failing output before the fix

```text
host: first.internal
test result: FAILED. 0 passed; 1 failed; 0 ignored; 187 filtered out
```

The probe carried the template's name rather than the target backend's.

## Fix

Each backend already carries its own `HostName` in `Backend::ext`
(`upstream.rs:165`). `check_inner` now reads it and uses it for both SNI and
`Host`, with an operator-stated `health_check.host` or `tls_server_name`
outranking it — those are explicit statements about what the certificate says
and what the origin expects.
