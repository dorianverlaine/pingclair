# Day 10 Admin reload state regression — expected red run

- Date: 2026-07-29
- Base commit: `db646d5eefed50a93d01b94fd8d7cad2ddce4168`
- Environment: local macOS development build
- Command:
  `cargo test --locked -p pingclair --test integration test_overload_and_circuit_breaker_fail_fast_and_survive_reload -- --nocapture`

The first real-binary run opened the `/circuit` backend after two configured
503 responses, then reloaded the same server through the Admin API. The
post-reload request reached the upstream and returned `200`, while the test
expected the still-open circuit to fail fast with `503` at
`pingclair/tests/integration.rs:951`.

The cause was a split reload path: SIGHUP used `update_config`, while the
Admin API used `add_server`, which always constructed fresh runtime state.
Both paths now retain the same `RouteProtection` only when the host, route,
policy, and configured upstream set remain compatible. The same command then
passed: the upstream hit count stayed at two across reload, and the later
half-open probe recovered with `200`.
