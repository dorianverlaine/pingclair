# Day 12 active-health red test

- Base commit: `2a4eaf7bf2fb6dcae0d901d1e9146df7dded1c47`
- Toolchain: Rust `1.88.0`
- Command: `cargo +1.88.0 test -p pingclair --test integration test_active_health_check_removes_idle_failed_upstream -- --nocapture`
- Result: failed as expected before the health-check driver was wired.

The fixture stopped one of two healthy origins, sent no proxy traffic for two
probe intervals, and then made its first proxied request. Pingclair returned
`502` instead of excluding the failed origin:

```text
assertion `left == right` failed: an idle failed upstream stayed in rotation instead of being actively removed
  left: 502
 right: 200

test result: FAILED. 0 passed; 1 failed; 0 ignored; 31 filtered out
```
