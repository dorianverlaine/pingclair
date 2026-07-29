# Day 9 status-retry regression — expected red run

- Date: 2026-07-29
- Base commit: `d6a6530561f07d180e57b8e0269f74c976a98001`
- Environment: local macOS development build
- Command:
  `cargo test --locked -p pingclair --test integration test_bounded_upstream_status_retry_preserves_request_body_safety -- --exact --nocapture`

The retry policy predicate was temporarily forced to reject status
redispatch, reproducing the behavior before the Day 9 execution-path fix. The
real-binary test failed at `pingclair/tests/integration.rs:646`: `/success`
returned `503`, while the test expected the second upstream attempt to return
`200`.

After restoring the Day 9 predicate, the same command passed with two upstream
hits. This directory intentionally preserves the failed result instead of
being reused for the green run.
