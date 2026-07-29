# Day 9 large-body retry fixture — failed setup run

- Date: 2026-07-29
- Base commit: `d6a6530561f07d180e57b8e0269f74c976a98001`
- Environment: local macOS development build
- Command:
  `cargo test --locked -p pingclair --test integration test_bounded_upstream_status_retry_preserves_request_body_safety -- --exact --nocapture`

The first 20 MiB PUT run failed with a downstream connection reset before the
retry assertion. The test server still used Pingclair's 1 MiB default
`client_max_body_size`, so it rejected the fixture rather than exercising the
intended body-streaming path.

The fixture now declares a 25 MiB request limit. The same command then passed:
the upstream observed all 20 MiB and exactly one PUT request, proving that a
configured idempotent method is still not status-replayed when it carries a
body.
