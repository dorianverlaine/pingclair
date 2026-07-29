# Day 9 connect-attempt fixture — nondeterministic backend order

- Date: 2026-07-29
- Base commit: `d6a6530561f07d180e57b8e0269f74c976a98001`
- Environment: local macOS development build
- Command:
  `cargo test --locked -p pingclair --test integration test_bounded_upstream_status_retry_preserves_request_body_safety -- --exact --nocapture`

The first max-attempt boundary fixture assumed that two independently
allocated loopback ports would be selected in declaration order. Pingora's
backend set selected the live lower port first, so `/connect-once` reached the
upstream and the fixture panicked on an unexpected path.

The fixture now reserves both sockets together, deliberately assigns the lower
address to the dead backend, and only then converts the higher listener to a
Tokio listener. This makes the first attempted address explicit.
