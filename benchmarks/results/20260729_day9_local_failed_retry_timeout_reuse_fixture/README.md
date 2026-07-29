# Day 9 total-timeout fixture — closed downstream reuse

- Date: 2026-07-29
- Base commit: `d6a6530561f07d180e57b8e0269f74c976a98001`
- Environment: local macOS development build
- Command:
  `cargo test --locked -p pingclair --test integration test_bounded_upstream_status_retry_preserves_request_body_safety -- --exact --nocapture`

The new slow-upstream case correctly returned its terminal 504 within the
100 ms retry total, but the next POST reused the downstream connection that
Pingclair had marked non-reusable. Reqwest reported
`connection closed before message completed` before the POST reached the
server.

The body-safety cases now start with a fresh no-proxy client after the terminal
timeout. This is a fixture isolation correction; the product's timeout result
was already the expected 504.
