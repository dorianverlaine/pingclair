# Day 9 connect-attempt fixture — closed downstream reuse

- Date: 2026-07-29
- Base commit: `d6a6530561f07d180e57b8e0269f74c976a98001`
- Environment: local macOS development build
- Command:
  `cargo test --locked -p pingclair --test integration test_bounded_upstream_status_retry_preserves_request_body_safety -- --exact --nocapture`

After the expected terminal `/connect-once` 502, reqwest attempted to reuse the
downstream connection that Pingclair had deliberately marked non-reusable.
The next `/connect-twice` request failed before reaching Pingclair with
`connection closed before message completed`; server diagnostics contained no
log for that path.

The boundary cases now use a fresh no-proxy client after the terminal connect
error. The corrected fixture passes: one allowed attempt returns 502 without
reaching the live peer, while two allowed attempts reach it once and return
200.
