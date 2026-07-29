# Day 9 retry configuration — locked clippy failure

- Date: 2026-07-29
- Base commit: `d6a6530561f07d180e57b8e0269f74c976a98001`
- Environment: local macOS development build
- Command:
  `cargo clippy --locked --workspace --all-targets -- -D warnings`

Adding the retry policy's status-code and method vectors directly to
`ReverseProxyConfig` increased `HandlerConfig::ReverseProxy` to at least 392
bytes. Locked clippy rejected the workspace with `large_enum_variant`; the
next-largest variant was 144 bytes.

The retry policy is now boxed inside `ReverseProxyConfig`. Serde preserves the
same JSON shape, while the handler enum no longer carries both vectors inline.
No lint exemption was added.
