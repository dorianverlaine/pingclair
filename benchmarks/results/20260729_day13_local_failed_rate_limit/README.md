# Day 13 failing rate-limit boundary

- Base commit: `e5efe2384d484cbe646b5792e1abd4f0c4aa1c31`
- Toolchain: Rust 1.88.0
- Command: `cargo +1.88.0 test -p pingclair-proxy rate_limit::tests::burst_capacity_has_an_exact_boundary -- --nocapture`
- Result: failed before the Day 13 implementation.

The configured base quota was five requests with two burst tokens. The legacy
probabilistic estimator rejected request six, proving that `burst` was not part
of the admission decision and that the boundary was not exact.
