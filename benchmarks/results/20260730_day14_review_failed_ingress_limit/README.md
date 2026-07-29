# Day 14 review: PROXY protocol ingress ignored `limits { max_connections }`

- Reviewed commit: `d15afeb` (Day 14)
- Toolchain: Rust `1.88.0`
- Command: `cargo +1.88.0 test -p pingclair-proxy --lib admission_tests::the_public`

## What was wrong

Day 8 shipped `limits { max_connections N }`, enforced by
`ResourceGuardedProxy::process_new` holding a `Semaphore` permit for the
lifetime of each downstream connection.

Day 14 moved the Pingora app onto a private loopback listener and put a new
public ingress in front of it. That ingress had **no admission control at all**:

```rust
let (stream, transport_peer) = listener.accept().await?;   // unbounded
...
tokio::spawn(async move { handle_connection(...) });        // unbounded
```

So with `proxy_protocol` enabled, the guard still bounded the *internal* hop
while external connections were unbounded. Each one costs a file descriptor, a
task, and up to five seconds in `connect_internal`'s retry loop — and Pingora's
503 does not release any of it, because the external socket belongs to the
ingress, not to Pingora.

`limits { max_connections }` therefore stopped describing how many downstream
connections the process actually holds, which is the whole point of the
setting. Untrusted peers were already refused before the spawn, so the exposure
is from inside `trusted_proxies` — which is exactly where a burst comes from,
since that is the load balancer.

## Failing output before the fix

```text
test result: FAILED. 0 passed; 1 failed; 0 ignored; 189 filtered out
```

With the ceiling set to one, a second concurrent tunnel was still forwarded and
answered instead of being refused.

## Fix

`run_ingress` now takes the same `max_connections` the Pingora app is built
with and holds an owned permit for the tunnel's lifetime. The two bounds are
one-to-one, so applying the same number at both layers still yields that
number. The trust check stays ahead of the acquisition so an untrusted flood
cannot consume the budget reserved for real traffic.
