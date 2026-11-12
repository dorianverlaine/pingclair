# 🔌 Pingora HTTP/1 upgrade backport

This directory contains the published **pingora-proxy 0.9.1** crate with three
narrow HTTP/1 fixes:

- [upstream PR #947](https://github.com/cloudflare/pingora/pull/947) keeps an
  upgraded tunnel open when the request body ends after the upstream's `101`;
- `329-write-timeout.patch` ends such a request as soon as writing its body
  fails, instead of waiting forever for an upstream response that may never
  arrive;
- `274-upgrade-half-close.patch` keeps the origin-to-client direction alive
  when the client half-closes the upgraded request direction.

It is not a snapshot of either upstream branch.
`UPSTREAM.json` records the immutable PR commit and registry archive checksum;
`947-backport.patch` records the first source change against that archive, and
`329-write-timeout.patch` and `274-upgrade-half-close.patch` apply after it in
that order.
Apply it from the extracted crate root with `git apply --unidiff-zero
947-backport.patch`, then apply `329-write-timeout.patch` and
`274-upgrade-half-close.patch` the same way; zero context keeps blank context
lines out of whitespace checks.
The original Apache-2.0 license and package metadata are retained.

The original request's empty-body task must be accounted for once, whether it
arrives before or after the upstream's 101. A client FIN ends only the request
direction: the origin response keeps flowing until its side closes or the local
downstream task disappears. No public API or dependency changes.

The regression lives in `pingclair-proxy/tests/websocket_handshake_ordering.rs`
and runs under `just ci`. It delays the original empty-body task to reproduce
the failing ordering. The existing real-binary WebSocket test also runs without
a retry exemption. The tunnel half-close regression is
`pingclair/tests/integration/websocket_upgrade.rs`.

`just audit` audits the resolved workspace graph, then restores this package's
registry coordinate in a temporary copy of that same lockfile. This keeps the
vendored version visible to RustSec without resolving a different graph.

Remove this directory, its workspace exclusion and `[patch.crates-io]` entry
when a published Pingora release contains the fix. Update the lockfile, remove
the additional audit pass, and run both WebSocket tests and `just ci` against
the registry release before removing the bridge.
