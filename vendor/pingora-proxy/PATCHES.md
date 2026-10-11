# 🔌 Pingora HTTP/1 upgrade backport

This directory contains the published **pingora-proxy 0.9.0** crate, with
only the runtime fix from [upstream PR #947](https://github.com/cloudflare/pingora/pull/947)
backported to `src/proxy_h1.rs`. It is not a snapshot of the older PR branch.
`UPSTREAM.json` records the immutable PR commit and registry archive checksum;
`947-backport.patch` records the complete source change against that archive.
Apply it from the extracted crate root with `git apply --unidiff-zero
947-backport.patch`; zero context keeps blank context lines out of whitespace
checks.
The original Apache-2.0 license and package metadata are retained.

The original request's empty-body task must be accounted for once, whether it
arrives before or after the upstream's 101. Only a later tunnel end or closed
task pipe ends the upgraded exchange. No public API or dependency changes.

The regression lives in `pingclair-proxy/tests/websocket_handshake_ordering.rs`
and runs under `just ci`. It delays the original empty-body task to reproduce
the failing ordering. The existing real-binary WebSocket test also runs without
a retry exemption. This patch does **not** fix tunnel half-close (#274).

`just audit` audits the resolved workspace graph, then restores this package's
registry coordinate in a temporary copy of that same lockfile. This keeps the
vendored version visible to RustSec without resolving a different graph.

Remove this directory, its workspace exclusion and `[patch.crates-io]` entry
when a published Pingora release contains the fix. Update the lockfile, remove
the additional audit pass, and run both WebSocket tests and `just ci` against
the registry release before removing the bridge.
