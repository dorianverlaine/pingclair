# 🛡️ Pingora header serializer zstd backport

This directory contains the published **pingora-header-serde 0.9.0** crate
with the dependency-only fix from
[upstream PR #1073](https://github.com/cloudflare/pingora/pull/1073)
backported to `Cargo.toml`. It is not a snapshot of the PR branch.

The released Pingora manifest requests `zstd 0.13.1` and `zstd-safe 7.1.0`.
RUSTSEC-2026-0391, RUSTSEC-2026-0398, and RUSTSEC-2026-0403 identify memory
safety and information-disclosure defects in those lines. The backport
requests `zstd 0.14.3` and `zstd-safe 8.2.0`; upstream verified the existing
compression API and implementation without source changes.

`UPSTREAM.json` records the immutable PR commit and registry archive checksum.
`zstd-advisories.patch` records the complete change against the extracted
crate. Apply it from the crate root with:

```bash
git apply --unidiff-zero zstd-advisories.patch
```

The original Apache-2.0 license and package metadata are retained.
The `samples/test` dictionary-training fixtures are copied from the same
upstream commit. Their redundant final blank line is removed to satisfy the
repository whitespace check. The published crate excludes these fixtures even
though its unit tests still read them from `CARGO_MANIFEST_DIR`.

`just audit` first audits the path-patched graph, then restores this package's
registry coordinate in a temporary copy of the same lockfile. That second pass
keeps the vendored package visible to RustSec while preserving every resolved
dependency version and edge.

Remove this directory, its `.gitignore` exception, workspace exclusion, and
`[patch.crates-io]` entry when a published Pingora release carries the fix.
Update the lockfile, remove this provenance entry from
`scripts/audit-dependencies.py`, and run `just audit` plus `just ci` against
the registry release before removing the bridge.
