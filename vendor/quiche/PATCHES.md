# 🛰️ quiche 0.30.1 HTTP/3 conformance backports

This directory contains the published **quiche 0.30.1** crate with bounded
transport and HTTP/3 conformance fixes for Pingclair #282:

- cloudflare/quiche#2515 keeps a transport error detected after authenticating
  the peer's first flight sendable as an Initial `CONNECTION_CLOSE`;
- cloudflare/quiche#2575 rejects non-zero reserved bits only after packet
  authentication succeeds;
- Pingclair maps cancelled-stream closure, frame parsing, duplicate SETTINGS,
  oversized declared frames, and invalid QPACK stream instructions to the
  protocol error codes required by RFC 9114 and RFC 9204.

`UPSTREAM.json` records the registry archive checksum and linked upstream
reports. `282-h3-conformance.patch` is the complete source change against that
archive. Apply it from the extracted crate root with:

```bash
git apply --unidiff-zero 282-h3-conformance.patch
```

The real-server regression is the h3spec matrix in
`scripts/test-h3spec-local.sh`. It targets the literal IPv4 address so
`localhost` resolving to an unrelated IPv6 listener cannot turn 72 expected
rejections into silent timeouts.

Remove this directory, the workspace exclusion, the `[patch.crates-io]` entry,
and its audit provenance when a published quiche release includes equivalent
fixes. Re-run `just h3spec` and `just h3` before removing the bridge.
