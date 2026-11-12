# 🪝 Pingora HTTP/1 upgraded half-close

This directory contains the published **pingora-core 0.9.1** crate with one
runtime fix in `src/protocols/http/v1/client.rs`.

`HttpSession::finish_body()` used to call `maybe_force_close_body_reader()`,
which replaced a live close-delimited response reader with a zero-length body
after the request direction finished. In an upgraded connection that silently
discarded every origin byte written after the client's FIN. The request and
response directions close independently (RFC 9110 §15.2.2 and RFC 9293
§3.6), so finishing the request body now shuts down only its write half and
leaves the response reader alive. The origin sees EOF in the request direction
while still being able to finish the upgraded protocol's response.

`UPSTREAM.json` records the registry archive checksum and the Pingclair issue.
`274-upgrade-half-close.patch` is the complete source change against that
archive. Apply it from the extracted crate root with:

```bash
git apply --unidiff-zero 274-upgrade-half-close.patch
```

The real-binary regression is
`pingclair/tests/integration/websocket_upgrade.rs`, which writes bytes only
after the client half-closes. Remove this directory and its workspace
exclusion, `[patch.crates-io]` entry, and audit provenance when a published
Pingora release preserves the upgraded response reader.
