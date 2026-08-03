# ⚡ Pingclair pingora-core performance fork

This directory is a local fork of
[`pingora-core`](https://crates.io/crates/pingora-core) `0.8.1`
(Apache-2.0, vendored from the crates.io registry snapshot at checksum
`cbf53077ae14b9a6b3db2dc8d723a2d9c4429e70e2038b5f60bfe6965abbb871`),
kept in-tree so Pingclair can ship allocation reductions on the HTTP/1 and
HTTP/2 proxy hot paths.

## Why it exists

The 2026-08-03 local jemalloc profile of the reverse-proxy path (300k
HTTP/2 proxied requests) showed that **91.2 % of cumulative allocations
come from one function**: `BodyReader::prepare_buf`, which allocates a
fresh 64 KiB `BytesMut` for every message body. That is roughly 40 KiB per
proxied 1 KiB request, dwarfing every other site (the `as_owned_parts`
`HeaderMap` clone that was previously suspected is only ~0.1 %).

On a keepalive connection the reader's buffer can be reused safely:

- `read_body_bytes` copies every returned slice out
  (`Bytes::copy_from_slice`), so no caller ever holds a view into the
  buffer across requests;
- a connection that overread bytes (`body_buf_overread` non-empty) is never
  returned to the pool (`check_reuse` disables keepalive), so the buffer is
  exclusively owned when the next request calls `prepare_buf`.

The change is one hunk in
`src/protocols/http/v1/body.rs`: take the existing `body_buf`, clear it,
and fall back to a fresh allocation only when it is `None`. Behavior is
byte-identical to upstream; only the allocation strategy changed. It also
benefits the downstream H1 request-body reader (server side), which shares
the same `BodyReader`.

The second hunk is in `src/protocols/http/v2/server.rs`: the downstream H2
write path consumed `ResponseHeader::as_owned_parts()` (a full `HeaderMap`
clone per response) so the original header could be kept for
`response_written()`. Every caller of that accessor only reads `.status`
(the informational guard and the access log), so the fork now consumes the
header via the existing `From<ResponseHeader> for RespParts` and stores a
status-only `ResponseHeader`. The H2 upstream client keeps its clone
because `pingora-proxy` reads the full sent request header
(`proxy_h2.rs`).

## Upgrading

To adopt a newer upstream pingora-core:

```bash
rm -rf vendor/pingora-core
cp -R ~/.cargo/registry/src/index.crates.io-*/pingora-core-<version> vendor/pingora-core
rm -f vendor/pingora-core/.cargo-ok vendor/pingora-core/.cargo_vcs_info.json vendor/pingora-core/Cargo.lock
# Re-apply both hunks, then run the workspace gates.
```

Verify the fork is actually in the build with:

```bash
cargo tree -i pingora-core
```

The output must show `pingora-core v0.8.1 (vendor/pingora-core)` rather
than a registry source.
