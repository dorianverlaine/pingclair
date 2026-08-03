# ⚡ Pingclair pingora-core performance fork

This directory is a local fork of
[`pingora-core`](https://crates.io/crates/pingora-core) `0.8.1`
(Apache-2.0, vendored from the crates.io registry snapshot at checksum
`cbf53077ae14b9a6b3db2dc8d723a2d9c4429e70e2038b5f60bfe6965abbb871`),
kept in-tree so Pingclair can ship one allocation reduction on the HTTP/1
proxy hot path.

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

## Upgrading

To adopt a newer upstream pingora-core:

```bash
rm -rf vendor/pingora-core
cp -R ~/.cargo/registry/src/index.crates.io-*/pingora-core-<version> vendor/pingora-core
rm -f vendor/pingora-core/.cargo-ok vendor/pingora-core/.cargo_vcs_info.json vendor/pingora-core/Cargo.lock
# Re-apply the prepare_buf hunk, then run the workspace gates.
```

Verify the fork is actually in the build with:

```bash
cargo tree -i pingora-core
```

The output must show `pingora-core v0.8.1 (vendor/pingora-core)` rather
than a registry source.
