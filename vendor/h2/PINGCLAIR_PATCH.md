# ⚡ Pingclair h2 performance fork

This directory is a local fork of [`h2`](https://crates.io/crates/h2)
`0.4.15` (Apache-2.0/MIT, vendored from the crates.io registry snapshot at
checksum `6cb093c84e8bd9b188d4c4a8cb6579fc016968d14c99882163cd3ff402a4f155`),
kept in-tree so Pingclair can ship one small allocation reduction on the
HTTP/2 hot path.

## Why it exists

The 2026-08-03 AWS t4g allocation profile showed HTTP/2 HPACK encoding as one
of the top per-request allocation sites. For every HEADERS frame, upstream h2
built a fresh `BytesMut` (growing through several capacity doublings) and then
froze it into a `Bytes` (allocating a refcount header), even though the block
is copied into the connection write buffer and dropped within the same call.

A header block lives only until it is copied into the frame buffer on the
common path (no CONTINUATION frames, i.e. any header block that fits one
16 KiB frame — the normal case for small responses). So the fork gives the
per-connection `hpack::Encoder` a reusable scratch `BytesMut`:

1. `src/hpack/encoder.rs` — add `scratch: BytesMut` to `Encoder`, plus
   `take_scratch()` / `return_scratch()`.
2. `src/frame/headers.rs` — `EncodingHeaderBlock.hpack` becomes `BytesMut`;
   `into_encoding()` takes the connection scratch; when the encoded block
   fits the frame, the buffer is returned to the encoder. CONTINUATION
   frames still own their remainder (a rare >16 KiB header block), and
   splitting that remainder is `split_to`, not a copy, because the scratch
   is uniquely owned.

The decoder and the dynamic table are untouched. Behavior is byte-identical
to upstream: only the allocation strategy of a temporary buffer changed.

## Upgrading

To adopt a newer upstream h2:

```bash
rm -rf vendor/h2
cp -R ~/.cargo/registry/src/index.crates.io-*/h2-<version> vendor/h2
rm -f vendor/h2/.cargo-ok vendor/h2/.cargo_vcs_info.json vendor/h2/Cargo.lock
# Re-apply the two hunks listed above, then run the workspace gates.
```

Verify the fork is actually in the build with:

```bash
cargo tree -i h2
```

The output must show `h2 v0.4.15 (vendor/h2)` rather than a registry source.
