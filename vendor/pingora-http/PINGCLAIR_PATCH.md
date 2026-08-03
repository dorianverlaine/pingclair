# ⚡ Pingclair pingora-http performance fork

This directory is a local fork of
[`pingora-http`](https://crates.io/crates/pingora-http) `0.8.1`
(Apache-2.0, vendored from the crates.io registry snapshot at checksum
`d553d310a15ec88107b9388a02885f798efc57764d8e9bdaaf32a76722927a10`),
kept in-tree so Pingclair can use no-case response headers on HTTP/1
without giving up conventional wire casing.

## Why it exists

Pingora's `ResponseHeader::build()` preserves header-name case through a
per-request `CaseMap` (several allocations per header). `build_no_case()`
skips that map, but its HTTP/1 wire serializer then title-cases only a
small built-in table (`titled_header_name_str`) and writes everything else
lowercase.

This fork extends that table with the headers Pingclair emits on locally
generated HTTP/1 responses (ETag, Content-Range, Location, Vary,
X-Request-Id, the X-Forwarded-* family, security-policy headers, etc.), so
no-case responses still hit the wire with conventional casing
(RFC 9110 §5.1 makes field names case-insensitive either way).

It also adds `RequestHeader::drop_case()` / `ResponseHeader::drop_case()`:
the case-preserving map is only needed while the original wire casing is
still wanted. Pingclair releases it on the proxy path once hop-by-hop
processing is done, so upstream requests and downstream responses skip the
per-header `CaseMap` allocations entirely (casing stays conventional via
the same titled map).

## Upgrading

```bash
rm -rf vendor/pingora-http
cp -R ~/.cargo/registry/src/index.crates.io-*/pingora-http-<version> vendor/pingora-http
rm -f vendor/pingora-http/.cargo-ok vendor/pingora-http/.cargo_vcs_info.json
# Re-apply the titled_header_name_str and drop_case hunks, then run the
# workspace gates.
```

Verify with `cargo tree -i pingora-http` (must show the `vendor/` path).
