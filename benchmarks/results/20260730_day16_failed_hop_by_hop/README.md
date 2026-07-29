# Day 16 — hop-by-hop headers reached the origin, including a credential

Commit `cf7fdd6`. Found by inspection while surveying protocol handling, then
proven from the origin's side rather than argued from our code.

## What the origin received

The client sent a normal `GET /` with connection-scoped fields attached. The
origin — one hop behind this proxy — saw all of them:

```
GET / HTTP/1.1
proxy-authorization: Basic c2VjcmV0OmNyZWRlbnRpYWw=
proxy-connection: keep-alive
keep-alive: timeout=5
te: trailers
x-sacrificial: should-be-dropped
connection: X-Sacrificial
...
via: 1.1 Pingclair
```

Three separate problems in one request:

- **`Proxy-Authorization` was forwarded.** RFC 9110 §11.7.1 has it consumed by
  the first inbound proxy. That is a credential addressed to *us*, handed to the
  origin. Our own `redaction.rs` already lists it as sensitive, so the code knew
  it was a secret and forwarded it anyway.
- **`Connection` and the field it named both survived.** §7.6.1 requires
  removing the field, every field it names, and the connection-specific ones.
  `x-sacrificial` should have been dropped; instead both it and the instruction
  went upstream.
- **`proxy-connection`, `keep-alive`, `te`** likewise.

`via: 1.1 Pingclair` being present is the shape of the bug: the proxy *added*
headers correctly and never *removed* any.

## Why it was there

Pingora strips these only on the HTTP/2 upstream path (`proxy_h2.rs:94-99`),
because the `h2` crate rejects them. `proxy_h1.rs` contains no `remove_header`
at all — only our `upstream_request_filter` hook. Ours removed nothing. The H3
path in `quic.rs` did strip them, so the gap was H1/H2 specifically.

## Fix

`strip_hop_by_hop_headers()` runs first in `upstream_request_filter`, before any
header of ours is added. Order is load-bearing in both directions: a client
naming our fields in `Connection` cannot strip headers we are about to set, and
the fields it names are gone before the origin sees them.

`Transfer-Encoding` is deliberately left alone — HTTP/1 framing belongs to
Pingora, which re-frames the body, and removing the field underneath it would
describe a body that is not what gets sent.

Genuine upgrades are exempt. Pingora detects a WebSocket tunnel by seeing
`Connection: upgrade` with `Upgrade`, so stripping those would harden nothing
and break WebSocket. `test_websocket_upgrade_tunnels_bytes_in_both_directions`
still passes.

## After

```
GET / HTTP/1.1
host: 127.0.0.1:57283
accept: */*
X-Forwarded-Proto: http
X-Forwarded-Host: 127.0.0.1:57283
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
Forwarded: for=127.0.0.1
X-Request-Id: 657c7197fa9a9-1
via: 1.1 Pingclair
```

## Noted, not changed

A request carrying `Trailer:` is answered 501, because Pingora discards HTTP/1
trailers and silently dropping them would be worse. `Trailer` is itself
connection-scoped, so the stricter reading would strip it rather than refuse the
request — but refusing is the safer of the two and it is already tested, so it
stays until the H3 work revisits trailers end to end.
