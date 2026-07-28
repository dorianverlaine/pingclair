# FAILED run — the pre-fix binary, kept deliberately

`scripts/test-matcher-roundtrip.sh` run against `333d99f` (the untagged
`Matcher` representation), to show the test fails without its fix.

Two distinct defects, both reachable through the Admin API:

## 1. The dump → post loop inverted a routing decision

```
❌ GET /config lost the negation
❌ after hot reload: /public matches — GET /public gave 404, wanted 200
❌ after hot reload: /admin/* is still excluded — GET /admin/secrets gave 200, wanted 404
```

The route was configured `not path /admin/*`. Untagged, `Not(inner)`
serialized as bare `inner`, so posting back the config Pingclair had *itself
just emitted* turned the route into `path /admin/*` — it then matched exactly
the requests it existed to exclude, and stopped matching everything else.

## 2. An unrecognised matcher aborted the process

`server_stack_overflow.txt`:

```
thread 'tokio-rt-worker' has overflowed its stack
fatal runtime error: stack overflow, aborting
```

Triggered by `POST /config` with `{"matcher": {"nonsense": ["/x"]}}`.

`Not(Box<Matcher>)` was a *newtype* variant of an untagged enum, so trying it
meant deserializing the whole payload as a `Matcher` again with **no input
consumed** — unbounded recursion for any value that matched no other variant.
serde's untagged replay does not go back through serde_json's parser, so
serde_json's own recursion limit never saw it, and the release profile's
`panic = "abort"` turned it into an immediate process abort.

The passing run is in `../20260728_matcher_roundtrip_pass/`.
