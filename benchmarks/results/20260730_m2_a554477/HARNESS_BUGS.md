# First M2 matrix run — three harness bugs, no product failures

Commit `a5544770f3b889981c1f8bee09874c9b26ce6b9c`, image `pingclair:rc-a554477`.
20 of 23 checks passed. All three failures were defects in this script, not in
the proxy. Kept per the rule that failed evidence is never overwritten.

## 1. "slow header client was not released (8018ms)"

```bash
(printf 'GET / HTTP/1.1\r\nHost: x\r\n'; sleep 8) | nc 127.0.0.1 "$PROXY_PORT"
```

The elapsed time measured the pipeline, and the pipeline contains `sleep 8`.
Even when the server closed the connection promptly the subshell kept sleeping,
so the measurement could never come in under the threshold — it was measuring
the test's own sleep. Replaced with a read on the socket that returns when the
server closes it.

## 2. "a listener requiring PROXY protocol served a header-less request (000000)"

The reading is inverted: `000000` means the connection *was* refused. The
helper ran

```bash
curl -s -w '%{http_code}' ... || echo "000"
```

so a failed curl printed `000` from `-w` and then `000` again from the fallback.
The assertion compared against `000` and missed. The proxy behaved correctly.
The helper now captures curl's exit status separately instead of concatenating.

## 3. "origin saw no forwarded identity"

`handle` does not strip its prefix (that is `handle_path`), so the origin
received `/identity/echo` while the fixture only answered on exactly `/echo`.
The request fell through to the normal mode handler and returned the origin
name, which contains no headers. The fixture now matches any path ending in
`/echo`.
