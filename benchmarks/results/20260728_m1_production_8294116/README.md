# M1 verification — the real site, RC `8294116`

`aqeonet-aws-tw-xray` (Amazon Linux 2023, aarch64).
`Cloudflare Tunnel → :6688 → app:8080`. Image `pingclair:rc-8294116`, linux/arm64,
built from `8294116` with no source changes.

Not a production-*like* rehearsal: this is the origin that serves
`portefeuille.aqeo.dev`. The production Caddyfile was translated directive for
directive into `Pingclairfile` (kept here), so a difference in behaviour is a
difference in the server rather than in the configuration.

| file | what it is |
|---|---|
| `m1_drill.txt` | 27 differential checks against the live Caddy. Zero production impact — Pingclair ran as a fourth container on the same network while Caddy kept serving the tunnel. |
| `reload_drill.txt` | SIGHUP applies a good config; a broken one is refused and the last known good keeps serving. |
| `dns_drill.txt` | Upstream re-resolution on Linux arm64 with the release image. |
| `cutover_and_live_traffic.txt` | The tunnel pointed at Pingclair, plus real browser traffic from a logged-in session. |
| `Pingclairfile` | The exact config under test. |

Most checks are differential rather than absolute. "It answered 200" says
nothing about whether one proxy can replace another; "the CSP header and the
response body are byte-identical to what Caddy returns" does.

## Failed runs, kept

Both are **test-harness** bugs, not product bugs. Neither is overwritten,
because the second one is the more instructive failure of the day.

- `dns_drill_FAILED_scriptbug.txt` — `grep -q` at the end of a pipeline under
  `set -o pipefail`. Matching early SIGPIPEs the upstream `docker logs`, and
  the resulting 141 becomes the pipeline's status, so **a match reads as a
  failure** — and only once the log is long enough to lose the race.
- `reload_drill_FAILED_staleinode.txt` — `sed -i` on a bind-mounted config.
  A bind mount is bound to an inode, not a path: `sed -i` renames a new file
  over the old one, the host sees the change and **the container goes on
  reading the original**. The reload reported success, having re-read exactly
  the same bytes. Two checks in that run passed for that reason and were
  worthless. The drill now asserts host and container inodes match before it
  trusts anything downstream.

## Scope, stated precisely

- The tunnel hop measured **HTTP/1.1**. cloudflared does not use h2 to an
  origin without `http2Origin: true`. HTTP/2 was verified directly against the
  origin (check 9 in `m1_drill.txt`), not through the tunnel.
- The public URL cannot be checked with curl: Cloudflare's managed challenge
  answers 403 at the **edge**, so the request never reaches the origin. Verified
  instead with a real browser plus the origin's own access log.
- The negative half of client-IP spoofing (an untrusted peer must be ignored)
  carries over from the 2026-07-27 fixture; it is not reproducible from inside
  the trusted subnet and was not re-run here.
- `aqeo-pingclair` is not a compose service. It is created and managed by
  `deployment/switch-proxy.sh` with `--restart unless-stopped`. Folding it into
  `docker-compose.yml` is the tidier end state.
