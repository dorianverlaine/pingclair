# 🛰️ Go HTTP/3 behavioral tests

This independent test module runs the real Pingclair binary through quic-go
v0.63.0. It adds controlled stream and lifecycle tests alongside the maintained
curl/ngtcp2/nghttp3 scripts. `just h3` keeps its existing behavior.

Install Go, then run `just h3-go` to build the release binary and test it.
`just h3-go-test /absolute/path/to/pingclair` tests an existing binary;
`just h3-go-check` checks formatting and runs vet. The recipes pin Go 1.27.1,
use read-only dependencies, and enable the race detector for live tests.
The post-merge HTTP/3 workflow runs both client matrices.

## 🔬 Contracts

| Test | Evidence |
| --- | --- |
| SSE | Four gated events arrive incrementally; an unrelated request succeeds on the same QUIC connection while the stream is open. |
| Cancellation | Context cancellation and response-body close release both writing and idle SSE origins. Cancellation before response headers also releases the origin; sibling requests still succeed. |
| Upstream reuse | Eight consumed responses reuse origin sockets, confirmed by repeated peer addresses and matching TCP accept counts below eight. |
| Local exhaustion | A barrier starts 64 concurrent streams with a descriptor ceiling applied only to Pingclair. Logs must prove a local resource failure; the backend must remain eligible and answer an immediate follow-up. |
| Invalid fields | Raw QPACK sends forbidden connection fields without net/http normalization. Each receives remote `H3_MESSAGE_ERROR`; the connection remains usable. |
| Graceful shutdown | SIGTERM produces GOAWAY refusal of new streams while an admitted request completes, followed by `H3_NO_ERROR` and successful process exit. |

Each fixture has fresh ports, a random readiness token, a short-lived trusted
certificate, and an isolated TLS store. A client owns one explicit QUIC
connection and cannot silently reconnect or fall back to H2. Direct loopback
dialing bypasses system proxies. Bodies and diagnostic reads are bounded;
full log assertions scan line by line so bursts cannot hide early failures.
Cleanup signals only the fixture's child process and waits for it to exit.

Eight-second operation deadlines detect hangs; they are not performance
thresholds. These tests do not replace TLS authentication, default-SNI,
large-upload, or curl interoperability coverage. The pinned quic-go API
reports GOAWAY as `connection in graceful shutdown`; it does not expose the
raw GOAWAY stream ID. quic-go may itself initiate the final clean close.
Downstream FIN can precede return of an upstream session to its pool, so the
reuse test proves actual socket reuse without demanding one socket for every
back-to-back request.

## 🛑 Idle-origin cancellation regression

The default matrix includes the regression for
[issue #286](https://github.com/dorianverlaine/pingclair/issues/286). After four
gated SSE events, the origin stops writing. Both cancellation APIs must release
it while keeping the QUIC connection usable. A second test cancels before the
origin sends any response headers. Run these checks separately with:

```bash
cd scripts/h3-go
PINGCLAIR_BINARY=/absolute/path/to/pingclair GOTOOLCHAIN=go1.27.1 \
  go test -mod=readonly -race \
  -run 'TestIdleSSECancellation|TestCancellationBeforeResponseHeaders' \
  -count=1 -timeout=45s -v
```
