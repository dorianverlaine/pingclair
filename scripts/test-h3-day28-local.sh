#!/usr/bin/env bash
#
# 🛰️ Day 28 functional matrix for HTTP/3, driven by a real HTTP/3 client.
#
# docs/guardrails/proxy.md requires this after any change to H3 or the TLS
# dependency tree:
# Alt-Svc, SNI, static and proxied bodies of several sizes, POST with and
# without Content-Length, 413, and upstream keepalive.
#
# The client is curl built on ngtcp2/nghttp3 — deliberately not quiche, so this
# tests interoperability rather than our own protocol implementation agreeing
# with itself.
#
# ⚠️ This runs on the developer machine. It proves H3 behaviour; it does NOT
# satisfy the Linux linking half of the gate. Run the release build on Linux
# separately.

set -Eeuo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly binary="${PINGCLAIR_BINARY:-${repository_root}/target/debug/pingclair}"
readonly run_dir="$(mktemp -d "${TMPDIR:-/tmp}/pingclair-h3-day28.XXXXXX")"
readonly primary_host="h3-primary.local"
readonly secondary_host="h3-secondary.local"
pingclair_pid=""
upstream_pid=""
checks_run=0
checks_failed=0

log() { printf '%s\n' "$*"; }

pass() {
    checks_run=$((checks_run + 1))
    log "  ✅ $*"
}

fail() {
    checks_run=$((checks_run + 1))
    checks_failed=$((checks_failed + 1))
    log "  ❌ $*"
}

check_eq() {
    local label="$1" expected="$2" actual="$3"
    if [[ "${expected}" == "${actual}" ]]; then
        pass "${label} (${actual})"
    else
        fail "${label}: expected '${expected}', got '${actual}'"
    fi
}

find_h3_curl() {
    local candidate=""
    if command -v brew >/dev/null 2>&1; then
        candidate="$(brew --prefix curl 2>/dev/null)/bin/curl"
    fi
    if [[ ! -x "${candidate}" ]]; then
        candidate="$(command -v curl || true)"
    fi
    if [[ -z "${candidate}" ]] || ! "${candidate}" --version | grep -q 'HTTP3'; then
        log "❌ A curl build with HTTP/3 support is required."
        exit 2
    fi
    printf '%s\n' "${candidate}"
}

reserve_tcp_udp_port() {
    python3 - <<'PY'
import socket
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.bind(("127.0.0.1", 0))
port = tcp.getsockname()[1]
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(("127.0.0.1", port))
print(port)
tcp.close()
udp.close()
PY
}

reserve_tcp_port() {
    python3 - <<'PY'
import socket
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(("127.0.0.1", 0))
print(listener.getsockname()[1])
listener.close()
PY
}

cleanup() {
    [[ -n "${pingclair_pid}" ]] && kill -TERM "${pingclair_pid}" 2>/dev/null || true
    [[ -n "${upstream_pid}" ]] && kill -TERM "${upstream_pid}" 2>/dev/null || true
    wait 2>/dev/null || true
    if [[ "${PINGCLAIR_H3_KEEP_TEMP:-0}" == "1" ]]; then
        log "📁 Preserved artifacts at ${run_dir}."
    else
        rm -rf -- "${run_dir}"
    fi
}
trap cleanup EXIT INT TERM

readonly curl_bin="$(find_h3_curl)"
readonly h3_port="$(reserve_tcp_udp_port)"
readonly upstream_port="$(reserve_tcp_port)"

log "🔧 curl: $("${curl_bin}" --version | head -1)"
log "🔧 H3 port ${h3_port}, upstream ${upstream_port}"

# 🔨 Always, not only when the binary is missing.
#
# 🤡 This used to be `if [[ ! -x "${binary}" ]]`, and the failure mode is the
# worst kind: the script runs, reports red, and the red is about a binary from
# before your change. Diagnosing that costs more than the rebuild ever will —
# and when it reports *green* against a stale binary, nothing tells you at all.
# `cargo build` is a no-op when nothing changed.
if [[ -z "${PINGCLAIR_BINARY:-}" ]]; then
    log "🔨 Building Pingclair."
    cargo build --manifest-path "${repository_root}/Cargo.toml" -p pingclair
elif [[ ! -x "${binary}" ]]; then
    log "❌ PINGCLAIR_BINARY=${binary} is not executable."
    exit 2
fi

mkdir -p "${run_dir}/tls" "${run_dir}/static"

# 📦 Static payloads spanning one packet, many packets, and a large body.
python3 - "${run_dir}/static" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1])
(root / "small.txt").write_bytes(b"S" * 64)
(root / "medium.bin").write_bytes(bytes((i % 251) for i in range(256 * 1024)))
(root / "large.bin").write_bytes(bytes((i % 251) for i in range(8 * 1024 * 1024)))
PY

# 🔁 Upstream that echoes what it received, so proxied bodies are checkable and
# keepalive reuse is observable by connection id.
cat >"${run_dir}/upstream.py" <<'PY'
import hashlib, itertools, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port = int(sys.argv[1])
counter = itertools.count(1)
connections = {}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _conn_id(self):
        key = id(self.connection)
        if key not in connections:
            connections[key] = next(counter)
        return connections[key]

    def do_GET(self):
        # 🛡️ Reports exactly which request fields survived the proxy, so the
        # sanitizer can be asserted against a real HTTP/3 request rather than
        # against a unit test's idea of one.
        if self.path.endswith("/echo-headers"):
            seen = sorted(name.lower() for name in self.headers.keys())
            body = ("\n".join(f"{n}={self.headers[n]}" for n in seen)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        # 🔐 Echoes the path back, so a `rewrite` template's resolved
        # placeholders are observable from outside the proxy.
        if self.path.startswith("/echo/"):
            body = self.path.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if "/big/" in self.path:
            size = int(self.path.rsplit("/", 1)[-1])
            body = bytes((i % 251) for i in range(size))
        else:
            body = b"proxied"
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Upstream-Conn", str(self._conn_id()))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            body = b""
            while True:
                line = self.rfile.readline().strip()
                size = int(line, 16)
                if size == 0:
                    self.rfile.readline()
                    break
                body += self.rfile.read(size)
                self.rfile.readline()
        else:
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        digest = hashlib.sha256(body).hexdigest()
        payload = f"{len(body)} {digest}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Upstream-Conn", str(self._conn_id()))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        pass


ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
PY

# 🔤 A template whose name only a percent-encoded request can spell. The
# `templates` handler turns a request path into a filename of its own, on a code
# path separate from the file server's, so H3 needs its own evidence that the
# decode happens there too — and that an escaped traversal still does not.
mkdir -p "${run_dir}/tpl"
printf 'Rendered: {{now | date "2006"}}\n' >"${run_dir}/tpl/範本.html"

python3 "${run_dir}/upstream.py" "${upstream_port}" >"${run_dir}/upstream.log" 2>&1 &
upstream_pid=$!

cat >"${run_dir}/config.json" <<JSON
{
  "global": { "auto_https": "off", "http3": true },
  "servers": [
    {
      "name": "${primary_host}",
      "listen": ["127.0.0.1:${h3_port}"],
      "tls": { "internal": true, "http3": true },
      "limits": { "max_request_body_bytes": 1048576 },
      "routes": [
        { "path": "/ready", "handler": { "type": "respond", "status": 200, "body": "ready" } },
        { "path": "/who", "handler": { "type": "respond", "status": 200, "body": "primary" } },
        { "path": "/static/*", "handler": { "type": "file_server", "root": "${run_dir}" } },
        {
          "path": "/tpl/*",
          "handler": {
            "type": "pipeline",
            "handlers": [
              { "type": "templates", "root": "${run_dir}" },
              { "type": "file_server", "root": "${run_dir}" }
            ]
          }
        },
        {
          "path": "/proxy/*",
          "handler": {
            "type": "reverse_proxy",
            "upstreams": ["http://127.0.0.1:${upstream_port}"],
            "load_balance": { "strategy": "round_robin" },
            "headers_up": {},
            "headers_down": {}
          }
        },
        {
          "path": "/scheme/*",
          "handler": {
            "type": "reverse_proxy",
            "upstreams": ["http://127.0.0.1:${upstream_port}"],
            "load_balance": { "strategy": "round_robin" },
            "rewrite_uri": "/echo/{http.request.scheme}",
            "headers_up": {},
            "headers_down": {}
          }
        }
      ]
    },
    {
      "name": "${secondary_host}",
      "listen": ["127.0.0.1:${h3_port}"],
      "tls": { "internal": true, "http3": true },
      "routes": [
        { "path": "/ready", "handler": { "type": "respond", "status": 200, "body": "ready" } },
        { "path": "/who", "handler": { "type": "respond", "status": 200, "body": "secondary" } }
      ]
    }
  ]
}
JSON

PINGCLAIR_TLS_STORE="${run_dir}/tls" "${binary}" run "${run_dir}/config.json" \
    >"${run_dir}/pingclair.log" 2>&1 &
pingclair_pid=$!

h3() {
    local host="$1"; shift
    "${curl_bin}" --noproxy '*' --http3-only -ksS \
        --resolve "${host}:${h3_port}:127.0.0.1" "$@"
}

ready=false
for _ in {1..150}; do
    if ! kill -0 "${pingclair_pid}" 2>/dev/null; then
        log "❌ Pingclair exited before H3 readiness."
        tail -n 60 "${run_dir}/pingclair.log" || true
        exit 1
    fi
    if [[ "$(h3 "${primary_host}" -fsS "https://${primary_host}:${h3_port}/ready" 2>/dev/null || true)" == "ready" ]]; then
        ready=true
        break
    fi
    sleep 0.1
done
[[ "${ready}" == true ]] || { log "❌ Not ready over H3."; tail -n 60 "${run_dir}/pingclair.log"; exit 1; }

log ""
log "🔎 SNI — one UDP port, two server names"
check_eq "primary SNI routes to its own vhost" "primary" \
    "$(h3 "${primary_host}" "https://${primary_host}:${h3_port}/who")"
check_eq "secondary SNI routes to its own vhost" "secondary" \
    "$(h3 "${secondary_host}" "https://${secondary_host}:${h3_port}/who")"

log ""
log "🔎 Host spelling — one name, however the client writes it"
# 🔤 `:authority` is the client's to spell. A miss on the virtual-host map falls
# through to the catch-all, so getting this wrong serves the wrong site rather
# than failing loudly. The two vhosts answer differently, which is what makes it
# visible from out here.
for spelling in "${primary_host}" "$(tr '[:lower:]' '[:upper:]' <<<"${primary_host}")" "${primary_host}."; do
    got="$(h3 "${primary_host}" -sS -H "Host: ${spelling}:${h3_port}" \
        "https://${primary_host}:${h3_port}/who" 2>/dev/null || true)"
    check_eq "authority '${spelling}' reaches its own vhost" "primary" "${got}"
done

log ""
log "🔎 Negotiated protocol"
check_eq "curl negotiated HTTP/3" "3" \
    "$(h3 "${primary_host}" -o /dev/null -w '%{http_version}' "https://${primary_host}:${h3_port}/ready")"

log ""
log "🔎 Alt-Svc advertised on the TLS (H1/H2) listener"
alt_svc="$("${curl_bin}" --noproxy '*' -ksSI --resolve "${primary_host}:${h3_port}:127.0.0.1" \
    "https://${primary_host}:${h3_port}/ready" 2>/dev/null | tr -d '\r' | grep -i '^alt-svc:' || true)"
if [[ "${alt_svc}" == *h3=* ]]; then
    pass "Alt-Svc offers h3 (${alt_svc})"
else
    fail "Alt-Svc missing or without h3: '${alt_svc}'"
fi

log ""
log "🔎 Static bodies across packet boundaries"
for name in small.txt medium.bin large.bin; do
    expected="$(shasum -a 256 "${run_dir}/static/${name}" | cut -d' ' -f1)"
    actual="$(h3 "${primary_host}" -fsS "https://${primary_host}:${h3_port}/static/${name}" | shasum -a 256 | cut -d' ' -f1)"
    check_eq "static ${name} byte-for-byte" "${expected}" "${actual}"
done

log ""
log "🔎 Proxied bodies"
check_eq "proxied small response" "proxied" \
    "$(h3 "${primary_host}" -fsS "https://${primary_host}:${h3_port}/proxy/hello")"
proxied_len="$(h3 "${primary_host}" -fsS "https://${primary_host}:${h3_port}/proxy/big/4194304" | wc -c | tr -d ' ')"
check_eq "proxied 4 MiB length" "4194304" "${proxied_len}"

log ""
log "🔎 POST with and without Content-Length"
payload="${run_dir}/post.bin"
python3 -c "
import sys
open(sys.argv[1],'wb').write(bytes((i%251) for i in range(300*1024)))
" "${payload}"
expected_post="$(python3 -c "
import hashlib,sys
d=open(sys.argv[1],'rb').read()
print(f'{len(d)} {hashlib.sha256(d).hexdigest()}')
" "${payload}")"

check_eq "POST with Content-Length round-trips" "${expected_post}" \
    "$(h3 "${primary_host}" -fsS --data-binary "@${payload}" \
        -H 'Content-Type: application/octet-stream' \
        "https://${primary_host}:${h3_port}/proxy/echo")"

check_eq "POST without Content-Length (chunked) round-trips" "${expected_post}" \
    "$(cat "${payload}" | h3 "${primary_host}" -fsS --data-binary @- \
        -H 'Content-Type: application/octet-stream' -H 'Transfer-Encoding: chunked' \
        "https://${primary_host}:${h3_port}/proxy/echo")"

log ""
log "🔎 413 over the configured body limit"
big_payload="${run_dir}/too-big.bin"
python3 -c "
import sys
open(sys.argv[1],'wb').write(b'x' * (5*1024*1024))
" "${big_payload}"
check_eq "5 MiB body is rejected" "413" \
    "$(h3 "${primary_host}" -o /dev/null -w '%{http_code}' --data-binary "@${big_payload}" \
        -H 'Content-Type: application/octet-stream' \
        "https://${primary_host}:${h3_port}/proxy/echo")"

log ""
log "🔎 Outbound header sanitizing — what the origin is allowed to be told"
sanitized="$(h3 "${primary_host}" -fsS \
    -H 'Proxy-Authorization: Basic c3B5Om11Y2g=' \
    -H 'Proxy-Authenticate: Basic realm="x"' \
    -H 'Proxy-Connection: keep-alive' \
    -H 'Forwarded: for=203.0.113.9;host=evil.test' \
    -H 'Proxy: http://attacker.test:3128' \
    -H 'Authorization: Bearer real-token' \
    -H 'Cookie: session=abc' \
    "https://${primary_host}:${h3_port}/proxy/echo-headers")"
# 🧭 `Connection` and the fields it names are deliberately not probed here:
# HTTP/3 forbids the field, so curl never sends one and there is nothing for it
# to name. That half of the filter is exercised on the HTTP/1.1 path, where a
# client can actually send it — see the integration test of the same name.
for blocked in proxy-authorization proxy-authenticate proxy-connection proxy; do
    if grep -qi "^${blocked}=" <<<"${sanitized}"; then
        fail "${blocked} reached the origin"
    else
        pass "${blocked} stopped at the proxy"
    fi
done
for kept in authorization cookie; do
    if grep -qi "^${kept}=" <<<"${sanitized}"; then
        pass "${kept} still reaches the origin"
    else
        fail "${kept} was dropped; the filter is refusing more than it should"
    fi
done
# 🌐 The client's Forwarded must be gone *and* replaced by ours, so a present
# header is not enough — the value has to be the one this server wrote.
forwarded_line="$(grep -i '^forwarded=' <<<"${sanitized}" || true)"
if [[ -z "${forwarded_line}" ]]; then
    fail "Forwarded is absent; HTTP/3 dropped the client's copy but rebuilt nothing"
elif [[ "${forwarded_line}" == *evil.test* ]]; then
    fail "the client's own Forwarded reached the origin: ${forwarded_line}"
elif [[ "${forwarded_line}" == *for=127.0.0.1* ]]; then
    pass "Forwarded was rebuilt from the verified peer (${forwarded_line})"
else
    fail "Forwarded carries neither the client's value nor ours: ${forwarded_line}"
fi

log ""
log "🔎 Upstream keepalive — several H3 requests must share one upstream connection"
conn_ids="$(for _ in 1 2 3 4; do
    h3 "${primary_host}" -fsS -o /dev/null -D - "https://${primary_host}:${h3_port}/proxy/hello" \
        | tr -d '\r' | grep -i '^x-upstream-conn:' | awk '{print $2}'
done | sort -u | wc -l | tr -d ' ')"
check_eq "four requests reused one upstream connection" "1" "${conn_ids}"

log ""
log "🔎 Several requests over one H3 connection"
multi="$(h3 "${primary_host}" -fsS \
    "https://${primary_host}:${h3_port}/who" \
    "https://${primary_host}:${h3_port}/who" \
    "https://${primary_host}:${h3_port}/who" | tr -d '\n')"
check_eq "three requests on one connection" "primaryprimaryprimary" "${multi}"

log ""
log "🔎 Placeholder scheme on the rewrite path — H3 is QUIC, so never cleartext"
# 🔐 The `rewrite` template is the one H3 placeholder site that passed "http"
# while its eight neighbours passed "https". The upstream echoes the path it was
# asked for, so the resolved scheme is visible from outside.
scheme_path="$(h3 "${primary_host}" -sS \
    "https://${primary_host}:${h3_port}/scheme/anything" | tr -d '\n')"
check_eq "rewrite placeholder resolved the real scheme" "/echo/https" "${scheme_path}"

log ""
log "🔎 Percent-decoding on the templates path — H3's own code, not the file server's"
# 🔤 Only an encoded request can name this template. Rendering it proves the
# decode happens on the H3 templates path; `{{` in the body would mean the
# handler missed the file and `file_server` served the source instead, which
# leaks the template rather than failing.
tpl_body="$(h3 "${primary_host}" -sS \
    "https://${primary_host}:${h3_port}/tpl/%E7%AF%84%E6%9C%AC.html")"
if [[ "${tpl_body}" == *"Rendered:"* && "${tpl_body}" != *"{{"* ]]; then
    pass "escaped template name rendered over H3"
else
    fail "escaped template name over H3: got '${tpl_body}'"
fi
# 🚫 …and an escaped traversal is refused rather than joined.
tpl_escape="$(h3 "${primary_host}" -o /dev/null -w '%{http_code}' -sS \
    "https://${primary_host}:${h3_port}/tpl/%2e%2e%2f%2e%2e%2fetc%2fpasswd")"
check_eq "escaped traversal refused on the H3 templates path" "404" "${tpl_escape}"

log ""
log "═══════════════════════════════════════════"
if [[ "${checks_failed}" -eq 0 ]]; then
    log "✅ Day 28 H3 functional matrix: ${checks_run}/${checks_run} passed."
else
    log "❌ Day 28 H3 functional matrix: ${checks_failed} of ${checks_run} FAILED."
    log "   Server log: ${run_dir}/pingclair.log"
    PINGCLAIR_H3_KEEP_TEMP=1
    exit 1
fi
