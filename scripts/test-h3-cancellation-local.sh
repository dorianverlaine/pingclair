#!/usr/bin/env bash

set -Eeuo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly binary="${PINGCLAIR_BINARY:-${repository_root}/target/debug/pingclair}"
readonly run_dir="$(mktemp -d "${TMPDIR:-/tmp}/pingclair-h3-local.XXXXXX")"
readonly host_name="h3.local"
readonly first_marker="${run_dir}/first-event"
readonly cancelled_marker="${run_dir}/upstream-cancelled"
readonly client_output="${run_dir}/client.out"
readonly client_error="${run_dir}/client.err"
pingclair_pid=""
upstream_pid=""
client_pid=""

log() {
    printf '%s\n' "$*"
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

stop_owned_process() {
    local pid="${1:-}"
    local expected_fragment="${2:-}"
    [[ -n "${pid}" ]] || return 0
    local command_line=""
    command_line="$(ps -p "${pid}" -o command= 2>/dev/null || true)"
    [[ -n "${command_line}" ]] || return 0
    if [[ "${command_line}" != *"${expected_fragment}"* ]]; then
        log "⚠️ Refusing to stop PID ${pid}; it no longer belongs to this H3 fixture."
        return 0
    fi
    if kill -0 "${pid}" 2>/dev/null; then
        kill -TERM "${pid}" 2>/dev/null || true
    fi
    wait "${pid}" 2>/dev/null || true
}

cleanup() {
    stop_owned_process "${client_pid}" "https://${host_name}:${h3_port:-}/events"
    stop_owned_process "${pingclair_pid}" "${run_dir}/config.json"
    stop_owned_process "${upstream_pid}" "${run_dir}/upstream.py"
    if [[ "${PINGCLAIR_H3_KEEP_TEMP:-0}" == "1" ]]; then
        log "📁 Preserved local H3 artifacts at ${run_dir}."
    else
        rm -rf -- "${run_dir}"
    fi
}
trap cleanup EXIT INT TERM

readonly curl_bin="$(find_h3_curl)"
readonly h3_port="$(reserve_tcp_udp_port)"
readonly upstream_port="$(reserve_tcp_port)"

if [[ ! -x "${binary}" ]]; then
    log "🔨 Building the local Pingclair binary."
    cargo build --manifest-path "${repository_root}/Cargo.toml" -p pingclair
fi

mkdir -p "${run_dir}/tls"

cat >"${run_dir}/upstream.py" <<'PY'
import pathlib
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port = int(sys.argv[1])
first_path = pathlib.Path(sys.argv[2])
cancelled_path = pathlib.Path(sys.argv[3])


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/response-trailers":
            self._write_trailer_response()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            # 🌊 Flushes the first event immediately so buffering is observable.
            self._write_chunk(b"data: first\n\n")
            first_path.write_text("sent\n")
            payload = b"data: " + (b"x" * (64 * 1024)) + b"\n\n"
            while True:
                time.sleep(0.01)
                self._write_chunk(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            # 🛑 Records when Pingclair closes the abandoned upstream exchange.
            cancelled_path.write_text("cancelled\n")

    def _write_trailer_response(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Trailer", "X-Checksum")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            # 🚫 Exercises fail-closed handling before trailer metadata can disappear.
            self._write_chunk(b"ok")
            self.wfile.write(b"0\r\nX-Checksum: abc\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _write_chunk(self, body):
        self.wfile.write(f"{len(body):X}\r\n".encode())
        self.wfile.write(body)
        self.wfile.write(b"\r\n")
        self.wfile.flush()

    def log_message(self, *_):
        return


server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
server.daemon_threads = True
server.serve_forever()
PY

python3 "${run_dir}/upstream.py" \
    "${upstream_port}" \
    "${first_marker}" \
    "${cancelled_marker}" \
    >"${run_dir}/upstream.log" 2>&1 &
upstream_pid=$!

cat >"${run_dir}/config.json" <<JSON
{
  "global": {
    "auto_https": "off",
    "http3": true
  },
  "servers": [{
    "name": "${host_name}",
    "listen": ["127.0.0.1:${h3_port}"],
    "tls": {
      "internal": true,
      "http3": true
    },
    "routes": [
      {
        "path": "/ready",
        "handler": { "type": "respond", "status": 200, "body": "ready" }
      },
      {
        "path": "/events",
        "handler": {
          "type": "reverse_proxy",
          "upstreams": ["http://127.0.0.1:${upstream_port}"],
          "load_balance": { "strategy": "round_robin" },
          "headers_up": {},
          "headers_down": {},
          "flush_interval": -1
        }
      },
      {
        "path": "/response-trailers",
        "handler": {
          "type": "reverse_proxy",
          "upstreams": ["http://127.0.0.1:${upstream_port}"],
          "load_balance": { "strategy": "round_robin" },
          "headers_up": {},
          "headers_down": {}
        }
      }
    ]
  }]
}
JSON

PINGCLAIR_TLS_STORE="${run_dir}/tls" \
    "${binary}" run "${run_dir}/config.json" \
    >"${run_dir}/pingclair.log" 2>&1 &
pingclair_pid=$!

ready=false
for _ in {1..100}; do
    if ! kill -0 "${pingclair_pid}" 2>/dev/null; then
        log "❌ Pingclair exited before local H3 readiness."
        tail -n 100 "${run_dir}/pingclair.log" || true
        exit 1
    fi
    if [[ "$("${curl_bin}" --noproxy '*' --http3-only -kfsS \
        --resolve "${host_name}:${h3_port}:127.0.0.1" \
        "https://${host_name}:${h3_port}/ready" 2>/dev/null || true)" == "ready" ]]; then
        ready=true
        break
    fi
    sleep 0.05
done
if [[ "${ready}" != "true" ]]; then
    log "❌ Pingclair did not become ready over local HTTP/3."
    exit 1
fi
if [[ ! -f "${run_dir}/tls/internal/authority.json" ]] \
    || [[ ! -f "${run_dir}/tls/internal/root.crt" ]] \
    || [[ ! -f "${run_dir}/tls/internal/certificates/h3_local.json" ]]; then
    log "❌ Internal CA material was not persisted before H3 readiness."
    exit 1
fi

request_trailer_status="$("${curl_bin}" --noproxy '*' --http3-only -ksS \
    --resolve "${host_name}:${h3_port}:127.0.0.1" \
    -H 'Trailer: X-Checksum' \
    -o "${run_dir}/request-trailer.out" \
    -w '%{http_code}' \
    "https://${host_name}:${h3_port}/ready")"
if [[ "${request_trailer_status}" != "501" ]] \
    || ! grep -Fq 'Request Trailers Not Supported' "${run_dir}/request-trailer.out"; then
    log "❌ Declared H3 request trailers did not fail clearly with 501."
    exit 1
fi

response_trailer_status="$("${curl_bin}" --noproxy '*' --http3-only -ksS \
    --resolve "${host_name}:${h3_port}:127.0.0.1" \
    -o "${run_dir}/response-trailer.out" \
    -w '%{http_code}' \
    "https://${host_name}:${h3_port}/response-trailers")"
if [[ "${response_trailer_status}" != "502" ]] \
    || ! grep -Fq 'Upstream Response Trailers Not Supported' \
        "${run_dir}/response-trailer.out"; then
    log "❌ H3 upstream response trailers did not fail clearly with 502."
    exit 1
fi

set +e
"${curl_bin}" --noproxy '*' --http3-only -kfsS --no-buffer \
    --max-time 1.5 \
    --resolve "${host_name}:${h3_port}:127.0.0.1" \
    "https://${host_name}:${h3_port}/events" \
    >"${client_output}" 2>"${client_error}" &
client_pid=$!
set -e

first_visible=false
for _ in {1..50}; do
    if [[ -f "${first_marker}" ]] && grep -Fq 'data: first' "${client_output}"; then
        first_visible=true
        break
    fi
    sleep 0.02
done
if [[ "${first_visible}" != "true" ]]; then
    log "❌ The first H3 SSE event was not delivered incrementally."
    exit 1
fi

set +e
wait "${client_pid}"
client_status=$?
set -e
client_pid=""
if [[ "${client_status}" -ne 28 ]]; then
    log "❌ The H3 client ended with status ${client_status}; expected timeout status 28."
    cat "${client_error}"
    exit 1
fi

upstream_cancelled=false
for _ in {1..150}; do
    if [[ -f "${cancelled_marker}" ]]; then
        upstream_cancelled=true
        break
    fi
    sleep 0.02
done
if [[ "${upstream_cancelled}" != "true" ]]; then
    log "❌ Pingclair kept the H3 upstream exchange alive after client cancellation."
    exit 1
fi

if [[ "$("${curl_bin}" --noproxy '*' --http3-only -kfsS \
    --resolve "${host_name}:${h3_port}:127.0.0.1" \
    "https://${host_name}:${h3_port}/ready")" != "ready" ]]; then
    log "❌ Pingclair stopped serving HTTP/3 after stream cancellation."
    exit 1
fi

log "✅ Local HTTP/3 SSE, cancellation, and trailer rejection passed."
