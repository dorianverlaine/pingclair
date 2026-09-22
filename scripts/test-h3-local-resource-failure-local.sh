#!/usr/bin/env bash
#
# 🧯 A genuine descriptor exhaustion on HTTP/3 must not blame the backend.
#
# `pingclair_proxy::upstream_failure` exists because the error type naming the
# real problem does not survive the trip: Pingora collapses `SocketError`
# (`EMFILE`/`ENFILE`) and `BindError` (ephemeral ports) into `InternalError`
# before returning, so a proxy that blames the backend for those takes a healthy
# upstream out of rotation because *this* process ran out of something.
#
# The H1/H2 half of that is covered by
# `test_local_descriptor_exhaustion_does_not_mark_the_backend_down` in
# `pingclair/tests/integration.rs`. The H3 half had no runtime test at all —
# only code reading and a shared classifier — because the H3 suite runs the
# server in-process, where lowering `RLIMIT_NOFILE` would poison every other
# test in the binary. This script runs the real binary instead, with the limit
# lowered for that process alone, and drives it with a real HTTP/3 client.
#
# What it proves, in the words the guardrails ask for: after a genuine `EMFILE`
# on H3, the backend is still in rotation.

set -Eeuo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly binary="${PINGCLAIR_BINARY:-${repository_root}/target/debug/pingclair}"
readonly run_dir="$(mktemp -d "${TMPDIR:-/tmp}/pingclair-h3-fd.XXXXXX")"
readonly host_name="h3-fd.local"
# 🔻 Small enough that the burst exhausts it, large enough that the server can
# still bind, load its store, and serve a request.
readonly fd_limit="${PINGCLAIR_H3_FD_LIMIT:-64}"
# 🔨 More concurrent requests than descriptors, so enough of them are inside
# `connect()` at the same moment.
readonly burst="${PINGCLAIR_H3_BURST:-64}"
pingclair_pid=""
upstream_pid=""

log() { printf '%s\n' "$*"; }

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
    stop_owned_process "${pingclair_pid}" "${run_dir}/Pingclairfile"
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

if [[ -z "${PINGCLAIR_BINARY:-}" ]]; then
    log "🔨 Building the local Pingclair binary."
    cargo build --manifest-path "${repository_root}/Cargo.toml" -p pingclair
elif [[ ! -x "${binary}" ]]; then
    log "❌ PINGCLAIR_BINARY=${binary} is not executable."
    exit 2
fi

mkdir -p "${run_dir}/tls"
log "🔧 curl: $("${curl_bin}" --version | head -1)"
log "🔧 H3 port ${h3_port}, upstream ${upstream_port}, descriptor limit ${fd_limit}, burst ${burst}"

# 🗄️ The upstream holds every connection open for two seconds before answering,
# so the burst's upstream sockets genuinely overlap — a backend that answered
# instantly would let each connection close before the next one opened and the
# descriptor budget would never bind.
cat >"${run_dir}/upstream.py" <<'PY'
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port = int(sys.argv[1])
connections = 0
lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        global connections
        with lock:
            connections += 1
        time.sleep(2.0)
        body = b"ok"
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        return


# 📚 A deep accept queue, because this backend is deliberately made the
# bottleneck: with the default backlog of five, sixty-four simultaneous
# connects are reset by the kernel instead of queued, and a reset is a *remote*
# failure — the proxy would then be right to blame the backend, and the script
# would be testing the wrong thing.
class DeepBacklogServer(ThreadingHTTPServer):
    request_queue_size = 512


server = DeepBacklogServer(("127.0.0.1", port), Handler)
server.daemon_threads = True
server.serve_forever()
PY

python3 "${run_dir}/upstream.py" "${upstream_port}" >"${run_dir}/upstream.log" 2>&1 &
upstream_pid=$!

cat >"${run_dir}/Pingclairfile" <<EOF
{
	auto_https off
	servers {
		protocols h1 h2 h3
	}
}

https://${host_name}:${h3_port} {
	bind 127.0.0.1
	tls internal
	handle /ready {
		respond "ready" 200
	}
	handle /probe {
		reverse_proxy 127.0.0.1:${upstream_port}
	}
}
EOF

# 🔻 The limit is lowered for the server process alone. Doing it in this shell
# would starve the client that has to generate the load.
(
    ulimit -n "${fd_limit}"
    PINGCLAIR_TLS_STORE="${run_dir}/tls" \
        exec "${binary}" run "${run_dir}/Pingclairfile"
) >"${run_dir}/pingclair.log" 2>&1 &
pingclair_pid=$!

ready=false
for _ in {1..100}; do
    if ! kill -0 "${pingclair_pid}" 2>/dev/null; then
        log "❌ Pingclair exited before local H3 readiness."
        tail -n 100 "${run_dir}/pingclair.log" || true
        exit 1
    fi
    if [[ "$("${curl_bin}" --noproxy '*' --http3-only -ksS --max-time 3 \
        --resolve "${host_name}:${h3_port}:127.0.0.1" \
        "https://${host_name}:${h3_port}/ready" 2>/dev/null || true)" == "ready" ]]; then
        ready=true
        break
    fi
    sleep 0.2
done
if [[ "${ready}" != "true" ]]; then
    log "❌ Pingclair never served HTTP/3 on 127.0.0.1:${h3_port}."
    tail -n 100 "${run_dir}/pingclair.log" || true
    exit 1
fi

log ""
log "🔻 Descriptor exhaustion, with ${burst} concurrent H3 requests to a live backend"
burst_pids=()
for _ in $(seq 1 "${burst}"); do
    "${curl_bin}" --noproxy '*' --http3-only -ksS --max-time 20 \
        --resolve "${host_name}:${h3_port}:127.0.0.1" \
        -o /dev/null "https://${host_name}:${h3_port}/probe" &
    burst_pids+=("$!")
done
# 🧹 The burst is expected to fail requests — that is the point — so its exit
# status carries no information; what the proxy decided does. The waiting names
# the burst explicitly: a bare `wait` would also wait on the upstream and the
# server, which are still running on purpose.
set +e
for pid in "${burst_pids[@]}"; do
    wait "${pid}"
done
set -e

local_failure=false
for _ in {1..200}; do
    if grep -q "Local resource failure on H3 connect" "${run_dir}/pingclair.log"; then
        local_failure=true
        break
    fi
    sleep 0.05
done

failed=0
if [[ "${local_failure}" != "true" ]]; then
    # 🚫 Guards against a vacuous pass: if the burst never exhausted the budget,
    # every assertion below holds for a reason that has nothing to do with the
    # behaviour under test.
    log "❌ The burst never produced a local resource failure, so this run proved nothing."
    log "   Raise PINGCLAIR_H3_BURST or lower PINGCLAIR_H3_FD_LIMIT and run again."
    failed=$((failed + 1))
else
    log "  ✅ a genuine local resource failure reached the H3 path"
fi

if grep -q "Marking H3 upstream" "${run_dir}/pingclair.log"; then
    log "  ❌ a healthy backend was marked down for a local failure"
    grep "Marking H3 upstream" "${run_dir}/pingclair.log" | head -3
    failed=$((failed + 1))
else
    log "  ✅ the backend was never marked down"
fi

# 🕰️ Three seconds is well above how long the burst's sockets take to close and
# well below the ten-second `FAIL_COOLDOWN`, so a backend that had been marked
# down could not pass this however patient the loop is.
probe_ok=false
for _ in $(seq 1 30); do
    code="$("${curl_bin}" --noproxy '*' --http3-only -ksS --max-time 10 \
        --resolve "${host_name}:${h3_port}:127.0.0.1" \
        -o /dev/null -w '%{http_code}' \
        "https://${host_name}:${h3_port}/probe" 2>/dev/null || true)"
    if [[ "${code}" == "200" ]]; then
        probe_ok=true
        break
    fi
    sleep 0.1
done
if [[ "${probe_ok}" == "true" ]]; then
    log "  ✅ a later request still reached the backend (200)"
else
    log "  ❌ the backend stopped answering after the local failure (last status ${code:-none})"
    failed=$((failed + 1))
fi

log ""
if [[ "${failed}" -eq 0 ]]; then
    log "✅ HTTP/3 keeps a healthy backend in rotation through a local resource failure."
    exit 0
fi
log "❌ HTTP/3 local resource failure handling failed ${failed} check(s)."
exit 1
