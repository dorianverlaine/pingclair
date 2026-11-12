#!/usr/bin/env bash
# 🛰️ Run h3spec against a real Pingclair HTTP/3 listener over literal IPv4.

set -Eeuo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly run_dir="$(mktemp -d "${TMPDIR:-/tmp}/pingclair-h3spec.XXXXXX")"
readonly readiness_token="h3spec-ready-${RANDOM}-$$"
pingclair_pid=""

cleanup() {
    local status=$?
    if [[ -n "${pingclair_pid}" ]]; then
        kill -TERM "${pingclair_pid}" 2>/dev/null || true
        wait "${pingclair_pid}" 2>/dev/null || true
    fi
    if [[ "${status}" -ne 0 || "${PINGCLAIR_H3SPEC_KEEP_TEMP:-0}" == "1" ]]; then
        printf '📁 Preserved h3spec artifacts at %s\n' "${run_dir}"
    else
        rm -rf -- "${run_dir}"
    fi
}
trap cleanup EXIT INT TERM

find_h3spec() {
    if [[ -n "${H3SPEC_BINARY:-}" ]]; then
        printf '%s\n' "${H3SPEC_BINARY}"
        return
    fi
    command -v h3spec
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

readonly h3spec_bin="$(find_h3spec)"
readonly port="$(reserve_tcp_udp_port)"
readonly binary="${PINGCLAIR_BINARY:-${repository_root}/target/debug/pingclair}"

if [[ -z "${PINGCLAIR_BINARY:-}" ]]; then
    cargo +1.99.0 build --locked --manifest-path "${repository_root}/Cargo.toml" -p pingclair
elif [[ ! -x "${binary}" ]]; then
    printf '❌ PINGCLAIR_BINARY=%s is not executable.\n' "${binary}" >&2
    exit 2
fi

mkdir -p "${run_dir}/tls"
cat >"${run_dir}/Pingclairfile" <<EOF
{
    auto_https off
    servers {
        protocols h1 h2 h3
    }
}

https://127.0.0.1:${port} {
    bind 127.0.0.1
    tls internal
    handle /ready {
        respond "${readiness_token}" 200
    }
    handle {
        respond "ok" 200
    }
}
EOF

PINGCLAIR_TLS_STORE="${run_dir}/tls" "${binary}" run "${run_dir}/Pingclairfile" \
    >"${run_dir}/pingclair.log" 2>&1 &
pingclair_pid=$!

ready=false
for _ in {1..150}; do
    if ! kill -0 "${pingclair_pid}" 2>/dev/null; then
        printf '❌ Pingclair exited before HTTP/3 readiness.\n' >&2
        tail -n 60 "${run_dir}/pingclair.log" >&2 || true
        exit 1
    fi
    if "${h3spec_bin}" 127.0.0.1 "${port}" -n -t 1000 \
        -m 'MUST accept TE with trailers' \
        >"${run_dir}/readiness.log" 2>&1; then
        ready=true
        break
    fi
    sleep 0.1
done
if [[ "${ready}" != true ]]; then
    printf '❌ Pingclair did not become ready over HTTP/3.\n' >&2
    printf '%s\n' \
        '   A TUN/transparent proxy can accept the TCP listener while dropping loopback UDP.' \
        '   Disable it and rerun `just h3spec`; TCP readiness is not evidence for QUIC.' >&2
    tail -n 60 "${run_dir}/pingclair.log" >&2 || true
    exit 1
fi

# 🧭 The literal IPv4 address is load-bearing: `localhost` can resolve to ::1
# while Pingclair is serving the IPv4 listener, turning every rejection into a
# misleading timeout instead of exercising the protocol.
"${h3spec_bin}" 127.0.0.1 "${port}" -n -t 4000
