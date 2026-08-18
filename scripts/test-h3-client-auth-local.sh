#!/usr/bin/env bash
#
# 🪪 Mutual TLS over HTTP/3, driven by a real HTTP/3 client.
#
# 🤡 Why this file exists: `pingclair-proxy/src/quic.rs` has enforced client
# authentication on HTTP/3 since it was written, and nothing executed it. The
# eight client-auth tests in `pingclair/tests/integration.rs` all drive the
# HTTP/1.1 and HTTP/2 listener; `requires_strict_sni_host` appeared twice in the
# tree, both times in the implementation, and zero times in any test. So the
# claim "client authentication is enforced on both transports" rested on
# reading the code — which is exactly the kind of claim this repository has
# already watched turn out to be half true.
#
# The case that matters most is the last one. A listener where one site demands
# a client certificate and another does not is not two listeners: there is one
# TLS handshake, and the name chosen there is what the certificate was checked
# against. A client may therefore offer the unprotected site's name, skip the
# certificate entirely, and then ask for the protected site by putting its name
# in `:authority`. If HTTP/3 skipped that check, an attacker would simply use
# HTTP/3 — the protection on the other two transports would be decoration.
#
# 🧾 The server is configured with a Pingclairfile rather than JSON on purpose.
# The other two H3 scripts use JSON and thereby skip `adapter/caddyfile.rs`,
# which is about half the path an operator's configuration takes; that is
# recorded as its own defect and this file does not add to it.

set -Eeuo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly binary="${PINGCLAIR_BINARY:-${repository_root}/target/debug/pingclair}"
readonly run_dir="$(mktemp -d "${TMPDIR:-/tmp}/pingclair-h3-clientauth.XXXXXX")"
# 🏷️ Two names, one listener. That shape is the whole point; see the header.
readonly secure_name="secure.h3.local"
readonly open_name="open.h3.local"
pingclair_pid=""
passed=0
failed=0

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

stop_owned_process() {
    local pid="${1:-}"
    local expected_fragment="${2:-}"
    [[ -n "${pid}" ]] || return 0
    local command_line=""
    command_line="$(ps -p "${pid}" -o command= 2>/dev/null || true)"
    [[ -n "${command_line}" ]] || return 0
    if [[ "${command_line}" != *"${expected_fragment}"* ]]; then
        log "⚠️ Refusing to stop PID ${pid}; it no longer belongs to this fixture."
        return 0
    fi
    if kill -0 "${pid}" 2>/dev/null; then
        kill -TERM "${pid}" 2>/dev/null || true
    fi
    wait "${pid}" 2>/dev/null || true
}

cleanup() {
    stop_owned_process "${pingclair_pid}" "${run_dir}/Pingclairfile"
    if [[ "${PINGCLAIR_H3_KEEP_TEMP:-0}" == "1" ]]; then
        log "📁 Preserved artifacts at ${run_dir}."
    else
        rm -rf -- "${run_dir}"
    fi
}
trap cleanup EXIT INT TERM

readonly curl_bin="$(find_h3_curl)"
readonly port="$(reserve_tcp_udp_port)"

# 🔨 Always, not only when the binary is missing: a script that reports on a
# binary from before your change is worse when it is green than when it is red.
if [[ -z "${PINGCLAIR_BINARY:-}" ]]; then
    log "🔨 Building Pingclair."
    cargo build --manifest-path "${repository_root}/Cargo.toml" -p pingclair
elif [[ ! -x "${binary}" ]]; then
    log "❌ PINGCLAIR_BINARY=${binary} is not executable."
    exit 2
fi

log "🔧 curl: $("${curl_bin}" --version | head -1)"
log "🔌 Listener: ${port} (TCP and UDP)"

# 🔐 A certificate authority that exists only for this run, one client it
# signed, and one it did not. The rogue client proves the check is a signature
# check rather than a "did you send anything" check.
openssl req -x509 -newkey rsa:2048 -keyout "${run_dir}/ca.key" -out "${run_dir}/ca.crt" \
    -days 1 -nodes -subj "/CN=Pingclair H3 test CA" 2>/dev/null
openssl req -x509 -newkey rsa:2048 -keyout "${run_dir}/rogue-ca.key" -out "${run_dir}/rogue-ca.crt" \
    -days 1 -nodes -subj "/CN=Pingclair H3 rogue CA" 2>/dev/null
# 🏷️ One server certificate covering both names, so the two sites genuinely
# share a listener and a handshake.
openssl req -x509 -newkey rsa:2048 -keyout "${run_dir}/server.key" -out "${run_dir}/server.crt" \
    -days 1 -nodes -subj "/CN=${secure_name}" \
    -addext "subjectAltName=DNS:${secure_name},DNS:${open_name}" 2>/dev/null
for who in client rogue; do
    ca="ca"
    [[ "${who}" == "rogue" ]] && ca="rogue-ca"
    openssl req -newkey rsa:2048 -keyout "${run_dir}/${who}.key" -out "${run_dir}/${who}.csr" \
        -nodes -subj "/CN=${who}" 2>/dev/null
    openssl x509 -req -in "${run_dir}/${who}.csr" -CA "${run_dir}/${ca}.crt" \
        -CAkey "${run_dir}/${ca}.key" -CAcreateserial -out "${run_dir}/${who}.crt" -days 1 2>/dev/null
done

cat >"${run_dir}/Pingclairfile" <<EOF
{
	auto_https off
	servers {
		protocols h1 h2 h3
	}
}

https://${secure_name}:${port} {
	tls ${run_dir}/server.crt ${run_dir}/server.key {
		client_auth {
			mode require_and_verify
			trusted_ca_cert_file ${run_dir}/ca.crt
		}
	}
	respond "secure ok" 200
}

https://${open_name}:${port} {
	tls ${run_dir}/server.crt ${run_dir}/server.key
	respond "open ok" 200
}
EOF

PINGCLAIR_TLS_STORE="${run_dir}/store" "${binary}" run "${run_dir}/Pingclairfile" \
    >"${run_dir}/server.log" 2>&1 &
pingclair_pid=$!

for _ in $(seq 1 60); do
    if "${curl_bin}" -sS --noproxy '*' --resolve "${secure_name}:${port}:127.0.0.1" \
        --cacert "${run_dir}/server.crt" --cert "${run_dir}/client.crt" --key "${run_dir}/client.key" \
        --http1.1 --max-time 3 -o /dev/null "https://${secure_name}:${port}/" 2>/dev/null; then
        break
    fi
    sleep 0.25
done

resolve_args=(
    --resolve "${secure_name}:${port}:127.0.0.1"
    --resolve "${open_name}:${port}:127.0.0.1"
)

# 🧪 One case. `expected` is the status code, or `refused` when the handshake
# itself must fail — a refused connection reports 000, and asserting on that
# rather than on any-non-200 is what stops "the server was down" from passing.
check() {
    local label="$1" expected="$2"; shift 2
    local body="${run_dir}/body.out" code=""
    code="$("${curl_bin}" -sS --noproxy '*' "${resolve_args[@]}" \
        --cacert "${run_dir}/server.crt" --max-time 15 \
        -o "${body}" -w '%{http_code}' "$@" 2>/dev/null || true)"
    local want="${expected}"
    [[ "${expected}" == "refused" ]] && want="000"
    if [[ "${code}" == "${want}" ]]; then
        log "  ✅ ${label}"
        passed=$((passed + 1))
    else
        log "  ❌ ${label} — got ${code}, expected ${want}"
        log "     body: $(head -c 90 "${body}" 2>/dev/null)"
        failed=$((failed + 1))
    fi
}

client_cert=(--cert "${run_dir}/client.crt" --key "${run_dir}/client.key")
rogue_cert=(--cert "${run_dir}/rogue.crt" --key "${run_dir}/rogue.key")

log ""
log "🔎 A trusted client certificate is admitted — on every transport"
for proto in --http1.1 --http2 --http3-only; do
    check "${proto}" 200 "${client_cert[@]}" "${proto}" "https://${secure_name}:${port}/"
done

log ""
log "🔎 No client certificate is refused at the handshake"
for proto in --http1.1 --http3-only; do
    check "${proto}" refused "${proto}" "https://${secure_name}:${port}/"
done

log ""
log "🔎 A certificate from an untrusted authority is refused"
for proto in --http1.1 --http3-only; do
    check "${proto}" refused "${rogue_cert[@]}" "${proto}" "https://${secure_name}:${port}/"
done

log ""
log "🔎 The site that never asked for one still answers without a certificate"
for proto in --http1.1 --http3-only; do
    check "${proto}" 200 "${proto}" "https://${open_name}:${port}/"
done

log ""
log "🔎 🛡️ Naming the unprotected site in the handshake and the protected one"
log "     in the request is refused with 421 — the reason this check exists"
for proto in --http1.1 --http2 --http3-only; do
    check "${proto}" 421 "${proto}" -H "Host: ${secure_name}" "https://${open_name}:${port}/"
done

log ""
log "═══════════════════════════════════════════"
if (( failed == 0 )); then
    log "✅ H3 client authentication: ${passed}/${passed} passed."
else
    log "❌ H3 client authentication: ${failed} of $((passed + failed)) failed."
    log "   Server log tail:"
    tail -15 "${run_dir}/server.log" | sed 's/^/     /'
    exit 1
fi
