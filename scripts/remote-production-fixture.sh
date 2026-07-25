#!/usr/bin/env bash

set -Eeuo pipefail

readonly action="${1:-}"
readonly run_dir="${2:-}"

log() {
    printf '[%(%H:%M:%S)T] %s\n' -1 "$*"
}

require_owned_process() {
    local pid="$1"
    local expected_path="$2"
    [[ -r "/proc/${pid}/cmdline" ]] || return 1
    tr '\0' ' ' <"/proc/${pid}/cmdline" | grep -Fq -- "${expected_path}"
}

terminate_owned_group() {
    local pid="${1:-}"
    local expected_path="$2"
    [[ -n "${pid}" ]] || return 0
    if ! kill -0 "${pid}" 2>/dev/null; then
        return 0
    fi
    if ! require_owned_process "${pid}" "${expected_path}"; then
        log "❌ Refusing to stop PID ${pid}; its command does not contain ${expected_path}."
        return 1
    fi
    kill -TERM -- "-${pid}" 2>/dev/null || kill -TERM "${pid}" 2>/dev/null || true
    for _ in {1..30}; do
        kill -0 "${pid}" 2>/dev/null || return 0
        sleep 0.1
    done
    kill -KILL -- "-${pid}" 2>/dev/null || kill -KILL "${pid}" 2>/dev/null || true
}

read_pid() {
    local name="$1"
    local path="${run_dir}/state/${name}.pid"
    [[ -r "${path}" ]] && tr -d '[:space:]' <"${path}" || true
}

stop_primaries() {
    terminate_owned_group "$(read_pid primary-a)" "${run_dir}/upstream.py"
    terminate_owned_group "$(read_pid primary-b)" "${run_dir}/upstream.py"
    log "✅ Primary upstream groups stopped."
}

stop_all() {
    terminate_owned_group "$(read_pid pingclair)" "${run_dir}/config.json"
    stop_primaries
    terminate_owned_group "$(read_pid backup)" "${run_dir}/upstream.py"
    ss -ltnup >"${run_dir}/results/listeners-after-stop.txt" 2>&1 || true
    log "✅ Production fixture stopped."
}

start_fixture() {
    local binary="${3:-}"
    local public_host="${4:-}"
    if [[ ! -x "${binary}" || ! "${public_host}" =~ ^[A-Za-z0-9.-]+$ ]]; then
        log "❌ Usage: $0 start <run-directory> <binary> <public-host>."
        exit 2
    fi
    if [[ -e "${run_dir}/state" ]]; then
        log "❌ The fixture state already exists: ${run_dir}/state."
        exit 1
    fi
    if ss -ltn '( sport = :80 or sport = :443 or sport = :2019 or sport = :9001 or sport = :9002 or sport = :9003 )' \
        | tail -n +2 | grep -q .; then
        log "❌ A required TCP port is already occupied."
        ss -ltnp '( sport = :80 or sport = :443 or sport = :2019 or sport = :9001 or sport = :9002 or sport = :9003 )'
        exit 1
    fi
    if ss -lun '( sport = :443 )' | tail -n +2 | grep -q .; then
        log "❌ UDP port 443 is already occupied."
        ss -lunp '( sport = :443 )'
        exit 1
    fi

    mkdir -p "${run_dir}/"{state,results,www/files,empty,tls}
    printf 'rewritten-over-public-network\n' >"${run_dir}/www/files/rewrite.txt"
    printf '<h1>public custom 404</h1>\n' >"${run_dir}/404.html"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${run_dir}/key.pem" \
        -out "${run_dir}/cert.pem" \
        -days 2 \
        -subj "/CN=${public_host}" \
        -addext "subjectAltName=DNS:${public_host}" \
        >"${run_dir}/results/openssl.log" 2>&1

    # 🧪 Return a stable backend identity so weight and backup behavior are observable.
    cat >"${run_dir}/upstream.py" <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

label = sys.argv[1]
port = int(sys.argv[2])

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"{label} {self.path}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        return

ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
PY

    local primary_a_pid primary_b_pid backup_pid
    setsid python3 "${run_dir}/upstream.py" primary-a 9001 \
        >"${run_dir}/results/primary-a.log" 2>&1 &
    primary_a_pid=$!
    setsid python3 "${run_dir}/upstream.py" primary-b 9002 \
        >"${run_dir}/results/primary-b.log" 2>&1 &
    primary_b_pid=$!
    setsid python3 "${run_dir}/upstream.py" backup 9003 \
        >"${run_dir}/results/backup.log" 2>&1 &
    backup_pid=$!
    printf '%s\n' "${primary_a_pid}" >"${run_dir}/state/primary-a.pid"
    printf '%s\n' "${primary_b_pid}" >"${run_dir}/state/primary-b.pid"
    printf '%s\n' "${backup_pid}" >"${run_dir}/state/backup.pid"

    readonly token="pingclair-public-${public_host}-$(date +%s)"
    cat >"${run_dir}/config.json" <<JSON
{
  "admin": {
    "enabled": true,
    "listen": "127.0.0.1:2019"
  },
  "global": {
    "auto_https": "off",
    "http3": true
  },
  "servers": [
    {
      "name": "${public_host}",
      "listen": ["0.0.0.0:80"],
      "routes": [
        {
          "path": "/ready",
          "handler": { "type": "respond", "status": 200, "body": "${token}-http" }
        },
        {
          "path": "/redirect",
          "handler": {
            "type": "redirect",
            "to": "https://${public_host}/ready",
            "code": 308
          }
        }
      ]
    },
    {
      "name": "${public_host}",
      "listen": ["0.0.0.0:443"],
      "tls": {
        "cert": "${run_dir}/cert.pem",
        "key": "${run_dir}/key.pem",
        "http3": true
      },
      "error_pages": {
        "404": "${run_dir}/404.html"
      },
      "routes": [
        {
          "path": "/ready",
          "handler": { "type": "respond", "status": 200, "body": "${token}-https" }
        },
        {
          "path": "/cors",
          "handler": {
            "type": "pipeline",
            "handlers": [
              {
                "type": "cors",
                "allowed_origins": ["https://app.example"],
                "allowed_methods": ["GET", "POST"],
                "allowed_headers": ["Content-Type"],
                "exposed_headers": ["X-Request-Id"],
                "allow_credentials": true,
                "max_age": 600
              },
              {
                "type": "access_control",
                "allowed_ips": ["0.0.0.0/0"],
                "denied_user_agents": ["(?i)blockedbot"]
              },
              { "type": "respond", "status": 200, "body": "cors-public-ok" }
            ]
          }
        },
        {
          "path": "/rewrite/*",
          "handler": {
            "type": "pipeline",
            "handlers": [
              {
                "type": "rewrite",
                "regex": "^/rewrite/(.*)$",
                "regex_replace": "/files/\$1"
              },
              {
                "type": "file_server",
                "root": "${run_dir}/www",
                "compress": true
              }
            ]
          }
        },
        {
          "path": "/missing/*",
          "handler": {
            "type": "file_server",
            "root": "${run_dir}/empty",
            "compress": false
          }
        },
        {
          "path": "/proxy/*",
          "handler": {
            "type": "reverse_proxy",
            "upstreams": [],
            "upstream_options": [
              { "address": "http://127.0.0.1:9001", "weight": 3, "backup": false },
              { "address": "http://127.0.0.1:9002", "weight": 1, "backup": false },
              { "address": "http://127.0.0.1:9003", "weight": 1, "backup": true }
            ],
            "load_balance": { "strategy": "round_robin" },
            "headers_up": {},
            "headers_down": {}
          }
        }
      ]
    }
  ]
}
JSON

    local pingclair_pid
    PINGCLAIR_TLS_STORE="${run_dir}/tls" \
        setsid "${binary}" run "${run_dir}/config.json" \
        >"${run_dir}/results/pingclair.log" 2>&1 &
    pingclair_pid=$!
    printf '%s\n' "${pingclair_pid}" >"${run_dir}/state/pingclair.pid"

    fixture_ready=false
    for _ in {1..100}; do
        if ! kill -0 "${pingclair_pid}" 2>/dev/null; then
            log "❌ Pingclair exited during fixture startup."
            tail -n 100 "${run_dir}/results/pingclair.log" || true
            stop_all
            exit 1
        fi
        http_body="$(curl --noproxy '*' -fsS -H "Host: ${public_host}" \
            http://127.0.0.1/ready 2>/dev/null || true)"
        https_body="$(curl --noproxy '*' -kfsS --resolve "${public_host}:443:127.0.0.1" \
            "https://${public_host}/ready" 2>/dev/null || true)"
        if [[ "${http_body}" == "${token}-http" && "${https_body}" == "${token}-https" ]] \
            && curl --noproxy '*' -fsS http://127.0.0.1:2019/health \
                >"${run_dir}/results/admin-health.json" 2>/dev/null; then
            fixture_ready=true
            break
        fi
        sleep 0.1
    done
    if [[ "${fixture_ready}" != true ]]; then
        log "❌ Production fixture did not become ready."
        stop_all
        exit 1
    fi

    curl --noproxy '*' -fsS http://127.0.0.1:2019/metrics \
        >"${run_dir}/results/metrics-before.prom"
    ss -ltnup >"${run_dir}/results/listeners-ready.txt" 2>&1 || true
    {
        printf 'PUBLIC_HOST=%q\n' "${public_host}"
        printf 'TOKEN=%q\n' "${token}"
        printf 'RUN_DIR=%q\n' "${run_dir}"
    } >"${run_dir}/ready.env"
    log "✅ Production fixture ready for external traffic."
    printf 'PUBLIC_HOST=%s\nTOKEN=%s\nRUN_DIR=%s\n' "${public_host}" "${token}" "${run_dir}"
}

case "${action}" in
    start)
        start_fixture "$@"
        ;;
    stop-primaries)
        stop_primaries
        ;;
    stop)
        stop_all
        ;;
    *)
        log "❌ Usage: $0 start|stop-primaries|stop <run-directory> [binary public-host]."
        exit 2
        ;;
esac
