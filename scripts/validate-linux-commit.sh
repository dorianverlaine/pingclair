#!/usr/bin/env bash

set -Eeuo pipefail

readonly repository_url="${PINGCLAIR_VALIDATION_REPOSITORY:-https://github.com/dorianverlaine/pingclair.git}"
readonly requested_commit="${1:-}"
readonly requested_results="${2:-${PWD}/pingclair-linux-validation-results}"
readonly requested_target="${PINGCLAIR_VALIDATION_TARGET_DIR:-}"
readonly release_lto="${PINGCLAIR_VALIDATION_RELEASE_LTO:-false}"
readonly release_codegen_units="${PINGCLAIR_VALIDATION_RELEASE_CODEGEN_UNITS:-16}"

if [[ -z "${requested_commit}" ]]; then
    printf '%s\n' "❌ Usage: $0 <full-commit-sha> [results-directory]"
    exit 2
fi
if [[ ! "${requested_commit}" =~ ^[0-9a-fA-F]{40}$ ]]; then
    printf '%s\n' "❌ The commit must be a full 40-character SHA."
    exit 2
fi
if [[ ! "${release_codegen_units}" =~ ^[1-9][0-9]*$ ]]; then
    printf '%s\n' "❌ Release codegen units must be a positive integer."
    exit 2
fi
case "${release_lto}" in
    false | true | off | thin | fat) ;;
    *)
        printf '%s\n' "❌ Release LTO must be false, true, off, thin, or fat."
        exit 2
        ;;
esac
for command_name in cargo curl git python3 rustc setsid sha256sum; do
    if ! command -v "${command_name}" >/dev/null 2>&1; then
        printf '%s\n' "❌ Missing required command: ${command_name}."
        exit 2
    fi
done

mkdir -p "${requested_results}"
readonly results_dir="$(cd "${requested_results}" && pwd)"
readonly work_dir="$(mktemp -d "${TMPDIR:-/tmp}/pingclair-linux-validation.XXXXXXXX")"
readonly checkout_dir="${work_dir}/checkout"

# 🧰 Keep functional validation reproducible on small hosts without changing runtime behavior.
export CARGO_PROFILE_TEST_DEBUG="${CARGO_PROFILE_TEST_DEBUG:-0}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_PROFILE_RELEASE_LTO="${release_lto}"
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS="${release_codegen_units}"

if [[ -n "${requested_target}" ]]; then
    mkdir -p "${requested_target}"
    CARGO_TARGET_DIR="$(cd "${requested_target}" && pwd)"
else
    CARGO_TARGET_DIR="${checkout_dir}/target"
fi
export CARGO_TARGET_DIR

active_pid=""
server_pid=""
validation_finished=false

log() {
    printf '[%(%H:%M:%S)T] %s\n' -1 "$*"
}

terminate_group() {
    local pid="${1:-}"
    [[ -n "${pid}" ]] || return 0
    if kill -0 "${pid}" 2>/dev/null; then
        kill -TERM -- "-${pid}" 2>/dev/null || kill -TERM "${pid}" 2>/dev/null || true
        for _ in {1..30}; do
            kill -0 "${pid}" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "${pid}" 2>/dev/null; then
            kill -KILL -- "-${pid}" 2>/dev/null || kill -KILL "${pid}" 2>/dev/null || true
        fi
    fi
    wait "${pid}" 2>/dev/null || true
}

cleanup() {
    local status=$?
    terminate_group "${server_pid}"
    terminate_group "${active_pid}"

    # 🧹 Remove only the uniquely named directory created by this invocation.
    case "${work_dir}" in
        "${TMPDIR:-/tmp}"/pingclair-linux-validation.*)
            rm -rf -- "${work_dir}"
            ;;
        *)
            log "❌ Refusing to remove unexpected work directory: ${work_dir}."
            ;;
    esac

    if [[ "${validation_finished}" != true && ! -e "${results_dir}/result.txt" ]]; then
        printf 'FAIL exit_status=%s\n' "${status}" >"${results_dir}/result.txt"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_step() {
    local name="$1"
    shift
    local output="${results_dir}/${name}.log"
    log "🧪 Running ${name}."
    setsid "$@" >"${output}" 2>&1 &
    active_pid=$!
    if wait "${active_pid}"; then
        active_pid=""
        log "✅ ${name} passed."
    else
        local status=$?
        active_pid=""
        log "❌ ${name} failed. Last 80 log lines follow."
        tail -n 80 "${output}" || true
        return "${status}"
    fi
}

allocate_port() {
    python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.bind(("127.0.0.1", 0))
    print(listener.getsockname()[1])
PY
}

log "📥 Fetching exact commit ${requested_commit}."
git init -q "${checkout_dir}"
git -C "${checkout_dir}" remote add origin "${repository_url}"
git -C "${checkout_dir}" fetch -q --depth=1 origin "${requested_commit}"
readonly resolved_commit="$(git -C "${checkout_dir}" rev-parse FETCH_HEAD)"
if [[ "${resolved_commit}" != "${requested_commit,,}" ]]; then
    log "❌ Resolved commit ${resolved_commit} does not match the request."
    exit 1
fi
git -C "${checkout_dir}" checkout -q --detach "${resolved_commit}"

{
    printf 'validated_at_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'repository=%s\n' "${repository_url}"
    printf 'commit=%s\n' "${resolved_commit}"
    printf 'kernel=%s\n' "$(uname -a)"
    printf 'rustc=%s\n' "$(rustc --version)"
    printf 'cargo=%s\n' "$(cargo --version)"
    printf 'cargo_profile_test_debug=%s\n' "${CARGO_PROFILE_TEST_DEBUG}"
    printf 'cargo_incremental=%s\n' "${CARGO_INCREMENTAL}"
    printf 'cargo_build_jobs=%s\n' "${CARGO_BUILD_JOBS:-auto}"
    printf 'cargo_target_dir=%s\n' "${CARGO_TARGET_DIR}"
    printf 'cargo_profile_release_lto=%s\n' "${CARGO_PROFILE_RELEASE_LTO}"
    printf 'cargo_profile_release_codegen_units=%s\n' \
        "${CARGO_PROFILE_RELEASE_CODEGEN_UNITS}"
    if command -v lsb_release >/dev/null 2>&1; then
        lsb_release -a 2>/dev/null || true
    fi
} >"${results_dir}/metadata.txt"
git -C "${checkout_dir}" status --short --branch >"${results_dir}/git-status.txt"

cd "${checkout_dir}"
run_step release-build cargo build --locked --release --workspace
run_step workspace-tests cargo test --locked --workspace
run_step integration-isolation scripts/test-integration-isolation.sh 20

readonly http_port="$(allocate_port)"
readonly admin_port="$(allocate_port)"
readonly smoke_token="pingclair-linux-smoke-${resolved_commit:0:12}"
readonly smoke_config="${work_dir}/smoke.json"

# 🚦 Exercise the release binary and preserve its exact runtime inputs and outputs.
cat >"${smoke_config}" <<JSON
{
  "admin": {
    "enabled": true,
    "listen": "127.0.0.1:${admin_port}"
  },
  "global": {
    "http3": false
  },
  "servers": [{
    "listen": ["127.0.0.1:${http_port}"],
    "routes": [{
      "path": "/ready",
      "handler": {
        "type": "respond",
        "status": 200,
        "body": "${smoke_token}"
      }
    }]
  }]
}
JSON
cp "${smoke_config}" "${results_dir}/smoke-config.json"

setsid "${CARGO_TARGET_DIR}/release/pingclair" run "${smoke_config}" \
    >"${results_dir}/release-smoke.log" 2>&1 &
server_pid=$!

smoke_ready=false
for _ in {1..100}; do
    if ! kill -0 "${server_pid}" 2>/dev/null; then
        log "❌ The release smoke server exited before readiness."
        tail -n 80 "${results_dir}/release-smoke.log" || true
        exit 1
    fi
    response="$(curl --noproxy '*' -fsS "http://127.0.0.1:${http_port}/ready" 2>/dev/null || true)"
    if [[ "${response}" == "${smoke_token}" ]] \
        && curl --noproxy '*' -fsS "http://127.0.0.1:${admin_port}/health" \
            >"${results_dir}/admin-health.json" 2>/dev/null; then
        smoke_ready=true
        break
    fi
    sleep 0.1
done
if [[ "${smoke_ready}" != true ]]; then
    log "❌ The release smoke server did not become ready."
    exit 1
fi

curl --noproxy '*' -fsS -D "${results_dir}/response-headers.txt" \
    "http://127.0.0.1:${http_port}/ready" >"${results_dir}/response-body.txt"
curl --noproxy '*' -fsS "http://127.0.0.1:${admin_port}/metrics" \
    >"${results_dir}/metrics.prom"
if command -v ss >/dev/null 2>&1; then
    ss -ltnp >"${results_dir}/listeners-before-stop.txt" 2>&1 || true
fi

terminate_group "${server_pid}"
server_pid=""
if command -v ss >/dev/null 2>&1; then
    ss -ltnp >"${results_dir}/listeners-after-stop.txt" 2>&1 || true
fi

find "${results_dir}" -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 sha256sum >"${results_dir}/SHA256SUMS"
printf 'PASS commit=%s\n' "${resolved_commit}" >"${results_dir}/result.txt"
validation_finished=true
log "✅ Linux validation passed. Results: ${results_dir}."
