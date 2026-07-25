#!/usr/bin/env bash

set -euo pipefail

readonly rounds="${1:-20}"
readonly workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly baseline_file="$(mktemp)"
readonly final_file="$(mktemp)"

cleanup() {
    rm -f "${baseline_file}" "${final_file}"
}
trap cleanup EXIT

log() {
    printf '%s\n' "$*"
}

snapshot_test_processes() {
    {
        pgrep -x pingclair 2>/dev/null | sed 's/^/pingclair:/' || true
        pgrep -f '[p]ingclair-test-watchdog' 2>/dev/null | sed 's/^/watchdog:/' || true
    } | sort -u
}

if [[ ! "${rounds}" =~ ^[1-9][0-9]*$ ]]; then
    log "❌ The repeat count must be a positive integer."
    exit 2
fi

cd "${workspace_root}"
snapshot_test_processes >"${baseline_file}"

for ((round = 1; round <= rounds; round++)); do
    log "🧪 Integration isolation round ${round}/${rounds}."
    cargo test -q -p pingclair --test integration -- --test-threads=9
done

snapshot_test_processes >"${final_file}"
new_processes="$(comm -13 "${baseline_file}" "${final_file}")"
if [[ -n "${new_processes}" ]]; then
    log "❌ Integration tests left new Pingclair processes behind:"
    printf '%s\n' "${new_processes}"
    exit 1
fi

log "✅ All ${rounds} rounds passed without new Pingclair or watchdog processes."
