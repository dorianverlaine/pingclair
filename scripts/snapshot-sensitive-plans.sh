#!/usr/bin/env bash

set -Eeuo pipefail

readonly script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly repository_root="$(cd "${script_dir}/.." && pwd)"
readonly snapshot_root="${repository_root}/.plan-snapshots"
readonly todo_source="${repository_root}/docs/TODO.md"
readonly triage_source="${repository_root}/TRIAGE.md"
readonly retention_limit=30

fail() {
    printf '🚫 %s\n' "$*" >&2
    exit 1
}

if [[ "$#" -ne 1 ]]; then
    fail "usage: $0 start|end"
fi

readonly phase="$1"
case "${phase}" in
    start | end) ;;
    *) fail "snapshot phase must be 'start' or 'end'" ;;
esac

# 🔐 Owner-only defaults keep local defect reproductions out of other users' reach.
umask 077

[[ -f "${todo_source}" && ! -L "${todo_source}" ]] \
    || fail "docs/TODO.md is missing, unreadable, or a symbolic link"
[[ -f "${triage_source}" && ! -L "${triage_source}" ]] \
    || fail "TRIAGE.md is missing, unreadable, or a symbolic link"
[[ ! -L "${snapshot_root}" ]] || fail ".plan-snapshots must not be a symbolic link"
mkdir -p "${snapshot_root}"
chmod 700 "${snapshot_root}"

readonly lock_directory="${snapshot_root}/.lock"
mkdir "${lock_directory}" 2>/dev/null \
    || fail "another snapshot is running or left ${lock_directory} behind"

snapshot_temporary=""
counter_temporary=""

cleanup() {
    # 🧹 Cleanup is restricted to temporary paths created below the dedicated snapshot root.
    if [[ -n "${snapshot_temporary}" && -d "${snapshot_temporary}" ]]; then
        case "${snapshot_temporary}" in
            "${snapshot_root}"/.tmp.*) rm -rf "${snapshot_temporary}" ;;
        esac
    fi
    if [[ -n "${counter_temporary}" && -f "${counter_temporary}" ]]; then
        case "${counter_temporary}" in
            "${snapshot_root}"/.counter.tmp.*) rm -f "${counter_temporary}" ;;
        esac
    fi
    rmdir "${lock_directory}" 2>/dev/null || true
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

validate_snapshot() {
    local directory="$1"
    local manifest="${directory}/SHA256SUMS"
    local directory_name="${directory##*/}"

    [[ -d "${directory}" && ! -L "${directory}" ]] \
        || fail "snapshot is missing or is a symbolic link: ${directory}"
    if [[ "${directory_name}" != .tmp.* ]]; then
        [[ "${directory_name}" =~ ^[0-9]{12}_[0-9]{8}T[0-9]{6}Z_(start|end)$ ]] \
            || fail "snapshot directory name is malformed: ${directory}"
    fi
    [[ -f "${directory}/TODO.md" && ! -L "${directory}/TODO.md" ]] \
        || fail "snapshot TODO.md is missing or is a symbolic link: ${directory}"
    [[ -f "${directory}/TRIAGE.md" && ! -L "${directory}/TRIAGE.md" ]] \
        || fail "snapshot TRIAGE.md is missing or is a symbolic link: ${directory}"
    [[ -f "${manifest}" && ! -L "${manifest}" ]] \
        || fail "snapshot manifest is missing or is a symbolic link: ${directory}"

    [[ "$(grep -cE '^[0-9a-f]{64}  TODO\.md$' "${manifest}" || true)" -eq 1 ]] \
        || fail "snapshot manifest does not name TODO.md exactly once: ${directory}"
    [[ "$(grep -cE '^[0-9a-f]{64}  TRIAGE\.md$' "${manifest}" || true)" -eq 1 ]] \
        || fail "snapshot manifest does not name TRIAGE.md exactly once: ${directory}"
    [[ "$(wc -l <"${manifest}" | tr -d '[:space:]')" -eq 2 ]] \
        || fail "snapshot manifest contains unexpected entries: ${directory}"

    (cd "${directory}" && shasum -a 256 -c SHA256SUMS >/dev/null) \
        || fail "snapshot checksum validation failed: ${directory}"
}

validate_all_snapshots() {
    local symbolic_link
    local unexpected_directory
    local directory

    symbolic_link="$(find "${snapshot_root}" -mindepth 1 -maxdepth 1 -type l -print -quit)"
    [[ -z "${symbolic_link}" ]] || fail "snapshot root contains a symbolic link: ${symbolic_link}"

    unexpected_directory="$(find "${snapshot_root}" -mindepth 1 -maxdepth 1 -type d \
        ! -name '.lock' ! -name '.tmp.*' ! -name '[0-9]*_*' -print -quit)"
    [[ -z "${unexpected_directory}" ]] \
        || fail "snapshot root contains an unexpected directory: ${unexpected_directory}"

    while IFS= read -r directory; do
        [[ -n "${directory}" ]] || continue
        validate_snapshot "${directory}"
    done < <(find "${snapshot_root}" -mindepth 1 -maxdepth 1 -type d \
        -name '[0-9]*_*' -print | LC_ALL=C sort)
}

# 🛡️ Existing evidence is verified before any source copy, counter update, or pruning.
validate_all_snapshots

readonly counter_file="${snapshot_root}/.counter"
counter=0
latest_snapshot="$(find "${snapshot_root}" -mindepth 1 -maxdepth 1 -type d \
    -name '[0-9]*_*' -print | LC_ALL=C sort | tail -n 1)"
if [[ -e "${counter_file}" ]]; then
    [[ -f "${counter_file}" && ! -L "${counter_file}" ]] \
        || fail "snapshot counter is not a regular file"
    IFS= read -r counter <"${counter_file}" || fail "snapshot counter is unreadable"
    [[ "${counter}" =~ ^[0-9]{1,12}$ ]] || fail "snapshot counter is corrupt"
elif [[ -n "${latest_snapshot}" ]]; then
    fail "snapshot counter is missing while snapshots already exist"
fi

if [[ -n "${latest_snapshot}" ]]; then
    latest_name="${latest_snapshot##*/}"
    latest_sequence="${latest_name%%_*}"
    [[ "$((10#${counter}))" -ge "$((10#${latest_sequence}))" ]] \
        || fail "snapshot counter is older than the newest snapshot"
fi
[[ "$((10#${counter}))" -lt 999999999999 ]] || fail "snapshot counter is exhausted"

next_counter=$((10#${counter} + 1))
printf -v sequence '%012d' "${next_counter}"
readonly timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
readonly snapshot_directory="${snapshot_root}/${sequence}_${timestamp}_${phase}"
[[ ! -e "${snapshot_directory}" ]] || fail "snapshot destination already exists"

snapshot_temporary="$(mktemp -d "${snapshot_root}/.tmp.XXXXXX")"
cp "${todo_source}" "${snapshot_temporary}/TODO.md"
cp "${triage_source}" "${snapshot_temporary}/TRIAGE.md"
(cd "${snapshot_temporary}" && shasum -a 256 TODO.md TRIAGE.md >SHA256SUMS)
validate_snapshot "${snapshot_temporary}"

# 🔢 The persisted sequence makes retention deterministic even within one second.
counter_temporary="$(mktemp "${snapshot_root}/.counter.tmp.XXXXXX")"
printf '%d\n' "${next_counter}" >"${counter_temporary}"
mv "${counter_temporary}" "${counter_file}"
counter_temporary=""
mv "${snapshot_temporary}" "${snapshot_directory}"
snapshot_temporary=""

snapshot_count="$(find "${snapshot_root}" -mindepth 1 -maxdepth 1 -type d \
    -name '[0-9]*_*' -print | wc -l | tr -d '[:space:]')"
while [[ "${snapshot_count}" -gt "${retention_limit}" ]]; do
    oldest_snapshot="$(find "${snapshot_root}" -mindepth 1 -maxdepth 1 -type d \
        -name '[0-9]*_*' -print | LC_ALL=C sort | sed -n '1p')"
    case "${oldest_snapshot}" in
        "${snapshot_root}"/[0-9]*_*) ;;
        *) fail "refusing to prune an unresolved snapshot path: ${oldest_snapshot}" ;;
    esac
    validate_snapshot "${oldest_snapshot}"
    rm -rf "${oldest_snapshot}"
    snapshot_count=$((snapshot_count - 1))
done

# 🎯 A final pass proves the newly published set and every retained predecessor.
validate_all_snapshots
printf '📸 Saved and verified %s snapshot: %s\n' "${phase}" "${snapshot_directory}"
