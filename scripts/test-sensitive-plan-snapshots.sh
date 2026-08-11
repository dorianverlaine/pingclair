#!/usr/bin/env bash

set -Eeuo pipefail

readonly script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly source_script="${script_dir}/snapshot-sensitive-plans.sh"
readonly temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/pingclair-plan-snapshots.XXXXXX")"
readonly fixture_root="${temporary_root}/repository"

cleanup() {
    # 🧹 The test removes only the mktemp directory it created for this run.
    case "${temporary_root}" in
        "${TMPDIR:-/tmp}"/pingclair-plan-snapshots.*) rm -rf "${temporary_root}" ;;
    esac
}
trap cleanup EXIT

fail() {
    printf '🚫 %s\n' "$*" >&2
    exit 1
}

# 🔐 Prints one path's permission bits as an octal number, on either platform.
#
# ⚠️ The order of the two attempts is the whole point, and it is not
# interchangeable. GNU `stat -c` fails outright on BSD, so trying it first
# falls through cleanly on macOS. The reverse does not hold: on GNU, `-f` means
# `--file-system` and **succeeds**, printing a block of filesystem statistics.
# A `stat -f … || stat -c …` chain therefore never reaches its fallback on
# Linux, and hands back "Block size: 4096 …" where the caller expected `700` —
# which is exactly how this failed in CI on 2026-08-11, on a check whose whole
# job is to notice when these files stop being private.
file_mode() {
    stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

mkdir -p "${fixture_root}/scripts" "${fixture_root}/docs"
cp "${source_script}" "${fixture_root}/scripts/snapshot-sensitive-plans.sh"
printf '# Plan\nfirst\n' >"${fixture_root}/docs/TODO.md"
printf '# Triage\nfirst\n' >"${fixture_root}/TRIAGE.md"

"${fixture_root}/scripts/snapshot-sensitive-plans.sh" start >/dev/null
snapshot_root="${fixture_root}/.plan-snapshots"
first_snapshot="$(find "${snapshot_root}" -mindepth 1 -maxdepth 1 -type d \
    -name '[0-9]*_*' -print | LC_ALL=C sort | sed -n '1p')"
[[ -n "${first_snapshot}" ]] || fail "the start snapshot was not created"
(cd "${first_snapshot}" && shasum -a 256 -c SHA256SUMS >/dev/null) \
    || fail "the start snapshot manifest did not verify"
snapshot_mode="$(file_mode "${first_snapshot}")"
todo_mode="$(file_mode "${first_snapshot}/TODO.md")"
[[ "${snapshot_mode}" == 700 ]] || fail "the snapshot directory mode is ${snapshot_mode}"
[[ "${todo_mode}" == 600 ]] || fail "the snapshot file mode is ${todo_mode}"

printf '# Plan\nsecond\n' >"${fixture_root}/docs/TODO.md"
printf '# Triage\nsecond\n' >"${fixture_root}/TRIAGE.md"
"${fixture_root}/scripts/snapshot-sensitive-plans.sh" end >/dev/null

# 🔢 A rolled-back sequence counter must fail before it can reorder retention.
counter_value="$(<"${snapshot_root}/.counter")"
printf '0\n' >"${snapshot_root}/.counter"
if "${fixture_root}/scripts/snapshot-sensitive-plans.sh" start \
    >"${temporary_root}/counter-output" 2>"${temporary_root}/counter-error"; then
    fail "a rolled-back snapshot counter was accepted"
fi
printf '%s\n' "${counter_value}" >"${snapshot_root}/.counter"

# 🚨 Corruption must stop before a new snapshot or retention mutation occurs.
printf 'tampered\n' >>"${first_snapshot}/TODO.md"
before_failure="$(find "${snapshot_root}" -mindepth 1 -maxdepth 1 -type d \
    -name '[0-9]*_*' -print | wc -l | tr -d '[:space:]')"
if "${fixture_root}/scripts/snapshot-sensitive-plans.sh" start \
    >"${temporary_root}/unexpected-output" 2>"${temporary_root}/expected-error"; then
    fail "a corrupt snapshot was accepted"
fi
after_failure="$(find "${snapshot_root}" -mindepth 1 -maxdepth 1 -type d \
    -name '[0-9]*_*' -print | wc -l | tr -d '[:space:]')"
[[ "${before_failure}" -eq "${after_failure}" ]] \
    || fail "a failed validation changed the snapshot set"

case "${first_snapshot}" in
    "${snapshot_root}"/[0-9]*_*) rm -rf "${first_snapshot}" ;;
    *) fail "the corrupt fixture path escaped the snapshot root" ;;
esac

# 🗂️ More than 30 successful runs retain exactly the newest 30 complete sets.
for iteration in $(seq 1 31); do
    printf '# Plan\niteration %s\n' "${iteration}" >"${fixture_root}/docs/TODO.md"
    "${fixture_root}/scripts/snapshot-sensitive-plans.sh" start >/dev/null
done

snapshot_count="$(find "${snapshot_root}" -mindepth 1 -maxdepth 1 -type d \
    -name '[0-9]*_*' -print | wc -l | tr -d '[:space:]')"
todo_count="$(find "${snapshot_root}" -mindepth 2 -maxdepth 2 -type f \
    -name TODO.md -print | wc -l | tr -d '[:space:]')"
triage_count="$(find "${snapshot_root}" -mindepth 2 -maxdepth 2 -type f \
    -name TRIAGE.md -print | wc -l | tr -d '[:space:]')"
[[ "${snapshot_count}" -eq 30 ]] || fail "retention kept ${snapshot_count} snapshot sets"
[[ "${todo_count}" -eq 30 ]] || fail "retention kept ${todo_count} TODO.md copies"
[[ "${triage_count}" -eq 30 ]] || fail "retention kept ${triage_count} TRIAGE.md copies"

while IFS= read -r directory; do
    (cd "${directory}" && shasum -a 256 -c SHA256SUMS >/dev/null) \
        || fail "a retained snapshot failed validation: ${directory}"
done < <(find "${snapshot_root}" -mindepth 1 -maxdepth 1 -type d \
    -name '[0-9]*_*' -print | LC_ALL=C sort)

printf '🎯 Sensitive plan snapshot tests passed.\n'
