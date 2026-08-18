#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

# 🎲 Run the nextest suite with the known-flaky retry policy.
#
# The websocket tunnel test is a known upstream (Pingora) flake, so the suite
# is rerun only when every failure is a known flake. The allowlist carries an
# ISO admission date and expires after 30 days: a flake that survives that
# long is a bug, not a flake. The test source is never modified for this.

set -Eeuo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly repository_root
readonly max_age_days=30

known_flaky=(
  "test_websocket_upgrade_tunnels_bytes_in_both_directions 2026-08-01"
)

now_epoch="$(date -u +%s)"
stale=0
for entry in "${known_flaky[@]}"; do
  flaky_name="${entry%% *}"
  flaky_date="${entry##* }"
  if date -u -d "${flaky_date}" +%s >/dev/null 2>&1; then
    entry_epoch="$(date -u -d "${flaky_date}" +%s)"
  elif date -j -u -f '%Y-%m-%d' "${flaky_date}" +%s >/dev/null 2>&1; then
    entry_epoch="$(date -j -u -f '%Y-%m-%d' "${flaky_date}" +%s)"
  else
    echo "::error::known_flaky entry '${flaky_name}' has an unparseable date '${flaky_date}'; the format is '<test name> <YYYY-MM-DD>'"
    stale=1
    continue
  fi
  age_days=$(( (now_epoch - entry_epoch) / 86400 ))
  if [ "$age_days" -gt "$max_age_days" ]; then
    echo "::error::known_flaky entry '${flaky_name}' was admitted ${flaky_date}, ${age_days} days ago, past the ${max_age_days}-day limit. Fix it, or re-admit it deliberately by moving its date and writing down what was investigated."
    stale=1
  else
    echo "🎲 known flake '${flaky_name}' admitted ${flaky_date} (${age_days}d old, expires at ${max_age_days}d)"
  fi
done
if [ "$stale" -ne 0 ]; then
  exit 1
fi

extract_failures() {
  local log="$1"
  rg '^FAIL \[[^]]+\] (\S+)' -or '$1' "$log" | sort -u
  awk '/^Failure list:/{f=1; next} f && /^[[:space:]]*[0-9]+\./{print $2}' "$log" | sort -u
}

max_attempts=3
attempt=0
log="/tmp/nextest.log"
status=1
while [ "$attempt" -lt "$max_attempts" ]; do
  attempt=$((attempt + 1))
  set +e
  (cd "${repository_root}" && just test) >"$log" 2>&1
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    echo "✅ nextest passed (attempt ${attempt}/${max_attempts})"
    break
  fi
  failed="$(extract_failures "$log" | sort -u)"
  if [ -z "$failed" ]; then
    break
  fi
  flaky_only=1
  while IFS= read -r test_name; do
    [ -z "$test_name" ] && continue
    match=0
    for known in "${known_flaky[@]}"; do
      if [ "$test_name" = "${known%% *}" ]; then
        match=1
      fi
    done
    if [ "$match" -ne 1 ]; then
      flaky_only=0
    fi
  done <<< "$failed"
  if [ "$flaky_only" -ne 1 ]; then
    break
  fi
  if [ "$attempt" -lt "$max_attempts" ]; then
    echo "⚠️  ${failed} is/are known upstream flake(s) (attempt ${attempt}/${max_attempts}); rerunning the suite"
  fi
done

rg -E 'Summary|test result|passed|failed' "$log" | tail -20 || true
if [ "$status" -ne 0 ]; then
  echo "::error::nextest failed on: $(printf '%s' "$failed" | tr '\n' ' ')"
  tail -n 80 "$log"
  exit 1
fi
exit 0
