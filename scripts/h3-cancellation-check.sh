#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

# 🎲 Run the H3 cancellation check, retrying once when it fails the way a known
# flake fails.
#
# The script asserts that the first SSE event reaches the client while the
# stream is still open. On 2026-09-22 that assertion failed four times in CI
# with the *same* binary that had passed it twenty minutes earlier:
#
#   ❌ The first H3 SSE event never appeared: the stream ended before it was
#   delivered.
#
# The client connects — it is the client's own `--max-time` that ends the run —
# and then receives nothing for the whole window, so this is not a slow handshake
# that a longer timeout would cover; it is the flush path over H3, intermittently.
# It is tracked as issue #68 and this retry is deliberately narrow: only that
# message is retried, and only once. Anything else fails on the first run.
#
# The rerun exists so a known flake does not turn an unrelated commit red. It is
# not a fix, and it expires with the issue: when the flake is understood, this
# file goes away.

set -Eeuo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly repository_root
readonly check="${repository_root}/scripts/test-h3-cancellation-local.sh"
readonly log_file="$(mktemp "${TMPDIR:-/tmp}/h3-cancellation.XXXXXX")"

run_check() {
    # 🎨 Tee keeps the transcript in the CI log while the copy decides the retry;
    # `pipefail` is on, so the pipeline reports the check's status, not tee's.
    "${check}" 2>&1 | tee "${log_file}"
}

if run_check; then
    exit 0
fi

if grep -q "The first H3 SSE event never appeared" "${log_file}"; then
    echo "🎲 known H3 flush flake (issue #68): retrying the cancellation check once"
    run_check
    exit $?
fi

echo "❌ the cancellation check failed for a reason that is not the known flake; not retrying"
exit 1
