#!/usr/bin/env bash

set -Eeuo pipefail

# 🧭 Verify the workspace still resolves every h2 dependency to the local
# performance fork. A future `cargo update` or Pingora upgrade that moves to
# a newer h2 version would silently fall back to the registry crate — the
# HPACK scratch-buffer optimization would stop applying while the build
# stays green. This check makes that regression loud instead.
readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

tree_output="$(cd "${repository_root}" && cargo tree -i h2)"

if ! grep -q 'vendor/h2' <<<"${tree_output}"; then
    echo "::error::h2 is not resolved to vendor/h2 — re-apply the Pingclair patch (see vendor/h2/PINGCLAIR_PATCH.md)" >&2
    echo "${tree_output}" >&2
    exit 1
fi

resolved_count="$(grep -c '^h2 v' <<<"${tree_output}")"
if [[ "${resolved_count}" -ne 1 ]]; then
    echo "::error::expected exactly one h2 version in the tree, found ${resolved_count}" >&2
    echo "${tree_output}" >&2
    exit 1
fi

echo "✅ h2 resolves to vendor/h2"
