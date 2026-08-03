#!/usr/bin/env bash

set -Eeuo pipefail

# 🧭 Verify the workspace still resolves pingora-core to the local
# performance fork (same rationale as scripts/check-vendored-h2.sh: a
# future `cargo update` or version bump would silently fall back to the
# registry crate and lose the BodyReader buffer-reuse patch).
readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

tree_output="$(cd "${repository_root}" && cargo tree -i pingora-core)"

if ! grep -q 'vendor/pingora-core' <<<"${tree_output}"; then
    echo "::error::pingora-core is not resolved to vendor/pingora-core — re-apply the Pingclair patch (see vendor/pingora-core/PINGCLAIR_PATCH.md)" >&2
    echo "${tree_output}" >&2
    exit 1
fi

resolved_count="$(grep -c '^pingora-core v' <<<"${tree_output}")"
if [[ "${resolved_count}" -ne 1 ]]; then
    echo "::error::expected exactly one pingora-core version in the tree, found ${resolved_count}" >&2
    echo "${tree_output}" >&2
    exit 1
fi

echo "✅ pingora-core resolves to vendor/pingora-core"
