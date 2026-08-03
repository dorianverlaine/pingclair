#!/usr/bin/env bash

set -Eeuo pipefail

# 🧭 Verify the workspace still resolves pingora-http to the local fork
# (same rationale as the h2/pingora-core guards).
readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

tree_output="$(cd "${repository_root}" && cargo tree -i pingora-http)"

if ! grep -q 'vendor/pingora-http' <<<"${tree_output}"; then
    echo "::error::pingora-http is not resolved to vendor/pingora-http — re-apply the Pingclair patch (see vendor/pingora-http/PINGCLAIR_PATCH.md)" >&2
    echo "${tree_output}" >&2
    exit 1
fi

resolved_count="$(grep -c '^pingora-http v' <<<"${tree_output}")"
if [[ "${resolved_count}" -ne 1 ]]; then
    echo "::error::expected exactly one pingora-http version in the tree, found ${resolved_count}" >&2
    echo "${tree_output}" >&2
    exit 1
fi

echo "✅ pingora-http resolves to vendor/pingora-http"
