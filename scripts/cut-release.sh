#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

# 🔖 Cuts a release commit and its annotated tag locally, and never pushes.
#
# main always carries version 0.0.0. A release is one commit on top of an
# up-to-date main (or of release/X.Y, for a patch to an older stable line)
# that changes only the workspace version in Cargo.toml and Cargo.lock. The
# tag `v<version>` points at that commit, and its message is the CHANGELOG's
# Unreleased section, which the release workflow publishes as the notes.
# The release commit is never merged back: main keeps saying 0.0.0.
#
# Usage: scripts/cut-release.sh <version> [--base release/X.Y] [--remote origin]
#
# The script refuses an invalid version, a version not newer than the newest
# existing release tag, a dirty tree, and a base branch that differs from its
# remote copy. It prints the push command instead of running it, so a person
# decides when a release goes out.

set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly versions="${script_dir}/release/versions.py"

fail() {
    printf '🚫 %s\n' "$*" >&2
    exit 1
}

usage() {
    fail "usage: $0 <version> [--base release/X.Y] [--remote origin]"
}

[[ "$#" -ge 1 ]] || usage
version="$1"
shift
base="main"
remote="origin"
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --base) [[ "$#" -ge 2 ]] || usage; base="$2"; shift 2 ;;
        --remote) [[ "$#" -ge 2 ]] || usage; remote="$2"; shift 2 ;;
        *) usage ;;
    esac
done

case "${version}" in
    v*) fail "pass the version without its v prefix: ${version#v}" ;;
esac
python3 "${versions}" check "${version}" \
    || fail "${version} is not a release version (X.Y.Z, X.Y.Z-alpha.N[.M], X.Y.Z-beta.N, X.Y.Z-rc.N)"

# 🛡️ A release branch only exists for patches to an older stable line, and
# its name must match the version being cut, or the workflow will refuse
# the tag after it is pushed.
if [[ "${base}" != "main" ]]; then
    line="$(printf '%s' "${version%%-*}" | cut -d. -f1-2)"
    [[ "${base}" == "release/${line}" ]] \
        || fail "a ${version} release is cut from main or release/${line}, not ${base}"
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "${repo_root}"

[[ -z "$(git status --porcelain)" ]] || fail "the working tree is not clean; commit or set changes aside first"

current_branch="$(git symbolic-ref --quiet --short HEAD || true)"
[[ "${current_branch}" == "${base}" ]] || fail "check out ${base} first (currently on ${current_branch:-a detached HEAD})"

printf '🔄 Fetching %s and its tags...\n' "${remote}"
git fetch --quiet --tags "${remote}" "${base}"
remote_sha="$(git rev-parse "refs/remotes/${remote}/${base}" 2>/dev/null || git rev-parse FETCH_HEAD)"
local_sha="$(git rev-parse HEAD)"
# 🛡️ Equal, not merely "not behind": a commit that exists only here would
# become the parent of a published release without ever being reviewed,
# and the workflow refuses a parent that is not on the remote branch.
[[ "${local_sha}" == "${remote_sha}" ]] \
    || fail "${base} (${local_sha:0:10}) differs from ${remote}/${base} (${remote_sha:0:10}); pull or push first"

git rev-parse --verify --quiet "refs/tags/v${version}" >/dev/null && fail "tag v${version} already exists"
latest="$(git tag -l 'v*' | python3 "${versions}" latest-tag)"
if [[ -n "${latest}" ]]; then
    python3 "${versions}" newer "${version}" "${latest}" \
        || fail "${version} is not newer than the latest release tag v${latest}"
fi

workspace_version="$(grep -m1 '^version = ' Cargo.toml | sed 's/^version = "\(.*\)"/\1/')"
[[ "${workspace_version}" == "0.0.0" ]] \
    || fail "${base} carries version ${workspace_version}; it must say 0.0.0"

# 📝 The notes are everything under `## [Unreleased]` up to the next release
# heading. An empty section means there is nothing to announce.
notes_file="$(mktemp)"
trap 'rm -f "${notes_file}"' EXIT
awk '
    /^## \[Unreleased\]/ { inside = 1; next }
    inside && /^## \[/ { exit }
    inside { print }
' CHANGELOG.md | sed -e '/./,$!d' >"${notes_file}"
[[ -s "${notes_file}" ]] || fail "CHANGELOG.md has no Unreleased section to use as release notes"

printf '🔖 Cutting %s from %s (%s)...\n' "${version}" "${base}" "${local_sha:0:10}"
git switch --quiet --detach "${local_sha}"
# 🧹 Whatever happens next, return to the branch the caller was on.
trap 'rm -f "${notes_file}"; git switch --quiet "${base}" 2>/dev/null || true' EXIT

# 📌 Only the `[workspace.package]` version line changes; every crate
# inherits it, and Cargo.lock follows from `cargo update --workspace`.
awk -v version="${version}" '
    /^\[workspace\.package\]/ { section = 1 }
    /^\[/ && !/^\[workspace\.package\]/ { section = 0 }
    section && !done && /^version = / { print "version = \"" version "\""; done = 1; next }
    { print }
' Cargo.toml >Cargo.toml.release
mv Cargo.toml.release Cargo.toml
cargo update --quiet --workspace --offline

changed="$(git diff --name-only | sort | tr '\n' ' ')"
[[ "${changed}" == "Cargo.lock Cargo.toml " ]] \
    || fail "the version change touched unexpected files: ${changed}"

git commit --quiet --all -m "🔖 chore(release): set version ${version}"
# 🧾 `--cleanup=verbatim` keeps the CHANGELOG's `###` headings, which the
# default cleanup would strip as comment lines.
git tag --annotate --cleanup=verbatim --file "${notes_file}" "v${version}"
release_sha="$(git rev-parse HEAD)"

cat <<EOF

🔖 Created release commit ${release_sha:0:10} (parent ${local_sha:0:10}) and tag v${version}.
   ${base} is unchanged and still says 0.0.0; the release commit is reachable only from the tag.

Review it:
    git show --stat v${version}

Publish it (pushing the tag pushes the commit it points at):
    git push ${remote} v${version}

Or discard it:
    git tag -d v${version}
EOF
