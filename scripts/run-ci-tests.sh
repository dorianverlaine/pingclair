#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

# 🧪 Run the nextest suite once; every enabled test must pass.
#
# 📌 Arguments are passed straight to nextest, which is how CI names the host
# target explicitly: without `--target`, cargo puts a bare target directory
# (`…/ci-test`) beside the archive job's (`…/x86_64-unknown-linux-gnu/ci-test`),
# and the two then share no Rust artifacts at all.

set -Eeuo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly repository_root

cd "${repository_root}"
exec just test "$@"
