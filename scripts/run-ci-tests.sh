#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

# 🎲 Run the nextest suite with the known-flaky retry policy.
#
# 🔗 The policy itself lives in `retry-known-flakes.sh`, which the nextest shards
# use too: the same known flake should not be retried for the suite and fatal for
# a partition.
#
# 📌 Arguments are passed straight to nextest, which is how CI names the host
# target explicitly: without `--target`, cargo puts a bare target directory
# (`…/ci-test`) beside the archive job's (`…/x86_64-unknown-linux-gnu/ci-test`),
# and the two then share no Rust artifacts at all.

set -Eeuo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly repository_root

exec "${repository_root}/scripts/retry-known-flakes.sh" just test "$@"
