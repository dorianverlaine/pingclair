#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

# 🛰️ Install apt packages without letting one bad mirror break the build (#59).
#
# Why this is not a plain `apt-get update && apt-get install`:
#
#   * `Acquire::Retries` retries a single file download. It does nothing when
#     the **mirror** is serving a corrupt index, so every retry inside one
#     `apt-get update` fails and the update is over. The whole update is
#     retried here instead.
#   * An update that dies — at a deadline, or on a hash mismatch — leaves the
#     index **partially written**, and the install then exits 100 in a fifth of
#     a second. That reads like a missing package rather than a mirror fault,
#     which is how a five-minute diagnosis becomes an hour.
#
# 🎯 So the invariant is: `apt-get install` runs only after an update that
# finished, and when no attempt finishes the failure says what it was. On
# 2026-09-11 `archive.ubuntu.com` served unusable indexes and this shape put a
# red required gate on a commit that touched only Markdown.
#
# Usage: apt-retry <package> [package...]

set -eu

attempts=3
attempt=1

while :; do
    if apt-get -o Acquire::Retries=3 update; then
        break
    fi

    if [ "${attempt}" -ge "${attempts}" ]; then
        echo "❌ apt-get update failed ${attempt} times in a row: the mirror is serving unusable indexes, not a missing package" >&2
        exit 1
    fi

    delay=$((attempt * 5))
    echo "⏳ apt-get update failed (attempt ${attempt}/${attempts}); retrying in ${delay}s"
    sleep "${delay}"
    attempt=$((attempt + 1))
done

apt-get -o Acquire::Retries=3 install -y --no-install-recommends "$@"

# 🔻 Keep the index out of the layer, as the one-liner did.
rm -rf /var/lib/apt/lists/*
