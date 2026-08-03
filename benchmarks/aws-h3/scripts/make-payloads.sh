#!/usr/bin/env bash
# 📦 Generates the benchmark payload tree (1 KiB and 1 MiB files, plus the
# `/proxy/` copies) into the given directory, defaulting to `./www`.
set -euo pipefail

dest="${1:-./www}"
mkdir -p "${dest}/proxy"

# 📝 Small file: repeated line so content is stable and human-readable.
yes 'pingclair-benchmark-payload' | head -n 64 >"${dest}/small.txt"
truncate -s 1048576 "${dest}/large.bin"
cp "${dest}/small.txt" "${dest}/proxy/small.txt"
cp "${dest}/large.bin" "${dest}/proxy/large.bin"

ls -l "${dest}" "${dest}/proxy"
