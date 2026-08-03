#!/usr/bin/env bash
# 🔐 Generates a 30-day self-signed ECDSA P-256 certificate for `h3.local`
# and writes `bench.crt` + `bench.key` into the current directory. The key is
# a benchmark-only artifact; never reuse it outside a throwaway environment.
set -euo pipefail

openssl req -x509 \
    -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -days 30 -nodes \
    -subj "/CN=h3.local" \
    -addext "subjectAltName=DNS:h3.local" \
    -keyout bench.key \
    -out bench.crt

openssl x509 -in bench.crt -noout -subject -dates
