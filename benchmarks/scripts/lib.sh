#!/usr/bin/env bash
# 📏 Rules every benchmark row has to pass before it counts as a number.
#
# 🤡 This file exists because the harness produced *successful-looking wrong
# numbers* three separate ways, and all three were caught after the fact by
# reading the output rather than by the harness refusing:
#
#   1. Measuring while the machine was busy. A background Rosetta x86 release
#      build made every round monotonically worse — proxy H2 went 53,836 →
#      39,447 → 36,172 rps — and nothing in the table said the machine was not
#      idle.
#   2. Rows that were entirely errors. `h2load -H "host: …"` cannot set an
#      HTTP/1.1 Host, which comes from the URL authority, so a vhost mismatch
#      turned all 30,000 requests into 4xx. The comparison point has no virtual
#      hosts and answered 200, so the table showed us winning by four times.
#      Both sides were measuring the cost of a 404.
#   3. Comparing runs that differed in more than the machine. Concurrency,
#      client threads and container CPU all varied between two hosts and the
#      difference was read as a generational effect.
#
# One copy, because the fix for (2) was written into `run_local_baseline.sh`
# alone and the other three harnesses kept the defect — which is the same shape
# as the bug: a rule enforced in one place and forgotten in the others.

# 🔇 Refuses to measure on a machine that is not idle.
#
# The load average is compared against the CPU count rather than a fixed number,
# because "busy" means "competing for these cores". Override with
# `BENCH_ALLOW_BUSY=1` when you know what the other load is and want the run
# anyway — the point is that it becomes a decision, not an accident.
require_quiet_machine() {
    local cores load busy
    cores="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
    load="$(uptime | sed -E 's/.*load averages?: *([0-9.]+).*/\1/')"
    busy="$(awk -v l="${load:-0}" -v c="${cores:-1}" 'BEGIN { print (l > c * 0.3) ? 1 : 0 }')"
    if [[ "${busy}" == "1" ]]; then
        if [[ "${BENCH_ALLOW_BUSY:-0}" == "1" ]]; then
            echo "⚠️  Load ${load} on ${cores} cores; measuring anyway (BENCH_ALLOW_BUSY=1)." >&2
            return 0
        fi
        echo "🚫 Refusing to measure: load average ${load} on ${cores} cores." >&2
        echo "   A busy machine produces numbers that look fine and decay per round." >&2
        echo "   Wait for it to settle, or set BENCH_ALLOW_BUSY=1 deliberately." >&2
        return 1
    fi
    return 0
}

# 🚫 A row that did not fully succeed is not a slow row, it is not a row.
#
# Prints the verdict and returns non-zero when the run must be voided, so a
# caller can skip recording it. `h2load` reports the count directly; `wrk` only
# prints `Non-2xx or 3xx responses` when there were some, so its absence is the
# success case.
assert_h2load_clean() {
    local file=$1 label=$2 expected=$3
    local succeeded
    succeeded="$(awk '/^requests:/ {print $8}' "${file}")"
    if [[ "${succeeded}" != "${expected}" ]]; then
        echo "   🚫 VOID ${label} — ${succeeded:-0}/${expected} succeeded" >&2
        return 1
    fi
    return 0
}

assert_wrk_clean() {
    local file=$1 label=$2
    local non2xx errors
    non2xx="$(awk '/Non-2xx or 3xx responses:/ {print $NF}' "${file}")"
    if [[ -n "${non2xx}" && "${non2xx}" != "0" ]]; then
        echo "   🚫 VOID ${label} — ${non2xx} non-2xx/3xx responses" >&2
        return 1
    fi
    # 🔌 A socket error is not a slow request either; the line is only printed
    # when at least one occurred.
    errors="$(awk '/Socket errors:/ {print}' "${file}")"
    if [[ -n "${errors}" ]] && ! echo "${errors}" | grep -q 'connect 0, read 0, write 0, timeout 0'; then
        echo "   🚫 VOID ${label} — ${errors}" >&2
        return 1
    fi
    if ! grep -q 'requests in' "${file}"; then
        echo "   🚫 VOID ${label} — no request total in the output" >&2
        return 1
    fi
    return 0
}

# 🔐 The TLS 1.3 suite both candidates must negotiate.
#
# 🤡 It was never pinned, and on a CPU without AES-NI the two servers picked
# differently: Pingclair (BoringSSL) got `TLS_CHACHA20_POLY1305_SHA256` and the
# comparison point (OpenSSL) got `TLS_AES_256_GCM_SHA384`. Those are very
# different amounts of work without hardware AES, so every TLS ratio measured on
# that machine had a second uncontrolled variable — and the reading was
# ambiguous in both directions at once: neither "we lost anyway" nor "we won
# fairly" could be claimed.
#
# ChaCha20 by default because it is fast in software on every machine, so the
# comparison is not dominated by an instruction one of them lacks. What matters
# is that both sides use the same one; override to measure something else.
BENCH_TLS13_CIPHER="${BENCH_TLS13_CIPHER:-TLS_CHACHA20_POLY1305_SHA256}"

# 🔐 The h2load arguments that pin the suite.
tls13_pin_args() {
    printf '%s' "--tls13-ciphers=${BENCH_TLS13_CIPHER}"
}

# 🔐 Voids a row whose handshake did not use the pinned suite.
#
# Pinning alone is not enough to trust: a client that silently ignores the flag,
# or a server with no suite in common, would fall back and the number would look
# ordinary. h2load prints `Cipher:` in every run, so the check is free.
assert_cipher_pinned() {
    local file=$1 label=$2
    local negotiated
    negotiated="$(awk '/^Cipher:/ {print $2}' "${file}")"
    if [[ -z "${negotiated}" ]]; then
        echo "   🚫 VOID ${label} — no cipher reported; the handshake is unverified" >&2
        return 1
    fi
    if [[ "${negotiated}" != "${BENCH_TLS13_CIPHER}" ]]; then
        echo "   🚫 VOID ${label} — negotiated ${negotiated}, not the pinned ${BENCH_TLS13_CIPHER}" >&2
        return 1
    fi
    return 0
}
