#!/usr/bin/env bash
# 📊 Local three-way baseline: Pingclair vs nginx vs pingap, on OrbStack.
#
# 🎯 What this measures and what it does not. Throughput here is close to
# meaningless on its own — on a machine with headroom every candidate
# saturates something other than itself and the rows converge. The number
# that carries information is **CPU per request**, taken from the container's
# own cgroup accounting, because it is what predicts behaviour on a machine
# that has no headroom. That prediction has already been checked once: the
# 2026-08-03 local run showed +37 % CPU/request against nginx while throughput
# tied, and the same day's t3.small run turned that into a 21–26 % throughput
# gap.
#
# 🧾 The candidate is configured from a **Pingclairfile**, not JSON. The JSON
# the earlier runs used skips the Caddyfile adapter entirely, so it measured a
# shape no operator can produce — see `benchmarks/configs/pingclair/Pingclairfile.bench`
# for the four settings that turned out to differ, two of them in the
# direction that flatters us.
#
# 🗜️ The `gzip` workload is new on 2026-08-11. `h2load` and `wrk` send no
# `Accept-Encoding`, so every previous row measured a server that never
# entered its compressor — while a browser always does. On an 80-byte body
# that path currently returns 97 bytes, so it is pure loss, and it was
# invisible to the entire earlier campaign.
set -uo pipefail

out=${1:-/tmp/ab-run/results}
h2load=${H2LOAD_BIN:-$(command -v h2load || echo /opt/homebrew/bin/h2load)}
rounds=${ROUNDS:-3}

# 🧵 Client threads. The load generator and the server under test share the
# machine, so this has to be sized against the *box*, not against the
# workload. On the 8-core development Mac two client threads leave the
# 2-vCPU containers plenty; on a 2-core box one thread for the client and
# one core for the candidate is the whole machine, which is the point —
# a server with no headroom is the condition the CPU/request number exists
# to predict.
threads=${CLIENT_THREADS:-2}
conns=${CLIENT_CONNS:-50}
# 📉 Fewer requests on a slow box, or one round takes long enough that
# thermal and background drift become part of the measurement.
requests=${REQUESTS:-100000}
mkdir -p "${out}"

# 🧭 Candidate → published TLS port. Only the TLS listener is measured: it is
# the one all three implement identically, and it is what a real deployment
# serves.
cand_port() {
    case "$1" in
        bl-pc) echo 18443 ;;
        bl-nginx) echo 28443 ;;
        bl-pingap) echo 48443 ;;
    esac
}

# 📈 cgroup v2 cumulative CPU microseconds for the whole container.
cpu_usec() {
    docker exec "$1" sh -c 'awk "/usage_usec/ {print \$2}" /sys/fs/cgroup/cpu.stat' 2>/dev/null || echo 0
}

run_one() {
    local cand="$1" workload="$2" round="$3"
    local port path args
    port="$(cand_port "${cand}")"
    case "${workload}" in
        static-h2)  path=/small.txt        ; args=(-t"${threads}" -c"${conns}" -m10 -n"${requests}" --alpn-list=h2 "$(tls13_pin_args)") ;;
        static-h1s) path=/small.txt        ; args=(-t"${threads}" -c"${conns}" -n"${requests}" --alpn-list=http/1.1 "$(tls13_pin_args)") ;;
        proxy-h2)   path=/proxy/small      ; args=(-t"${threads}" -c"${conns}" -m10 -n"${requests}" --alpn-list=h2 "$(tls13_pin_args)") ;;
        proxy-h1s)  path=/proxy/small      ; args=(-t"${threads}" -c"${conns}" -n"${requests}" --alpn-list=http/1.1 "$(tls13_pin_args)") ;;
        # 🗜️ The row every earlier matrix was blind to.
        gzip-h2)    path=/small.json       ; args=(-t"${threads}" -c"${conns}" -m10 -n"${requests}" --alpn-list=h2 "$(tls13_pin_args)" -H "accept-encoding: gzip") ;;
    esac

    local dest="${out}/${cand}-${workload}-r${round}.txt"
    local before after
    before="$(cpu_usec "${cand}")"
    "${h2load}" "${args[@]}" --connect-to="127.0.0.1:${port}" \
        "https://h3.local:8443${path}" > "${dest}.tmp" 2>&1
    after="$(cpu_usec "${cand}")"
    mv "${dest}.tmp" "${dest}"
    echo "$((after - before))" > "${out}/${cand}-${workload}-cpu-r${round}.txt"

    # 🚫 A row that did not fully succeed is not a slow row, it is not a row.
    # `h2load -H "host: …"` cannot set an HTTP/1.1 Host — that comes from the
    # URL authority — so a vhost mismatch turns every request into a 404 that
    # the throughput column reports as a *win*. Measured on 2026-08-11: 30000
    # 4xx read as "four times faster than nginx". The succeeded count is the
    # only thing that caught it, so it travels beside every number.
    local rps
    rps="$(awk '/finished in/ {print $4}' "${dest}" | tr -d ',')"
    if ! assert_h2load_clean "${dest}" "${cand} ${workload} r${round}" "${requests}" \
        || ! assert_cipher_pinned "${dest}" "${cand} ${workload} r${round}"; then
        mv "${dest}" "${dest%.txt}.VOID.txt" 2>/dev/null || true
        return
    fi
    printf '   %-10s %-11s r%s  %s\n' "${cand}" "${workload}" "${round}" "${rps:-FAILED}"
}

# 🔥 One short run per candidate before anything is recorded: a cold process
# answering its first hundred requests is measuring page faults, not routing.
warmup() {
    for cand in bl-pc bl-nginx bl-pingap; do
        "${h2load}" -t1 -c5 -m5 -n2000 --alpn-list=h2 \
            --connect-to="127.0.0.1:$(cand_port "${cand}")" \
            "https://h3.local:8443/proxy/small" >/dev/null 2>&1
        "${h2load}" -t1 -c5 -m5 -n2000 --alpn-list=h2 \
            --connect-to="127.0.0.1:$(cand_port "${cand}")" \
            "https://h3.local:8443/small.txt" >/dev/null 2>&1
    done
}

echo "🔥 warmup"
warmup

# 🧭 Interleaved by round rather than grouped by candidate: a thermal or
# background-load drift then hits all three roughly equally instead of
# landing entirely on whichever one ran last.
for r in $(seq 1 "${rounds}"); do
    echo "== round ${r} =="
    for workload in static-h2 static-h1s proxy-h2 proxy-h1s gzip-h2; do
        for cand in bl-pc bl-nginx bl-pingap; do
            # 🚫 pingap serves no static files, so it has no static row.
            [[ "${workload}" == static-* || "${workload}" == gzip-* ]] \
                && [[ "${cand}" == bl-pingap ]] && continue
            run_one "${cand}" "${workload}" "${r}"
        done
    done
done

echo "✅ baseline written to ${out}"
