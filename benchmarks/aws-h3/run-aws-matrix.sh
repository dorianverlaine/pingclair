#!/usr/bin/env bash
# 🛰️ Orchestrates the AWS H1/H2/H3 comparison matrix for pingclair, nginx,
# caddy, and pingap on two Linux instances in one VPC subnet.
#
# 🔑 Required environment (no personal defaults are baked into the repo):
#   AWS_SSH_KEY      — path to the SSH private key for ubuntu@
#   AWS_SERVER_PUB   — public address of the server (candidate) host
#   AWS_SERVER_PRIV  — private address of the server host, used by the client
#   AWS_CLIENT_PUB   — public address of the client (load-generator) host
#
# ▶️ Optional arguments:
#   $1 — result directory (default: ./aws-run next to this script)
#   $2 — resume from a 1-based segment number (see the numbered calls below)
set -uo pipefail

KEY="${AWS_SSH_KEY:?AWS_SSH_KEY is required}"
SERVER_PUB="${AWS_SERVER_PUB:?AWS_SERVER_PUB is required}"
SERVER_PRIV="${AWS_SERVER_PRIV:?AWS_SERVER_PRIV is required}"
CLIENT_PUB="${AWS_CLIENT_PUB:?AWS_CLIENT_PUB is required}"
OUT_DIR="${1:-$(cd "$(dirname "$0")" && pwd)/aws-run}"
mkdir -p "${OUT_DIR}"

# 🧭 Completed earlier segments are kept as-is when resuming.
START_SEGMENT="${2:-1}"

ssh_run() {
    # 📡 Runs a remote command and streams its stdout back.
    ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 \
        -i "${KEY}" "$1" "${@:2}"
}

start_candidate() {
    local candidate="$1" mode="$2"
    ssh_run "ubuntu@${SERVER_PUB}" \
        "sudo bash /home/ubuntu/bench/configs/start-candidate.sh ${candidate} ${mode}" \
        >"${OUT_DIR}/start-${candidate}-${mode}.log" 2>&1 || return 1
    sleep 3
}

candidate_version() {
    local candidate="$1"
    case "${candidate}" in
        pingclair)
            ssh_run "ubuntu@${SERVER_PUB}" \
                "docker exec bench-candidate sh -c 'sha256sum /usr/local/bin/pingclair; pingclair --version 2>&1 | head -2'" \
                >"${OUT_DIR}/version-${candidate}.txt" 2>&1 || true
            ;;
        nginx)
            ssh_run "ubuntu@${SERVER_PUB}" \
                "docker exec bench-candidate nginx -V 2>&1 | head -2; docker inspect --format '{{.Image}}' bench-candidate" \
                >"${OUT_DIR}/version-${candidate}.txt" 2>&1 || true
            ;;
        caddy)
            ssh_run "ubuntu@${SERVER_PUB}" \
                "docker exec bench-candidate caddy version; docker inspect --format '{{.Image}}' bench-candidate" \
                >"${OUT_DIR}/version-${candidate}.txt" 2>&1 || true
            ;;
        pingap)
            ssh_run "ubuntu@${SERVER_PUB}" \
                "docker inspect --format '{{.Image}} {{.Config.Image}}' bench-candidate" \
                >"${OUT_DIR}/version-${candidate}.txt" 2>&1 || true
            ;;
    esac
}

readiness() {
    # ✅ Verifies H1 and TLS listeners before spending time on the matrix.
    local code_h1 code_tls
    code_h1="$(ssh_run "ubuntu@${CLIENT_PUB}" \
        "curl -s -H 'Host: bench.local' -o /dev/null -w '%{http_code}' http://${SERVER_PRIV}:8080/small.txt")"
    code_tls="$(ssh_run "ubuntu@${CLIENT_PUB}" \
        "curl -sk --resolve h3.local:8443:${SERVER_PRIV} -o /dev/null -w '%{http_code}' https://h3.local:8443/small.txt")"
    if [[ "${code_h1}" != "200" || "${code_tls}" != "200" ]]; then
        echo "readiness failed: h1=${code_h1} tls=${code_tls}" >&2
        return 1
    fi
}

h3_smoke() {
    # 🔥 Small warm-up that also proves the QUIC listener answers.
    ssh_run "ubuntu@${CLIENT_PUB}" \
        "timeout 60 docker run --rm goodideal/nghttp2:latest h2load \
            -t1 -c5 -m5 -n200 --alpn-list=h3 --connect-to=${SERVER_PRIV}:8443 \
            https://h3.local:8443/small.txt" \
        >/dev/null 2>&1
}

run_bench() {
    # 📊 Runs one benchmark on the client and stores its raw output.
    local label="$1" remote_cmd="$2"
    echo "--- ${label} $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    # ⏱️ Each remote command carries its own timeout, so no host-side wrapper
    # (macOS has no `timeout` binary); ssh itself bounds connect time.
    if ! ssh_run "ubuntu@${CLIENT_PUB}" "${remote_cmd}" \
        >"${OUT_DIR}/${label}.txt" 2>&1; then
        echo "FAILED ${label}" | tee -a "${OUT_DIR}/failed.txt"
    fi
}

benchmark_candidate() {
    local candidate="$1" mode="$2" round="$3"
    local prefix="${round}-${candidate}-${mode}"
    local has_h3=1
    if [[ "${candidate}" == pingap ]]; then
        # 🚫 Pingap has no HTTP/3 listener; its H3 rows would just time out.
        has_h3=0
    fi
    local small_path="/small.txt" large_path="/large.bin"
    if [[ "${mode}" == proxy ]]; then
        small_path="/proxy/small.txt"
        large_path="/proxy/large.bin"
    fi

    echo "### ${prefix} starting at $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    start_candidate "${candidate}" "${mode}" || { echo "FAILED start ${prefix}" >>"${OUT_DIR}/failed.txt"; return 1; }
    candidate_version "${candidate}"
    readiness || { echo "FAILED readiness ${prefix}" >>"${OUT_DIR}/failed.txt"; return 1; }

    # 🔌 HTTP/1.1 on the plaintext listener.
    run_bench "${prefix}-wrk-h1-small" \
        "timeout 60 wrk -t2 -c100 -d30s --latency -H 'Host: bench.local' http://${SERVER_PRIV}:8080${small_path}"

    # ⚡ HTTP/2 and HTTPS/1.1 on the TLS listener. Large-file concurrency is
    # capped at 50×4 because pingclair buffers sub-5 MiB files in memory and
    # 2,000 in-flight 1 MiB responses OOM a t3.small (2 GiB) host.
    run_bench "${prefix}-h2load-h2-small" \
        "timeout 90 h2load -t2 -c100 -m20 -n100000 --alpn-list=h2 --connect-to=${SERVER_PRIV}:8443 https://h3.local:8443${small_path}"
    run_bench "${prefix}-h2load-h2-large" \
        "timeout 180 h2load -t2 -c50 -m4 -n5000 --alpn-list=h2 --connect-to=${SERVER_PRIV}:8443 https://h3.local:8443${large_path}"
    run_bench "${prefix}-h2load-h1s-small" \
        "timeout 90 h2load -t2 -c100 -n100000 --alpn-list=http/1.1 --connect-to=${SERVER_PRIV}:8443 https://h3.local:8443${small_path}"
    run_bench "${prefix}-h2load-h1s-large" \
        "timeout 180 h2load -t2 -c50 -n5000 --alpn-list=http/1.1 --connect-to=${SERVER_PRIV}:8443 https://h3.local:8443${large_path}"

    if [[ "${has_h3}" == 1 ]]; then
        # 🚀 HTTP/3 via the ngtcp2-enabled h2load image.
        run_bench "${prefix}-h2load-h3-small" \
            "timeout 120 docker run --rm goodideal/nghttp2:latest h2load \
                -t2 -c100 -m20 -n100000 --alpn-list=h3 --connect-to=${SERVER_PRIV}:8443 \
                https://h3.local:8443${small_path}"
        run_bench "${prefix}-h2load-h3-large" \
            "timeout 240 docker run --rm goodideal/nghttp2:latest h2load \
                -t2 -c50 -m4 -n5000 --alpn-list=h3 --connect-to=${SERVER_PRIV}:8443 \
                https://h3.local:8443${large_path}"

        # ✈️ aioquic parity rows (the published harness).
        run_bench "${prefix}-aio-reuse-small" \
            "timeout 90 /home/ubuntu/h3-venv/bin/python /home/ubuntu/bench/h3_bench.py \
                --host ${SERVER_PRIV} --port 8443 --server-name h3.local \
                --path ${small_path} --mode reuse --requests 20000 --concurrency 20 \
                --expect-bytes 1024"
        run_bench "${prefix}-aio-pipeline-small" \
            "timeout 120 /home/ubuntu/h3-venv/bin/python /home/ubuntu/bench/h3_bench_pipeline.py \
                --host ${SERVER_PRIV} --port 8443 --server-name h3.local \
                --path ${small_path} --requests 30000 --concurrency 20 --streams 10 \
                --expect-bytes 1024"
    else
        # 🏷️ Records why pingap rows are absent so the summarizer can explain.
        for scenario in h2load-h3-small h2load-h3-large aio-reuse-small aio-pipeline-small; do
            rm -f "${OUT_DIR}/${prefix}-${scenario}.txt"
            echo "skipped: pingap has no HTTP/3 listener" \
                >"${OUT_DIR}/${prefix}-${scenario}.txt"
        done
    fi
}

run_segment() {
    # 🧭 Runs one numbered matrix segment unless it belongs to an earlier,
    # already-completed part of the run.
    local segment="$1"
    shift
    if (( segment >= START_SEGMENT )); then
        benchmark_candidate "$@"
    fi
}

echo "matrix started $(date -u '+%Y-%m-%dT%H:%M:%SZ')" | tee "${OUT_DIR}/failed.txt"

# Round 1: forward order.
run_segment 1 pingclair static 1
run_segment 2 nginx static 1
run_segment 3 caddy static 1
run_segment 4 pingclair proxy 1
run_segment 5 nginx proxy 1
run_segment 6 caddy proxy 1
run_segment 7 pingap proxy 1

# Round 2: reverse order to cancel drift.
run_segment 8 pingap proxy 2
run_segment 9 caddy proxy 2
run_segment 10 nginx proxy 2
run_segment 11 pingclair proxy 2
run_segment 12 caddy static 2
run_segment 13 nginx static 2
run_segment 14 pingclair static 2

echo "matrix finished $(date -u '+%Y-%m-%dT%H:%M:%SZ')" | tee -a "${OUT_DIR}/failed.txt"
