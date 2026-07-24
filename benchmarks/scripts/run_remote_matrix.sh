#!/usr/bin/env bash
# Remote real-network benchmark: client = this Mac (over the Shadowrocket
# tunnel — see benchmarks/README.md for why absolute latency numbers here
# are inflated but the pingclair/nginx/caddy *comparison* is still valid,
# since every candidate is measured over the identical path), server = the
# Aliyun Shenzhen VPS (2 vCPU / 1.6GB).
#
# Only one candidate is ever bound to :8080 on the VPS at a time — the box
# is too small to host all three concurrently without skewing results.
# Concurrency is deliberately modest given the 2 vCPU ceiling.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST_ALIAS="aqeonet-aliyun-shenzhen"
VPS_IP="$(ssh -G "$HOST_ALIAS" | awk '/^hostname /{print $2}')"
RESULTS_DIR="${1:-results/remote_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$RESULTS_DIR"

HOST_HDR="Host: bench.local"
DURATION=15s
THREADS=2
CONNS_LIST=(20 50 100) # kept modest: 2 vCPU on the server

log() { echo "[$(date +%H:%M:%S)] $*"; }

remote_stop_all() {
    ssh "$HOST_ALIAS" "
        pkill -f 'pingclair run' 2>/dev/null || true
        pkill -f 'nginx.*configs/nginx.conf' 2>/dev/null || true
        pkill -f 'caddy run' 2>/dev/null || true
        sleep 1
    " || true
}

remote_start() {
    local name=$1
    case "$name" in
        pingclair)
            ssh "$HOST_ALIAS" "cd /root/pingclair && nohup ./target/release/pingclair run /root/bench/configs/Pingclairfile > /root/bench/pingclair.log 2>&1 & disown"
            ;;
        nginx)
            ssh "$HOST_ALIAS" "nginx -c /root/bench/configs/nginx.conf"
            ;;
        caddy)
            ssh "$HOST_ALIAS" "nohup caddy run --config /root/bench/configs/Caddyfile --adapter caddyfile > /root/bench/caddy.log 2>&1 & disown"
            ;;
    esac
}

wait_healthy() {
    for _ in $(seq 1 30); do
        if curl -sf -o /dev/null -H "$HOST_HDR" "http://${VPS_IP}:8080/small.txt"; then
            return 0
        fi
        sleep 1
    done
    log "❌ server never became healthy"
    return 1
}

run_wrk() {
    local name=$1 path=$2 conns=$3 extra_hdr=${4:-}
    local out="${RESULTS_DIR}/${name}_${path//\//_}_c${conns}.txt"
    local hdrs=(-H "$HOST_HDR")
    [[ -n "$extra_hdr" ]] && hdrs+=(-H "$extra_hdr")
    log "wrk -t${THREADS} -c${conns} -d${DURATION} ${name}${path} ${extra_hdr}"
    wrk -t"$THREADS" -c"$conns" -d"$DURATION" --latency "${hdrs[@]}" \
        "http://${VPS_IP}:8080${path}" | tee "$out"
}

remote_memory_sample() {
    local name=$1 out=$2
    ssh "$HOST_ALIAS" "ps -C pingclair,nginx,caddy -o comm,rss,pcpu --no-headers 2>/dev/null" >> "$out" 2>/dev/null || true
}

log "VPS resolved to ${VPS_IP}"
log "Checking backend is up..."
ssh "$HOST_ALIAS" "curl -sf http://127.0.0.1:9000/ >/dev/null" || {
    log "❌ backend not running — run provision_remote.sh first"
    exit 1
}

for name in pingclair nginx caddy; do
    log "=== ${name} ==="
    remote_stop_all
    remote_start "$name"
    wait_healthy

    for c in "${CONNS_LIST[@]}"; do
        run_wrk "$name" "/small.txt" "$c"
    done
    for c in "${CONNS_LIST[@]}"; do
        run_wrk "$name" "/small.txt" "$c" "Accept-Encoding: gzip"
    done
    for c in "${CONNS_LIST[@]}"; do
        run_wrk "$name" "/proxy/" "$c"
    done

    # Large-body gzip stress test with memory sampling
    mem_out="${RESULTS_DIR}/${name}_large_gzip_memory.tsv"
    echo -e "comm\trss_kb\tcpu_pct" > "$mem_out"
    (
        for _ in $(seq 1 15); do
            remote_memory_sample "$name" "$mem_out"
            sleep 1
        done
    ) &
    SAMPLER_PID=$!
    wrk -t2 -c10 -d15s --latency -H "$HOST_HDR" -H "Accept-Encoding: gzip" \
        "http://${VPS_IP}:8080/large.html" | tee "${RESULTS_DIR}/${name}_large_gzip_c10.txt"
    wait "$SAMPLER_PID" || true

    remote_stop_all
done

log "Done. Results in ${RESULTS_DIR}"
