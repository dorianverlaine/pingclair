#!/usr/bin/env bash
# Focused re-run of just the large-body (20MB) gzip stress test — the one
# that exposed bug #9 (static-file compression with no cache). Used to
# verify the fix: pingclair should now finish in ~20s like nginx/caddy
# instead of grinding for 16 minutes.
set -euo pipefail
cd "$(dirname "$0")/.."

RESULTS_DIR="${1:-results/largebody_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$RESULTS_DIR"
HOST_HDR="Host: bench.local"
SERVERS=(pingclair nginx caddy)

port_for() { case "$1" in pingclair) echo 18080;; nginx) echo 18081;; caddy) echo 18082;; esac; }
log() { echo "[$(date +%H:%M:%S)] $*"; }

wait_healthy() {
    local port=$1
    for _ in $(seq 1 30); do
        curl -sf -o /dev/null -H "$HOST_HDR" "http://127.0.0.1:${port}/small.txt" && return 0
        sleep 1
    done
    return 1
}

log "Starting stack..."
docker compose up -d
for name in "${SERVERS[@]}"; do wait_healthy "$(port_for "$name")"; done
log "All healthy."

for name in "${SERVERS[@]}"; do
    port=$(port_for "$name")
    mem_out="${RESULTS_DIR}/${name}_large_gzip_memory.tsv"
    echo -e "container\tmem_usage\tcpu_pct" > "$mem_out"
    (
        for _ in $(seq 1 25); do
            docker stats --no-stream --format '{{.Container}}\t{{.MemUsage}}\t{{.CPUPerc}}' \
                "pingclair-bench-${name}-1" >> "$mem_out" 2>/dev/null || true
            sleep 1
        done
    ) &
    sampler=$!
    log "=== ${name}: wrk -t2 -c20 -d20s /large.html (gzip) ==="
    wrk -t2 -c20 -d20s --latency -H "$HOST_HDR" -H "Accept-Encoding: gzip" \
        "http://127.0.0.1:${port}/large.html" | tee "${RESULTS_DIR}/${name}_large_gzip_c20.txt"
    wait "$sampler" || true
done

log "Done. Results in ${RESULTS_DIR}"
docker compose down
