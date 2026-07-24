#!/usr/bin/env bash
# Local Docker-bridge benchmark matrix: pingclair vs nginx vs caddy.
#
# Methodology: each server runs in its own container on a bridge network,
# capped at 2 CPUs / 512MB (see docker-compose.yml). wrk runs on the host
# against each container's published port in turn — never more than one
# server under test at a time, so there's no cross-server CPU contention
# on the host's 8 cores. Host header is faked via -H since we hit
# localhost:<port> directly rather than resolving bench.local.
#
# Usage: ./run_local_matrix.sh [results_dir]
set -euo pipefail
cd "$(dirname "$0")/.."

RESULTS_DIR="${1:-results/$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$RESULTS_DIR"
HOST_HDR="Host: bench.local"
DURATION=15s
THREADS=4
CONNS_LIST=(50 200 500)

SERVERS=(pingclair nginx caddy)

# macOS ships bash 3.2 (no associative arrays), so map name -> port with a
# plain function instead of `declare -A` to keep this portable.
port_for() {
    case "$1" in
        pingclair) echo 18080 ;;
        nginx)     echo 18081 ;;
        caddy)     echo 18082 ;;
    esac
}

log() { echo "[$(date +%H:%M:%S)] $*"; }

wait_healthy() {
    local port=$1 name=$2
    for _ in $(seq 1 30); do
        if curl -sf -o /dev/null -H "$HOST_HDR" "http://127.0.0.1:${port}/small.txt"; then
            return 0
        fi
        sleep 1
    done
    log "❌ ${name} never became healthy on port ${port}"
    return 1
}

run_wrk() {
    # label distinguishes otherwise-identical (path,conns) runs — e.g. the
    # plain vs gzip static-file passes both hit /small.txt and would
    # otherwise clobber each other's result file.
    local name=$1 port=$2 path=$3 conns=$4 label=$5 extra_hdr=${6:-}
    local out="${RESULTS_DIR}/${name}_${label}_c${conns}.txt"
    local hdrs=(-H "$HOST_HDR")
    [[ -n "$extra_hdr" ]] && hdrs+=(-H "$extra_hdr")
    log "wrk -t${THREADS} -c${conns} -d${DURATION} ${name}${path} [${label}] ${extra_hdr}"
    wrk -t"$THREADS" -c"$conns" -d"$DURATION" --latency "${hdrs[@]}" \
        "http://127.0.0.1:${port}${path}" | tee "$out"
}

memory_sample() {
    local container=$1 out=$2
    docker stats --no-stream --format '{{.Container}}\t{{.MemUsage}}\t{{.CPUPerc}}' "$container" >> "$out" 2>/dev/null || true
}

log "Building and starting all three servers + shared backend..."
docker compose build pingclair
docker compose up -d

for name in "${SERVERS[@]}"; do
    wait_healthy "$(port_for "$name")" "$name"
done
log "All servers healthy. Starting matrix."

# --- 1. Static file, 1KB, no compression requested ---
for name in "${SERVERS[@]}"; do
    for c in "${CONNS_LIST[@]}"; do
        run_wrk "$name" "$(port_for "$name")" "/small.txt" "$c" "static_plain"
    done
done

# --- 2. Static file, 1KB, gzip requested ---
for name in "${SERVERS[@]}"; do
    for c in "${CONNS_LIST[@]}"; do
        run_wrk "$name" "$(port_for "$name")" "/small.txt" "$c" "static_gzip" "Accept-Encoding: gzip"
    done
done

# --- 3. Reverse proxy passthrough ---
for name in "${SERVERS[@]}"; do
    for c in "${CONNS_LIST[@]}"; do
        run_wrk "$name" "$(port_for "$name")" "/proxy/" "$c" "proxy"
    done
done

# --- 4. Large-body gzip stress test (the exact P0 OOM scenario) ---
# Lower concurrency, longer duration; we care about memory ceiling and
# correctness (no crash / no 5xx) more than raw RPS here.
log "Large-body (20MB) gzip stress test — sampling container memory throughout."
for name in "${SERVERS[@]}"; do
    mem_out="${RESULTS_DIR}/${name}_large_gzip_memory.tsv"
    echo -e "container\tmem_usage\tcpu_pct" > "$mem_out"
    (
        for _ in $(seq 1 20); do
            memory_sample "pingclair-bench-${name}-1" "$mem_out"
            sleep 1
        done
    ) &
    SAMPLER_PID=$!
    wrk -t2 -c20 -d20s --latency -H "$HOST_HDR" -H "Accept-Encoding: gzip" \
        "http://127.0.0.1:$(port_for "$name")/large.html" | tee "${RESULTS_DIR}/${name}_large_gzip_c20.txt"
    wait "$SAMPLER_PID" || true
done

log "Done. Results in ${RESULTS_DIR}"
log "Bringing the stack down..."
docker compose down
