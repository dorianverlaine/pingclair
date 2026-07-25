#!/usr/bin/env bash
# On-box benchmark matrix: pingclair vs nginx vs caddy, all on one host.
#
# Unlike run_remote_matrix.sh (which drives wrk from a laptop over the
# network and is therefore network-bound), this script runs entirely ON
# the benchmark host: each candidate listens on 127.0.0.1:8080 in turn,
# wrk hits it over loopback. Same conditions for every server; only one
# server under test at a time.
#
# Expects (see provision commands at the bottom of this file):
#   /root/bench/html/{small.txt,large.html}   payloads
#   /root/bench/configs/{Pingclairfile,nginx.conf,Caddyfile,backend.conf}
#   /root/pingclair/target/release/pingclair  release binary
#   nginx, caddy, wrk installed
#
# Usage: ./run_onbox_matrix.sh [results_dir]
set -euo pipefail

BENCH=/root/bench
RESULTS_DIR="${1:-$BENCH/results/$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$RESULTS_DIR"
HOST_HDR="Host: bench.local"
DURATION=15s
THREADS=2            # the box has 2 vCPU, shared with the server under test
CONNS_LIST=(50 200 500)

log() { echo "[$(date +%H:%M:%S)] $*"; }

wait_healthy() {
    for _ in $(seq 1 50); do
        if curl -sf -o /dev/null -H "$HOST_HDR" "http://127.0.0.1:8080/small.txt"; then
            return 0
        fi
        sleep 0.2
    done
    log "❌ $1 never became healthy"; return 1
}

run_wrk() { # name path conns label extra_hdr
    local name=$1 path=$2 conns=$3 label=$4 extra_hdr=${5:-}
    local out="${RESULTS_DIR}/${name}_${label}_c${conns}.txt"
    local hdrs=(-H "$HOST_HDR")
    [[ -n "$extra_hdr" ]] && hdrs+=(-H "$extra_hdr")
    log "wrk -t${THREADS} -c${conns} -d${DURATION} ${name}${path} [${label}]"
    wrk -t"$THREADS" -c"$conns" -d"$DURATION" --latency "${hdrs[@]}" \
        "http://127.0.0.1:8080${path}" | tee "$out"
}

rss_of() { # pattern -> total RSS in KiB of all matching processes
    pgrep -f "$1" | xargs -r ps -o rss= -p | awk '{s+=$1} END {print s+0}'
}

large_body_test() { # name rss_pattern
    local name=$1 pattern=$2
    log "=== ${name}: large body 20MB gzip -c20 (memory sampled) ==="
    ( MAX=0
      for _ in $(seq 1 400); do
          RSS=$(rss_of "$pattern")
          [ "$RSS" -gt "$MAX" ] && { MAX=$RSS; echo "$MAX" > "${RESULTS_DIR}/${name}_largebody_peak_rss_kb"; }
          sleep 0.1
      done ) &
    local sampler=$!
    wrk -t"$THREADS" -c20 -d20s --latency -H "$HOST_HDR" -H "Accept-Encoding: gzip" \
        "http://127.0.0.1:8080/large.html" | tee "${RESULTS_DIR}/${name}_largebody_c20.txt"
    kill "$sampler" 2>/dev/null || true
    log "   peak RSS: $(( $(cat "${RESULTS_DIR}/${name}_largebody_peak_rss_kb") / 1024 )) MiB"
}

matrix() { # name
    local name=$1
    for c in "${CONNS_LIST[@]}"; do run_wrk "$name" /small.txt "$c" static_plain; done
    for c in "${CONNS_LIST[@]}"; do run_wrk "$name" /small.txt "$c" static_gzip "Accept-Encoding: gzip"; done
    for c in "${CONNS_LIST[@]}"; do run_wrk "$name" /proxy/ "$c" proxy; done
}

stop_all() {
    pkill -f 'release/pingclair run' 2>/dev/null || true
    [ -f "$BENCH/nginx_under_test.pid" ] && kill "$(cat "$BENCH/nginx_under_test.pid")" 2>/dev/null || true
    pkill -f 'caddy run --config' 2>/dev/null || true
    sleep 1
}

# ---------- backend (shared, unmeasured) ----------
log "==> starting shared backend on 127.0.0.1:9000"
pkill -f 'nginx.*backend.conf' 2>/dev/null || true
sleep 1
nginx -c "$BENCH/configs/backend.conf"
curl -sf http://127.0.0.1:9000/ >/dev/null && log "   backend OK"

# ---------- pingclair ----------
log "==> pingclair"
stop_all
cd "$BENCH"
PINGCLAIR_TLS_STORE=$BENCH/tls-store nohup /root/pingclair/target/release/pingclair \
    run "$BENCH/configs/Pingclairfile" > "$BENCH/pingclair.log" 2>&1 &
wait_healthy pingclair
matrix pingclair
large_body_test pingclair 'release/pingclair run'
stop_all

# ---------- nginx ----------
log "==> nginx"
nginx -c "$BENCH/configs/nginx.conf"
wait_healthy nginx
matrix nginx
large_body_test nginx 'nginx: worker'
stop_all

# ---------- caddy ----------
log "==> caddy"
nohup caddy run --config "$BENCH/configs/Caddyfile" > "$BENCH/caddy.log" 2>&1 &
wait_healthy caddy
matrix caddy
large_body_test caddy 'caddy run --config'
stop_all

log "==> done. raw results in $RESULTS_DIR"
