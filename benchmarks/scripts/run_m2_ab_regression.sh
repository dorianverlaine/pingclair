#!/usr/bin/env bash
# A/B throughput regression across the M2 guardrail work.
#
# The question is *not* "how fast is Pingclair" — that is a release-day
# question and needs a quiet, dedicated box. The question here is narrower and
# answerable today: **did seven days of guardrails make every request more
# expensive?**
#
# That matters because the new work is not opt-in. A reverse-proxy route gets a
# RouteProtection whether or not it configures `overload` or `circuit_breaker`,
# upstream selection now goes through admission, peers carry a packed group
# key, and a health-check driver polls on a timer even with no probe
# configured. None of that shows up in a functional test.
#
# Only the comparison is meaningful, so both sides must run on the same box
# under the same conditions, one at a time — never concurrently, or they
# compete for the same cores and the numbers describe the contention instead.
#
# Deliberately not run on the production origin: that box is serving the live
# site and is midway through a soak measurement, and a load run would corrupt
# both.
#
# Usage: ./run_m2_ab_regression.sh [results_dir]
set -euo pipefail
cd "$(dirname "$0")/.."
# 📏 Every row is checked before it counts; see the file for why.
source "$(dirname "$0")/lib.sh"
require_quiet_machine

RESULTS_DIR="${1:-results/m2_ab_$(date +%Y%m%d_%H%M%S)}"
case "$RESULTS_DIR" in
    /*) : ;;
    *) RESULTS_DIR="$(pwd)/$RESULTS_DIR" ;;
esac
mkdir -p "$RESULTS_DIR"
LOG="$RESULTS_DIR/ab.txt"

BEFORE_IMAGE="${BEFORE_IMAGE:-pingclair:pre-m2-39c5623}"
AFTER_IMAGE="${AFTER_IMAGE:-pingclair:rc-a554477}"
NET=pingclair-ab
SUBNET="${AB_SUBNET:-10.99.0.0/24}"
BASE="${SUBNET%.*}"
PORT=18099
DURATION="${AB_DURATION:-20s}"
THREADS=2
CONNS=50
FIXTURES="$(pwd)/fixtures/m2"

log() { printf '%s\n' "$*" | tee -a "$LOG"; }

cleanup() {
    docker rm -f pingclair-ab-proxy pingclair-ab-origin >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# 🧪 A configuration both images understand. The post-M2 directives are
# deliberately absent: the cost being measured is what every request pays by
# default, not the cost of a feature someone opted into.
cat > "$RESULTS_DIR/Pingclairfile" <<'EOF'
{
	admin off
}

:8080 {
	handle /proxy/* {
		reverse_proxy http://origin-ab:8080
	}

	respond "ab-control"
}
EOF

# 🏎️ nginx, not the Python fixture the functional matrix uses. A
# `ThreadingHTTPServer` tops out near a thousand requests a second, so it would
# be the bottleneck on the proxy leg and both sides would be measuring the
# origin instead of the proxy — which is what the first run of this script did.
# The origin has to be comfortably faster than the thing under test.
start_origin() {
    docker network create --subnet "$SUBNET" "$NET" >/dev/null 2>&1 || true
    docker rm -f pingclair-ab-origin >/dev/null 2>&1 || true
    printf 'origin-ab' > "$RESULTS_DIR/index.html"
    cat > "$RESULTS_DIR/origin.conf" <<'NGINX'
server {
    listen 8080;
    access_log off;
    location / { root /usr/share/nginx/html; index index.html; }
}
NGINX
    docker run -d --name pingclair-ab-origin \
        --network "$NET" --ip "$BASE.10" --network-alias origin-ab \
        --cpus 2 \
        -v "$RESULTS_DIR/index.html:/usr/share/nginx/html/index.html:ro" \
        -v "$RESULTS_DIR/origin.conf:/etc/nginx/conf.d/default.conf:ro" \
        nginx:alpine >/dev/null
    sleep 3
}

# 📏 Both sides get identical CPU and memory. Without the cap the host's other
# work decides the result.
run_side() { # run_side <label> <image>
    local label="$1" image="$2"

    docker rm -f pingclair-ab-proxy >/dev/null 2>&1 || true
    docker run -d --name pingclair-ab-proxy \
        --network "$NET" --ip "$BASE.5" \
        --cpus 2 --memory 512m \
        -p "127.0.0.1:$PORT:8080" \
        -e PINGCLAIR_TLS_STORE=/tmp/pingclair-tls \
        -v "$RESULTS_DIR/Pingclairfile:/etc/pingclair/Pingclairfile:ro" \
        "$image" pingclair run /etc/pingclair/Pingclairfile >/dev/null

    local ready=0
    for _ in $(seq 1 60); do
        if curl -sf --noproxy '*' -o /dev/null "http://127.0.0.1:$PORT/"; then
            ready=1
            break
        fi
        sleep 1
    done
    if [ "$ready" != 1 ]; then
        log "❌ $label never became ready"
        docker logs pingclair-ab-proxy 2>&1 | tail -20 | tee -a "$LOG"
        exit 1
    fi

    for route in / /proxy/x; do
        local name
        name="$(printf '%s' "$route" | tr -d '/' )"
        name="${name:-root}"
        # 🔥 One warm-up pass that is not measured: the first requests pay for
        # connection-pool fill and allocator growth on both sides, and
        # whichever side runs first would otherwise absorb it alone.
        wrk -t"$THREADS" -c"$CONNS" -d5s "http://127.0.0.1:$PORT$route" >/dev/null 2>&1 || true
        wrk -t"$THREADS" -c"$CONNS" -d"$DURATION" --latency \
            "http://127.0.0.1:$PORT$route" > "$RESULTS_DIR/${label}_${name}.txt" 2>&1 || true
        # 🚫 A row that was entirely errors still reports a throughput, and a
        # better one than a correct row, because an error is cheap to serve.
        if ! assert_wrk_clean "$RESULTS_DIR/${label}_${name}.txt" "$label $route"; then
            mv "$RESULTS_DIR/${label}_${name}.txt" "$RESULTS_DIR/${label}_${name}.VOID.txt"
            log "  $label $route → 🚫 VOID"
            continue
        fi
        local rps p99
        rps=$(awk '/Requests\/sec/ {print $2}' "$RESULTS_DIR/${label}_${name}.txt")
        p99=$(awk '/^ *99%/ {print $2}' "$RESULTS_DIR/${label}_${name}.txt")
        log "  $label $route → ${rps:-?} req/s, p99 ${p99:-?}"
    done

    # 🧠 Idle cost: the health-check driver polls on a timer whether or not any
    # route configures a probe, and this configuration configures none.
    sleep 10
    local idle
    idle=$(docker stats --no-stream --format '{{.CPUPerc}} {{.MemUsage}}' pingclair-ab-proxy)
    log "  $label idle after load → $idle"

    docker rm -f pingclair-ab-proxy >/dev/null 2>&1 || true
}

for image in "$BEFORE_IMAGE" "$AFTER_IMAGE"; do
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        log "❌ image not found: $image"
        exit 1
    fi
done

log "📊 M2 A/B throughput regression"
log "   before: $BEFORE_IMAGE"
log "   after:  $AFTER_IMAGE"
log "   load:   wrk -t$THREADS -c$CONNS -d$DURATION, one side at a time, 2 CPU / 512M each"
log "   date:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log ""

cleanup
start_origin

log "── before ──────────────────────────────────────────"
run_side before "$BEFORE_IMAGE"
log ""
log "── after ───────────────────────────────────────────"
run_side after "$AFTER_IMAGE"

log ""
log "── delta ───────────────────────────────────────────"
for name in root proxyx; do
    b=$(awk '/Requests\/sec/ {print $2}' "$RESULTS_DIR/before_${name}.txt" 2>/dev/null)
    a=$(awk '/Requests\/sec/ {print $2}' "$RESULTS_DIR/after_${name}.txt" 2>/dev/null)
    if [ -n "$b" ] && [ -n "$a" ]; then
        pct=$(awk -v b="$b" -v a="$a" 'BEGIN {printf "%+.1f", (a-b)/b*100}')
        log "  $name: $b → $a req/s  (${pct}%)"
    fi
done
log ""
log "Full wrk output per side and route is in $RESULTS_DIR."
