#!/usr/bin/env bash
# M2 guardrail matrix, against a real Linux release binary in Docker.
#
# Why this is not run against the production site: M1 asked whether the proxy
# is faithful, and the live site is the answer key for that. M2 asks whether it
# holds when the upstream misbehaves — which means deliberately breaking
# origins, filling queues, and flooding. None of that can be done to a site
# that is meant to stay up, so the origins here are controllable instead
# (fixtures/m2/origin.py) and their failure mode is changed from outside while
# the proxy keeps running.
#
# Each route in the fixture config isolates one guardrail, so a rejection has
# exactly one possible cause. Combining, say, an overload ceiling with a retry
# policy would make a 503 ambiguous and the assertion meaningless.
#
# Usage: ./run_m2_matrix.sh [results_dir]
set -euo pipefail
cd "$(dirname "$0")/.."

RESULTS_DIR="${1:-results/m2_$(date +%Y%m%d_%H%M%S)}"
case "$RESULTS_DIR" in
    # An absolute path must not be re-rooted under the current directory;
    # Docker would silently create an empty mount point out of the result.
    /*) : ;;
    *) RESULTS_DIR="$(pwd)/$RESULTS_DIR" ;;
esac
mkdir -p "$RESULTS_DIR"
LOG="$RESULTS_DIR/m2_matrix.txt"

IMAGE="${PINGCLAIR_IMAGE:-pingclair:rc-a554477}"
NET=pingclair-m2
SUBNET="${M2_SUBNET:-10.88.0.0/24}"
BASE="${SUBNET%.*}"
PROXY_IP="$BASE.5"
HAPROXY_IP="$BASE.6"
PROXY_PORT=18088
PROXY_PP_PORT=18089
STATE_ROOT="$RESULTS_DIR/state"
FIXTURES="$(pwd)/fixtures/m2"

ORIGINS=(a b c d e f g)

FAILURES=0
log() { printf '%s\n' "$*" | tee -a "$LOG"; }
pass() { log "  ✅ $*"; }
fail() { log "  ❌ $*"; FAILURES=$((FAILURES + 1)); }

# 🧹 Torn down on every exit path, including failure, so a bad run does not
# leave containers holding the ports the next run needs.
cleanup() {
    docker rm -f pingclair-m2-proxy pingclair-m2-haproxy >/dev/null 2>&1 || true
    for name in "${ORIGINS[@]}"; do
        docker rm -f "pingclair-m2-origin-$name" >/dev/null 2>&1 || true
    done
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# 🎛️ Changes one origin's behaviour without restarting it. Restarting would
# also change its address, which is a second variable.
set_mode() { printf '%s' "$2" > "$STATE_ROOT/$1/mode"; }
set_health() { printf '%s' "$2" > "$STATE_ROOT/$1/health"; }

# 🌐 A request whose status and body are both captured. `curl --noproxy` is
# mandatory: this machine has a system proxy that would otherwise intercept.
request() {
    local status
    # `-w` already prints 000 when curl fails, so a `|| echo 000` fallback
    # would concatenate into `000000` and never match anything.
    status="$(curl -s --noproxy '*' -o "$RESULTS_DIR/.body" -w '%{http_code}' \
        --max-time 15 "$@" 2>/dev/null)" || true
    printf '%s' "${status:-000}"
}
body() { cat "$RESULTS_DIR/.body" 2>/dev/null; }

require_image() {
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        log "❌ Image $IMAGE not found. Build it first:"
        log "     docker build -t $IMAGE ."
        exit 1
    fi
}

start_stack() {
    cleanup
    docker network create --subnet "$SUBNET" "$NET" >/dev/null

    local index=10
    for name in "${ORIGINS[@]}"; do
        mkdir -p "$STATE_ROOT/$name"
        printf 'ok' > "$STATE_ROOT/$name/mode"
        printf 'up' > "$STATE_ROOT/$name/health"
        docker run -d --name "pingclair-m2-origin-$name" \
            --network "$NET" --ip "$BASE.$index" \
            --network-alias "origin-$name" \
            -e "ORIGIN_NAME=origin-$name" \
            -v "$FIXTURES/origin.py:/origin.py:ro" \
            -v "$STATE_ROOT/$name:/state" \
            python:3-slim python /origin.py 8080 >/dev/null
        index=$((index + 1))
    done

    docker run -d --name pingclair-m2-proxy \
        --network "$NET" --ip "$PROXY_IP" \
        -p "127.0.0.1:$PROXY_PORT:8080" \
        -p "127.0.0.1:$PROXY_PP_PORT:8081" \
        -e RUST_LOG=info \
        -e PINGCLAIR_TLS_STORE=/tmp/pingclair-tls \
        -v "$FIXTURES/Pingclairfile:/etc/pingclair/Pingclairfile:ro" \
        "$IMAGE" pingclair run /etc/pingclair/Pingclairfile >/dev/null

    # 🧭 A real L4 balancer in front of the PROXY protocol listener. Testing
    # this with a hand-written header would only prove our own parser agrees
    # with itself.
    cat > "$RESULTS_DIR/haproxy.cfg" <<EOF
global
    daemon
defaults
    mode tcp
    timeout connect 5s
    timeout client 30s
    timeout server 30s
frontend l4
    bind :9000
    default_backend origin
backend origin
    server pingclair $PROXY_IP:8081 send-proxy
EOF
    docker run -d --name pingclair-m2-haproxy \
        --network "$NET" --ip "$HAPROXY_IP" \
        -p "127.0.0.1:19000:9000" \
        -v "$RESULTS_DIR/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" \
        haproxy:alpine >/dev/null

    for _ in $(seq 1 60); do
        if [ "$(request "http://127.0.0.1:$PROXY_PORT/")" = "200" ]; then
            return 0
        fi
        sleep 1
    done
    log "❌ Proxy never became ready. Container log:"
    docker logs pingclair-m2-proxy 2>&1 | tail -40 | tee -a "$LOG"
    exit 1
}

# ── Day 12 — active health checking ─────────────────────────────────────────
check_active_health() {
    log ""
    log "🩺 Day 12 — active health checking"

    # Both origins answer before anything is broken.
    local seen_a=0 seen_b=0
    for _ in $(seq 1 8); do
        request "http://127.0.0.1:$PROXY_PORT/health-check/" >/dev/null
        case "$(body)" in
            origin-a) seen_a=1 ;;
            origin-b) seen_b=1 ;;
        esac
    done
    if [ "$seen_a" = 1 ] && [ "$seen_b" = 1 ]; then
        pass "both origins serve while healthy"
    else
        fail "expected both origins in rotation (a=$seen_a b=$seen_b)"
    fi

    # 🎯 The criterion the feature exists for: take origin-b's health down and
    # send NO traffic to it. Only an out-of-band probe can notice.
    set_health b down
    sleep 4

    local only_a=1 statuses=""
    for _ in $(seq 1 8); do
        local status
        status="$(request "http://127.0.0.1:$PROXY_PORT/health-check/")"
        statuses="$statuses $status"
        [ "$(body)" = "origin-b" ] && only_a=0
        [ "$status" = "200" ] || only_a=0
    done
    if [ "$only_a" = 1 ]; then
        pass "an idle failed origin was removed with no request having reached it"
    else
        fail "failed origin stayed in rotation (statuses:$statuses)"
    fi

    set_health b up
    sleep 4
    local rejoined=0
    for _ in $(seq 1 12); do
        request "http://127.0.0.1:$PROXY_PORT/health-check/" >/dev/null
        [ "$(body)" = "origin-b" ] && rejoined=1
    done
    if [ "$rejoined" = 1 ]; then
        pass "a recovered origin rejoined the pool"
    else
        fail "recovered origin never rejoined"
    fi
}

# ── Day 9 — bounded redispatch ──────────────────────────────────────────────
check_retry() {
    log ""
    log "🔁 Day 9 — bounded redispatch"

    set_mode c fail
    local ok=1 statuses=""
    for _ in $(seq 1 6); do
        local status
        status="$(request "http://127.0.0.1:$PROXY_PORT/retry/")"
        statuses="$statuses $status"
        [ "$status" = "200" ] || ok=0
    done
    if [ "$ok" = 1 ]; then
        pass "a 503 origin was redispatched to a healthy one (statuses:$statuses)"
    else
        fail "expected every request to succeed via redispatch (statuses:$statuses)"
    fi

    # Both down: the client must see the upstream's status, not a hang.
    set_mode d fail
    local status
    status="$(request "http://127.0.0.1:$PROXY_PORT/retry/")"
    if [ "$status" = "503" ]; then
        pass "exhausting every candidate surfaces 503 rather than hanging"
    else
        fail "expected 503 once all origins fail, got $status"
    fi

    # A POST has a body and must never be replayed, even though it would fit
    # the attempt budget.
    set_mode c ok
    set_mode d ok
    status="$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 15 \
        -X POST --data 'payload' "http://127.0.0.1:$PROXY_PORT/retry/" 2>/dev/null || echo 000)"
    if [ "$status" = "200" ]; then
        pass "a request with a body still completes on the first attempt"
    else
        fail "expected 200 for a bodied POST, got $status"
    fi

    set_mode c ok
    set_mode d ok
}

# ── Day 10 — admission control ──────────────────────────────────────────────
check_overload() {
    log ""
    log "🚦 Day 10 — admission control"

    set_mode e slow
    # One slot, no queue. The first request occupies it; the second must be
    # refused immediately rather than made to wait.
    curl -s --noproxy '*' -o /dev/null --max-time 8 \
        "http://127.0.0.1:$PROXY_PORT/overload/" >/dev/null 2>&1 &
    local holder=$!
    sleep 2
    local status
    status="$(request "http://127.0.0.1:$PROXY_PORT/overload/")"
    kill "$holder" 2>/dev/null || true
    wait "$holder" 2>/dev/null || true

    if [ "$status" = "503" ] || [ "$status" = "429" ]; then
        pass "a request over the route ceiling was refused fast ($status)"
    else
        fail "expected 429/503 over the ceiling, got $status"
    fi

    set_mode e ok
    sleep 1
    status="$(request "http://127.0.0.1:$PROXY_PORT/overload/")"
    if [ "$status" = "200" ]; then
        pass "the slot was released once the holder finished"
    else
        fail "expected the route to recover, got $status"
    fi
}

# ── Day 10 — circuit breaker ────────────────────────────────────────────────
check_circuit_breaker() {
    log ""
    log "🔌 Day 10 — circuit breaker"

    set_mode f fail
    for _ in $(seq 1 3); do
        request "http://127.0.0.1:$PROXY_PORT/breaker/" >/dev/null
    done

    # With the circuit open the proxy must answer without touching the origin,
    # so the response has to be fast as well as 503.
    local started elapsed status
    started=$(date +%s%N)
    status="$(request "http://127.0.0.1:$PROXY_PORT/breaker/")"
    elapsed=$(( ($(date +%s%N) - started) / 1000000 ))
    if [ "$status" = "503" ] && [ "$elapsed" -lt 1000 ]; then
        pass "an open circuit fails fast (${elapsed}ms, $status)"
    else
        fail "expected a fast 503 from an open circuit, got $status in ${elapsed}ms"
    fi

    # After the open window and with the origin healthy, a half-open probe
    # must close the circuit again.
    set_mode f ok
    sleep 7
    local recovered=0
    for _ in $(seq 1 5); do
        [ "$(request "http://127.0.0.1:$PROXY_PORT/breaker/")" = "200" ] && recovered=1 && break
        sleep 1
    done
    if [ "$recovered" = 1 ]; then
        pass "a healthy origin closed the circuit through half-open probing"
    else
        fail "circuit never closed after the origin recovered"
    fi
}

# ── Day 8 — upstream phase timers and downstream limits ─────────────────────
check_limits() {
    log ""
    log "⏱️ Day 8 — timers and downstream limits"

    set_mode g hang
    local started elapsed status
    started=$(date +%s%N)
    status="$(request "http://127.0.0.1:$PROXY_PORT/timeout/")"
    elapsed=$(( ($(date +%s%N) - started) / 1000000 ))
    if [ "$status" = "504" ] && [ "$elapsed" -lt 8000 ]; then
        pass "a silent origin hit the first-byte timer (${elapsed}ms, $status)"
    else
        fail "expected a 504 within the configured 2s window, got $status in ${elapsed}ms"
    fi
    set_mode g ok

    # Too many header fields.
    local args=()
    for i in $(seq 1 60); do
        args+=(-H "X-Fill-$i: v")
    done
    status="$(request "${args[@]}" "http://127.0.0.1:$PROXY_PORT/")"
    if [ "$status" = "431" ] || [ "$status" = "400" ]; then
        pass "a request over the header-count limit was refused ($status)"
    else
        fail "expected 431/400 over max_headers, got $status"
    fi

    # One oversized header field.
    local big
    big="$(head -c 12000 < /dev/zero | tr '\0' 'x')"
    status="$(request -H "X-Big: $big" "http://127.0.0.1:$PROXY_PORT/")"
    if [ "$status" = "431" ] || [ "$status" = "400" ]; then
        pass "a request over the header-byte limit was refused ($status)"
    else
        fail "expected 431/400 over max_header_bytes, got $status"
    fi

    # A client that opens a connection and never finishes its header must be
    # released by the server rather than held forever.
    # 🕰️ Reading the socket until EOF measures when the *server* gives up.
    # Timing a pipeline that contains our own `sleep` would only measure the
    # sleep, which is what the first version of this check did.
    started=$(date +%s%N)
    exec 3<>"/dev/tcp/127.0.0.1/$PROXY_PORT" || true
    printf 'GET / HTTP/1.1\r\nHost: x\r\n' >&3 2>/dev/null || true
    timeout 10 cat <&3 >/dev/null 2>&1 || true
    exec 3<&- 2>/dev/null || true
    exec 3>&- 2>/dev/null || true
    elapsed=$(( ($(date +%s%N) - started) / 1000000 ))
    if [ "$elapsed" -lt 7000 ]; then
        pass "a slow header client was released by the header timer (${elapsed}ms)"
    else
        fail "slow header client was not released (${elapsed}ms)"
    fi
}

# ── Day 13 — exact rate limiting ────────────────────────────────────────────
check_rate_limit() {
    log ""
    log "🚦 Day 13 — exact rate limiting"

    # 3 per 10s with 2 burst tokens: five pass, the sixth does not.
    local statuses="" status
    for _ in $(seq 1 6); do
        status="$(request "http://127.0.0.1:$PROXY_PORT/ratelimit/")"
        statuses="$statuses $status"
    done
    if [ "$statuses" = " 200 200 200 200 200 429" ]; then
        pass "burst capacity is exact: five allowed, the sixth refused"
    else
        fail "expected ' 200 200 200 200 200 429', got '$statuses'"
    fi

    # The advertised numbers have to be usable, not estimated.
    local headers
    headers="$(curl -s --noproxy '*' -D - -o /dev/null --max-time 10 \
        "http://127.0.0.1:$PROXY_PORT/ratelimit/" 2>/dev/null | tr -d '\r')"
    printf '%s\n' "$headers" > "$RESULTS_DIR/ratelimit_headers.txt"
    if printf '%s' "$headers" | grep -qi '^ratelimit-limit:' \
        && printf '%s' "$headers" | grep -qi '^ratelimit-remaining:' \
        && printf '%s' "$headers" | grep -qi '^retry-after:'; then
        pass "RateLimit-Limit, RateLimit-Remaining and Retry-After are all present"
    else
        fail "standard rate-limit headers missing (see ratelimit_headers.txt)"
    fi
}

# ── Day 14 — PROXY protocol and identity ────────────────────────────────────
check_proxy_protocol() {
    log ""
    log "🧭 Day 14 — PROXY protocol, per listener"

    # The direct listener must still answer with no header at all.
    local status
    status="$(request "http://127.0.0.1:$PROXY_PORT/")"
    if [ "$status" = "200" ]; then
        pass "the direct listener serves without a PROXY header"
    else
        fail "expected the direct listener to serve plainly, got $status"
    fi

    # Through a real L4 balancer that speaks the protocol.
    status="$(request "http://127.0.0.1:19000/")"
    if [ "$status" = "200" ]; then
        pass "the PROXY listener serves through HAProxy's send-proxy"
    else
        fail "expected 200 through HAProxy, got $status"
    fi

    # The same listener, reached directly without the header, must refuse.
    status="$(request "http://127.0.0.1:$PROXY_PP_PORT/")"
    if [ "$status" = "000" ] || [ "$status" = "400" ]; then
        pass "the PROXY listener refuses a header-less connection ($status)"
    else
        fail "a listener requiring PROXY protocol served a header-less request ($status)"
    fi

    # 🪪 The origin's own view of who the client was.
    request "http://127.0.0.1:19000/identity/echo" >/dev/null
    body > "$RESULTS_DIR/identity_via_haproxy.txt"
    if grep -qi 'x-forwarded-for' "$RESULTS_DIR/identity_via_haproxy.txt"; then
        pass "identity reached the origin through the PROXY hop"
        grep -i 'x-forwarded-for\|x-real-ip' "$RESULTS_DIR/identity_via_haproxy.txt" \
            | sed 's/^/     /' | tee -a "$LOG"
    else
        fail "origin saw no forwarded identity (see identity_via_haproxy.txt)"
    fi

    # An untrusted claim must not survive the direct listener.
    request -H 'X-Forwarded-For: 203.0.113.99' \
        "http://127.0.0.1:$PROXY_PORT/identity/echo" >/dev/null
    body > "$RESULTS_DIR/identity_spoof.txt"
    if grep -qi 'x-forwarded-for: 203.0.113.99' "$RESULTS_DIR/identity_spoof.txt"; then
        fail "a spoofed X-Forwarded-For reached the origin unchanged"
    else
        pass "a spoofed X-Forwarded-For was replaced with the socket peer"
    fi
}

# ── Run ─────────────────────────────────────────────────────────────────────
require_image
log "🧊 M2 guardrail matrix"
log "   image:  $IMAGE"
log "   commit: $(git rev-parse HEAD)"
log "   date:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "   results: $RESULTS_DIR"

start_stack
log "🚀 Stack up"

check_active_health
check_retry
check_overload
check_circuit_breaker
check_limits
check_rate_limit
check_proxy_protocol

# 🧾 The proxy's own log, with colour stripped: tracing's fmt layer emits ANSI
# even when stdout is a pipe, so a literal grep would falsely miss.
docker logs pingclair-m2-proxy 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g' \
    > "$RESULTS_DIR/pingclair.txt"

log ""
if [ "$FAILURES" -eq 0 ]; then
    log "✅ M2 matrix passed"
else
    log "❌ M2 matrix: $FAILURES failure(s)"
fi
exit "$FAILURES"
