#!/usr/bin/env bash
# Upstream DNS re-resolution E2E, against a real Docker network.
#
# What this proves, with a real release binary and Docker's own embedded
# resolver rather than a mock:
#
#   1. A hostname upstream that does not resolve at boot is adopted once it
#      appears, instead of being dropped for the life of the process.
#   2. When the app container is replaced on a different IP, the proxy
#      follows it — the criterion the whole feature exists for.
#   3. When the name stops resolving but the old address is still serving,
#      the proxy keeps using it. A resolver hiccup must not take the site
#      down; last-known-good is the safe reading.
#   4. `dns_refresh off` pins upstreams to their startup address, so an
#      operator who wants the old behaviour still has it.
#
# Addresses are assigned explicitly with `--ip` on a fixed subnet: letting
# Docker pick would make "did the backend move?" depend on the daemon's
# address recycling, and a test that only passes when the pool happens to
# hand out a fresh IP is not a test.
#
# Usage: ./run_dns_refresh_e2e.sh [results_dir]
set -euo pipefail
cd "$(dirname "$0")/.."

RESULTS_DIR="${1:-results/dns_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$RESULTS_DIR"
LOG="$RESULTS_DIR/dns_refresh.txt"

IMAGE="${PINGCLAIR_IMAGE:-pingclair:dns-e2e}"
NET=pingclair-dns-e2e
# Overridable: a hard-coded 172.31/16 would shadow an AWS VPC's own range on
# an EC2 host and take the box's networking with it.
SUBNET="${DNS_E2E_SUBNET:-10.77.0.0/24}"
APP_A_IP="${SUBNET%.*}.10"
APP_B_IP="${SUBNET%.*}.20"
PROXY_PORT=18099
REFRESH=3        # seconds; the config below must match
SETTLE=12        # generous multiple of REFRESH before declaring a failure

FAILURES=0

log() { printf '%s\n' "$*" | tee -a "$LOG"; }

pass() { log "  ✅ $*"; }
fail() {
    log "  ❌ $*"
    FAILURES=$((FAILURES + 1))
}

cleanup() {
    docker rm -f pc-dns-proxy pc-dns-app-a pc-dns-app-b >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Body served by each app container, so a response identifies which one
# answered without having to trust the proxy's own logging.
start_app() {
    local name="$1" ip="$2" body="$3" alias_flag="$4"
    local net_args=(--network "$NET" --ip "$ip")
    if [ "$alias_flag" = "alias" ]; then
        net_args+=(--network-alias app)
    fi
    docker run -d --name "$name" "${net_args[@]}" \
        "${APP_IMAGE:-nginx:1.27-alpine}" >/dev/null
    docker exec "$name" sh -c "printf '%s' '$body' > /usr/share/nginx/html/index.html"
}

# Poll until the proxy answers with the expected body, or give up.
expect_body() {
    local want="$1" timeout="$2" desc="$3"
    local deadline=$((SECONDS + timeout)) got=""
    while [ $SECONDS -lt $deadline ]; do
        got=$(curl -s --noproxy '*' --max-time 2 "http://127.0.0.1:$PROXY_PORT/" || true)
        if [ "$got" = "$want" ]; then
            pass "$desc (after $((timeout - (deadline - SECONDS)))s)"
            return 0
        fi
        sleep 1
    done
    # Never a nonzero return: `set -e` would abort the run on the first
    # failure and hide every later case behind it.
    fail "$desc — wanted '$want', last saw '${got:-<no response>}'"
}

# Assert the body stays put for the whole window rather than merely being
# right once: keeping a stale backend is only meaningful if it *keeps*
# working across several refresh ticks.
expect_body_stable() {
    local want="$1" seconds="$2" desc="$3"
    local deadline=$((SECONDS + seconds)) got=""
    while [ $SECONDS -lt $deadline ]; do
        got=$(curl -s --noproxy '*' --max-time 2 "http://127.0.0.1:$PROXY_PORT/" || true)
        if [ "$got" != "$want" ]; then
            fail "$desc — drifted to '${got:-<no response>}' after $((seconds - (deadline - SECONDS)))s"
            return 0
        fi
        sleep 1
    done
    pass "$desc (held for ${seconds}s)"
}

expect_status() {
    local want="$1" timeout="$2" desc="$3"
    local deadline=$((SECONDS + timeout)) got=""
    while [ $SECONDS -lt $deadline ]; do
        got=$(curl -s -o /dev/null -w '%{http_code}' --noproxy '*' --max-time 2 \
            "http://127.0.0.1:$PROXY_PORT/" || true)
        if [ "$got" = "$want" ]; then
            pass "$desc"
            return 0
        fi
        sleep 1
    done
    fail "$desc — wanted HTTP $want, last saw '${got:-<none>}'"
}

start_proxy() {
    local refresh_directive="$1"
    local conf="$RESULTS_DIR/Pingclairfile"
    cat >"$conf" <<EOF
{
    admin off
    auto_https off
    dns_refresh $refresh_directive
}

proxy.test {
    listen :8080
    reverse_proxy http://app:80
}
EOF
    # RUST_LOG is required for anything below ERROR: the subscriber is built
    # from `EnvFilter::from_default_env()`, so an unset RUST_LOG hides the
    # refresher's own account of what it did.
    docker run -d --name pc-dns-proxy --network "$NET" \
        -p "$PROXY_PORT:8080" \
        -v "$(cd "$(dirname "$conf")" && pwd)/$(basename "$conf"):/etc/pingclair/Pingclairfile:ro" \
        -e PINGCLAIR_TLS_STORE=/tmp/pingclair-tls \
        -e RUST_LOG=info \
        "$IMAGE" pingclair run /etc/pingclair/Pingclairfile >/dev/null
}

# Assert the proxy logged something, so the operator-facing signal is part of
# the evidence and not just the response body.
expect_log() {
    local pattern="$1" desc="$2" snapshot="$RESULTS_DIR/.logsnap"
    # Snapshot to a file rather than grepping a live pipeline. `grep -q` exits
    # as soon as it matches, which SIGPIPEs the upstream `docker logs`, and
    # under `set -o pipefail` that 141 becomes the pipeline's status — a match
    # then reads as a failure, and only once the log is long enough for the
    # race to be lost. The fmt layer also colours field names even when stdout
    # is not a tty, so the escapes come out here too.
    docker logs pc-dns-proxy >"$snapshot" 2>&1 || true
    sed -i.bak $'s/\033\\[[0-9;]*m//g' "$snapshot" 2>/dev/null || true
    if grep -qa -- "$pattern" "$snapshot"; then
        pass "$desc"
    else
        fail "$desc — no log line matching '$pattern'"
    fi
}

# curl hits the published port with a Host the config knows about; without
# it the request lands on no vhost and the result says nothing about DNS.
curl() { command curl -H 'Host: proxy.test' "$@"; }

# ---------------------------------------------------------------------------

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Missing image $IMAGE — build it first:" >&2
    echo "  docker build -t $IMAGE ." >&2
    exit 1
fi

log "=== Upstream DNS re-resolution E2E ==="
log "image=$IMAGE refresh=${REFRESH}s subnet=$SUBNET"
log "started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log ""

cleanup
docker network create --subnet "$SUBNET" "$NET" >/dev/null

# --- 1. The proxy starts before its app exists --------------------------------
log "1. upstream absent at boot"
start_proxy "${REFRESH}s"
expect_status 502 "$SETTLE" "no backend yet → 502 rather than a crash or a hang"

start_app pc-dns-app-a "$APP_A_IP" "app-a" alias
expect_body "app-a" "$SETTLE" "the upstream is adopted once it resolves"
log ""

# --- 2. The container is replaced on a new address -----------------------------
log "2. container moves to a new address"
docker rm -f pc-dns-app-a >/dev/null
start_app pc-dns-app-b "$APP_B_IP" "app-b" alias
log "  app: $APP_A_IP → $APP_B_IP"
expect_body "app-b" "$SETTLE" "the backend follows the container to its new IP"
expect_log "from=$APP_A_IP:80 to=$APP_B_IP:80" "the move is logged with both addresses"
log ""

# --- 3. The name stops resolving while the address still serves ----------------
log "3. resolver failure with a healthy old address"
# Dropping the alias removes `app` from Docker's embedded DNS while the very
# same container keeps listening on the very same address.
docker network disconnect "$NET" pc-dns-app-b
docker network connect --ip "$APP_B_IP" "$NET" pc-dns-app-b
if docker exec pc-dns-proxy getent hosts app >/dev/null 2>&1; then
    fail 'precondition: `app` still resolves, so this case proves nothing'
else
    pass 'precondition: `app` no longer resolves'
fi
expect_body_stable "app-b" "$SETTLE" "the last known address keeps serving"
expect_log "keeping the last known address" "the failed lookup is logged as a warning, not swallowed"

# ...and recovers on its own once the name comes back.
docker network disconnect "$NET" pc-dns-app-b
docker network connect --ip "$APP_B_IP" --alias app "$NET" pc-dns-app-b
expect_body "app-b" "$SETTLE" "traffic continues once the name resolves again"
log ""

# --- 4. dns_refresh off pins the startup address -------------------------------
log "4. dns_refresh off"
docker logs pc-dns-proxy 2>&1 | sed $'s/\033\\[[0-9;]*m//g' >"$RESULTS_DIR/proxy_refresh.txt" || true
docker rm -f pc-dns-proxy >/dev/null
start_proxy off
expect_body "app-b" "$SETTLE" "baseline: the pinned address serves"

docker rm -f pc-dns-app-b >/dev/null
start_app pc-dns-app-a "$APP_A_IP" "app-a" alias
log "  app: $APP_B_IP → $APP_A_IP, but re-resolution is off"
sleep "$SETTLE"
body=$(curl -s --noproxy '*' --max-time 2 "http://127.0.0.1:$PROXY_PORT/" || true)
if [ "$body" = "app-a" ]; then
    fail "\`dns_refresh off\` still followed the move"
else
    pass "the address stays pinned (got '${body:-<no response>}')"
fi
log ""

docker logs pc-dns-proxy 2>&1 | sed $'s/\033\\[[0-9;]*m//g' >"$RESULTS_DIR/proxy_off.txt" || true

log "=== $([ "$FAILURES" -eq 0 ] && echo PASS || echo "FAIL ($FAILURES)") ==="
log "evidence: $RESULTS_DIR"
exit "$FAILURES"
