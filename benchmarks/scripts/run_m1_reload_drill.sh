#!/usr/bin/env bash
# M1 reload drill — SIGHUP against the parallel Pingclair container.
#
# Two things matter here and they pull in opposite directions: a good config
# must take effect without dropping the listener, and a bad one must not. A
# reload that applies garbage is worse than one that refuses, because the
# operator who typed the garbage has already moved on.
#
# Runs beside the live Caddy on the origin; nothing here touches the tunnel.
#
# Usage: ./run_m1_reload_drill.sh [results_dir]
set -uo pipefail

RESULTS_DIR="${1:-/tmp/m1reload}"
mkdir -p "$RESULTS_DIR"
LOG="$RESULTS_DIR/reload.txt"
: >"$LOG"

SITE=portefeuille.aqeo.dev
PORT=6688
PC=aqeo-pingclair-verify
CONF="/tmp/m1drill/Pingclairfile"
FAILURES=0

log() { printf '%s\n' "$*" | tee -a "$LOG"; }
pass() { log "  ✅ $*"; }
fail() {
    log "  ❌ $*"
    FAILURES=$((FAILURES + 1))
}

d() { sudo docker "$@"; }
pc_ip() { d inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$PC"; }

hdr() { # hdr <path> <header>
    curl -s -k --max-time 10 --resolve "$SITE:$PORT:$(pc_ip)" -D - -o /dev/null \
        "https://$SITE:$PORT$1" |
        awk -v h="$(printf '%s' "$2" | tr 'A-Z' 'a-z')" \
            'BEGIN{IGNORECASE=1} tolower($1)==h":" {sub(/\r$/,""); $1=""; sub(/^ /,""); print; exit}'
}
code() {
    curl -s -k --max-time 10 --resolve "$SITE:$PORT:$(pc_ip)" -o /dev/null -w '%{http_code}' \
        "https://$SITE:$PORT${1:-/}"
}

# Always rewrite the config *in place*. A bind-mounted single file is bound to
# an inode, not a path: `sed -i` writes a new file and renames over the old
# one, so the host sees the change and the container goes on reading the
# original. That does not fail loudly — the reload reports success, having
# re-read exactly the same bytes — and every assertion after it is worthless.
write_conf() { cat "$1" >"$CONF"; }
restore() { write_conf "$RESULTS_DIR/Pingclairfile.orig"; }

# Cheap standing proof that the mount is still the same file.
assert_same_inode() {
    local host container
    host=$(stat -c %i "$CONF")
    container=$(d exec "$PC" stat -c %i /etc/pingclair/Pingclairfile)
    if [ "$host" = "$container" ]; then
        return 0
    fi
    fail "the config bind mount is stale (host inode $host, container $container) — \
every reload assertion below would be meaningless"
    return 1
}
trap 'restore; d kill -s HUP "$PC" >/dev/null 2>&1 || true' EXIT

cp "$CONF" "$RESULTS_DIR/Pingclairfile.orig"

log "=== M1 reload drill ==="
log "$(date -u +%Y-%m-%dT%H:%M:%SZ)  container=$PC"

log ""
log "1. a good config is picked up by SIGHUP"
if [ "$(code /)" != "200" ]; then
    fail "not serving before the drill even starts"
    exit 1
fi
assert_same_inode || exit 1
before=$(hdr / X-Drill)
sed 's|^\t\t-Server$|\t\t-Server\n\t\tX-Drill "reloaded"|' \
    "$RESULTS_DIR/Pingclairfile.orig" >"$RESULTS_DIR/Pingclairfile.drill"
if ! grep -q 'X-Drill' "$RESULTS_DIR/Pingclairfile.drill"; then
    fail "could not edit the config for the drill"
    exit 1
fi
write_conf "$RESULTS_DIR/Pingclairfile.drill"
assert_same_inode || exit 1
d kill -s HUP "$PC" >/dev/null
sleep 3
after=$(hdr / X-Drill)
if [ -z "$before" ] && [ "$after" = "reloaded" ]; then
    pass "SIGHUP applied the new header without a restart (absent → '$after')"
else
    fail "reload did not apply — before='$before' after='$after'"
fi
if [ "$(code /)" = "200" ]; then
    pass "the listener stayed up across the reload"
else
    fail "the site stopped answering after a reload"
fi

log ""
log "2. a broken config is refused and the last known good keeps serving"
{ cat "$RESULTS_DIR/Pingclairfile.drill"; printf '\nthis is not a valid pingclairfile {{{\n'; } \
    >"$RESULTS_DIR/Pingclairfile.broken"
write_conf "$RESULTS_DIR/Pingclairfile.broken"
d kill -s HUP "$PC" >/dev/null
sleep 3
if [ "$(code /)" = "200" ]; then
    pass "still serving after a reload with a broken config"
else
    fail "a broken config took the site down — fail-closed is not holding"
fi
still=$(hdr / X-Drill)
if [ "$still" = "reloaded" ]; then
    pass "the previous good config is still in effect (X-Drill='$still')"
else
    fail "config state after the failed reload is '$still', wanted the last known good"
fi
d logs --tail 40 "$PC" >"$RESULTS_DIR/reload_log.txt" 2>&1
if grep -qai "reload\|config" "$RESULTS_DIR/reload_log.txt"; then
    pass "the refusal is visible in the log"
else
    fail "nothing in the log explains why the reload did not apply"
fi

log ""
log "3. restoring the original config reloads cleanly"
restore
d kill -s HUP "$PC" >/dev/null
sleep 3
back=$(hdr / X-Drill)
if [ -z "$back" ] && [ "$(code /)" = "200" ]; then
    pass "back to the production config (X-Drill gone, still 200)"
else
    fail "restore did not take — X-Drill='$back' code=$(code /)"
fi

log ""
log "=== $([ "$FAILURES" -eq 0 ] && echo PASS || echo "FAIL ($FAILURES)") ==="
log "evidence: $RESULTS_DIR"
exit "$FAILURES"
