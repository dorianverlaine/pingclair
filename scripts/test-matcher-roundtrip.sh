#!/usr/bin/env bash
# Matcher JSON round-trip E2E, against a real pingclair binary.
#
# The unit tests prove the representation is recoverable. This proves the
# thing an operator actually does with it: dump the running config from the
# Admin API and post it straight back. Under the old untagged representation
# that loop was lossy — `not path /admin/*` serialized as bare `path
# /admin/*`, so re-posting a config Pingclair had itself just emitted turned
# the route into the exact opposite of what was written, and the /admin/*
# requests it existed to exclude started matching.
#
# Also checks that a hand-written `0.1.7`-shaped (untagged) matcher still
# loads, since those files exist in the wild.
#
# Usage: ./scripts/test-matcher-roundtrip.sh [results_dir]
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RESULTS_DIR="${1:-$(mktemp -d)}"
mkdir -p "$RESULTS_DIR"

BIN=target/release/pingclair
HTTP_PORT=19310
ADMIN_PORT=19311
FAILURES=0
PID=""

log() { printf '%s\n' "$*"; }
pass() { log "  ✅ $*"; }
fail() {
    log "  ❌ $*"
    FAILURES=$((FAILURES + 1))
}

cleanup() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
}
trap cleanup EXIT

# macOS routes through a system proxy at 127.0.0.1:1082 unless told otherwise,
# which would answer these requests instead of the server under test.
req() { curl -s --noproxy '*' --max-time 5 "$@"; }

status_for() {
    req -o /dev/null -w '%{http_code}' -H 'Host: matcher.test' \
        "http://127.0.0.1:$HTTP_PORT$1"
}

expect_status() {
    local path="$1" want="$2" desc="$3" got
    got=$(status_for "$path" || true)
    if [ "$got" = "$want" ]; then
        pass "$desc"
    else
        fail "$desc — GET $path gave $got, wanted $want"
    fi
}

# The route below carries `not path /admin/*`, so /admin/* must fall through
# to the catch-all 404 while everything else is served by the matched route.
assert_negation_holds() {
    local when="$1"
    expect_status /public 200 "$when: /public matches"
    expect_status /admin/secrets 404 "$when: /admin/* is still excluded"
}

log "=== Matcher JSON round-trip E2E ==="

cargo build --release --bin pingclair >/dev/null 2>&1
CONF="$RESULTS_DIR/Pingclairfile"
cat >"$CONF" <<EOF
{
    auto_https off
    admin 127.0.0.1:$ADMIN_PORT
}

matcher.test {
    listen :$HTTP_PORT

    @notadmin not path /admin/*
    respond @notadmin "matched" 200

    respond "fell through" 404
}
EOF

# The TLS manager initializes before the config is read and panics when its
# default store is not writable, even with no TLS configured.
PINGCLAIR_TLS_STORE="$RESULTS_DIR/tls" RUST_LOG=warn \
    "$BIN" run "$CONF" >"$RESULTS_DIR/server.txt" 2>&1 &
PID=$!

for _ in $(seq 1 50); do
    [ "$(status_for /public || true)" = "200" ] && break
    sleep 0.2
done

log ""
log "1. baseline, straight from the Pingclairfile"
assert_negation_holds "baseline"

log ""
log "2. the Admin API dump keeps the negation"
req "http://127.0.0.1:$ADMIN_PORT/config" >"$RESULTS_DIR/dump.json"
if grep -q '"not"' "$RESULTS_DIR/dump.json"; then
    pass "GET /config emits a tagged \`not\`"
else
    fail "GET /config lost the negation — $(head -c 400 "$RESULTS_DIR/dump.json")"
fi

log ""
log "3. posting the dump back is lossless"
# The dump is keyed by listen address; POST /config wants a single server.
python3 - "$RESULTS_DIR/dump.json" "$RESULTS_DIR/server_config.json" <<'PY'
import json, sys
dump = json.load(open(sys.argv[1]))
servers = [s for group in dump.values() for s in group]
match = [s for s in servers if s.get("name") == "matcher.test"]
if not match:
    sys.exit(f"no matcher.test server in the dump: {list(dump)}")
json.dump(match[0], open(sys.argv[2], "w"))
PY

code=$(req -o "$RESULTS_DIR/post.txt" -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' \
    --data-binary "@$RESULTS_DIR/server_config.json" \
    "http://127.0.0.1:$ADMIN_PORT/config")
if [ "$code" = "200" ]; then
    pass "POST /config accepted the config it had just emitted"
else
    fail "POST /config returned $code: $(cat "$RESULTS_DIR/post.txt")"
fi
assert_negation_holds "after hot reload"

log ""
log "4. a hand-written 0.1.7 (untagged) matcher still loads"
python3 - "$RESULTS_DIR/server_config.json" "$RESULTS_DIR/legacy_config.json" <<'PY'
import json, sys
config = json.load(open(sys.argv[1]))
# The shape 0.1.7 wrote for a bare `path` matcher: no tag, just the payload.
for route in config["routes"]:
    if route.get("matcher") is not None:
        route["matcher"] = {"patterns": ["/legacy/*"]}
json.dump(config, open(sys.argv[2], "w"))
PY

code=$(req -o /dev/null -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' \
    --data-binary "@$RESULTS_DIR/legacy_config.json" \
    "http://127.0.0.1:$ADMIN_PORT/config")
if [ "$code" = "200" ]; then
    pass "POST /config accepted the untagged legacy shape"
else
    fail "POST /config rejected the legacy shape with $code"
fi
expect_status /legacy/thing 200 "legacy: the untagged path matcher routes"
expect_status /public 404 "legacy: a non-matching path falls through"

log ""
log "5. an unreadable matcher is refused, not ignored"
python3 - "$RESULTS_DIR/server_config.json" "$RESULTS_DIR/broken_config.json" <<'PY'
import json, sys
config = json.load(open(sys.argv[1]))
for route in config["routes"]:
    if route.get("matcher") is not None:
        route["matcher"] = {"nonsense": ["/x"]}
json.dump(config, open(sys.argv[2], "w"))
PY

code=$(req -o /dev/null -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' \
    --data-binary "@$RESULTS_DIR/broken_config.json" \
    "http://127.0.0.1:$ADMIN_PORT/config")
if [ "$code" = "400" ]; then
    pass "POST /config rejects an unrecognised matcher (fail closed)"
else
    fail "POST /config returned $code for an unrecognised matcher, wanted 400"
fi

log ""
log "=== $([ "$FAILURES" -eq 0 ] && echo PASS || echo "FAIL ($FAILURES)") ==="
log "evidence: $RESULTS_DIR"
exit "$FAILURES"
