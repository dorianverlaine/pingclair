#!/usr/bin/env bash
# M1 verification drill — Pingclair beside the real Caddy on the real origin.
#
# Runs on the origin host (`aqeonet-aws-tw-xray`). Pingclair joins the existing
# `aqeo_default` network as an extra container, serving the production
# Caddyfile expressed as a Pingclairfile, against the production app. Caddy
# keeps serving live traffic throughout: nothing here touches the tunnel, and
# every probe is a GET.
#
# The point is differential — each check asks Pingclair for the same thing the
# live Caddy is asked for, and where the answer should be identical it is
# compared byte for byte. "It responded 200" is not evidence that a proxy can
# replace another one.
#
# Usage: ./run_m1_production_drill.sh [results_dir]
set -uo pipefail

RESULTS_DIR="${1:-/tmp/m1drill}"
mkdir -p "$RESULTS_DIR"
LOG="$RESULTS_DIR/drill.txt"
: >"$LOG"

NET=aqeo_default
SITE=portefeuille.aqeo.dev
PORT=6688
PC=aqeo-pingclair-verify
CADDY=aqeo-caddy-1
IMAGE="${PINGCLAIR_IMAGE:-pingclair:rc-8294116}"

FAILURES=0
CHECKS=0

log() { printf '%s\n' "$*" | tee -a "$LOG"; }
pass() {
    CHECKS=$((CHECKS + 1))
    log "  ✅ $*"
}
fail() {
    CHECKS=$((CHECKS + 1))
    FAILURES=$((FAILURES + 1))
    log "  ❌ $*"
}
section() {
    log ""
    log "$*"
}

d() { sudo docker "$@"; }

ip_of() { d inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"; }

# Every probe pins the SNI/Host to the production site name and resolves it to
# whichever container is under test, so Pingclair and Caddy answer the exact
# same request.
probe() {
    local target_ip="$1"
    shift
    curl -s -k --max-time 10 --resolve "$SITE:$PORT:$target_ip" "$@" \
        "https://$SITE:$PORT${PROBE_PATH:-/}"
}

pc() { PROBE_PATH="${PROBE_PATH:-/}" probe "$PC_IP" "$@"; }
cad() { PROBE_PATH="${PROBE_PATH:-/}" probe "$CADDY_IP" "$@"; }

header_of() { # header_of <server-fn> <path> <header-name>
    local fn="$1" path="$2" name="$3"
    PROBE_PATH="$path" "$fn" -sD - -o /dev/null |
        awk -v h="$(printf '%s' "$name" | tr 'A-Z' 'a-z')" \
            'BEGIN{IGNORECASE=1} tolower($1)==h":" {sub(/\r$/,""); $1=""; sub(/^ /,""); print; exit}'
}

expect_header() { # expect_header <path> <header> <expected> <desc>
    local path="$1" name="$2" want="$3" desc="$4" got
    got=$(header_of pc "$path" "$name")
    if [ "$got" = "$want" ]; then
        pass "$desc"
    else
        fail "$desc — $name on $path was '${got:-<absent>}', wanted '$want'"
    fi
}

# ---------------------------------------------------------------------------

log "=== M1 production drill ==="
log "image=$IMAGE  host=$(hostname)  $(uname -m)  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Caddy keeps serving the tunnel throughout; Pingclair is a parallel container."

section "0. bring Pingclair up beside Caddy"

# 🗂️ Stage the config before the mount. Docker silently creates a *directory*
# at a bind-mount source that does not exist, and the container then exits
# without a word — the drill previously reported only "never became ready".
CONFIG_SRC="${PINGCLAIR_CONFIG:-$HOME/aqeo/Pingclairfile}"
if [ ! -f "$CONFIG_SRC" ]; then
    log "  ❌ config not found: $CONFIG_SRC (set PINGCLAIR_CONFIG)"
    exit 1
fi
rm -rf "$RESULTS_DIR/Pingclairfile"
cp "$CONFIG_SRC" "$RESULTS_DIR/Pingclairfile"

d rm -f "$PC" >/dev/null 2>&1
d volume create pingclair-verify-tls >/dev/null
d run -d --name "$PC" --network "$NET" \
    --log-driver json-file --log-opt max-size=20m --log-opt max-file=2 \
    -v "$RESULTS_DIR/Pingclairfile:/etc/pingclair/Pingclairfile:ro" \
    -v pingclair-verify-tls:/var/lib/pingclair/certs \
    "$IMAGE" pingclair run /etc/pingclair/Pingclairfile >/dev/null

PC_IP=$(ip_of "$PC")
CADDY_IP=$(ip_of "$CADDY")
log "  pingclair=$PC_IP  caddy=$CADDY_IP"

for _ in $(seq 1 40); do
    [ "$(PROBE_PATH=/ pc -o /dev/null -w '%{http_code}')" = "200" ] && break
    sleep 1
done
if [ "$(PROBE_PATH=/ pc -o /dev/null -w '%{http_code}')" = "200" ]; then
    pass "serves the production site over TLS on the custom port $PORT"
else
    fail "never became ready — $(d logs --tail 20 "$PC" 2>&1 | tail -5)"
    log "=== ABORTED ==="
    exit 1
fi

section "1. admin off"
if d exec "$PC" sh -c 'command -v ss >/dev/null && ss -tln || cat /proc/net/tcp' 2>/dev/null |
    grep -qiE ':(2019|07E3)\b'; then
    fail "an admin listener is open despite \`admin off\`"
else
    pass "no admin listener in the container (\`admin off\` honoured)"
fi

section "2. security headers — set and remove"
for spec in \
    "Strict-Transport-Security|max-age=31536000; includeSubDomains" \
    "X-Content-Type-Options|nosniff" \
    "X-Frame-Options|DENY" \
    "Referrer-Policy|strict-origin-when-cross-origin"; do
    expect_header / "${spec%%|*}" "${spec#*|}" "${spec%%|*} is set"
done

csp_pc=$(header_of pc / Content-Security-Policy)
csp_cad=$(header_of cad / Content-Security-Policy)
if [ -n "$csp_pc" ] && [ "$csp_pc" = "$csp_cad" ]; then
    pass "Content-Security-Policy is byte-identical to Caddy's"
else
    fail "CSP differs from Caddy — pingclair='$csp_pc' caddy='$csp_cad'"
fi

server_hdr=$(header_of pc / Server)
if [ -z "$server_hdr" ]; then
    pass "\`-Server\` removed the Server header"
else
    fail "Server header still present: '$server_hdr'"
fi

section "3. three Cache-Control classes and \`not path\` AND semantics"
# `@rest { not path /assets/*; not path /api/* }` is an AND of two negations:
# only a path that is neither may take no-cache.
expect_header /api/ping Cache-Control "no-store" "/api/* → no-store"
expect_header /assets/nonexistent.js Cache-Control \
    "public, max-age=31536000, immutable" "/assets/* → immutable"
expect_header / Cache-Control "no-cache" "/ → no-cache (matched both negations)"

for path in /api/ping /assets/nonexistent.js; do
    got=$(header_of pc "$path" Cache-Control)
    if [ "$got" = "no-cache" ]; then
        fail "$path leaked into @rest — the AND of negations collapsed"
    else
        pass "$path is excluded from @rest"
    fi
done

section "4. compression negotiation"
enc() { PROBE_PATH=/ pc -H "Accept-Encoding: $1" -sD - -o /dev/null | awk 'BEGIN{IGNORECASE=1} /^content-encoding:/{sub(/\r$/,"");print $2; exit}'; }
for pair in "gzip, deflate, br, zstd|zstd" "gzip, deflate|gzip" "br|" "identity|"; do
    want="${pair#*|}"
    got=$(enc "${pair%%|*}")
    if [ "$got" = "$want" ]; then
        pass "Accept-Encoding: ${pair%%|*} → ${want:-identity}"
    else
        fail "Accept-Encoding: ${pair%%|*} → '${got:-identity}', wanted '${want:-identity}'"
    fi
done

# The decompressed body must equal what Caddy serves, or compression is not
# transparent and the comparison above proves nothing.
PROBE_PATH=/ pc -H 'Accept-Encoding: gzip' -o "$RESULTS_DIR/body.gz" >/dev/null
PROBE_PATH=/ cad -H 'Accept-Encoding: identity' -o "$RESULTS_DIR/body.caddy" >/dev/null
if gunzip -c "$RESULTS_DIR/body.gz" 2>/dev/null | cmp -s - "$RESULTS_DIR/body.caddy"; then
    pass "gzip body decodes byte-exact to what Caddy serves"
else
    fail "gzip body differs from Caddy's"
fi

section "5. verified client IP"
# cloudflared is the only peer on this network and it is inside
# trusted_proxies, so a header arriving from here is honoured. The negative
# half — an untrusted peer being ignored — was verified on 2026-07-27 with a
# dedicated fixture and is not repeatable from inside the trusted subnet.
PROBE_PATH=/api/ping pc -H 'CF-Connecting-IP: 203.0.113.77' -o /dev/null >/dev/null
sleep 1
if d logs --tail 30 "$PC" 2>&1 | grep -q '203.0.113.77'; then
    pass "CF-Connecting-IP from the trusted tunnel subnet becomes the client IP"
else
    fail "CF-Connecting-IP was not adopted — $(d logs --tail 3 "$PC" 2>&1 | tail -1)"
fi

section "6. JSON access log and redaction"
PROBE_PATH='/api/ping?token=SUPERSECRET&q=ok' pc \
    -H 'Cookie: session=SESSIONSECRET' \
    -H 'Authorization: Bearer BEARERSECRET' \
    -H 'Referer: https://example.com/callback?code=CODESECRET' \
    -o /dev/null >/dev/null
sleep 1
d logs --tail 200 "$PC" >"$RESULTS_DIR/pingclair_log.txt" 2>&1

if grep -q '^{.*"level"' "$RESULTS_DIR/pingclair_log.txt" ||
    grep -qE '^\{.*\}$' "$RESULTS_DIR/pingclair_log.txt"; then
    pass "access log lines are JSON"
else
    fail "no JSON log lines found"
fi

leaked=""
for secret in SUPERSECRET SESSIONSECRET BEARERSECRET CODESECRET; do
    grep -q "$secret" "$RESULTS_DIR/pingclair_log.txt" && leaked="$leaked $secret"
done
if [ -z "$leaked" ]; then
    pass "no credential reached the log (query token, Cookie, Authorization, Referer code)"
else
    fail "secrets leaked into the log:$leaked"
fi

section "7. internal CA survives a restart"
fp_before=$(PROBE_PATH=/ pc -o /dev/null -w '%{certs}' 2>/dev/null | grep -i '^Start date\|^Serial' | head -2)
openssl_fp() {
    echo | openssl s_client -connect "$PC_IP:$PORT" -servername "$SITE" 2>/dev/null |
        openssl x509 -noout -fingerprint -sha256 2>/dev/null
}
leaf_before=$(openssl_fp)
root_before=$(d exec "$PC" sha256sum /var/lib/pingclair/certs/internal/root.crt 2>/dev/null | awk '{print $1}')

d restart "$PC" >/dev/null
for _ in $(seq 1 40); do
    [ "$(PROBE_PATH=/ pc -o /dev/null -w '%{http_code}')" = "200" ] && break
    sleep 1
done
leaf_after=$(openssl_fp)
root_after=$(d exec "$PC" sha256sum /var/lib/pingclair/certs/internal/root.crt 2>/dev/null | awk '{print $1}')

if [ -n "$root_before" ] && [ "$root_before" = "$root_after" ]; then
    pass "internal CA root is the same authority after a restart"
else
    fail "internal CA root changed across restart ($root_before → $root_after)"
fi
if [ -n "$leaf_before" ] && [ "$leaf_before" = "$leaf_after" ]; then
    pass "leaf certificate is reused, not re-issued, after a restart"
else
    fail "leaf changed across restart — clients pinning the origin would break"
fi
PC_IP=$(ip_of "$PC")

section "8. body equivalence with Caddy"
for path in / /api/ping; do
    PROBE_PATH="$path" pc -H 'Accept-Encoding: identity' -o "$RESULTS_DIR/pc$(echo "$path" | tr / _)" >/dev/null
    PROBE_PATH="$path" cad -H 'Accept-Encoding: identity' -o "$RESULTS_DIR/cad$(echo "$path" | tr / _)" >/dev/null
    if cmp -s "$RESULTS_DIR/pc$(echo "$path" | tr / _)" "$RESULTS_DIR/cad$(echo "$path" | tr / _)"; then
        pass "$path body is byte-identical to Caddy's"
    else
        fail "$path body differs from Caddy's"
    fi
done

section "9. HTTP/2 to the origin"
ver=$(PROBE_PATH=/ pc --http2 -o /dev/null -w '%{http_version}')
if [ "$ver" = "2" ]; then
    pass "negotiates HTTP/2 over TLS (what the tunnel asks for)"
else
    fail "HTTP/2 negotiation gave version '$ver'"
fi

section "10. graceful shutdown"
d stop -t 15 "$PC" >/dev/null 2>&1
code=$(d inspect -f '{{.State.ExitCode}}' "$PC")
if [ "$code" = "0" ]; then
    pass "SIGTERM shutdown exited cleanly (code 0, no SIGKILL)"
else
    fail "shutdown exit code was $code — docker had to kill it"
fi
d start "$PC" >/dev/null
for _ in $(seq 1 40); do
    PC_IP=$(ip_of "$PC")
    [ "$(PROBE_PATH=/ pc -o /dev/null -w '%{http_code}')" = "200" ] && break
    sleep 1
done

log ""
log "=== $([ "$FAILURES" -eq 0 ] && echo PASS || echo "FAIL ($FAILURES/$CHECKS)") ==="
log "checks=$CHECKS failures=$FAILURES"
log "evidence: $RESULTS_DIR"
exit "$FAILURES"
