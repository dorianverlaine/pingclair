#!/usr/bin/env bash
# Switch the Cloudflare Tunnel's origin between Caddy and Pingclair.
#
#   ./switch-proxy.sh status      what is live right now
#   ./switch-proxy.sh pingclair   point the tunnel at Pingclair
#   ./switch-proxy.sh caddy       point it back
#
# Both proxies stay running the whole time. Only the tunnel's `service:` line
# moves, so a switch is a cloudflared restart (a second or two of connection
# churn) and never a rebuild of the thing serving the site.
#
# Three rules this script exists to enforce, all of them learned the hard way:
#
#   1. Never switch to an origin that is not already answering. Checking after
#      the fact means the outage has already happened.
#   2. Verify after the switch too, and put it back automatically if the new
#      origin does not answer. An unattended switch that half-works is worse
#      than one that refuses.
#   3. Rewrite the config *in place*. A bind-mounted file is bound to an inode,
#      not a path — `sed -i` renames a new file over the old one, the host sees
#      the change and the container goes on reading the original. That failure
#      is silent: the restart succeeds, having re-read exactly the same bytes.
set -uo pipefail

# --- what this deployment looks like ---------------------------------------
STACK_DIR="${STACK_DIR:-$HOME/aqeo}"
CF_CONFIG="${CF_CONFIG:-$STACK_DIR/cloudflared/config.yml}"
CF_CONTAINER="${CF_CONTAINER:-aqeo-cloudflared-1}"
NETWORK="${NETWORK:-aqeo_default}"
SITE="${SITE:-portefeuille.aqeo.dev}"
PORT="${PORT:-6688}"

CADDY_CONTAINER="${CADDY_CONTAINER:-aqeo-caddy-1}"
CADDY_ORIGIN="${CADDY_ORIGIN:-caddy}"

PC_CONTAINER="${PC_CONTAINER:-aqeo-pingclair}"
PC_ORIGIN="${PC_ORIGIN:-$PC_CONTAINER}"
PC_IMAGE="${PC_IMAGE:-pingclair:rc-8294116}"
PC_CONFIG="${PC_CONFIG:-$STACK_DIR/Pingclairfile}"
PC_TLS_VOLUME="${PC_TLS_VOLUME:-pingclair-tls}"

BACKUP_DIR="${BACKUP_DIR:-$STACK_DIR/backup}"

# --- plumbing ---------------------------------------------------------------
if docker ps >/dev/null 2>&1; then D=docker; else D="sudo docker"; fi
d() { $D "$@"; }

say() { printf '%s\n' "$*"; }
die() {
    printf '❌ %s\n' "$*" >&2
    exit 1
}

ip_of() { d inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1" 2>/dev/null; }
running() { [ "$(d inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = "true" ]; }

current_origin() {
    awk '/^[[:space:]]*service:[[:space:]]*https?:\/\//{
        sub(/.*:\/\//,""); sub(/:.*/,""); print; exit }' "$CF_CONFIG"
}

# Ask the container directly, with the production SNI and Host, exactly as
# cloudflared will. A plain `docker ps` says the process exists; it does not
# say the site answers.
serves() {
    local target="$1" ip
    ip=$(ip_of "$target")
    [ -n "$ip" ] || return 1
    [ "$(curl -s -k --max-time 5 --resolve "$SITE:$PORT:$ip" \
        -o /dev/null -w '%{http_code}' "https://$SITE:$PORT/")" = "200" ]
}

wait_serving() { # wait_serving <container> <seconds>
    local target="$1" deadline=$((SECONDS + ${2:-30}))
    while [ $SECONDS -lt $deadline ]; do
        serves "$target" && return 0
        sleep 1
    done
    return 1
}

# Rule 3: truncate and rewrite, never rename over.
write_config() { cat "$1" >"$CF_CONFIG"; }

set_origin() { # set_origin <hostname>
    local want="$1" tmp
    tmp=$(mktemp)
    sed -E "s|(^[[:space:]]*service:[[:space:]]*https?://)[^:]+(:$PORT)|\1$want\2|" \
        "$CF_CONFIG" >"$tmp"
    grep -q "://$want:$PORT" "$tmp" || {
        rm -f "$tmp"
        die "could not rewrite the origin to $want — check $CF_CONFIG by hand"
    }
    write_config "$tmp"
    rm -f "$tmp"
}

# Pingclair is not part of the compose stack, so this script owns its
# container. Created on demand with the same restart policy as the rest of the
# stack, so a switch survives a reboot.
ensure_pingclair() {
    if running "$PC_CONTAINER"; then return 0; fi

    if d inspect "$PC_CONTAINER" >/dev/null 2>&1; then
        say "▶️  starting existing $PC_CONTAINER"
        d start "$PC_CONTAINER" >/dev/null
        return 0
    fi

    [ -f "$PC_CONFIG" ] || die "no Pingclairfile at $PC_CONFIG"
    d image inspect "$PC_IMAGE" >/dev/null 2>&1 ||
        die "image $PC_IMAGE is not loaded (docker load < pingclair.tar.gz)"

    say "▶️  creating $PC_CONTAINER from $PC_IMAGE"
    d volume create "$PC_TLS_VOLUME" >/dev/null
    d run -d --name "$PC_CONTAINER" --network "$NETWORK" \
        --restart unless-stopped \
        --log-driver json-file --log-opt max-size=20m --log-opt max-file=3 \
        -v "$PC_CONFIG:/etc/pingclair/Pingclairfile:ro" \
        -v "$PC_TLS_VOLUME:/var/lib/pingclair/certs" \
        "$PC_IMAGE" pingclair run /etc/pingclair/Pingclairfile >/dev/null
}

switch_to() { # switch_to <container> <origin-hostname> <label>
    local container="$1" origin="$2" label="$3" previous backup
    previous=$(current_origin)

    if [ "$previous" = "$origin" ] && serves "$container"; then
        say "✅ already on $label ($origin), and it is serving. Nothing to do."
        return 0
    fi

    [ "$container" = "$PC_CONTAINER" ] && ensure_pingclair
    running "$container" || d start "$container" >/dev/null 2>&1

    # Rule 1: prove the target answers before any traffic is sent to it.
    say "🔍 checking $label is serving $SITE:$PORT ..."
    wait_serving "$container" 45 ||
        die "$label is not answering on $PORT — refusing to switch. Logs: docker logs --tail 50 $container"
    say "   $label is up at $(ip_of "$container")"

    mkdir -p "$BACKUP_DIR"
    backup="$BACKUP_DIR/config.yml.$(date +%Y%m%d%H%M%S).$previous"
    cp "$CF_CONFIG" "$backup"

    say "🔀 $previous → $origin"
    set_origin "$origin"
    d restart "$CF_CONTAINER" >/dev/null

    # Rule 2: and prove it afterwards, or put it back.
    if wait_serving "$container" 30 && wait_tunnel_ready 30; then
        say "✅ live origin is now $label ($origin)"
        say "   previous config saved at $backup"
        say "   roll back with: $0 $([ "$label" = pingclair ] && echo caddy || echo pingclair)"
        return 0
    fi

    say "⚠️  $label did not come up cleanly behind the tunnel — rolling back"
    write_config "$backup"
    d restart "$CF_CONTAINER" >/dev/null
    wait_tunnel_ready 30 >/dev/null
    die "rolled back to $previous. Investigate with: docker logs --tail 50 $container"
}

# cloudflared re-registers its connections on restart; until it says so, the
# tunnel is not carrying traffic and any verdict about the origin is premature.
wait_tunnel_ready() {
    local deadline=$((SECONDS + ${1:-30}))
    while [ $SECONDS -lt $deadline ]; do
        if d logs --since 60s "$CF_CONTAINER" 2>&1 |
            grep -qiE 'Registered tunnel connection|Connection .* registered'; then
            return 0
        fi
        sleep 1
    done
    return 1
}

show_status() {
    local origin
    origin=$(current_origin)
    say "tunnel origin : $origin"
    printf 'live proxy    : '
    case "$origin" in
        "$PC_ORIGIN") say "🦀 pingclair" ;;
        "$CADDY_ORIGIN") say "🧱 caddy" ;;
        *) say "unknown ($origin)" ;;
    esac
    say ""
    printf '%-24s %-10s %s\n' CONTAINER STATE "SERVES $SITE:$PORT"
    for c in "$CADDY_CONTAINER" "$PC_CONTAINER" "$CF_CONTAINER" ${EXTRA_CONTAINERS:-}; do
        local state serving
        state=$(d inspect -f '{{.State.Status}}' "$c" 2>/dev/null | tr -d '\n')
        [ -n "$state" ] || state=absent
        if [ "$c" = "$CF_CONTAINER" ]; then
            serving="-"
        elif serves "$c"; then
            serving="yes"
        else
            serving="no"
        fi
        printf '%-24s %-10s %s\n' "$c" "$state" "$serving"
    done
}

[ -f "$CF_CONFIG" ] || die "no cloudflared config at $CF_CONFIG"

case "${1:-status}" in
    pingclair | pc) switch_to "$PC_CONTAINER" "$PC_ORIGIN" pingclair ;;
    caddy) switch_to "$CADDY_CONTAINER" "$CADDY_ORIGIN" caddy ;;
    status | "") show_status ;;
    *)
        say "usage: $0 {pingclair|caddy|status}"
        exit 2
        ;;
esac
