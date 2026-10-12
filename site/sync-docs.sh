#!/bin/sh
# 🔁 Keeps pingclair.com's static tree at the newest pingclair-docs build.
#
# The docs repository's CI builds every push to main and publishes the result
# to its rolling `site-latest` release: `site.tar.gz`, and `site.json` naming
# the commit and the tarball's sha256. This script, run from cron, compares
# that commit with the one being served and, when they differ, installs the new
# bundle beside the old one and switches a symlink to it.
#
# 📌 Why a symlink: the web root Pingclair serves is
# /usr/local/www/pingclair.pingclair.com, and it points at
# /usr/local/www/pingclair-site/<commit>. Renaming a new link over it is one
# atomic step, so a request never sees half of one build and half of another,
# and the previous build stays on disk for a rollback. Pingclair needs no
# reload: it resolves paths under the root on every request.
#
# 🛡️ A bundle is installed only if its sha256 matches `site.json` and its key
# pages exist; after the switch, the live site must answer, or the link goes
# back to the build that was serving before.
set -eu

# 🧭 The first run expects $LIVE to be a symlink already. Converting the
# original directory is a one-time step, described in this directory's README.

# 🧪 Every path can be overridden, so a dry run can use a scratch tree.
BASE=${BASE:-https://github.com/dorianverlaine/pingclair-docs/releases/download/site-latest}
WWW=${WWW:-/usr/local/www}
LIVE=${LIVE:-$WWW/pingclair.pingclair.com}
STORE=${STORE:-$WWW/pingclair-site}
KEEP=${KEEP:-3}

# 📌 Plain ASCII in the messages themselves: syslogd escapes every byte above
# 0x7f, so an emoji arrives in /var/log/messages as a run of `M-^` sequences.
log() { logger -t pingclair-site-sync "$*"; }

# 🚦 One run at a time: a slow download must not overlap the next cron tick.
if [ "${SYNC_LOCKED:-}" != 1 ]; then
	exec env SYNC_LOCKED=1 lockf -s -t 0 /var/run/pingclair-site-sync.lock "$0" "$@"
fi

work=$(mktemp -d /tmp/site-sync.XXXXXX)
trap 'rm -rf "$work"' EXIT

fetch -q -T 30 -o "$work/site.json" "$BASE/site.json"
commit=$(sed -n 's/.*"commit":"\([0-9a-f]\{40\}\)".*/\1/p' "$work/site.json")
want=$(sed -n 's/.*"sha256":"\([0-9a-f]\{64\}\)".*/\1/p' "$work/site.json")
if [ -z "$commit" ] || [ -z "$want" ]; then
	log "site.json is not readable; keeping the current build"
	exit 1
fi

current=$(readlink "$LIVE" 2>/dev/null || true)
[ "$current" = "$STORE/$commit" ] && exit 0

fetch -q -T 120 -o "$work/site.tar.gz" "$BASE/site.tar.gz"
got=$(sha256 -q "$work/site.tar.gz")
if [ "$got" != "$want" ]; then
	# 📌 Expected for a moment while CI uploads a new bundle; the next run
	# finds the pair consistent.
	log "tarball sha256 $got does not match site.json for $commit yet"
	exit 0
fi

mkdir -p "$STORE"
rm -rf "$STORE/$commit.new"
mkdir "$STORE/$commit.new"
tar -xzf "$work/site.tar.gz" -C "$STORE/$commit.new"
for f in index.html 404.html index.md llms.txt sitemap-index.xml; do
	if [ ! -f "$STORE/$commit.new/$f" ]; then
		log "bundle $commit lacks $f; keeping the current build"
		rm -rf "$STORE/$commit.new"
		exit 1
	fi
done
chown -R root:wheel "$STORE/$commit.new"
chmod -R u=rwX,go=rX "$STORE/$commit.new"
rm -rf "${STORE:?}/$commit"
mv "$STORE/$commit.new" "$STORE/$commit"

# 🔀 The switch: a new link renamed over the old one.
rm -f "$WWW/.pingclair-site-next"
ln -s "$STORE/$commit" "$WWW/.pingclair-site-next"
mv -h "$WWW/.pingclair-site-next" "$LIVE"

# 🩺 The live site must still answer; otherwise go back.
ok=1
for path in / /start/install/ /llms.txt /sitemap-index.xml; do
	status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
		--resolve pingclair.com:443:127.0.0.1 "https://pingclair.com$path" || echo 000)
	[ "$status" = 200 ] || { ok=0; log "$path answered $status after switching to $commit"; }
done
if [ "$ok" != 1 ]; then
	if [ -n "$current" ] && [ -d "$current" ]; then
		rm -f "$WWW/.pingclair-site-next"
		ln -s "$current" "$WWW/.pingclair-site-next"
		mv -h "$WWW/.pingclair-site-next" "$LIVE"
		log "rolled back to $current"
	fi
	exit 1
fi
log "now serving pingclair-docs $commit (was ${current:-nothing})"

# 🧹 Keep the newest builds for rollback; never the one being served.
find "$STORE" -mindepth 1 -maxdepth 1 -type d ! -name '*.new' -exec stat -f '%m %N' {} + |
	sort -rn | tail -n +$((KEEP + 1)) | while read -r _ old; do
	[ "$old" = "$STORE/$commit" ] || rm -rf "$old"
done
