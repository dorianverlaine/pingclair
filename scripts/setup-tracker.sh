#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

# 🗂️ Create the labels and the project board that CONTRIBUTING.md describes.
#
# Idempotent: run it as often as you like. Existing labels are updated to the
# colour and description below rather than skipped, so this file stays the one
# place the scheme is defined — the alternative is a scheme that lives half in
# a document and half in somebody's browser tab, which is the arrangement this
# whole tracker was built to escape.
#
# 🔑 Creating a project board needs a token scope the default `gh` login does
# not include. If this script tells you to run `gh auth refresh`, that is why;
# labels are created either way and the board step is skipped rather than
# failing the run.

set -Eeuo pipefail

readonly repository="${PINGCLAIR_REPO:-dorianverlaine/pingclair}"
readonly owner="${repository%%/*}"
readonly project_title="Pingclair"

# 🏷️ label|colour|description — severity first, then kind, then routing.
readonly -a labels=(
  "p0|b60205|Data loss, remotely triggerable crash, or security defect. Interrupts the current session."
  "p1|d93f0b|Wrong behaviour a user can reach."
  "p2|fbca04|Cleanups, missing coverage, papercuts, drifted documentation."
  "needs-triage|ededed|Not classified yet. Both issue templates set this."
  "bug|d73a4a|Something is not working"
  "compatibility|1d76db|A Caddyfile that works with Caddy and does not work here"
  "enhancement|a2eeef|New feature or request"
  "documentation|0075ca|Improvements or additions to documentation"
  "h1-h2|c5def5|Affects the H1/H2 path only (server.rs)"
  "h3|bfd4f2|Affects the H3 path only (quic.rs)"
  "blocked-upstream|5319e7|Waiting on a dependency. The body names the upstream issue."
  "wontfix|ffffff|Investigated, understood, deliberately unchanged. The body says why."
)

# 📊 The board columns, in flow order. Kept identical to CONTRIBUTING.md.
readonly -a columns=(
  "📥 Inbox"
  "🔬 Triage"
  "📋 Ready"
  "🔧 In Progress"
  "👀 Review"
  "✅ Done"
)

log() { printf '%s\n' "$*" >&2; }

create_labels() {
  log "🏷️  Labels on ${repository}"
  local entry name colour description
  for entry in "${labels[@]}"; do
    IFS='|' read -r name colour description <<<"${entry}"
    # 🔁 --force turns create into upsert, so the scheme here always wins.
    if gh label create "${name}" \
      --repo "${repository}" \
      --color "${colour}" \
      --description "${description}" \
      --force >/dev/null 2>&1; then
      log "   ✅ ${name}"
    else
      log "   ❌ ${name} — could not be created or updated"
      return 1
    fi
  done
}

# 🔍 Returns the node ID of the existing project, or nothing.
find_project() {
  gh project list --owner "${owner}" --format json 2>/dev/null |
    python3 -c "
import json, sys
title = sys.argv[1]
try:
    projects = json.load(sys.stdin).get('projects', [])
except (json.JSONDecodeError, ValueError):
    sys.exit(0)
for project in projects:
    if project.get('title') == title:
        print(project['number'])
        break
" "${project_title}"
}

create_board() {
  if ! gh auth status 2>&1 | grep -q 'project'; then
    log ""
    log "⏭️  Skipping the board: the current token has no project scope."
    log "    Grant it, then run this script again:"
    log ""
    log "        gh auth refresh -s project,read:project"
    log ""
    return 0
  fi

  log "📊 Project board"
  local number
  number="$(find_project)"
  if [[ -z "${number}" ]]; then
    number="$(gh project create --owner "${owner}" --title "${project_title}" \
      --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["number"])')"
    log "   ✅ created project #${number}"
  else
    log "   ↩️  project #${number} already exists"
  fi

  log ""
  log "📌 One manual step remains, and gh cannot do it: the built-in Status"
  log "   field's options are not writable through the CLI. Open the project"
  log "   settings and set Status to exactly these, in this order:"
  log ""
  local column
  for column in "${columns[@]}"; do
    log "        ${column}"
  done
  log ""
  log "   Then set the workflow 'Item added to project' → 📥 Inbox, and"
  log "   'Pull request merged' → ✅ Done, so the board maintains itself."
}

main() {
  if ! command -v gh >/dev/null 2>&1; then
    log "❌ gh is not installed."
    return 1
  fi
  create_labels
  create_board
  log ""
  log "🎯 Done. The scheme itself is documented in CONTRIBUTING.md."
}

main "$@"
