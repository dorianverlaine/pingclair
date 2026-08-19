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

# 🏷️ name|colour|description|former-name — severity first, then kind, then
# routing. The emoji is a category marker and is part of the name, so it must
# match the issue templates character for character.
#
# The fourth field is the pre-emoji name, kept so this script can rename an
# existing label rather than leaving a duplicate behind. It is also why the
# names below are not free to churn: renaming a label breaks every saved
# filter and every template referencing it, so pick one and keep it.
readonly -a labels=(
  "💥 p0|b60205|Data loss, remotely triggerable crash, or security defect. Interrupts the current session.|p0"
  "🔥 p1|d93f0b|Wrong behaviour a user can reach.|p1"
  "🧹 p2|fbca04|Cleanups, missing coverage, papercuts, drifted documentation.|p2"
  "🔬 needs-triage|ededed|Not classified yet. Both issue templates set this.|needs-triage"
  "🐛 bug|d73a4a|Something is not working|bug"
  "🧩 compatibility|1d76db|A Caddyfile that works with Caddy and does not work here|compatibility"
  "✨ enhancement|a2eeef|New feature or request|enhancement"
  "📚 documentation|0075ca|Improvements or additions to documentation|documentation"
  "🔗 h1-h2|c5def5|Affects the H1/H2 path only (server.rs)|h1-h2"
  "🛰️ h3|bfd4f2|Affects the H3 path only (quic.rs)|h3"
  "⏳ blocked-upstream|5319e7|Waiting on a dependency. The body names the upstream issue.|blocked-upstream"
  "🚫 wontfix|ffffff|Investigated, understood, deliberately unchanged. The body says why.|wontfix"
)

# 📊 name|colour|description — the board columns in flow order, kept identical
# to CONTRIBUTING.md. Colours are the GitHub project palette (GRAY, BLUE,
# GREEN, YELLOW, ORANGE, RED, PINK, PURPLE), and they run cool to warm so the
# board reads as temperature before you read a single word.
readonly -a columns=(
  "📥 Inbox|GRAY|Newly opened, nobody has looked yet."
  "🔬 Triage|PURPLE|Being assessed: is it real, how exposed is a user, which transport?"
  "📋 Ready|BLUE|Understood well enough that someone could start cold."
  "🔧 In Progress|YELLOW|Actively being worked on. Say so in the issue."
  "👀 Review|ORANGE|Pull request open, waiting on review or CI."
  "✅ Done|GREEN|Merged, or closed with a recorded reason."
)

log() { printf '%s\n' "$*" >&2; }

# 🔍 Is this label already on the repository?
label_exists() {
  gh label list --repo "${repository}" --limit 200 --json name \
    --jq ".[] | select(.name == \"$1\") | .name" 2>/dev/null | grep -q .
}

create_labels() {
  log "🏷️  Labels on ${repository}"
  local entry name colour description former
  for entry in "${labels[@]}"; do
    IFS='|' read -r name colour description former <<<"${entry}"

    # 🔁 Rename the pre-emoji label rather than creating a second one beside
    # it. GitHub carries the issues across a rename; a delete-and-create would
    # strip the label off every issue already wearing it.
    if [[ -n "${former}" && "${former}" != "${name}" ]] &&
      label_exists "${former}" && ! label_exists "${name}"; then
      if gh label edit "${former}" --repo "${repository}" --name "${name}" \
        --color "${colour}" --description "${description}" >/dev/null 2>&1; then
        log "   🔁 ${former} → ${name}"
        continue
      fi
      log "   ❌ ${former} — rename to ${name} failed"
      return 1
    fi

    # 🆕 --force turns create into upsert, so the scheme here always wins.
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

  # 🔗 A user-owned project is not attached to the repository just because it
  # was created by its owner. Without this, the repository's Projects tab
  # cheerfully reports "No projects found" while the board sits there fully
  # configured, which is a confusing ten minutes nobody needs twice.
  if gh project link "${number}" --owner "${owner}" --repo "${repository}" >/dev/null 2>&1; then
    log "   🔗 linked to ${repository}"
  else
    log "   ↩️  already linked to ${repository}"
  fi

  configure_status_field "${number}"
}

# 🎚️ Rewrite the built-in Status field's options to the columns above.
#
# `gh project field-list` can read them and no gh subcommand can write them,
# so this drops to GraphQL. `updateProjectV2Field` replaces the option set
# wholesale — options not named here are removed, which is the point: the
# defaults (Todo / In Progress / Done) are not our columns.
configure_status_field() {
  local number="$1" field_id options entry name colour description
  field_id="$(gh project field-list "${number}" --owner "${owner}" --format json |
    python3 -c "
import json, sys
for field in json.load(sys.stdin)['fields']:
    if field['name'] == 'Status':
        print(field['id'])
        break
")"
  if [[ -z "${field_id}" ]]; then
    log "   ❌ no Status field on project #${number}"
    return 1
  fi

  options=""
  for entry in "${columns[@]}"; do
    IFS='|' read -r name colour description <<<"${entry}"
    options+="{name: \"${name}\", color: ${colour}, description: \"${description}\"} "
  done

  if gh api graphql -f query="
mutation {
  updateProjectV2Field(input: {
    fieldId: \"${field_id}\"
    singleSelectOptions: [${options}]
  }) { projectV2Field { ... on ProjectV2SingleSelectField { name } } }
}" >/dev/null 2>&1; then
    log "   ✅ Status field set to the six columns"
  else
    log "   ❌ could not write the Status field options"
    return 1
  fi

  log ""
  log "📌 One step is still manual — project workflows are not scriptable:"
  log "   set 'Item added to project' → 📥 Inbox and 'Pull request merged'"
  log "   → ✅ Done, so the board maintains itself instead of you."
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
