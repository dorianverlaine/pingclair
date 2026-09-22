#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

# 🧊 The environment behind `just shared-build`, sourced rather than executed.
#
# The credentials live outside the checkout, one file per machine, mode 600:
# `~/.config/pingclair/cache.env`. That file is what makes a machine part of the
# cache fabric, and it is the only file a new machine needs. Everything else —
# which levels sccache uses, how a remote write failure is treated, where the
# local layer lives — is set here so every machine agrees.
#
# 🔐 Nothing in here is ever printed: `set -x` would leak the key, so this file
# must not be run under it.

set -euo pipefail

cache_env_file="${PINGCLAIR_CACHE_ENV:-$HOME/.config/pingclair/cache.env}"

if [[ ! -f "$cache_env_file" ]]; then
  cat >&2 <<EOF
🚫 No cache credentials at $cache_env_file

   Ask the maintainer for this machine's credential file, or create one with:

     mkdir -p ~/.config/pingclair && touch $cache_env_file && chmod 600 $cache_env_file
     # then paste the export lines for this machine into it

   AGENTS.md, "Shared build cache", describes what the values mean and which
   bucket each kind of machine is allowed to use.
EOF
  exit 1
fi

# shellcheck source=/dev/null
source "$cache_env_file"

: "${SCCACHE_BUCKET:?the credential file must set SCCACHE_BUCKET}"
: "${SCCACHE_ENDPOINT:?the credential file must set SCCACHE_ENDPOINT}"
: "${AWS_ACCESS_KEY_ID:?the credential file must set AWS_ACCESS_KEY_ID}"
: "${AWS_SECRET_ACCESS_KEY:?the credential file must set AWS_SECRET_ACCESS_KEY}"

# 🪜 Disk first, R2 second. `l0` keeps a Cloudflare wobble from failing a build:
# only the local layer, whose failure means the machine itself is broken, is
# allowed to abort one.
export SCCACHE_MULTILEVEL_CHAIN="${SCCACHE_MULTILEVEL_CHAIN:-disk,s3}"
export SCCACHE_MULTILEVEL_WRITE_ERROR_POLICY="${SCCACHE_MULTILEVEL_WRITE_ERROR_POLICY:-l0}"
export SCCACHE_REGION="${SCCACHE_REGION:-auto}"
export SCCACHE_S3_USE_SSL="${SCCACHE_S3_USE_SSL:-true}"
# 🌍 The AWS CLI reads its own region variables, and R2 only accepts `auto`.
# Setting this here keeps `aws s3 ...` in the same shell (the cache audit, for
# instance) from falling back to whatever region the machine's aws config names.
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-auto}"
export AWS_REGION="${AWS_REGION:-auto}"
export RUSTC_WRAPPER=sccache
# 🔁 Incremental artifacts cannot be shared between machines, so a shared build
# turns them off. The everyday `cargo build` keeps them; this is opt-in.
export CARGO_INCREMENTAL=0

if [[ -z "${SCCACHE_DIR:-}" ]]; then
  if [[ "$(uname -s)" == "Darwin" ]]; then
    SCCACHE_DIR="$HOME/Library/Caches/pingclair/sccache"
    SCCACHE_CACHE_SIZE="${SCCACHE_CACHE_SIZE:-20G}"
  else
    SCCACHE_DIR="$HOME/.cache/pingclair/sccache"
    SCCACHE_CACHE_SIZE="${SCCACHE_CACHE_SIZE:-10G}"
  fi
fi
export SCCACHE_DIR SCCACHE_CACHE_SIZE
mkdir -p "$SCCACHE_DIR"
