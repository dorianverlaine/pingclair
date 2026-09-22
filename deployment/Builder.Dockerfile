# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

# 🧊 The Linux build environment, in one image that every Linux builder uses.
#
# Why this exists at all: compiled artifacts are only shared between machines
# whose compiler invocation is identical — the same workspace path, the same
# CARGO_HOME, the same target directory, the same toolchain, the same libraries.
# The alternative was a package list in each workflow, kept in step with
# `deployment/Dockerfile` by hand; the guardrail in `docs/guardrails/testing.md`
# already records where that ends. This file is the one place the environment is
# defined, and both CI and a maintainer's machine run it.
#
# 🚫 One architecture per build, on a matching runner: the amd64 image on
# `ubuntu-24.04`, the arm64 image on `ubuntu-24.04-arm`. Never build one from the
# other. An emulated build would make every artifact this image produces suspect
# and would hand the fabric cache entries that no real machine agrees with.
FROM ubuntu:24.04

# 🔨 What each package is for, because a missing one fails far from its cause:
#   cmake, make, g++     — BoringSSL's build; cmake on Ubuntu does not pull
#                          `make`, so the "Unix Makefiles" generator has nothing
#                          to run without it
#   clang, libclang-dev  — bindgen needs libclang for the FFI bindings
#   git                  — boring-sys runs `git init` on the vendored BoringSSL
#                          source to apply its patches
#   curl, ca-certificates — fetching rustup and sccache below
#   perl, pkg-config     — BoringSSL's build scripts and flag discovery
#   jq                   — the justfile asks cargo where the target dir is
#   python3              — scripts/repo_lint, scripts/cache-audit.py
#   python3-venv         — the codespell step builds a venv with ensurepip
#   zstd, xz-utils, unzip — archive handling for actions/cache and installers
#   sudo                 — the workflows are written for a runner where it
#                          exists; inside the image it is a no-op for root, and
#                          keeping it means one set of steps serves both
COPY deployment/apt-retry.sh /usr/local/bin/apt-retry
RUN apt-retry \
        cmake \
        make \
        g++ \
        perl \
        pkg-config \
        clang \
        libclang-dev \
        git \
        curl \
        ca-certificates \
        jq \
        python3 \
        python3-venv \
        zstd \
        xz-utils \
        unzip \
        sudo

# 🧭 Paths are part of the cache key, so they are fixed here rather than chosen
# per machine: a crate compiled at /workspace/pingclair with CARGO_HOME
# /usr/local/cargo produces the same key on every builder that uses this image.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    CARGO_TARGET_DIR=/cache/cargo-target \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /workspace/pingclair

RUN mkdir -p /workspace /cache && chmod 777 /cache

# 🎯 Downloaded to a file rather than `curl | sh`: `RUN` execs a plain shell with
# no `pipefail`, so a curl that dies mid-stream feeds `sh` an empty script that
# exits 0. The final `cargo --version` is the guard: no later layer can build
# against a toolchain that silently never arrived.
RUN curl --proto '=https' --tlsv1.2 --retry 3 --retry-connrefused -sSf \
        https://sh.rustup.rs -o /tmp/rustup-init.sh \
    && sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain 1.98.1 \
        -c rustfmt -c clippy \
    && rm -f /tmp/rustup-init.sh \
    && cargo --version \
    && rustc --version

# 🗃️ sccache, pinned. The clients of one cache agree on the storage format, and
# the version is part of that agreement; CI's action installs the same one.
ARG SCCACHE_VERSION=0.17.0
RUN arch="$(uname -m)" \
    && case "$arch" in x86_64) sc_arch=x86_64 ;; aarch64) sc_arch=aarch64 ;; \
       *) echo "unsupported architecture for sccache: $arch" >&2; exit 1 ;; esac \
    && curl -fsSL --retry 3 --retry-connrefused -o /tmp/sccache.tar.gz \
        "https://github.com/mozilla/sccache/releases/download/v${SCCACHE_VERSION}/sccache-v${SCCACHE_VERSION}-${sc_arch}-unknown-linux-musl.tar.gz" \
    && tar -xzf /tmp/sccache.tar.gz -C /tmp \
    && install -m 0755 "/tmp/sccache-v${SCCACHE_VERSION}-${sc_arch}-unknown-linux-musl/sccache" /usr/local/bin/sccache \
    && rm -rf /tmp/sccache.tar.gz "/tmp/sccache-v${SCCACHE_VERSION}-${sc_arch}-unknown-linux-musl" \
    && sccache --version

# 🧰 `just`, at the version `.github/actions/setup-ci` pins, so a build inside
# this image runs the same recipes as a build on a runner.
ARG JUST_VERSION=1.58.0
RUN arch="$(uname -m)" \
    && case "$arch" in x86_64) just_arch=x86_64 ;; aarch64) just_arch=aarch64 ;; \
       *) echo "unsupported architecture for just: $arch" >&2; exit 1 ;; esac \
    && curl -fsSL --retry 3 --retry-connrefused -o /tmp/just.tar.gz \
        "https://github.com/casey/just/releases/download/${JUST_VERSION}/just-${JUST_VERSION}-${just_arch}-unknown-linux-musl.tar.gz" \
    && tar -xzf /tmp/just.tar.gz -C /usr/local/bin just \
    && rm -f /tmp/just.tar.gz \
    && just --version
