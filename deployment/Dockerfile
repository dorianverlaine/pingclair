# 🏗️ Build Stage
#
# Ubuntu 24.04 LTS, pinned the same way CI pins `ubuntu-24.04` runners: a
# floating `latest` tag lets the image drift to a newer release than the tests
# ran under, which is the "green locally, red in production" trap one layer
# further out. The toolchain comes from rustup rather than the distribution
# because `rust-version = "1.97"` is pinned in Cargo.toml and CI verifies
# exactly that.
FROM ubuntu:24.04 AS builder

# 🔨 What each of these is for, because a missing one fails far from its cause:
#   cmake, make, g++     — BoringSSL's own build; cmake on Ubuntu does not
#                          pull `make`, so the "Unix Makefiles" generator
#                          has nothing to run without it
#   clang, libclang-dev  — bindgen needs libclang to generate the FFI bindings
#   git                  — boring-sys runs `git init` on the vendored BoringSSL
#                          source to apply its patches; without the binary it
#                          panics as a bare `NotFound` that names no file
#   curl, ca-certificates — fetching rustup below; the Ubuntu base ships no
#                           CA bundle, so curl cannot verify sh.rustup.rs
#                           without it
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
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
    && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
# 🎯 Downloaded to a file rather than `curl | sh`: `RUN` execs a plain shell
# with no `pipefail`, so a `curl` that dies mid-stream feeds `sh` an empty
# script that exits 0, and the layer succeeds having installed nothing. The
# next `RUN` would then fail on a plain `cargo: command not found` that names
# no cause. The final `cargo --version` is the actual guard: no later layer
# can build against a toolchain that silently never arrived.
RUN curl --proto '=https' --tlsv1.2 --retry 3 --retry-connrefused -sSf \
        https://sh.rustup.rs -o /tmp/rustup-init.sh \
    && sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain 1.97.1 \
    && rm -f /tmp/rustup-init.sh \
    && cargo --version

WORKDIR /usr/src/pingclair
COPY . .

# 🔒 `--locked` so the image is built from the resolved versions the tests ran
# against, not whatever the registry offers today.
RUN cargo build --release --locked

# 🚀 Runtime Stage — same pinned LTS as the builder and the CI runners.
FROM ubuntu:24.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/pingclair/target/release/pingclair /usr/local/bin/pingclair

# 📂 Same convention as caddy's official image: bake a stable data path into
# the image so the store lands on the declared volume and survives container
# recreation. Without this, HOME=/root sends it to the container's writable
# layer, which `docker compose up --force-recreate` silently drops.
ENV PINGCLAIR_TLS_STORE=/var/lib/pingclair/certs

WORKDIR /var/lib/pingclair
VOLUME ["/etc/pingclair", "/var/lib/pingclair"]

EXPOSE 80 443

ENTRYPOINT ["pingclair"]
CMD ["run", "/etc/pingclair/Pingclairfile"]
