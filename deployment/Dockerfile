# 🏗️ Build Stage
#
# Ubuntu rather than Fedora, with the toolchain from rustup rather than the
# distribution: `rust-version = "1.97"` is pinned in Cargo.toml and CI verifies
# exactly that, so whatever Rust Ubuntu happens to ship is the wrong one.
# Building a release image with a compiler the tests never ran under is the
# "green locally, red in CI" trap one layer further out.
FROM ubuntu:latest AS builder

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

# 🚀 Runtime Stage
FROM ubuntu:latest

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/pingclair/target/release/pingclair /usr/local/bin/pingclair

WORKDIR /var/lib/pingclair
VOLUME ["/etc/pingclair", "/var/lib/pingclair"]

EXPOSE 80 443

ENTRYPOINT ["pingclair"]
CMD ["run", "/etc/pingclair/Pingclairfile"]
