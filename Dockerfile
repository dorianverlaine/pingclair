# Build Stage
#
# Stable, not nightly: the workspace has no nightly-only feature gates
# (edition 2024 plus quiche needs Rust 1.88+, which stable has had for a
# 2025), and nightly's codegen backend has a known internal-compiler-error
# on aarch64 under this crate's release profile (panic="abort" + fat LTO +
# codegen-units=1) — it ICEs partway through compiling `tokio` itself.
FROM ghcr.io/rust-lang/rust:1-slim AS builder

WORKDIR /usr/src/app

# Install build dependencies (cmake + a C/C++ toolchain are needed to
# build the vendored BoringSSL used by quiche / pingora-boringssl; no
# system OpenSSL is required anymore)
RUN apt-get update && apt-get install -y \
    pkg-config \
    build-essential \
    cmake \
    git \
    clang \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY pingclair pingclair
COPY pingclair-api pingclair-api
COPY pingclair-config pingclair-config
COPY pingclair-core pingclair-core
COPY pingclair-plugin pingclair-plugin
COPY pingclair-proxy pingclair-proxy
COPY pingclair-static pingclair-static
COPY pingclair-tls pingclair-tls

# Build release
# Ensure we use standard libc (gnu) which jemalloc supports well
RUN cargo build --release --workspace

# Runtime Stage
FROM debian:sid-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/src/app/target/release/pingclair /usr/local/bin/pingclair

# Create folder for static files
RUN mkdir -p /var/www/html

EXPOSE 8080

CMD ["pingclair", "file-server", "--listen", ":8080", "--root", "/var/www/html"]
