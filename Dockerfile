# Build Stage
FROM ghcr.io/rust-lang/rust:nightly-slim AS builder

WORKDIR /usr/src/app

# Install build dependencies (needed for Pingora/OpenSSL/etc)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
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
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/src/app/target/release/pingclair /usr/local/bin/pingclair

# Create folder for static files
RUN mkdir -p /var/www/html

EXPOSE 8080

CMD ["pingclair", "file-server", "--listen", ":8080", "--root", "/var/www/html"]
