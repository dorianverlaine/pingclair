# 🏗️ Build Stage
#
# 🧊 The environment is `deployment/Builder.Dockerfile`, the same image CI and
# every Linux builder runs — which is also what makes this image's build
# artifacts interchangeable with theirs. It pins Ubuntu 24.04, Rust 1.98.1,
# clang/cmake/BoringSSL's dependencies, and the workspace path; the apt list
# that used to live here is defined once, there.
#
# 📌 `:v1` is a tag this repository controls and moves deliberately (the digest
# of record is recorded in .github/workflows/builder-image.yml); the base image
# is pinned the same way CI pins `ubuntu-24.04`.
FROM ghcr.io/dorianverlaine/pingclair-builder:v1 AS builder

COPY . .

# 🔒 `--locked` so the image is built from the resolved versions the tests ran
# against, not whatever the registry offers today.
RUN cargo build --release --locked

# 🚀 Runtime Stage — same pinned LTS as the builder and the CI runners.
FROM ubuntu:24.04

# 🛰️ Same retry policy as the builder stage, and the helper does not stay in
# the runtime image.
COPY deployment/apt-retry.sh /usr/local/bin/apt-retry
RUN apt-retry ca-certificates \
    && rm -f /usr/local/bin/apt-retry

COPY --from=builder /cache/cargo-target/release/pingclair /usr/local/bin/pingclair

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
