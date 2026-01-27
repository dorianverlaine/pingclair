# Build Stage
FROM rust:1.85-slim-bookworm AS builder

WORKDIR /usr/src/pingclair
COPY . .

RUN apt-get update && apt-get install -y cmake g++ pkg-config libssl-dev
RUN cargo build --release

# Runtime Stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/pingclair/target/release/pingclair /usr/local/bin/pingclair

WORKDIR /var/lib/pingclair
VOLUME ["/etc/pingclair", "/var/lib/pingclair"]

EXPOSE 80 443

ENTRYPOINT ["pingclair"]
CMD ["run", "/etc/pingclair/Pingclairfile"]
