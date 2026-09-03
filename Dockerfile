# syntax=docker/dockerfile:1

# `blst`, `hashtree-rs` and `mimalloc` compile C (and hashtree, assembly), and
# both `build.rs` scripts shell out to `buf`.
FROM rust:1.91-bookworm AS builder

ARG BUF_VERSION=1.67.0
RUN apt-get update && \
    apt-get install -y --no-install-recommends clang && \
    rm -rf /var/lib/apt/lists/* && \
    curl -fsSL -o /usr/local/bin/buf \
      "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-Linux-$(uname -m)" && \
    chmod +x /usr/local/bin/buf

WORKDIR /silver
COPY . .

# `--locked`: the committed Cargo.lock is under a publish-age cooldown (see
# the justfile), so resolution must not drift in the image.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/silver/target \
    cargo build --release --locked --no-default-features --bin silver && \
    cp target/release/silver /usr/local/bin/silver

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/silver /usr/local/bin/silver

# Without this the tracing subscriber writes to rolling files under LOG_PATH,
# where `docker logs` never sees them.
ENV LOG_STDOUT=1

ENTRYPOINT ["/usr/local/bin/silver"]
