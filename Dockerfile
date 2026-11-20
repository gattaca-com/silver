# syntax=docker/dockerfile:1

# `blst`, `hashtree-rs` and `mimalloc` compile C (and hashtree, assembly).
FROM rust:1.91-bookworm AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends clang && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /silver
COPY . .

ARG SILVER_BUILD_COMMIT

# `--locked`: the committed Cargo.lock is under a publish-age cooldown (see
# the justfile), so resolution must not drift in the image.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/silver/target \
    cargo build --profile release-prod --locked --bin silver --bin silver_surfer && \
    cp target/release-prod/silver target/release-prod/silver_surfer /usr/local/bin/

FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

LABEL org.opencontainers.image.source="https://github.com/gattaca-com/silver" \
    org.opencontainers.image.licenses="MIT"

# Without this the tracing subscriber writes to rolling files under LOG_PATH,
# where `docker logs` never sees them.
ENV LOG_STDOUT=1

ENTRYPOINT ["/usr/local/bin/silver"]

# Release builds package the exact binaries attached to the GitHub release.
# `BIN_ARCH` is the asset suffix (x86_64, aarch64), not the Docker platform name.
FROM runtime AS release
ARG BIN_ARCH=x86_64
COPY --chmod=755 silver-linux-${BIN_ARCH} /usr/local/bin/silver
COPY --chmod=755 silver_surfer-linux-${BIN_ARCH} /usr/local/bin/silver_surfer

FROM runtime AS silver
COPY --from=builder /usr/local/bin/silver /usr/local/bin/silver_surfer /usr/local/bin/
