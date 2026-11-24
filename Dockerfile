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
    cargo build --profile release-prod --locked --features silver/metrics --bin silver --bin silver_surfer && \
    cp target/release-prod/silver target/release-prod/silver_surfer /usr/local/bin/

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS runtime

WORKDIR /

LABEL org.opencontainers.image.source="https://github.com/gattaca-com/silver" \
    org.opencontainers.image.licenses="MIT"

# Without this the tracing subscriber writes to rolling files under LOG_PATH,
# where `docker logs` never sees them.
ENV LOG_STDOUT=1
# The loopback default is unreachable through `-p 5051:5051`.
ENV SILVER_BEACON_API_BIND=0.0.0.0:5051

ENTRYPOINT ["/usr/local/bin/silver"]

# Release builds package the exact binaries attached to the GitHub release.
# `BIN_ARCH` is the asset suffix (x86_64, aarch64), not the Docker platform name.
FROM runtime AS release
ARG BIN_ARCH=x86_64
COPY --chmod=755 silver-linux-${BIN_ARCH} /usr/local/bin/silver
COPY --chmod=755 silver_surfer-linux-${BIN_ARCH} /usr/local/bin/silver_surfer

# The kurtosis launcher runs silver through `sh -c`, which distroless lacks.
FROM gcr.io/distroless/cc-debian12:debug@sha256:bc3546a529388660b583cc85ca6559927652d54391dc8059419d7b4bf3921154 AS kurtosis
ENV LOG_STDOUT=1
ENTRYPOINT ["/usr/local/bin/silver"]
COPY --from=builder /usr/local/bin/silver /usr/local/bin/silver_surfer /usr/local/bin/

FROM runtime AS silver
COPY --from=builder /usr/local/bin/silver /usr/local/bin/silver_surfer /usr/local/bin/
