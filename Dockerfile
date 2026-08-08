# syntax=docker/dockerfile:1.7

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
# One image builds both halves: the native server binary and the WebAssembly
# bundle, via cargo-leptos. There is no second frontend image and no nginx —
# the server serves its own frontend, which is the point of the SSR move.
#
# protoc is vendored and there is no utoipa-swagger-ui downloading a zip
# mid-build, so the application's own build touches nothing but the crates
# registry. Two things in this stage still do: `cargo install cargo-leptos`
# compiles openssl-sys from source (openssl-src is in its tree), and
# cargo-leptos fetches the Tailwind CLI on first use because this project sets
# `tailwind-input-file`. Both happen while building the image, not while
# building the application — but calling the image "air-gapped" would be wrong.
#
# perl and make are what openssl-src needs. The slim image ships perl-base,
# which lacks FindBin, so OpenSSL's ./Configure aborts on line 15 and
# `cargo install cargo-leptos` fails outright — this image could not be built
# without them.
FROM rust:1.94.1-slim-bookworm AS chef
WORKDIR /app
RUN apt-get update \
 && apt-get install -y --no-install-recommends perl make pkg-config \
 && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked \
 && cargo install cargo-leptos --locked \
 && rustup target add wasm32-unknown-unknown

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Cached layer: dependencies only. Invalidated by Cargo.lock, not by source edits.
RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
# `--locked` so the image is built from the committed lockfile, which is the
# same graph `cargo audit` and `cargo deny` inspect in CI.
RUN cargo leptos build --release --locked

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
# Distroless: no shell, no package manager, nothing for an attacker who reaches
# code execution to pivot with. The previous image was debian-slim with curl and
# libssl-dev installed at runtime.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
WORKDIR /app

COPY --from=builder /app/target/release/secreton-server /usr/local/bin/secreton-server
COPY --from=builder /app/target/site /app/site

ENV LEPTOS_SITE_ROOT=/app/site \
    LEPTOS_SITE_ADDR=0.0.0.0:3000 \
    RUST_LOG=info

# One port. The previous deployment needed three: warp, axum at +10, and gRPC.
EXPOSE 3000

# Already `nonroot` (uid 65532) from the base image; stated explicitly so a
# future base change cannot silently promote the process to root.
USER nonroot:nonroot

# No HEALTHCHECK: distroless has no shell and no curl. Kubernetes should probe
# /health (liveness) and /health/ready (readiness) directly over HTTP.

ENTRYPOINT ["/usr/local/bin/secreton-server"]
