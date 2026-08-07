# syntax=docker/dockerfile:1.7

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
# One image builds both halves: the native server binary and the WebAssembly
# bundle, via cargo-leptos. There is no second frontend image and no nginx —
# the server serves its own frontend, which is the point of the SSR move.
#
# No build stage reaches the network for anything but the crates registry:
# protoc is vendored, Tailwind is compiled locally, and there is no
# utoipa-swagger-ui downloading a zip mid-build. That is what makes this
# reproducible and air-gappable.
FROM rust:1.94.1-slim-bookworm AS chef
WORKDIR /app
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
