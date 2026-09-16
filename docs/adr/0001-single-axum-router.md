# 1. One Axum router, one listener

Date: 2026-08-06 · Status: accepted

## Context

The server ran two HTTP stacks at once. `crates/api/src/lib.rs` built a warp filter graph
served on the configured port; `create_api_router` built an Axum router served on that
port **plus ten**. The binary's own comments explained why: warp is built on hyper 0.14
and Axum 0.8 on hyper 1.0, so the two could not be composed, and unifying them was
declared out of scope.

The consequences were not confined to the server:

- Two major versions of `axum` resolved into one dependency tree.
- `crates/ui/Trunk.toml` hardcoded the `+10` offset, splitting the frontend's proxy
  across two backends. Changing the port silently broke half the API.
- Two listeners meant two TLS configurations, two readiness probes, two Kubernetes
  Service ports and two NetworkPolicy rules.
- A complete, correctly-layered Axum router already existed in `handlers/mod.rs` — with
  tracing, compression, timeouts, CORS, body limits, security headers, rate limiting,
  seal and auth — but was reachable only from `#[cfg(test)]`. Production traffic went
  through the weaker `create_api_router`, which applied `CorsLayer::allow_origin(Any)`
  and required authentication even for health checks.

## Decision

Delete warp. One `axum::Router` serves the Leptos application, `/api/v1`, static assets,
health, metrics and — behind the `grpc` feature — gRPC, on one listener.

gRPC is mounted into that same router rather than given its own port. `tonic` 0.14
depends on `axum` 0.8 and `hyper` 1, so its `Routes` is an `axum::Router` and merges
directly; `axum::serve` uses hyper-util's auto builder, which handles the HTTP/2
prior-knowledge upgrade a `tonic` client makes over `http://`.

## Consequences

One port to expose, one TLS configuration, one middleware stack shared by REST and gRPC.
`nginx/`, `Dockerfile.frontend` and `Trunk.toml` are all deleted — the process serves its
own frontend. The port offset and its documentation disappear.

The cost is that any future protocol must be expressible as a tower service. That has
been true of everything considered so far.
