# 3. Keep gRPC, on tonic 0.14, in the shared router

Date: 2026-08-06 · Status: accepted

## Context

gRPC was served by `tonic` 0.12 on a separate port. Its real cost was not the protocol
but the version: `tonic` 0.12 depends on `axum` 0.6/0.7, so keeping it meant two major
versions of Axum in the tree — the same coupling that made unifying the HTTP stack look
impossible. The `proto` file declared an `AuthService::Login` that was never implemented,
and there was no health service and no reflection, so neither `grpcurl` nor a Kubernetes
gRPC probe could talk to it.

Five options were weighed: keep 0.12 as-is; upgrade to 0.14 on a separate port; upgrade
and mount into the shared router; drop gRPC for REST plus a generated OpenAPI client; or
drop it for server functions plus a typed Rust client crate.

## Decision

Keep gRPC. Upgrade to `tonic` 0.14 — which depends on `axum` 0.8 and `hyper` 1, removing
the duplicate-Axum problem entirely — and merge its `Routes` into the shared router, so it
answers on the same port behind the same middleware. Put it behind a default-on `grpc`
feature so a deployment that does not want it can compile it out, and build both shapes
in CI.

Add `tonic-health` and `tonic-reflection`, and implement the `AuthService::Login` the
proto already promised.

## Consequences

The stated use — east-west service-to-service traffic inside Kubernetes — keeps deadline
propagation, streaming, mTLS and a strict schema, none of which REST provides. Both costs
that made gRPC expensive here are gone: the duplicate Axum (fixed by 0.14) and the second
listener (fixed by mounting into the shared router).

Migrating 0.12 to 0.14 means moving prost codegen to `tonic-prost-build`. Layers that
buffer or time out whole request bodies must be scoped so they do not break streaming
RPCs.
