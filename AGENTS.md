# AGENTS.md

Instructions for AI coding agents working in this repository. This file is the single
source of truth; `.github/copilot-instructions.md` points here rather than repeating it.

Secreton is a secrets-management platform: a Leptos web application and a REST/gRPC API
served by one Axum process. Treat everything under `crates/` as security-sensitive.

## Layout

Ten crates, layered. A crate may only depend on crates above it in this list.

| Crate | Contains | May not contain |
|---|---|---|
| `crates/domain` | Shared types, the one `SecretonError`, the API envelope | Any I/O, any web framework — it must keep compiling for `wasm32-unknown-unknown` |
| `crates/crypto` | AEAD, KDF, signing, Shamir, the transit engine, the barrier | Storage, HTTP |
| `crates/storage` | One `StorageBackend` trait; memory, file, PostgreSQL, Redis, Raft | Business logic |
| `crates/auth` | Auth methods, identity, MFA, tokens, policy engine, governance | HTTP, axum layers |
| `crates/engines` | Secret engines, seal, audit, lifecycle, the `Services` graph | HTTP — no `axum`, no `Request`, no `StatusCode` |
| `crates/ui` | Leptos components, routes, server functions | Server-only dependencies (see below) |
| `crates/server` | Axum router, handlers, middleware, gRPC, the binary | Business logic — delegate to `engines` |
| `crates/client` | Typed HTTP client over `/api/v1` | — |
| `crates/cli`, `crates/agent` | Binaries built on `client` | Direct storage access |

## Commands

```bash
cargo check  --workspace --locked --all-targets
cargo clippy --workspace --locked --all-targets -- -D warnings
cargo fmt --all
cargo test   --workspace --locked

# The UI must compile for wasm. This is the guardrail that catches a server-only
# dependency leaking into crates/ui — run it before touching that crate's Cargo.toml.
cargo check -p secreton-ui --locked --target wasm32-unknown-unknown \
    --no-default-features --features hydrate

# Run the app (server + wasm + Tailwind, one process on :3000)
cargo leptos serve

# Both feature combinations must build
cargo check -p secreton-server --locked --no-default-features
cargo check -p secreton-server --locked --features grpc
```

The toolchain is pinned in `rust-toolchain.toml`. Do not add `+nightly` to any command.

## Invariants

These are not style preferences. Each one is here because violating it previously caused a
real defect in this repository.

1. **Axum only.** No `warp`, no second HTTP framework, no second listener, no port
   offsets. The process serves the UI, the REST API and gRPC from one router on one port.
   If you find yourself adding a second `serve()` call, stop.
2. **No tokens in `localStorage`.** Browser sessions are `httpOnly`, `Secure`,
   `SameSite=Lax` cookies. Programmatic clients (CLI, agent, other services) use
   `Authorization: Bearer`. A secrets manager that stores its own session token where
   any injected script can read it defeats its own purpose.
3. **CORS is an allowlist.** Never `allow_origin(Any)`. An empty origin list means
   same-origin only, which is correct now that the UI is served by this process.
4. **5xx bodies say nothing.** Internal errors return a fixed string to the client; the
   detail goes to the log, correlated by `x-request-id`. Connection strings and file
   paths must not reach a response body.
5. **No build-time network access.** A build script that downloads an artifact breaks
   hermetic, offline and air-gapped builds. This is why `utoipa-swagger-ui` is not a
   dependency — serve `/api-docs/openapi.json` and vendor any UI asset under `public/`.
6. **No reachable RSA.** Never construct or accept an RSA key. Use Ed25519, or
   P-256/P-384 where interoperability demands a NIST curve. `rsa` is in the tree
   transitively via `jsonwebtoken`'s provider and cannot currently be dropped without
   swapping to a C dependency; it stays unreachable because JWT validation allowlists
   HS256 only. If you touch `crates/auth/src/jwt.rs`, keep
   `only_hs256_tokens_are_accepted` passing — it is what makes that claim true.
7. **Secrets are `Zeroize`.** Key material and plaintext get zeroed on drop, and never
   appear in a `Debug` impl, a log line or an error message.
8. **Config is validated at startup.** A missing or malformed setting must stop the
   process. Never generate a JWT secret at boot: it silently invalidates every issued
   token on the next restart.
9. **`Cargo.lock` is committed.** Every CI and Docker command uses `--locked`.
10. **Audit before returning.** Any handler that reads, writes or deletes a secret emits
    an `AuditEvent` — including on the denial path, which is the path that matters.

## Adding things

**A REST endpoint.** Handler in `crates/server/src/handlers/`, exposed from that module's
`routes()`. Business logic goes in `crates/engines`, never in the handler. Add the
`utoipa` annotation so it appears in the OpenAPI document. Public (pre-auth) routes go in
`public_routes()`; everything else is behind the auth layer by default.

**A UI feature.** Components in `crates/ui/src/components/`, pages in
`crates/ui/src/pages/`, routed in `app.rs`. Fetch data with a `#[server]` function, not a
hand-written `fetch` — the server function shares its request and response types with the
backend, so a mismatch is a compile error. Any page you add must be reachable from
`app.rs`; an unrouted page is dead code.

**A storage backend.** Implement `StorageBackend` in `crates/storage/src/backends/`,
behind a cargo feature, with integration tests. A backend without tests does not go in.
Nineteen were deleted for exactly this reason — they compiled, were selectable from
config, and returned `"Not implemented"` in production.

**A dependency.** Add it to `[workspace.dependencies]` in the root manifest and reference
it as `foo.workspace = true`. Never pin a version in a member crate: that is how this repo
ended up with two versions of `axum` and `reqwest` in one tree.

## Testing

Unit tests live beside the code in `#[cfg(test)]`. Integration tests go in that crate's
`tests/`. There is no root `tests/` directory — the root manifest is a virtual workspace,
so cargo never builds one, and ~30 files sat there for months being silently ignored.

Write tests that would fail if the bug came back, and name them after the property, not
the function: `rolled_back_transaction_writes_are_discarded`, not `test_transaction`.
Cryptographic code gets property tests in `crates/crypto/tests/properties.rs`.

Never make a test depend on the network. If you need an endpoint that cannot be reached,
use `192.0.2.1` (RFC 5737).

## Pull requests

Conventional-commit titles (`feat:`, `fix:`, `refactor:`, …) with a capitalised subject.
Before pushing, run `fmt`, `clippy -D warnings`, `test`, and the wasm check above. State
in the description what you verified and what you did not.
