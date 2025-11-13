## Quick onboarding for AI coding agents

This file contains focused guidance to help AI agents be productive in the Secreton repo.

### Big picture (read first)
- This is a multi-crate Rust workspace (see `Cargo.toml`). The service is composed of many crates under `crates/` such as `api`, `core`, `crypto`, `auth`, `agent`, `storage`, `security`, `secrets-*` and `ui`.
- `secreton-api` exposes HTTP endpoints; `secreton-agent` is a sidecar helper (auto-auth, template rendering, token sinks). Shared logic lives in `crates/common`, `crates/errors`, and `crates/config`.
- Key concepts: async-first design (`tokio` + `async_trait`), strong reliance on RustCrypto suite (no OpenSSL), `tracing` for logs, `zeroize` for secret handling, and `AuditLogger` for compliance/audit events.

### Which files show the architecture
- `Cargo.toml` (root) — main workspace membership and repo-wide constraints
- `CONTRIBUTING.md` — developer workflows, build/test steps, and expectations (clippy, fmt, coverage, Docker for DB)
- `crates/api/src/handlers/mod.rs` — API router and middleware setup (prefer this when editing API routes)
- `crates/api/src/bin/api_server.rs` and `crates/agent/src/main.rs` — how to run services locally
- `crates/crypto/src/transit/mod.rs` — example of `AuditLogger` trait usage and cryptography patterns
- `crates/errors/src/lib.rs` — `SecretonError` enum used across the workspace
- `config/default.toml`, `.env.example` — runtime configuration examples (DB, JWT secret, server ports)

### Build / test / run (developer workflows)
- Build all crates: `cargo build --workspace` (or `--workspace --all-features` for feature coverage)
- Run tests: `cargo test --workspace --all-features` or per-crate `cargo test -p secreton-api`
- Lint and formatting: `cargo fmt --all` and `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Run API locally (log/tracing enabled):
  - `cargo run -p secreton-api --bin api_server`
  - Or `cargo build -p secreton-api --release && ./target/release/api_server` (binary path may vary)
- Run agent locally: `cargo run -p secreton-agent` (or build with `--release` and inspect binary name)
- Integration tests require a DB: start Postgres for local tests: `docker run --name secreton-dev-db -e POSTGRES_PASSWORD=dev_password -e POSTGRES_USER=secreton_user -e POSTGRES_DB=secreton_db -p 5432:5432 -d postgres:15`
- Coverage: `cargo tarpaulin --workspace --all-features --out Lcov`
- Watch/iterative testing: `cargo watch -x test`

### Project-specific conventions & patterns
- Crate naming: `secreton-<module>` for top-level crates. Keep shared logic in `crates/common`.
- Audit: Most security/crypto modules call `AuditLogger` trait; implement or provide `DefaultAuditLogger` for audit events. See `crates/crypto/src/transit/mod.rs`.
- Error handling: Use `SecretonError` (see `crates/errors`) for standardized errors and HTTP status mapping. Map to `ApiResponse`/`ApiResult` patterns.
- HTTP frameworks: The repo contains both `axum` and `warp` usages (varies by crate/file). When editing API handlers prefer the pattern in `crates/api/src/handlers/*` where `axum::Router` is used. When adding endpoints, search for existing `create_routes()` / `create_router()` patterns.
- Secrets & memory hygiene: Use `zeroize` and clear secret material when appropriate. Many cryptographic structures use `Zeroize` traits; follow those patterns.
- Async & concurrency: Use `tokio`, `async_trait`, `Arc` + `RwLock` where shared mutable state is required (see `TransitEngine`).

### Integration points & external dependencies
- Databases: PostgreSQL is recommended (see `config/default.toml`), but Mongo and SQLite appear in the workspace for tests/alternate drivers.
- External SDKs: AWS SDK, Kube, and other cloud SDKs are optional, used in integrations under `crates/integrations`/`crates/infrastructure`.
- Telemetry & monitoring: Prometheus, OpenTelemetry, `tracing` used widely; health endpoints exist (`/health` or `/healthz` in agent).
- CI: There are no visible GitHub Actions workflows in the repo; follow `CONTRIBUTING.md` commands for local verification (clippy, fmt, tests, audit).

### Search shortcuts & things to inspect before edits
- Find API router: search for `create_router(` and `create_routes()` (e.g., `api/src/handlers/`)
- Audit & logging: `AuditLogger`, `AuditLog`, and `ApiResponse` (in `crates/errors` and `crates/crypto`)
- Error types: `SecretonError` and mapping to HTTP codes (`crates/errors/src/lib.rs`)
- Shared services: `ServiceContainer` and `AppState` (used to wire dependencies for tests and runtime)
- Secret handling: `crates/crypto` for transit engine and `zeroize` usage

### Quick PR checklist for agents
1. Match existing crate boundaries—implement features inside the appropriate `crates/<name>`.
2. Run `cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and `cargo test --workspace --all-features` before proposing changes.
3. Update `CONTRIBUTING.md` or crate-level README if you modify developer workflow or important commands.
4. If implementing public APIs, add unit and integration tests; prefer `#[tokio::test]` for async flows.

### Additional notes for AI agents
- The repo mixes a few frameworks (Axum, Warp) and older/newer patterns; when uncertain, prefer code patterns used in the same crate (e.g., `axum` in `crates/api` handlers).
- Where security or crypto is involved, follow existing crypto wrappers and auditing usage (e.g., `TransitEngine` and `AuditLogger`).
- Keep changes minimal and localized: prefer adding functions/traits in the same crate or shared crate (`common`) and avoid cross-crate cycles.

If any section is unclear or you'd like specific examples for a particular crate or code pattern, ask and I'll expand the instructions. ✅
