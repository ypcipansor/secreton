# Secreton

> **Alpha.** Under active development and not production-ready. APIs and storage
> schemas may change without a migration path.

A secrets-management platform in Rust: a [Leptos](https://leptos.dev) web application and a
REST + gRPC API, served by **one Axum process on one port**.

## What it is

Storage, encryption and access control for sensitive values, with a versioned KV engine,
encryption-as-a-service, a certificate authority, SSH certificate signing, dynamic database
credentials and TOTP.

The architecture is the point: it is meant to be a foundation you build on, so the
boundaries are enforced rather than described. `crates/domain` has no I/O and compiles for
WebAssembly, which is why the UI shares its types. `crates/engines` has no HTTP, which is
why the same service backs a REST handler, a gRPC method and a Leptos server function
without a translation layer.

## Quick start

Requires the toolchain pinned in `rust-toolchain.toml` (installed automatically by rustup)
and [`cargo-leptos`](https://github.com/leptos-rs/cargo-leptos).

```bash
cargo install cargo-leptos --locked

# Required: the server refuses to start without it.
export SECRETON__AUTH__JWT__SECRET="$(openssl rand -base64 48)"

cargo leptos serve
```

Then open <http://localhost:3000>. No database is needed — storage defaults to in-memory,
so a fresh checkout runs with no setup. State is lost on restart; configure PostgreSQL in
`secreton.toml` for anything else.

With Docker:

```bash
cp .env.example .env   # fill in SECRETON_JWT_SECRET and POSTGRES_PASSWORD
docker compose up --build
```

## Layout

Ten crates, strictly layered — a crate may only depend on those above it.

| Crate | What it holds |
|---|---|
| `crates/domain` | Shared types, the one `SecretonError`, the API envelope. No I/O, no web framework, compiles for wasm32. |
| `crates/crypto` | AEAD, KDFs, signing, Shamir sharing, the transit engine, the storage barrier. |
| `crates/storage` | One `StorageBackend` trait; memory, file, PostgreSQL, Redis, Raft. |
| `crates/auth` | Authentication methods, identity, MFA, tokens, the policy engine, governance. |
| `crates/engines` | Secret engines, seal, audit, lifecycle, and the `Services` graph. No HTTP. |
| `crates/ui` | The Leptos application. Compiles twice: into the server, and to wasm. |
| `crates/server` | Axum router, handlers, middleware, gRPC, and the binary. |
| `crates/client` · `cli` · `agent` | Typed HTTP client and the two auxiliary binaries. |

## What is supported

Claims here match what is implemented and tested; anything not listed is not present.

**Secret engines** — KV v2 (versioned, with rollback), Transit (encryption as a service),
PKI, SSH certificate signing, dynamic database credentials, TOTP.

**Storage** — in-memory and file (always available, no external service), PostgreSQL
(recommended), Redis, and Raft. Raft is single-node and **experimental**: no cluster
membership changes, no leader election across processes.

**Authentication** — username/password, AppRole for machine-to-machine, and OIDC for human
SSO. Sessions in the browser are `HttpOnly` cookies; programmatic clients use
`Authorization: Bearer`.

**Cryptography** — AES-256-GCM and ChaCha20-Poly1305 for data, Argon2id for passwords,
Ed25519 and P-256/P-384 for signatures, Shamir sharing for the unseal flow. There is no
RSA: the `rsa` crate carries an unfixed timing side channel (RUSTSEC-2023-0071).

**Interfaces** — REST under `/api/v1`, OpenAPI at `/api-docs/openapi.json`, gRPC (with
health checking and reflection) on the same port, and Leptos server functions for the UI.

## Development

```bash
cargo fmt --all
cargo clippy --workspace --locked --all-targets -- -D warnings
cargo test   --workspace --locked

# The UI must keep compiling for wasm; this is the check that catches a
# server-only dependency leaking into crates/ui.
cargo check -p secreton-ui --locked --target wasm32-unknown-unknown \
    --no-default-features --features hydrate
```

[`AGENTS.md`](AGENTS.md) is the working reference: layout, commands, the invariants that
review enforces, and how to add an endpoint, a page or a storage backend. It applies to
human contributors as much as to AI agents.

Architecture decisions and the evidence behind them are in [`docs/adr/`](docs/adr/).

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Do not open a public
issue.

## License

Apache-2.0. See [LICENSE](LICENSE).
