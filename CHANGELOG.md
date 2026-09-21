# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Full architectural rewrite. The workspace went from 23 crates and ~170k lines to 10 crates
and ~59k, and from not compiling at all to a green build with a full test suite.

### Fixed

- The Docker image builds and runs. It never had been built: `cargo install cargo-leptos`
  failed for want of perl, `cargo leptos build --locked` used a flag that does not exist,
  `style-file` pointed at a file that has never been in the repository, `secreton-server`
  had no `ssr` feature for cargo-leptos to build with, the Tailwind config was v3 syntax
  against the v4 CLI cargo-leptos fetches, and the runtime bound 127.0.0.1:8080 — so even
  once it built, the container served nobody.

- `cargo deny check` passes. It had never been run against this branch: the `bincode`
  direct dependency is permanently unmaintained (RUSTSEC-2025-0141), an ignore for
  `fxhash`/wasmtime referred to a dependency this repository no longer has, and the
  advisories for `rustls-pemfile` and `proc-macro-error2` were undeclared. Every remaining
  ignore now states why it is there and what would let it be removed.
- The in-memory cache encodes entries with `postcard` instead of `bincode`, and the
  encoding is covered by round-trip tests — including that corrupt bytes are rejected
  rather than decoded into a partial entry and returned as a cache hit.

- **The workspace could not be built.** `rust-version = "1.95"` exceeded every available
  toolchain, and with `--ignore-rust-version` the build still failed because
  `utoipa-swagger-ui`'s build script downloads a zip over the network at compile time.
- **Transactions silently discarded writes.** `begin_transaction()` on the in-memory
  backend returned a transaction whose `store`, `update` and `delete` were `Ok(())` no-ops;
  a caller that committed was told it had succeeded.
- **One failing webhook aborted secret expiry.** `trigger_lifecycle_hook` propagated errors
  with `?`, so an unreachable third-party endpoint left expired secrets live and skipped
  every hook after it.
- **Services were resolved by string from a `Box<dyn Any>` registry**, and the router
  resolved the admin service from a field holding the audit logger.
- **CORS defaulted to `allow_origin: ["*"]`** and the router applied `Any` for origins,
  methods and headers — on a secrets manager, out of the box.
- **Sessions were JWTs in `localStorage`**, readable by any injected script.
- **`/metrics` returned hardcoded zeros**, so a dashboard built on it looked healthy.
- **The liveness probe required a bearer token**, because the middleware's list of public
  paths had drifted from the router.
- **Rate limiting silently did nothing** whenever its `init_rate_limiting()` call was
  skipped, and identified clients by the first `X-Forwarded-For` entry, which any client
  can set.
- **5xx bodies could leak connection strings and file paths.**
- Two `try_into().unwrap()` calls panicked on short caller-supplied key material.
- Dynamic database credentials now work. The `postgres` and `mysql` features the engine
  branched on were never declared, so both paths compiled out and the endpoint answered
  "feature disabled" in every build; the MongoDB and Redis paths returned a generated
  username and password without creating any account. PostgreSQL and MySQL are now wired
  with real drivers and integration tests against live servers; MongoDB and Redis are gone.
- MySQL revocation now drops the account on every host it exists for. It dropped only
  `'user'@'%'`, so an account created under any other host survived revocation and stayed
  usable — the one outcome revocation exists to prevent. The host is also configurable
  per role now (`mysql_host`, default `%`) instead of hardcoded.
- Concurrent credential issuance for one role no longer fails with `tuple concurrently
  updated`, and PostgreSQL errors now carry the SQLSTATE and server message instead of
  the literal string "db error".
- Argon2id no longer panics when `parallelism` is absent from a parameter set.
- JWT `iat`/`exp` conversion is checked; a clock before 1970 used to wrap into a token
  that never expired.
- A malformed OIDC URL in configuration is an error rather than a startup panic.
- The cache and the agent's metrics registry use non-poisoning locks; one panicking
  holder no longer turns a cache into a process-wide outage.

### Removed

- `warp`. The process ran two HTTP stacks on two ports because warp is on hyper 0.14 and
  Axum on hyper 1.0; `cargo tree -i warp` now finds nothing and there is no duplicate axum.
- The root `tests/` tree (~30 files). The root manifest is a virtual workspace, so cargo
  never compiled any of it.
- Three orphan crates with no dependents (graphql, enterprise, infrastructure) and four
  stub-only ones (integrations, monitoring, performance, replication).
- 19 of 24 storage backends. Each was a 130–320 line sketch with no tests that returned
  `"Not implemented"` at runtime while being selectable from configuration.
- 8 of 12 authentication methods. None was reachable from a route; the Kubernetes one had
  never been compiled at all, and failed with thirty errors when its feature was enabled.
- All direct use of the `rsa` crate (RUSTSEC-2023-0071), which the manifest already
  claimed not to use. It remains in the tree transitively via `jsonwebtoken`'s provider;
  SECURITY.md documents why that code is unreachable, and a test pins it.
- `nginx/`, `Dockerfile.frontend`, `Trunk.toml`, the `cdn.tailwindcss.com` script, the
  second HTTP client in the WASM bundle, and the `+10` port offset.

### Added

- Leptos SSR with hydration, built by `cargo-leptos` into the same binary. Data flows
  through typed `#[server]` functions; the browser holds no token.
- gRPC on `tonic` 0.14 merged into the shared Axum router, with health checking,
  reflection, and the `AuthService::Login` the proto had always declared but never
  implemented.
- Configuration validated at startup: a missing or short JWT secret, a wildcard CORS
  origin, or a zero timeout stops the process rather than surfacing later.
- Property-based tests for the cryptographic primitives (AEAD round-trip, tamper
  detection, nonce reuse, Shamir quorum behaviour).
- `AGENTS.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CODEOWNERS`, issue and PR templates,
  and three ADRs recording the single-router, Leptos-SSR and gRPC decisions.
- Rebuilt CI: concurrency groups, a wasm guardrail job, a feature matrix, SHA-pinned
  third-party actions, and `--locked` everywhere. `Cargo.lock` is now committed.
- A single multi-stage `Dockerfile` producing a distroless, non-root image on one port.

## [0.1.0] - 2026-05-20

Initial release.
