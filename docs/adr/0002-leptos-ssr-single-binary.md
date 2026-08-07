# 2. Leptos SSR with hydration, in one crate

Date: 2026-08-06 · Status: accepted

## Context

The UI was client-side rendered only (`leptos = { features = ["csr"] }`): no
`leptos_axum`, no server functions, no `cargo-leptos`. It shipped an empty `<body>` and
built the page in WebAssembly after load. It pulled Tailwind from `cdn.tailwindcss.com`
at runtime — a build tool never meant for production, and a third-party script with full
DOM access on pages that render secrets, which also made `tailwind.config.js` inert.

Data fetching went through a hand-written `reqwest` client in WASM (alongside `gloo-net`,
already a dependency) that parsed responses by trying `ApiResponse<T>` and falling back to
raw `T`, because the warp and Axum halves of the API returned different envelopes. The
session JWT lived in `localStorage`, readable by any injected script.

## Decision

Leptos 0.8 with `leptos_axum`, built by `cargo-leptos` into one binary that serves both
rendered HTML and the WASM bundle. Data fetching moves to `#[server]` functions, which
share their request and response types with the backend so a mismatch is a compile error.
Tailwind is compiled locally. Browser sessions become `httpOnly`, `Secure`, `SameSite=Lax`
cookies; `Authorization: Bearer` remains for the CLI, the agent and other services.

`crates/ui` is a single crate with `crate-type = ["cdylib", "rlib"]` and `ssr`/`hydrate`
features, not the three-crate split the official workspace template uses. That template
separates `app` from a thin `frontend` cdylib to stop feature unification enabling `ssr`
during the WASM build and to keep the app crate a pure rlib. Neither applies here: only
`secreton-server` depends on `secreton-ui`, and `cargo-leptos` invokes the WASM build as
a separate `--target wasm32-unknown-unknown` compilation.

The guardrail that crate would have provided is a CI job instead:
`cargo check -p secreton-ui --target wasm32-unknown-unknown --no-default-features
--features hydrate`. It fails if a server-only dependency leaks into the UI.

The UI is deliberately *not* merged into `secreton-server`. In that shape every server
dependency — postgres, redis, tonic, tokio — must be `optional = true` behind `ssr`, and
one forgotten `optional` breaks the WASM build. A crate boundary makes that structural
rather than a matter of discipline.

## Consequences

First paint no longer waits on WASM. The double-parse heuristic, the second HTTP client
and the CDN dependency are all gone. The cost is that `crates/ui` must compile for two
targets, which the CI job enforces on every pull request.
