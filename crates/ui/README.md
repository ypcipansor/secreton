# Secreton UI

The `secreton-ui` crate contains the web user interface for Secreton, implemented with Leptos for client-side features. The UI is an optional component of the workspace and is gated behind the `client` feature.

## Building the UI (WASM)

To compile the UI for a WASM target, install the wasm32 target and enable the `client` feature:

```bash
rustup target add wasm32-unknown-unknown
cargo build --manifest-path crates/ui/Cargo.toml --features client --target wasm32-unknown-unknown --release
```

This builds the Leptos client components and generates a WASM binary. You can then use `wasm-bindgen` (or `trunk`) to create a final bundle for the web if desired.

## Building the server and workspace

The `client` feature is optional, so the rest of the workspace (server, api, cli, core crates) will build and test normally without installing `wasm32` or enabling `client`.

```bash
cargo build --workspace
cargo test --workspace
```

## Notes

- The `client` feature is intended for browser-side components only. It avoids compiling `leptos` and wasm-only code on native host builds to prevent compile-time failures on CI or local machines without the wasm toolchain.
- If you want the client artifacts to be part of the release, we added a `client-build` CI job that builds the UI for the wasm target in CI. If you would like the build process to additionally package front-end artifacts, we can extend the CI steps to use `wasm-bindgen` / `wasm-pack` or `trunk`.