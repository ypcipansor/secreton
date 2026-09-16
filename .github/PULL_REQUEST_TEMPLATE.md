## What changed

<!-- What this does, and why. Link the issue if there is one. -->

## Verification

<!-- Tick only what you actually ran. An unticked box is information, not a failure. -->

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --locked --all-targets -- -D warnings`
- [ ] `cargo test --workspace --locked`
- [ ] `cargo check -p secreton-ui --locked --target wasm32-unknown-unknown --no-default-features --features hydrate`
- [ ] Ran the app (`cargo leptos serve`) and exercised the change

## Security

- [ ] No new build-time network access
- [ ] No secret, token or key material added to a log line, `Debug` impl or error message
- [ ] Secret-touching paths emit an audit event, including on denial
- [ ] Any new dependency is declared in `[workspace.dependencies]`

## Not covered

<!-- What you did not test, and anything a reviewer should look at closely. -->
