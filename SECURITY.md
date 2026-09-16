# Security Policy

## Reporting a vulnerability

**Do not open a public issue.**

Report privately through GitHub's
[Report a vulnerability](https://github.com/analisaperlengkapan/secreton/security/advisories/new)
form. Include the affected version or commit, what an attacker gains, and a reproduction
if you have one.

Expect an acknowledgement within 72 hours and an assessment within 7 days. We will tell
you when a fix is released and credit you in the advisory unless you ask us not to.

## Supported versions

Secreton is pre-1.0 and under active development. Only `main` receives security fixes.
It is not yet suitable for production use.

## Design commitments

These are enforced by review and by the checks in `.github/workflows/security.yml`:

- **No reachable RSA.** Nothing in this codebase constructs or uses an RSA key:
  signing is Ed25519, or P-256/P-384 where interoperability requires a NIST curve.
  The `rsa` crate is nevertheless *present in the dependency tree*, pulled in by
  `jsonwebtoken`'s `rust_crypto` provider — jsonwebtoken 10 installs its provider from
  exactly one of `rust_crypto` or `aws_lc_rs`, and the alternative is a C dependency.
  RUSTSEC-2023-0071 is a timing side channel in RSA operations, and those operations
  are unreachable here: JWT validation uses `Validation::new(Algorithm::HS256)`, whose
  allowlist rejects every RS*/PS* token before a key is constructed. This is pinned by
  `only_hs256_tokens_are_accepted` in `crates/auth/src/jwt.rs` and recorded as a
  documented ignore in `deny.toml`. Do not describe this as "RSA removed".
- **Hermetic builds.** No build script may fetch anything over the network. A dependency
  that does is not admissible, regardless of convenience.
- **Committed lockfile.** `Cargo.lock` is in the repository and every CI and Docker
  command runs with `--locked`, so an advisory scan describes the artifact that ships.
- **Browser sessions are cookies.** `httpOnly`, `Secure`, `SameSite=Lax`. Tokens are
  never placed in `localStorage`, where any injected script can read them.
- **CORS is an allowlist.** Never `Any`.
- **Server errors are opaque.** A 5xx response body carries a fixed string; details go to
  the log, correlated by `x-request-id`.
- **Secrets are zeroed.** Key material and plaintext implement `Zeroize` and never appear
  in a `Debug` impl, a log line, or an error message.

## Known limitations

Documented rather than hidden, because knowing them is part of assessing the project:

- The Raft storage backend is single-node and experimental; it has no cluster membership
  changes and no leader election across processes.
- MFA delivery services (SMS, email, push) ship with in-memory implementations intended
  for development. Wire real providers before relying on them.
- The identity store is in-memory by default.
