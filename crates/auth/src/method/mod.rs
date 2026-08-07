//! Authentication methods.
//!
//! The set is deliberately small and each entry is reachable from a route:
//!
//! - `userpass`  — username and password, the bootstrap path
//! - `approle`   — role id plus secret id, for machine-to-machine authentication
//! - `oidc`      — human SSO against an OpenID Connect provider
//!
//! Eight further methods (LDAP, GitHub, Okta, AWS IAM, SAML, RADIUS, X.509, Kubernetes)
//! previously lived here. None was reachable from a route. The Kubernetes one had never
//! been compiled at all — its feature was never enabled in CI — and contained API misuse
//! that only surfaced when the feature was finally turned on
//! (`Api::all(client.to_string())`, among thirty errors). They were removed rather than
//! left to imply support that did not exist; the `AuthMethod` trait is the extension
//! point for adding one back, with tests and a CI job that builds its feature.

pub mod approle;
#[cfg(feature = "oidc")]
pub mod oidc;
pub mod userpass;

pub use approle::*;
#[cfg(feature = "oidc")]
pub use oidc::*;
pub use userpass::*;
