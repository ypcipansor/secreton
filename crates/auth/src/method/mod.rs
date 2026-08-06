//! Authentication methods.
//!
//! The set is deliberately small and each entry is reachable from a route:
//!
//! - `userpass`  — username and password, the bootstrap path
//! - `approle`   — role id plus secret id, for machine-to-machine authentication
//! - `oidc`      — human SSO against an OpenID Connect provider
//! - `kubernetes`— workload identity via a projected service-account token
//!
//! Seven further methods (LDAP, GitHub, Okta, AWS IAM, SAML, RADIUS, X.509) previously
//! lived here as unwired, untested implementations that no route could reach. They were
//! removed rather than left to imply support that did not exist; the `AuthMethod` trait
//! is the extension point for adding one back with tests.

pub mod approle;
#[cfg(feature = "kubernetes")]
pub mod kubernetes;
#[cfg(feature = "oidc")]
pub mod oidc;
pub mod userpass;

pub use approle::*;
#[cfg(feature = "kubernetes")]
pub use kubernetes::*;
#[cfg(feature = "oidc")]
pub use oidc::*;
pub use userpass::*;
