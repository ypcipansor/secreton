//! Individual authentication method implementations

pub mod approle;
#[cfg(feature = "aws")]
pub mod aws;
pub mod certificate;
pub mod github;
#[cfg(feature = "kubernetes")]
pub mod kubernetes;
#[cfg(feature = "ldap")]
pub mod ldap;
#[cfg(feature = "oidc")]
pub mod oidc;
pub mod okta;
#[cfg(feature = "radius")]
pub mod radius;
#[cfg(feature = "saml")]
pub mod saml;
pub mod userpass;

pub use approle::*;
#[cfg(feature = "aws")]
pub use aws::*;
pub use certificate::*;
pub use github::*;
#[cfg(feature = "kubernetes")]
pub use kubernetes::*;
#[cfg(feature = "ldap")]
pub use ldap::*;
#[cfg(feature = "oidc")]
pub use oidc::*;
pub use okta::*;
#[cfg(feature = "radius")]
pub use radius::*;
#[cfg(feature = "saml")]
pub use saml::*;
pub use userpass::*;
