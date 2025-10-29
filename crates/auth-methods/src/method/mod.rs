//! Individual authentication method implementations

pub mod certificate;
pub mod userpass;
#[cfg(feature = "ldap")]
pub mod ldap;
#[cfg(feature = "oidc")]
pub mod oidc;
pub mod approle;
#[cfg(feature = "kubernetes")]
pub mod kubernetes;
#[cfg(feature = "aws")]
pub mod aws;
pub mod github;
pub mod okta;
#[cfg(feature = "radius")]
pub mod radius;
#[cfg(feature = "saml")]
pub mod saml;

pub use certificate::*;
pub use userpass::*;
#[cfg(feature = "ldap")]
pub use ldap::*;
#[cfg(feature = "oidc")]
pub use oidc::*;
pub use approle::*;
#[cfg(feature = "kubernetes")]
pub use kubernetes::*;
#[cfg(feature = "aws")]
pub use aws::*;
pub use github::*;
pub use okta::*;
#[cfg(feature = "radius")]
pub use radius::*;
#[cfg(feature = "saml")]
pub use saml::*;