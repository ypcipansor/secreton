//! SSH secret engine: signs client and host certificates against a CA key.

pub mod engine;
pub mod error;
pub mod model;
pub mod service;

pub use engine::SshEngine;
pub use error::SecretError;
pub use model::SshConfig;
pub use service::SecretEngine;
