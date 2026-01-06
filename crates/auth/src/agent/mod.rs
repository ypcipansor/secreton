//! Agent authentication and templating

#[allow(clippy::module_inception)]
pub mod agent;
pub mod service;
pub mod template;

pub use agent::*;
pub use service::*;
pub use template::*;
