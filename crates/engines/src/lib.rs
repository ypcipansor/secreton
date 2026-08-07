//! # Secreton Engines
//!
//! The business logic of the platform: secret engines (KV v2, transit, PKI, SSH, database,
//! TOTP), the seal, the audit pipeline, and the services that orchestrate them.
//!
//! Nothing here knows about HTTP. Every type takes and returns domain values, which is what
//! lets the same service back a REST handler, a gRPC method and a Leptos server function
//! without a translation layer in between. Transport lives in `secreton-server`.

pub mod audit_config;
pub mod config;
pub mod database;
pub mod lifecycle;
pub mod performance;
pub mod pki;
pub mod services;

#[cfg(test)]
pub(crate) mod test_support;
pub mod telemetry;
pub mod ssh;

pub use config::ServerConfig;
pub use services::Services;
