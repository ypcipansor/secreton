//! Secrets module

#[path = "../secrets/mod.rs"]
pub mod secrets_impl;

// Re-export engine module from secrets_impl
pub use secrets_impl::engine;
