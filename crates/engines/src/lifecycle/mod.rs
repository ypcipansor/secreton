//! Secret lifecycle: expiry, grace period, archival and webhook hooks.
//!
//! Recovered from the deleted `secreton-integrations` crate. It is the one part of that
//! crate the running server actually used, so it lives here next to its only consumer
//! (`services::lifecycle`) rather than behind a crate boundary.

pub mod manager;

pub use manager::{
    ArchiveRecord, ExpirationPolicy, HookType, LifecycleConfig, LifecycleHook,
    SecretLifecycleManagement,
};
