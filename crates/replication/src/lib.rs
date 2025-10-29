//! # Secreton Replication
//!
//! Unified replication system providing both Disaster Recovery and Performance replication
//! across Secreton clusters.

pub mod disaster_recovery;
pub mod performance;
pub mod common;
pub mod error;

pub use disaster_recovery::DisasterRecoveryService;
pub use performance::PerformanceReplication;
pub use common::*;
pub use error::*;