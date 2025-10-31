//! # Secreton Replication
//!
//! Unified replication system providing both Disaster Recovery and Performance replication
//! across Secreton clusters.

pub mod common;
pub mod disaster_recovery;
pub mod error;
pub mod performance;

pub use common::*;
pub use disaster_recovery::DisasterRecoveryService;
pub use error::*;
pub use performance::PerformanceReplication;
