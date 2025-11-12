//! Database Secret Engines
//!
//! This crate provides database secret engines for dynamic credential generation
//! in database systems like PostgreSQL, MySQL, MongoDB, and Redis.

pub mod engine;
pub mod error;
pub mod model;

// Re-export main types
pub use engine::DatabaseEngine;
pub use error::DatabaseError;
pub use model::{DatabaseConfig, DatabaseRole, DatabaseType};
