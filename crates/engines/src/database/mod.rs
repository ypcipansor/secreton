//! Database secret engine: issues short-lived database credentials on demand.

pub mod engine;
pub mod error;
pub mod model;

pub use engine::DatabaseEngine;
pub use error::DatabaseError;
pub use model::{DatabaseConfig, DatabaseRole, DatabaseType};
