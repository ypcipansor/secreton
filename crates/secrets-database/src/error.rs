//! Database-specific errors

use thiserror::Error;

/// Database-specific errors
#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("Invalid database configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Query execution failed: {0}")]
    QueryFailed(String),

    #[error("Role not found: {0}")]
    RoleNotFound(String),

    #[error("Unsupported database type: {0}")]
    UnsupportedDatabaseType(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Storage error: {0}")]
    Storage(#[from] Box<dyn std::error::Error + Send + Sync>),

    #[error("Database engine is disabled")]
    EngineDisabled,
}
