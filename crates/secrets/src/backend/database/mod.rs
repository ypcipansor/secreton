//! Database backend implementations

use crate::error::SecretResult;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

pub mod mongodb;
pub mod mysql;
pub mod postgres;

pub use mongodb::*;
pub use mysql::*;
pub use postgres::*;

/// Database backend trait
#[async_trait]
pub trait DatabaseBackend: Send + Sync {
    /// Generate credentials for a specific role
    async fn generate_credentials(
        &self,
        role_name: &str,
        role_sql: &str,
    ) -> SecretResult<HashMap<String, Value>>;

    /// Test the connection to the database
    async fn test_connection(&self) -> SecretResult<()>;

    /// Revoke credentials (user)
    async fn revoke_credentials(&self, username: &str) -> SecretResult<()>;
}
