// use mongodb;

use crate::error::*;
use serde_json::Value;
use std::collections::HashMap;

/// MongoDB database backend
#[allow(dead_code)]
pub struct MongodbBackend {
    connection_string: String,
}

impl MongodbBackend {
    pub fn new(connection_string: String) -> Self {
        Self { connection_string }
    }

    /// Test connection to MongoDB
    pub async fn test_connection(&self) -> SecretResult<()> {
        Err(SecretError::BackendNotSupported(
            "MongoDB backend requires mongodb crate which is not available".to_string(),
        ))
    }

    /// Create a database user with specified privileges
    pub async fn create_user(
        &self,
        _username: &str,
        _password: &str,
        _role_sql: &str,
    ) -> SecretResult<()> {
        Err(SecretError::BackendNotSupported(
            "MongoDB backend requires mongodb crate which is not available".to_string(),
        ))
    }

    /// Revoke database user
    pub async fn revoke_user(&self, _username: &str) -> SecretResult<()> {
        Err(SecretError::BackendNotSupported(
            "MongoDB backend requires mongodb crate which is not available".to_string(),
        ))
    }

    /// Generate dynamic credentials
    pub async fn generate_credentials(
        &self,
        _role_name: &str,
        _role_sql: &str,
    ) -> SecretResult<HashMap<String, Value>> {
        Err(SecretError::BackendNotSupported(
            "MongoDB backend requires mongodb crate which is not available".to_string(),
        ))
    }
}
