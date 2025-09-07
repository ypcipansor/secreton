//! Secrets engine module for Brankas Adhyaksa
//!
//! This module provides the core abstractions and implementations for different
//! types of secrets engines.

mod database;
mod kv;
mod memory;
mod pki; // Re-enabled for PKI certificate management
mod ssh;
mod totp;
pub mod transit;

use crate::storage::StorageEngine;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

// Import macros
use tracing::error;

// Import AppError from the re-export
use crate::AppError;

pub use database::DatabaseEngine;
pub use kv::KVSecretsEngine;
pub use memory::MemorySecretsEngine;
pub use pki::PkiSecretsEngine; // Re-enabled for PKI certificate management
pub use ssh::SshSecretsEngine;
pub use totp::TotpSecretsEngine;
pub use transit::TransitSecretsEngine;
pub use transit::{CreateKeyRequest, DecryptRequest, EncryptRequest};

/// Common error type for secrets engine operations
#[derive(Error, Debug)]
pub enum SecretsError {
    #[error("Secret not found: {0}")]
    NotFound(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Invalid secret data: {0}")]
    InvalidData(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Execution error: {0}")]
    ExecutionError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<crate::error::CoreError> for SecretsError {
    fn from(error: crate::error::CoreError) -> Self {
        match error {
            crate::error::CoreError::NotFound { resource } => SecretsError::NotFound(resource),
            crate::error::CoreError::Authorization { message } => {
                SecretsError::PermissionDenied(message)
            }
            crate::error::CoreError::Validation { message } => SecretsError::InvalidData(message),
            _ => SecretsError::ExecutionError(format!("Core error: {:?}", error)),
        }
    }
}

/// Metadata about a secret
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecretMetadata {
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub version: u32,
    pub ttl: Option<i64>, // dalam detik
    pub expired_at: Option<chrono::DateTime<chrono::Utc>>,
    pub custom_metadata: Option<HashMap<String, String>>,
}

/// A secret with its data and metadata
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Secret {
    pub id: Uuid,
    pub path: String,
    pub data: Value,
    pub metadata: SecretMetadata,
}

/// Trait that all secrets engines must implement
#[async_trait]
pub trait SecretsEngine: Send + Sync + 'static {
    /// Get the type of the secrets engine
    fn engine_type(&self) -> &'static str;

    /// Create a new secret
    async fn create_secret(
        &self,
        path: &str,
        data: Value,
        options: Option<Value>,
    ) -> Result<Secret, SecretsError>;

    /// Read a secret
    async fn read_secret(&self, path: &str) -> Result<Secret, SecretsError>;

    /// Update a secret
    async fn update_secret(
        &self,
        path: &str,
        data: Value,
        options: Option<Value>,
    ) -> Result<Secret, SecretsError>;

    /// Delete a secret
    async fn delete_secret(&self, path: &str) -> Result<(), SecretsError>;

    /// List secrets under a path
    async fn list_secrets(&self, path: &str) -> Result<Vec<String>, SecretsError>;
}

/// Type alias for a boxed secrets engine
pub type BoxedSecretsEngine = Box<dyn SecretsEngine>;

/// Registry of available secrets engines
#[derive(Default)]
pub struct SecretsEngineRegistry {
    engines: std::sync::RwLock<HashMap<String, Arc<BoxedSecretsEngine>>>,
}

impl SecretsEngineRegistry {
    /// Create a new registry
    pub fn new() -> Self {
        Self {
            engines: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Register a new secrets engine
    pub fn register(&self, engine: impl SecretsEngine) -> Result<(), AppError> {
        let engine_type = engine.engine_type().to_string();
        let mut engines = self.engines.write().map_err(|_| {
            AppError::InternalError("Failed to acquire write lock on engines registry".to_string())
        })?;

        if engines.contains_key(&engine_type) {
            return Err(AppError::BadRequest(format!(
                "Secrets engine '{}' is already registered",
                engine_type
            )));
        }

        engines.insert(
            engine_type,
            Arc::new(Box::new(engine) as BoxedSecretsEngine),
        );
        Ok(())
    }

    /// Get a secrets engine by type
    pub fn get_engine(&self, engine_type: &str) -> Option<Arc<BoxedSecretsEngine>> {
        self.engines.read().ok()?.get(engine_type).cloned()
    }
}

/// Initialize the default secrets engines
pub async fn init_default_engines(
    data_dir: impl AsRef<Path>,
    _with_memory: bool,
) -> Result<SecretsEngineRegistry, AppError> {
    let registry = SecretsEngineRegistry::new();

    // Create storage instance using test utilities
    use std::collections::HashMap;

    #[derive(Debug)]
    struct TestStorageEngine {
        data: Arc<tokio::sync::RwLock<HashMap<String, crate::storage::StorageEntry>>>,
    }

    #[async_trait::async_trait]
    impl StorageEngine for TestStorageEngine {
        async fn get(
            &self,
            key: &str,
        ) -> Result<Option<crate::storage::StorageEntry>, crate::error::CoreError> {
            let data = self.data.read().await;
            Ok(data.get(key).cloned())
        }

        async fn put(
            &self,
            entry: crate::storage::StorageEntry,
        ) -> Result<(), crate::error::CoreError> {
            let mut data = self.data.write().await;
            data.insert(entry.key.clone(), entry);
            Ok(())
        }

        async fn delete(&self, key: &str) -> Result<(), crate::error::CoreError> {
            let mut data = self.data.write().await;
            data.remove(key);
            Ok(())
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, crate::error::CoreError> {
            let data = self.data.read().await;
            Ok(data
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    let storage: Arc<RwLock<dyn StorageEngine + Send + Sync>> =
        Arc::new(RwLock::new(TestStorageEngine {
            data: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }));

    // Initialize and register the KV secrets engine
    let kv_base_path = data_dir.as_ref().join("kv");
    let kv_engine = KVSecretsEngine::new(kv_base_path)?;
    registry.register(kv_engine)?;

    // Initialize and register the SSH secrets engine
    let ssh_engine = SshSecretsEngine::new(storage.clone()).await?;
    registry.register(ssh_engine)?;

    // Initialize and register the TOTP secrets engine
    let totp_engine = TotpSecretsEngine::new(storage.clone()).await?;
    registry.register(totp_engine)?;

    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_secrets_engine_registry() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let registry = init_default_engines(temp_dir.path(), false).await?;

        // Test getting the KV engine
        let kv_engine = registry.get_engine("kv");
        assert!(kv_engine.is_some());

        // Test getting a non-existent engine
        let non_existent = registry.get_engine("nonexistent");
        assert!(non_existent.is_none());

        Ok(())
    }
}
