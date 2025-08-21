//! Secrets engine module for Brankas Adhyaksa
//! 
//! This module provides the core abstractions and implementations for different
//! types of secrets engines.


mod kv;
mod memory;

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

pub use kv::KVSecretsEngine;
pub use memory::MemorySecretsEngine;

/// Common error type for secrets engine operations
#[derive(Error, Debug)]
pub enum SecretsError {
    #[error("Secret not found")]
    NotFound,
    
    #[error("Permission denied")]
    PermissionDenied,
    
    #[error("Invalid secret data: {0}")]
    InvalidData(String),
    
    #[error(transparent)]
    Io(#[from] std::io::Error),
    
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    
    #[error(transparent)]
    Other(#[from] anyhow::Error),
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
type BoxedSecretsEngine = Box<dyn SecretsEngine>;

/// Registry of available secrets engines
#[derive(Default)]
pub struct SecretsEngineRegistry {
    engines: std::sync::RwLock<HashMap<String, Arc<BoxedSecretsEngine>>>>,
}

impl SecretsEngineRegistry {
    /// Create a new registry
    pub fn new() -> Self {
        Self {
            engines: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Register a new secrets engine
    pub fn register(&self, engine: impl SecretsEngine) -> Result<(), crate::error::AppError> {
        let engine_type = engine.engine_type().to_string();
        let mut engines = self.engines.write().map_err(|_| {
            crate::error::AppError::InternalServerError(
                "Failed to acquire write lock on engines registry".to_string(),
            )
        })?;
        
        if engines.contains_key(&engine_type) {
            return Err(crate::error::AppError::BadRequest(format!(
                "Secrets engine '{}' is already registered",
                engine_type
            )));
        }
        
        engines.insert(engine_type, Arc::new(Box::new(engine) as BoxedSecretsEngine));
        Ok(())
    }

    /// Get a secrets engine by type
    pub fn get_engine(&self, engine_type: &str) -> Option<Arc<BoxedSecretsEngine>>> {
        self.engines.read().ok()?.get(engine_type).cloned()
    }
}

/// Initialize the default secrets engines
pub fn init_default_engines(
    data_dir: impl AsRef<Path>,
    with_memory: bool,
) -> Result<SecretsEngineRegistry, crate::error::AppError> {
    let registry = SecretsEngineRegistry::new();
    // Register in-memory secrets engine (optional, for zero trust/memory-only mode)
    if with_memory {
        let mem_engine = MemorySecretsEngine::new();
        registry.register(mem_engine)?;
    }
    // Initialize and register the KV secrets engine
    let kv_engine = KVSecretsEngine::new(data_dir.as_ref().join("secrets"))?;
    registry.register(kv_engine)?;
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use serde_json::json;

    #[tokio::test]
    async fn test_secrets_engine_registry() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let registry = init_default_engines(temp_dir.path())?;
        
        // Test getting the KV engine
        let kv_engine = registry.get_engine("kv");
        assert!(kv_engine.is_some());
        
        // Test getting a non-existent engine
        let non_existent = registry.get_engine("nonexistent");
        assert!(non_existent.is_none());
        
        Ok(())
    }
}
